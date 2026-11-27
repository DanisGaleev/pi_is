import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.container import container
from app.enums import Channel, DeliveryStatus, IncidentStatus, Role, Severity, SourceType
from app.integration.adapters import TelegramAdapter
from main import app


class TestTelegramAdapterTransport(unittest.TestCase):
    def test_in_memory_and_bot_api_transport(self) -> None:
        # In-memory fallback without token or transport
        local = TelegramAdapter()
        self.assertTrue(local.send_message("12345", "Привет"))
        self.assertEqual(local.sent_messages, [{"user": "12345", "text": "Привет"}])
        self.assertFalse(local.send_message("", "text"))
        self.assertFalse(local.send_message("12345", "   "))

        # Custom transport simulating Bot API
        calls: list[tuple[str, dict[str, Any]]] = []

        def ok_transport(method: str, payload: dict[str, Any]) -> dict[str, Any]:
            calls.append((method, payload))
            if method == "getMe":
                return {"ok": True, "result": {"id": 99, "username": "ib_notice_bot"}}
            return {"ok": True, "result": {"message_id": 1}}

        api = TelegramAdapter(bot_token="123:ABC", transport=ok_transport)
        me = api.get_me()
        self.assertTrue(me["ok"])
        self.assertEqual(me["result"]["username"], "ib_notice_bot")

        long_text = "A" * 5000
        self.assertTrue(api.send_message("-100555", long_text, parse_mode="HTML"))
        method, payload = calls[-1]
        self.assertEqual(method, "sendMessage")
        self.assertEqual(payload["chat_id"], "-100555")
        self.assertEqual(payload["parse_mode"], "HTML")
        self.assertLessEqual(len(payload["text"]), TelegramAdapter.MAX_MESSAGE_LENGTH)

        # Failing transport returns False and records last_error
        def fail_transport(_method: str, _payload: dict[str, Any]) -> dict[str, Any]:
            return {"ok": False, "description": "Forbidden: bot was blocked by the user"}

        failing = TelegramAdapter(bot_token="123:ABC", transport=fail_transport)
        self.assertFalse(failing.send_message("123", "test"))
        self.assertIn("blocked", failing.last_error or "")


class TestTelegramNotificationServiceApi(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        self._prev_env = {
            k: os.environ.get(k)
            for k in (
                "TELEGRAM_BOT_TOKEN",
                "TELEGRAM_CHAT_ID",
                "TELEGRAM_WEBHOOK_SECRET",
                "TELEGRAM_ENABLED",
                "TELEGRAM_INCLUDE_PDN",
                "APP_BASE_URL",
            )
        }
        for k in self._prev_env:
            os.environ.pop(k, None)

        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_tg.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

        self.tg_calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_chats: set[str] = set()
        self.fake_updates: list[dict[str, Any]] = []

        tg = container.adapters[SourceType.TELEGRAM]
        assert isinstance(tg, TelegramAdapter)
        self.tg_adapter = tg
        self.tg_adapter.sent_messages.clear()
        self.tg_adapter.last_error = None
        self.tg_adapter._transport = self._fake_transport

        self.ib_hdr = self._login("ib")
        self.sys_hdr = self._login("sysadmin")
        self.head_hdr = self._login("it_head")
        self.lawyer_hdr = self._login("lawyer")

    def tearDown(self) -> None:
        self.tg_adapter._transport = None
        self.tg_adapter.last_error = None
        self.tg_adapter.sent_messages.clear()
        self._client_cm.__exit__(None, None, None)

        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        for k, v in self._prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp_dir.cleanup()

    def _fake_transport(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.tg_calls.append((method, payload))
        if method == "getMe":
            return {"ok": True, "result": {"id": 777, "is_bot": True, "username": "sec_alert_bot"}}
        if method == "getUpdates":
            return {"ok": True, "result": list(self.fake_updates)}
        if method == "setWebhook":
            return {"ok": True, "result": True, "description": "Webhook was set"}
        if method == "sendMessage":
            chat_id = str(payload.get("chat_id", ""))
            if chat_id in self.fail_chats:
                return {"ok": False, "description": "Bad Request: chat not found"}
            return {"ok": True, "result": {"message_id": len(self.tg_calls), "chat": {"id": chat_id}}}
        return {"ok": True, "result": True}

    def _login(self, username: str) -> dict[str, str]:
        resp = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": "password123"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        return {"Authorization": f"Bearer {resp.json()['token']}"}

    def test_rbac_and_config_masking(self) -> None:
        self.assertEqual(self.client.get("/api/telegram/config").status_code, 401)
        self.assertEqual(self.client.get("/api/telegram/config", headers=self.sys_hdr).status_code, 403)
        self.assertEqual(self.client.get("/api/telegram/config", headers=self.lawyer_hdr).status_code, 403)
        self.assertEqual(
            self.client.post(
                "/api/telegram/subscriptions",
                json={"chat_id": "1001"},
                headers=self.sys_hdr,
            ).status_code,
            403,
        )

        # Save token & config via IB specialist; verify response masks secret
        upd = self.client.put(
            "/api/telegram/config",
            json={
                "bot_token": "987654321:AAHSecretBotTokenXYZ",
                "enabled": True,
                "webhook_secret": "my-webhook-secret-token",
                "app_base_url": "https://sec.example.local/",
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(upd.status_code, 200, upd.text)
        cfg = upd.json()
        self.assertTrue(cfg["has_token"])
        self.assertEqual(cfg["token_source"], "db")
        self.assertNotIn("AAHSecretBotTokenXYZ", cfg["bot_token"])
        self.assertNotIn("my-webhook-secret-token", cfg["webhook_secret"])
        self.assertEqual(cfg["app_base_url"], "https://sec.example.local")

        # Verify & discover chats via IT head
        ver = self.client.post("/api/telegram/verify", headers=self.head_hdr)
        self.assertEqual(ver.status_code, 200, ver.text)
        self.assertTrue(ver.json()["connected"])
        self.assertEqual(ver.json()["bot"]["username"], "sec_alert_bot")

        self.fake_updates = [
            {
                "update_id": 10,
                "message": {
                    "chat": {"id": -100112233, "type": "supergroup", "title": "SOC Alerts"},
                    "text": "/start",
                },
            }
        ]
        disc = self.client.get("/api/telegram/discover", headers=self.ib_hdr)
        self.assertEqual(disc.status_code, 200, disc.text)
        self.assertEqual(len(disc.json()), 1)
        self.assertEqual(disc.json()[0]["chat_id"], "-100112233")
        self.assertFalse(disc.json()[0]["already_subscribed"])

    def test_subscription_rbac_incident_create_status_pdn_and_fail_isolation(self) -> None:
        self.client.put(
            "/api/telegram/config",
            json={
                "bot_token": "111:TOKEN",
                "enabled": True,
                "app_base_url": "https://soc.corp.local",
            },
            headers=self.ib_hdr,
        )

        # Sysadmin subscription cannot enable include_pdn
        bad_sub = self.client.post(
            "/api/telegram/subscriptions",
            json={
                "chat_id": "2001",
                "label": "Sysadmin",
                "role": Role.SYS_ADMIN.value,
                "include_pdn": True,
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(bad_sub.status_code, 400)

        # Create 3 subscriptions:
        # 1) IB SOC chat (all severities, includes PDn)
        # 2) Sysadmin chat (high+, no PDn)
        # 3) Lawyer chat (PDn only)
        s_ib = self.client.post(
            "/api/telegram/subscriptions",
            json={
                "chat_id": "-1001",
                "label": "SOC IB",
                "role": Role.SECURITY_SPECIALIST.value,
                "min_severity": "low",
                "include_pdn": True,
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(s_ib.status_code, 200, s_ib.text)
        s_sys = self.client.post(
            "/api/telegram/subscriptions",
            json={
                "chat_id": "2002",
                "label": "Sysadmin Alert",
                "role": Role.SYS_ADMIN.value,
                "min_severity": "high",
                "include_pdn": False,
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(s_sys.status_code, 200, s_sys.text)
        s_law = self.client.post(
            "/api/telegram/subscriptions",
            json={
                "chat_id": "3003",
                "label": "Lawyer PDn",
                "role": Role.LAWYER.value,
                "min_severity": "low",
                "include_pdn": True,
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(s_law.status_code, 200, s_law.text)

        # Test notification endpoint
        test_res = self.client.post(
            "/api/telegram/test",
            json={"chat_id": "-1001", "message": "Проверка связи"},
            headers=self.ib_hdr,
        )
        self.assertEqual(test_res.status_code, 200, test_res.text)
        self.assertTrue(test_res.json()["ok"])
        self.assertEqual(test_res.json()["sent"], 1)

        self.tg_calls.clear()

        # 1. Medium non-PDn signal with HTML special chars -> only IB chat receives (sys min=high, lawyer PDn-only)
        r_med = self.client.post(
            "/api/signals",
            json={
                "source": "mail_gateway",
                "body": "Фишинг <script>alert(1)</script> & ссылка",
                "computer": "WS-01",
                "severity": "medium",
            },
        )
        self.assertEqual(r_med.status_code, 200, r_med.text)
        med_id = r_med.json()["incident_id"]

        sent_to = [p["chat_id"] for m, p in self.tg_calls if m == "sendMessage"]
        self.assertEqual(sent_to, ["-1001"])
        sent_text = self.tg_calls[0][1]["text"]
        self.assertIn("&lt;script&gt;", sent_text)
        self.assertIn(f"#{med_id}", sent_text)
        self.assertIn("https://soc.corp.local/?incident=", sent_text)

        # Duplicate signal does NOT spam Telegram
        self.tg_calls.clear()
        r_dup = self.client.post(
            "/api/signals",
            json={
                "source": "mail_gateway",
                "body": "Повторный сигнал",
                "computer": "WS-01",
                "incident_type": "phishing",
            },
        )
        self.assertTrue(r_dup.json()["deduplicated"])
        self.assertEqual(self.tg_calls, [])

        # 2. Status transitions notify subscribers; no-op same status does not
        st1 = self.client.post(
            f"/api/incidents/{med_id}/status",
            json={"status": IncidentStatus.IN_PROGRESS.value},
            headers=self.ib_hdr,
        )
        self.assertEqual(st1.status_code, 200, st1.text)
        self.assertEqual(len(self.tg_calls), 1)
        self.assertIn("Новый →", self.tg_calls[0][1]["text"])

        self.tg_calls.clear()
        st_noop = self.client.post(
            f"/api/incidents/{med_id}/status",
            json={"status": IncidentStatus.IN_PROGRESS.value},
            headers=self.ib_hdr,
        )
        self.assertEqual(st_noop.status_code, 200)
        self.assertEqual(self.tg_calls, [])

        st_close = self.client.post(
            f"/api/incidents/{med_id}/status",
            json={"status": "closed", "outcome": "Устранен"},
            headers=self.ib_hdr,
        )
        self.assertEqual(st_close.status_code, 200, st_close.text)
        self.assertEqual(len(self.tg_calls), 1)
        self.assertIn("Устранен", self.tg_calls[0][1]["text"])

        # 3. PDn signal -> delivered to IB and Lawyer, NEVER to Sysadmin
        self.tg_calls.clear()
        r_pdn = self.client.post(
            "/api/signals",
            json={
                "source": "dlp",
                "body": "Утечка файла clients_pdn.csv",
                "computer": "SRV-CRM-99",
                "severity": "critical",
                "has_personal_data": 1,
            },
        )
        self.assertEqual(r_pdn.status_code, 200, r_pdn.text)
        self.assertFalse(r_pdn.json()["deduplicated"])
        pdn_id = r_pdn.json()["incident_id"]
        pdn_chats = {p["chat_id"] for m, p in self.tg_calls if m == "sendMessage"}
        self.assertEqual(pdn_chats, {"-1001", "3003"})
        self.assertNotIn("2002", pdn_chats)

        # 4. Telegram outage / blocked chat does NOT break incident creation or status change, and logs FAILED
        self.fail_chats.add("-1001")
        self.tg_calls.clear()
        r_fail = self.client.post(
            "/api/incidents",
            json={
                "title": "Сбой при доставке ТГ",
                "description": "Тест изоляции ошибок",
                "incident_type": "virus",
                "severity": "high",
                "source": "manual",
                "computer": "WS-ERR-01",
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(r_fail.status_code, 200, r_fail.text)
        fail_inc_id = r_fail.json()["id"]

        notifs = self.client.get(
            "/api/notifications",
            params={"incident_id": fail_inc_id},
            headers=self.ib_hdr,
        ).json()
        by_name = {n["recipient_name"]: n for n in notifs}
        self.assertEqual(by_name["SOC IB"]["channel"], Channel.TELEGRAM.value)
        self.assertEqual(by_name["SOC IB"]["status"], DeliveryStatus.FAILED.value)
        self.assertEqual(by_name["Sysadmin Alert"]["status"], DeliveryStatus.SENT.value)

        # 5. Update and delete subscription
        sub_sys_id = s_sys.json()["id"]
        patched = self.client.patch(
            f"/api/telegram/subscriptions/{sub_sys_id}",
            json={"active": False, "min_severity": "critical"},
            headers=self.ib_hdr,
        )
        self.assertEqual(patched.status_code, 200, patched.text)
        self.assertFalse(patched.json()["active"])
        self.assertEqual(patched.json()["min_severity"], Severity.CRITICAL.value)

        deleted = self.client.delete(
            f"/api/telegram/subscriptions/{sub_sys_id}",
            headers=self.ib_hdr,
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["deleted"])

        # Verify PDn incident notifications are recorded in journal
        pdn_notifs = self.client.get(
            "/api/notifications",
            params={"incident_id": pdn_id, "kind": "tg_incident_created"},
            headers=self.ib_hdr,
        ).json()
        self.assertEqual(len(pdn_notifs), 2)

    def test_webhook_commands_and_escalation_routing(self) -> None:
        self.client.put(
            "/api/telegram/config",
            json={
                "bot_token": "111:TOKEN",
                "enabled": True,
                "webhook_secret": "sec-42",
            },
            headers=self.ib_hdr,
        )
        setup = self.client.post(
            "/api/telegram/webhook/setup",
            json={"webhook_url": "https://example.com/api/telegram/webhook"},
            headers=self.ib_hdr,
        )
        self.assertEqual(setup.status_code, 200, setup.text)

        # Wrong secret -> 403
        bad_wh = self.client.post(
            "/api/telegram/webhook",
            json={"update_id": 1, "message": {"chat": {"id": 500}, "text": "/start"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"},
        )
        self.assertEqual(bad_wh.status_code, 403)

        # /start from unsubscribed chat shows chat_id
        start_wh = self.client.post(
            "/api/telegram/webhook",
            json={"update_id": 2, "message": {"chat": {"id": 500}, "text": "/start"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "sec-42"},
        )
        self.assertEqual(start_wh.status_code, 200, start_wh.text)
        self.assertTrue(start_wh.json()["handled"])
        self.assertIn("500", start_wh.json()["reply"])

        # /status from unsubscribed chat is denied
        deny_status = self.client.post(
            "/api/telegram/webhook",
            json={"update_id": 3, "message": {"chat": {"id": 500}, "text": "/status 1"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "sec-42"},
        )
        self.assertIn("не подключён", deny_status.json()["reply"])

        # Subscribe chat 500 as sysadmin (no PDn)
        self.client.post(
            "/api/telegram/subscriptions",
            json={"chat_id": "500", "label": "Sysadmin", "role": Role.SYS_ADMIN.value, "include_pdn": False},
            headers=self.ib_hdr,
        )
        # Incident #1 is non-PDn -> visible; Incident #2 is PDn -> hidden!
        ok_status = self.client.post(
            "/api/telegram/webhook",
            json={"update_id": 4, "message": {"chat": {"id": 500}, "text": "/status 1"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "sec-42"},
        )
        self.assertIn("Инцидент #1", ok_status.json()["reply"])

        pdn_status = self.client.post(
            "/api/telegram/webhook",
            json={"update_id": 5, "message": {"chat": {"id": 500}, "text": "/status 2"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "sec-42"},
        )
        self.assertIn("недоступен", pdn_status.json()["reply"])

        # Escalation check routes to matching Telegram subscriber (it_head)
        self.client.post(
            "/api/telegram/subscriptions",
            json={"chat_id": "600", "label": "IT Head", "role": Role.IT_HEAD.value, "include_pdn": True},
            headers=self.ib_hdr,
        )
        self.tg_calls.clear()
        esc = self.client.post("/api/escalations/check", headers=self.ib_hdr)
        self.assertEqual(esc.status_code, 200, esc.text)
        esc_chats = {p["chat_id"] for m, p in self.tg_calls if m == "sendMessage"}
        self.assertIn("600", esc_chats)
        self.assertNotIn("500", esc_chats)

    def test_env_fallback_zero_config(self) -> None:
        os.environ["TELEGRAM_BOT_TOKEN"] = "env-token:123"
        os.environ["TELEGRAM_CHAT_ID"] = "999888"

        cfg = self.client.get("/api/telegram/config", headers=self.ib_hdr).json()
        self.assertEqual(cfg["token_source"], "env")
        self.assertEqual(cfg["env_chat_id"], "999888")

        r = self.client.post(
            "/api/signals",
            json={"source": "zabbix", "body": "Высокая нагрузка CPU", "computer": "SRV-01"},
        )
        self.assertEqual(r.status_code, 200, r.text)
        sent_to = [p["chat_id"] for m, p in self.tg_calls if m == "sendMessage"]
        self.assertEqual(sent_to, ["999888"])


if __name__ == "__main__":
    unittest.main()
