import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.container import AppContainer
from app.enums import AccessCategory, IncidentType, Role, Severity, SourceType
from app.services.dispatch import DispatchRule, IncidentDispatcher
from main import app


class TestIncidentDispatcherUnit(unittest.TestCase):
    def setUp(self) -> None:
        self.dispatcher = IncidentDispatcher()

    def test_rules_cover_all_incident_types(self) -> None:
        rules = self.dispatcher.list_rules()
        self.assertEqual(len(rules), len(IncidentType))
        self.assertEqual({r.incident_type for r in rules}, set(IncidentType))

        for rule in rules:
            self.assertIsInstance(rule, DispatchRule)
            serialized = rule.to_dict()
            self.assertEqual(serialized["incident_type"], rule.incident_type.value)
            self.assertEqual(serialized["default_severity"], rule.default_severity.value)
            self.assertEqual(serialized["access_category"], rule.access_category.value)
            self.assertEqual(serialized["responsible_role"], rule.responsible_role.value)
            self.assertIsInstance(serialized["urgent_notify_roles"], list)
            self.assertTrue(serialized["description"])

        self.assertIn(
            Role.ACCOUNTANT,
            self.dispatcher.get_rule(IncidentType.PAYMENT_FRAUD).urgent_notify_roles,
        )
        self.assertIn(
            Role.LAWYER,
            self.dispatcher.get_rule(IncidentType.DATA_LEAK).urgent_notify_roles,
        )

    def test_classify_signal_all_categories_and_precedence(self) -> None:
        cases = [
            # CVE
            ("Обнаружена CVE-2026-12345 в OpenSSL", None, None, None, IncidentType.CVE),
            ("Критическая уязвимость на сервере", None, None, None, IncidentType.CVE),
            ("Remote code execution vulnerability", None, None, None, IncidentType.CVE),
            ("Обычное сообщение", "Прочее", "zabbix", "CVE-2025-9001", IncidentType.CVE),
            # BRUTEFORCE
            ("Обнаружен bruteforce на SSH", None, None, None, IncidentType.BRUTEFORCE),
            ("Brute force attack detected", None, None, None, IncidentType.BRUTEFORCE),
            ("Массовый подбор пароля к AD", None, None, None, IncidentType.BRUTEFORCE),
            ("Multiple failed login attempts", None, None, None, IncidentType.BRUTEFORCE),
            ("Попытки входа по RDP с внешнего IP", None, None, None, IncidentType.BRUTEFORCE),
            # VIRUS
            ("Найден Trojan.GenericKD", None, None, None, IncidentType.VIRUS),
            ("Зафиксирован ransom шифровальщик", None, None, None, IncidentType.VIRUS),
            ("Malware blocked on workstation", None, None, None, IncidentType.VIRUS),
            ("Обнаружен вирус в загрузках", None, None, None, IncidentType.VIRUS),
            ("Файл заражён макросом", None, None, None, IncidentType.VIRUS),
            ("Неизвестное событие", None, "antivirus", None, IncidentType.VIRUS),
            ("Подозрительный файл", None, "kaspersky", None, IncidentType.VIRUS),
            # DATA_LEAK
            ("Возможная утечка данных", None, None, None, IncidentType.DATA_LEAK),
            ("Пересылка таблицы ПДн наружу", None, None, None, IncidentType.DATA_LEAK),
            ("Экспорт файла clients_pdn.csv", None, None, None, IncidentType.DATA_LEAK),
            ("Отправка архива на личную почту", None, "dlp", None, IncidentType.DATA_LEAK),
            # PAYMENT_FRAUD
            ("Письмо с подменой реквизитов", None, None, None, IncidentType.PAYMENT_FRAUD),
            ("Подозрительный платёж контрагенту", None, None, None, IncidentType.PAYMENT_FRAUD),
            ("Срочно оплатите счёт во вложении", None, None, None, IncidentType.PAYMENT_FRAUD),
            ("Fraudulent payment instruction", None, None, None, IncidentType.PAYMENT_FRAUD),
            # PHISHING
            ("Массовый фишинг на почту", None, None, None, IncidentType.PHISHING),
            ("Phish URL clicked by employee", None, None, None, IncidentType.PHISHING),
            # UNAUTHORIZED_ACCESS
            ("Несанкционированный доступ к БД", None, None, None, IncidentType.UNAUTHORIZED_ACCESS),
            ("Unauthorized root access", None, None, None, IncidentType.UNAUTHORIZED_ACCESS),
            ("Privilege escalation attempt", None, None, None, IncidentType.UNAUTHORIZED_ACCESS),
            # OTHER fallback & explicit preservation
            ("High CPU usage on DB server", "Прочее", "zabbix", None, IncidentType.OTHER),
            ("Плановая перезагрузка", None, "zabbix", None, IncidentType.OTHER),
            ("WordPress plugin updated", None, "zabbix", None, IncidentType.OTHER),
            ("Упоминается CVE-2026-1111, но это фишинг", "phishing", None, None, IncidentType.PHISHING),
            ("CVE-2026-2222 в продукте", None, "kaspersky", None, IncidentType.CVE),
        ]
        for body, inc_type, source, err_code, expected in cases:
            with self.subTest(body=body, inc_type=inc_type, source=source, err_code=err_code):
                actual = self.dispatcher.classify_signal(
                    body=body,
                    incident_type=inc_type,
                    source=source,
                    error_code=err_code,
                )
                self.assertIs(actual, expected)

    def test_resolve_urgent_roles(self) -> None:
        self.assertEqual(
            self.dispatcher.resolve_urgent_roles(IncidentType.PAYMENT_FRAUD, Severity.HIGH),
            (Role.ACCOUNTANT,),
        )
        self.assertEqual(
            self.dispatcher.resolve_urgent_roles(IncidentType.DATA_LEAK, Severity.HIGH),
            (Role.LAWYER,),
        )
        self.assertEqual(
            self.dispatcher.resolve_urgent_roles(IncidentType.DATA_LEAK, Severity.CRITICAL),
            (Role.LAWYER, Role.DIRECTOR),
        )
        self.assertEqual(
            self.dispatcher.resolve_urgent_roles(IncidentType.CVE, Severity.CRITICAL),
            (Role.DIRECTOR,),
        )
        self.assertEqual(
            self.dispatcher.resolve_urgent_roles(IncidentType.VIRUS, Severity.HIGH),
            (),
        )


class TestIncidentDispatchApiAndServices(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_dispatch.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _login(self, username: str) -> tuple[dict[str, str], dict]:
        resp = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": "password123"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        return {"Authorization": f"Bearer {data['token']}"}, data["user"]

    def test_container_wires_dispatcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            container = AppContainer(db_path=str(Path(tmp) / "wired.db"))
            container.init_db()
            self.assertIsInstance(container.dispatcher, IncidentDispatcher)
            self.assertIs(container.ingestion_service.dispatcher, container.dispatcher)
            self.assertIs(container.report_service.dispatcher, container.dispatcher)

    def test_dispatch_rules_endpoint_auth_and_table(self) -> None:
        unauth = self.client.get("/api/incidents/dispatch-rules")
        self.assertEqual(unauth.status_code, 401)

        ib_hdr, _ = self._login("ib")
        resp = self.client.get("/api/incidents/dispatch-rules", headers=ib_hdr)
        self.assertEqual(resp.status_code, 200, resp.text)
        rules = resp.json()
        self.assertEqual(len(rules), len(IncidentType))
        by_type = {item["incident_type"]: item for item in rules}
        self.assertEqual(set(by_type.keys()), {t.value for t in IncidentType})
        self.assertEqual(by_type[IncidentType.PAYMENT_FRAUD.value]["urgent_notify_roles"], [Role.ACCOUNTANT.value])
        self.assertEqual(by_type[IncidentType.DATA_LEAK.value]["urgent_notify_roles"], [Role.LAWYER.value])
        self.assertEqual(by_type[IncidentType.CVE.value]["responsible_role"], Role.SYS_ADMIN.value)

    def test_signal_auto_classification_dispatch_and_urgent_notifications(self) -> None:
        ib_hdr, ib_user = self._login("ib")
        sys_hdr, sys_user = self._login("sysadmin")

        # 1. CVE via error_code (incident_type omitted, severity omitted -> HIGH, technical, sysadmin)
        r_cve = self.client.post(
            "/api/signals",
            json={
                "source": "zabbix",
                "sender": "ZBX-Scanner",
                "body": "Требуется обновление пакета nginx",
                "computer": "SRV-WEB-01",
                "error_code": "CVE-2026-1010",
            },
        )
        self.assertEqual(r_cve.status_code, 200, r_cve.text)
        cve_id = r_cve.json()["incident_id"]
        cve_card = self.client.get(f"/api/incidents/{cve_id}", headers=ib_hdr).json()
        self.assertEqual(cve_card["incident_type"], IncidentType.CVE.value)
        self.assertEqual(cve_card["severity"], Severity.HIGH.value)
        self.assertEqual(cve_card["access_category"], AccessCategory.TECHNICAL.value)
        self.assertEqual(cve_card["assigned_to"], sys_user["id"])
        self.assertEqual(cve_card["has_personal_data"], 0)

        # Duplicate CVE signal without explicit incident_type deduplicates properly
        r_cve_dup = self.client.post(
            "/api/signals",
            json={
                "source": "zabbix",
                "body": "Повторный скан CVE-2026-1010",
                "computer": "SRV-WEB-01",
            },
        )
        self.assertEqual(r_cve_dup.status_code, 200, r_cve_dup.text)
        self.assertTrue(r_cve_dup.json()["deduplicated"])
        self.assertEqual(r_cve_dup.json()["incident_id"], cve_id)

        # 2. BRUTEFORCE (explicit "Прочее" triggers auto-classification -> Подбор пароля)
        r_bf = self.client.post(
            "/api/signals",
            json={
                "source": "zabbix",
                "body": "Множественный подбор пароля по RDP с внешнего IP",
                "computer": "SRV-GW-01",
                "incident_type": "Прочее",
            },
        )
        self.assertEqual(r_bf.status_code, 200, r_bf.text)
        bf_card = self.client.get(f"/api/incidents/{r_bf.json()['incident_id']}", headers=ib_hdr).json()
        self.assertEqual(bf_card["incident_type"], IncidentType.BRUTEFORCE.value)
        self.assertEqual(bf_card["assigned_to"], sys_user["id"])

        # 3. VIRUS via kaspersky source with CRITICAL severity -> notifies director
        r_vir = self.client.post(
            "/api/signals",
            json={
                "source": "kaspersky",
                "body": "Обнаружен новый объект в памяти процесса",
                "computer": "WS-ENG-05",
                "severity": "critical",
            },
        )
        self.assertEqual(r_vir.status_code, 200, r_vir.text)
        vir_id = r_vir.json()["incident_id"]
        vir_card = self.client.get(f"/api/incidents/{vir_id}", headers=ib_hdr).json()
        self.assertEqual(vir_card["incident_type"], IncidentType.VIRUS.value)
        self.assertEqual(vir_card["severity"], Severity.CRITICAL.value)
        self.assertEqual(vir_card["source"], SourceType.KASPERSKY.value)
        self.assertEqual(vir_card["assigned_to"], sys_user["id"])

        # 4. PHISHING -> employee_involved, assigned to ib_specialist
        r_phish = self.client.post(
            "/api/signals",
            json={
                "source": "mail_gateway",
                "body": "Зафиксирован фишинг в письме от внешнего домена",
                "computer": "WS-MGR-02",
            },
        )
        self.assertEqual(r_phish.status_code, 200, r_phish.text)
        phish_card = self.client.get(f"/api/incidents/{r_phish.json()['incident_id']}", headers=ib_hdr).json()
        self.assertEqual(phish_card["incident_type"], IncidentType.PHISHING.value)
        self.assertEqual(phish_card["severity"], Severity.MEDIUM.value)
        self.assertEqual(phish_card["access_category"], AccessCategory.EMPLOYEE_INVOLVED.value)
        self.assertEqual(phish_card["assigned_to"], ib_user["id"])

        # 5. DATA_LEAK via dlp source -> auto has_personal_data=1, CRITICAL, lawyer + director notified, sysadmin 403
        r_dlp = self.client.post(
            "/api/signals",
            json={
                "source": "dlp",
                "body": "Отправлен архив clients_pdn.zip на внешний облачный диск",
                "computer": "WS-HR-01",
                "has_personal_data": 0,
            },
        )
        self.assertEqual(r_dlp.status_code, 200, r_dlp.text)
        dlp_id = r_dlp.json()["incident_id"]
        dlp_card = self.client.get(f"/api/incidents/{dlp_id}", headers=ib_hdr).json()
        self.assertEqual(dlp_card["incident_type"], IncidentType.DATA_LEAK.value)
        self.assertEqual(dlp_card["has_personal_data"], 1)
        self.assertEqual(dlp_card["access_category"], AccessCategory.PERSONAL_DATA.value)
        self.assertEqual(dlp_card["severity"], Severity.CRITICAL.value)
        self.assertEqual(dlp_card["assigned_to"], ib_user["id"])
        self.assertEqual(self.client.get(f"/api/incidents/{dlp_id}", headers=sys_hdr).status_code, 403)

        # 6. PAYMENT_FRAUD -> chief_accountant urgent notification
        r_pay = self.client.post(
            "/api/signals",
            json={
                "source": "mail_gateway",
                "body": "Просьба перевести оплату счета по измененным реквизитам",
                "computer": "WS-ACC-03",
            },
        )
        self.assertEqual(r_pay.status_code, 200, r_pay.text)
        pay_id = r_pay.json()["incident_id"]
        pay_card = self.client.get(f"/api/incidents/{pay_id}", headers=ib_hdr).json()
        self.assertEqual(pay_card["incident_type"], IncidentType.PAYMENT_FRAUD.value)
        self.assertEqual(pay_card["severity"], Severity.HIGH.value)
        self.assertEqual(pay_card["access_category"], AccessCategory.EMPLOYEE_INVOLVED.value)
        self.assertEqual(pay_card["assigned_to"], ib_user["id"])

        # 7. UNAUTHORIZED_ACCESS with explicit assigned_to preserved
        r_unauth = self.client.post(
            "/api/signals",
            json={
                "source": "zabbix",
                "body": "Несанкционированный доступ: privilege escalation on DB host",
                "computer": "SRV-DB-05",
                "assigned_to": sys_user["id"],
            },
        )
        self.assertEqual(r_unauth.status_code, 200, r_unauth.text)
        unauth_card = self.client.get(
            f"/api/incidents/{r_unauth.json()['incident_id']}", headers=ib_hdr
        ).json()
        self.assertEqual(unauth_card["incident_type"], IncidentType.UNAUTHORIZED_ACCESS.value)
        self.assertEqual(unauth_card["assigned_to"], sys_user["id"])

        # Verify urgent notifications emitted for PAYMENT_FRAUD, DATA_LEAK, and CRITICAL
        notifs = self.client.get("/api/notifications", headers=ib_hdr)
        self.assertEqual(notifs.status_code, 200, notifs.text)
        notif_pairs = {(n["incident_id"], n["recipient_role"]) for n in notifs.json()}
        self.assertIn((vir_id, Role.DIRECTOR.value), notif_pairs)
        self.assertIn((dlp_id, Role.LAWYER.value), notif_pairs)
        self.assertIn((dlp_id, Role.DIRECTOR.value), notif_pairs)
        self.assertIn((pay_id, Role.ACCOUNTANT.value), notif_pairs)
        # Non-critical CVE should NOT trigger urgent notification
        self.assertFalse(any(n["incident_id"] == cve_id for n in notifs.json()))

        # 8. Verify /api/reports/by-type authentication and aggregated distributions
        self.assertEqual(self.client.get("/api/reports/by-type").status_code, 401)
        rep_resp = self.client.get("/api/reports/by-type", headers=ib_hdr)
        self.assertEqual(rep_resp.status_code, 200, rep_resp.text)
        rep = rep_resp.json()

        # 3 seeded incidents + 7 unique ingested incidents = 10 total (duplicate CVE not double-counted)
        self.assertEqual(rep["total"], 10)
        self.assertEqual(rep["personal_data_count"], 2)
        self.assertEqual(
            rep["by_incident_type"],
            {
                IncidentType.VIRUS.value: 2,
                IncidentType.DATA_LEAK.value: 2,
                IncidentType.PHISHING.value: 2,
                IncidentType.CVE.value: 1,
                IncidentType.BRUTEFORCE.value: 1,
                IncidentType.PAYMENT_FRAUD.value: 1,
                IncidentType.UNAUTHORIZED_ACCESS.value: 1,
            },
        )
        self.assertEqual(
            rep["by_access_category"],
            {
                AccessCategory.EMPLOYEE_INVOLVED.value: 4,
                AccessCategory.PERSONAL_DATA.value: 2,
                AccessCategory.TECHNICAL.value: 4,
            },
        )
        self.assertEqual(
            rep["by_severity"],
            {
                Severity.HIGH.value: 5,
                Severity.CRITICAL.value: 3,
                Severity.MEDIUM.value: 2,
            },
        )
        self.assertEqual(
            rep["by_responsible_role"],
            {
                Role.SYS_ADMIN.value: 4,
                Role.SECURITY_SPECIALIST.value: 6,
            },
        )


if __name__ == "__main__":
    unittest.main()
