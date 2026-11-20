import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient


def _login(client: TestClient, username: str, password: str = "password123") -> dict[str, str]:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def run_e2e() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        os.environ["DB_PATH"] = str(Path(tmp_dir) / "test_e2e.db")

        from main import app

        with TestClient(app) as client:
            ib_hdr = _login(client, "ib")
            sys_hdr = _login(client, "sysadmin")
            head_hdr = _login(client, "it_head")
            lawyer_hdr = _login(client, "lawyer")

            # 1. Signal ingestion & deduplication (2 identical signals -> 1 incident, 2 messages)
            sig = {
                "source": "antivirus",
                "sender": "AV-Agent",
                "body": "Обнаружен Ransom.Test на WS-DEV-09",
                "computer": "WS-DEV-09",
                "employee": "Кузнецов А.А.",
                "incident_type": "Вирус / Вредоносное ПО",
                "severity": "high",
                "incident_key": "av-ws-dev-09-ransom",
                "has_personal_data": 0,
            }
            r1 = client.post("/api/signals", json=sig)
            assert r1.status_code == 200, r1.text
            d1 = r1.json()
            assert d1["deduplicated"] is False
            inc_id = d1["incident_id"]

            r2 = client.post("/api/signals", json=sig)
            assert r2.status_code == 200, r2.text
            d2 = r2.json()
            assert d2["deduplicated"] is True
            assert d2["incident_id"] == inc_id
            assert d2["message_id"] != d1["message_id"]

            card = client.get(f"/api/incidents/{inc_id}", headers=ib_hdr)
            assert card.status_code == 200, card.text
            card_data = card.json()
            assert len(card_data["messages"]) == 2
            assert [h["action"] for h in card_data["history"]] == [
                "signal_created",
                "signal_deduplicated",
            ]
            print("PASS 1: Signal ingestion & deduplication")

            # 2. Instruction steps, tasks, and RBAC
            sys_user_id = client.get("/api/auth/me", headers=sys_hdr).json()["id"]
            due_date = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat()
            t_tech = client.post(
                f"/api/incidents/{inc_id}/tasks",
                json={
                    "title": "Изолировать WS-DEV-09",
                    "description": "Отключить от сети",
                    "assigned_to": sys_user_id,
                    "due_date": due_date,
                },
                headers=ib_hdr,
            )
            assert t_tech.status_code == 200, t_tech.text
            tech_task_id = t_tech.json()["id"]

            t_pdn = client.post(
                "/api/incidents/2/tasks",
                json={
                    "title": "Проверить выгрузку ПДн",
                    "description": "Проверить журнал выгрузок ПДн",
                    "assigned_to": sys_user_id,
                    "due_date": due_date,
                },
                headers=ib_hdr,
            )
            assert t_pdn.status_code == 200, t_pdn.text
            pdn_task_id = t_pdn.json()["id"]

            sys_list = client.get("/api/incidents", headers=sys_hdr)
            assert sys_list.status_code == 200, sys_list.text
            sys_inc_ids = {item["id"] for item in sys_list.json()}
            assert inc_id in sys_inc_ids
            assert 2 not in sys_inc_ids

            assert client.get("/api/incidents/2", headers=sys_hdr).status_code == 403
            assert client.patch("/api/incidents/2", json={"severity": "low"}, headers=sys_hdr).status_code == 403
            assert client.put("/api/incidents/2/steps/0", json={"completed": True}, headers=sys_hdr).status_code == 403
            assert client.get("/api/incidents/2/rkn", headers=sys_hdr).status_code == 403

            sys_tasks = client.get("/api/tasks", headers=sys_hdr)
            assert sys_tasks.status_code == 200, sys_tasks.text
            sys_task_ids = {t["id"] for t in sys_tasks.json()}
            assert tech_task_id in sys_task_ids
            assert pdn_task_id not in sys_task_ids
            assert client.patch(f"/api/tasks/{pdn_task_id}", json={"status": "Выполнена"}, headers=sys_hdr).status_code == 403

            take_resp = client.post(
                f"/api/incidents/{inc_id}/status",
                json={"status": "В работе"},
                headers=sys_hdr,
            )
            assert take_resp.status_code == 200, take_resp.text
            assert take_resp.json()["taken_at"] is not None

            instr_resp = client.get("/api/instructions", headers=sys_hdr)
            assert instr_resp.status_code == 200, instr_resp.text
            instr_map = {item["id"]: item for item in instr_resp.json()}
            steps = instr_map[card_data["instruction_id"]]["steps"]
            for idx in range(len(steps)):
                step_resp = client.put(
                    f"/api/incidents/{inc_id}/steps/{idx}",
                    json={"completed": True},
                    headers=sys_hdr,
                )
                assert step_resp.status_code == 200, step_resp.text
                assert step_resp.json()["completed"] is True

            done_task = client.patch(
                f"/api/tasks/{tech_task_id}",
                json={"status": "Выполнена", "result": "Станция изолирована и очищена"},
                headers=sys_hdr,
            )
            assert done_task.status_code == 200, done_task.text
            assert done_task.json()["completed_at"] is not None

            close_resp = client.post(
                f"/api/incidents/{inc_id}/status",
                json={"status": "Закрыт", "outcome": "Устранен"},
                headers=ib_hdr,
            )
            assert close_resp.status_code == 200, close_resp.text
            assert close_resp.json()["closed_at"] is not None
            print("PASS 2: Instruction steps, tasks, and RBAC")

            # 3. RKN 24h/72h deadlines + draft generation, and 30-min escalation check
            rkn_resp = client.get("/api/incidents/2/rkn", headers=lawyer_hdr)
            assert rkn_resp.status_code == 200, rkn_resp.text
            rkn = rkn_resp.json()
            det = datetime.fromisoformat(rkn["detected_at"])
            assert datetime.fromisoformat(rkn["deadline_24h"]) == (det + timedelta(hours=24)).replace(microsecond=0)
            assert datetime.fromisoformat(rkn["deadline_72h"]) == (det + timedelta(hours=72)).replace(microsecond=0)
            assert rkn["is_auto_generated"] is True
            assert "РОСКОМНАДЗОР" in rkn["rkn_draft"]

            rkn_put = client.put(
                "/api/incidents/2/rkn",
                json={"rkn_draft": "Согласованный черновик уведомления РКН"},
                headers=lawyer_hdr,
            )
            assert rkn_put.status_code == 200, rkn_put.text
            assert rkn_put.json()["is_auto_generated"] is False

            esc1 = client.post("/api/escalations/check", headers=head_hdr)
            assert esc1.status_code == 200, esc1.text
            created_notifs = esc1.json()
            kinds = {(n["incident_id"], n["recipient_role"], n["kind"]) for n in created_notifs}
            assert (1, "it_head", "escalation_30m") in kinds
            assert (2, "lawyer", "pdn_lawyer_notice") in kinds
            assert (2, "chief_accountant", "pdn_accounting_notice") in kinds

            esc2 = client.post("/api/escalations/check", headers=head_hdr)
            assert esc2.status_code == 200, esc2.text
            assert esc2.json() == []

            notifs = client.get("/api/notifications", headers=head_hdr)
            assert notifs.status_code == 200, notifs.text
            assert len(notifs.json()) >= 3
            print("PASS 3: RKN deadlines/draft & 30-min escalation notifications")

            # 4. Monthly report aggregation (unique incidents, no duplicate signals)
            rep_resp = client.get("/api/reports/monthly", headers=ib_hdr)
            assert rep_resp.status_code == 200, rep_resp.text
            rep = rep_resp.json()
            assert rep["total"] == 4, rep
            assert rep["personal_data_count"] == 1, rep
            assert rep["by_incident_type"]["Вирус / Вредоносное ПО"] == 2, rep
            assert rep["by_outcome"]["Устранен"] == 1, rep
            assert rep["by_outcome"]["Ложное срабатывание"] == 1, rep
            print("PASS 4: Monthly report aggregation")


if __name__ == "__main__":
    run_e2e()
    print("ALL E2E CHECKS PASSED")
