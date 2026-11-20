import os
import tempfile
import unittest
from enum import StrEnum
from pathlib import Path

from fastapi.testclient import TestClient

from app.enums import ROLE_LABELS, Role
from auth import get_current_user, hash_password
from db import get_conn
from main import app


class TestRoleEnum(unittest.TestCase):
    def test_all_eight_role_members_and_values(self) -> None:
        expected = {
            "SECURITY_SPECIALIST": "ib_specialist",
            "SYS_ADMIN": "sysadmin",
            "IT_HEAD": "it_head",
            "LAWYER": "lawyer",
            "DIRECTOR": "director",
            "ACCOUNTANT": "chief_accountant",
            "FOREMAN": "foreman",
            "EMPLOYEE": "employee",
        }
        self.assertTrue(issubclass(Role, StrEnum))
        self.assertEqual(len(Role), 8)
        self.assertEqual({member.name: member.value for member in Role}, expected)
        for name, val in expected.items():
            member = Role[name]
            self.assertIsInstance(member, str)
            self.assertEqual(member, val)
            self.assertEqual(str(member), val)

    def test_role_labels_russian_titles(self) -> None:
        expected_labels = {
            Role.SECURITY_SPECIALIST: "Специалист ИБ",
            Role.SYS_ADMIN: "Системный администратор",
            Role.IT_HEAD: "Руководитель ИТ",
            Role.LAWYER: "Юрист",
            Role.DIRECTOR: "Директор",
            Role.ACCOUNTANT: "Главный бухгалтер",
            Role.FOREMAN: "Прораб",
            Role.EMPLOYEE: "Сотрудник",
        }
        self.assertEqual(set(ROLE_LABELS.keys()), set(Role))
        self.assertEqual(ROLE_LABELS, expected_labels)
        for role in Role:
            label = role.label
            self.assertIsInstance(label, str)
            self.assertTrue(label.strip())
            self.assertEqual(label, expected_labels[role])
            self.assertTrue(any("\u0400" <= ch <= "\u04ff" for ch in label))

    def test_role_parsing(self) -> None:
        for role in Role:
            parsed = Role(role.value)
            self.assertIs(parsed, role)

        for invalid in ("", "admin", "SYS_ADMIN", "unknown", "accountant"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    Role(invalid)


class TestRoleAuthAndRbac(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_role_enum.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _login(self, username: str, password: str = "password123") -> tuple[dict[str, str], dict]:
        resp = self.client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        return {"Authorization": f"Bearer {body['token']}"}, body

    def test_seeded_users_auth_and_roles(self) -> None:
        seeded = [
            ("ib", Role.SECURITY_SPECIALIST),
            ("sysadmin", Role.SYS_ADMIN),
            ("it_head", Role.IT_HEAD),
            ("lawyer", Role.LAWYER),
        ]
        for username, expected_role in seeded:
            with self.subTest(username=username):
                headers, login_data = self._login(username)
                self.assertEqual(login_data["user"]["role"], expected_role.value)

                me_resp = self.client.get("/api/auth/me", headers=headers)
                self.assertEqual(me_resp.status_code, 200, me_resp.text)
                self.assertEqual(me_resp.json()["role"], expected_role.value)

                current_user = get_current_user(headers["Authorization"])
                self.assertIs(current_user["role"], expected_role)
                self.assertEqual(current_user["role"].label, expected_role.label)

    def test_new_roles_auth_roundtrip(self) -> None:
        new_roles = [
            ("dir_user", "Иванова М.А.", Role.DIRECTOR),
            ("acc_user", "Петрова С.Н.", Role.ACCOUNTANT),
            ("foreman_user", "Сидоров В.П.", Role.FOREMAN),
            ("emp_user", "Кузнецов А.А.", Role.EMPLOYEE),
        ]
        conn = get_conn()
        try:
            conn.executemany(
                "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                [(u, hash_password("password123"), name, role.value) for u, name, role in new_roles],
            )
            conn.commit()
        finally:
            conn.close()

        for username, _name, expected_role in new_roles:
            with self.subTest(role=expected_role):
                headers, login_data = self._login(username)
                self.assertEqual(login_data["user"]["role"], expected_role.value)
                me_resp = self.client.get("/api/auth/me", headers=headers)
                self.assertEqual(me_resp.status_code, 200)
                self.assertEqual(me_resp.json()["role"], expected_role.value)
                current_user = get_current_user(headers["Authorization"])
                self.assertIs(current_user["role"], expected_role)

    def test_sysadmin_rbac_and_non_sysadmin_access(self) -> None:
        ib_hdr, _ = self._login("ib")
        sys_hdr, sys_login = self._login("sysadmin")
        lawyer_hdr, _ = self._login("lawyer")
        head_hdr, _ = self._login("it_head")

        # Seeded incident #2 has has_personal_data = 1
        ib_list = self.client.get("/api/incidents", headers=ib_hdr)
        self.assertEqual(ib_list.status_code, 200)
        self.assertIn(2, {item["id"] for item in ib_list.json()})

        sys_list = self.client.get("/api/incidents", headers=sys_hdr)
        self.assertEqual(sys_list.status_code, 200)
        sys_ids = {item["id"] for item in sys_list.json()}
        self.assertIn(1, sys_ids)
        self.assertNotIn(2, sys_ids)

        # Sysadmin cannot access or mutate PDn incident #2 or RKN endpoints
        self.assertEqual(self.client.get("/api/incidents/2", headers=sys_hdr).status_code, 403)
        self.assertEqual(
            self.client.patch("/api/incidents/2", json={"severity": "low"}, headers=sys_hdr).status_code,
            403,
        )
        self.assertEqual(
            self.client.post("/api/incidents/2/status", json={"status": "В работе"}, headers=sys_hdr).status_code,
            403,
        )
        self.assertEqual(
            self.client.put("/api/incidents/2/steps/0", json={"completed": True}, headers=sys_hdr).status_code,
            403,
        )
        self.assertEqual(self.client.get("/api/incidents/2/rkn", headers=sys_hdr).status_code, 403)
        self.assertEqual(
            self.client.put("/api/incidents/2/rkn", json={"rkn_draft": "test"}, headers=sys_hdr).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/incidents",
                json={
                    "title": "Утечка файла",
                    "description": "Выгрузка файла с персональными данными",
                    "incident_type": "Утечка ПДн",
                    "source": "manual",
                    "has_personal_data": 1,
                },
                headers=sys_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.patch("/api/incidents/1", json={"has_personal_data": 1}, headers=sys_hdr).status_code,
            403,
        )

        # Lawyer and IB specialist can access PDn incident & RKN info
        self.assertEqual(self.client.get("/api/incidents/2", headers=lawyer_hdr).status_code, 200)
        self.assertEqual(self.client.get("/api/incidents/2/rkn", headers=lawyer_hdr).status_code, 200)
        self.assertEqual(self.client.get("/api/incidents/2/rkn", headers=ib_hdr).status_code, 200)

        # Task assignment requires valid user id, description, and due_date; hides PDn tasks from sysadmin
        t_open = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Проверить WS-FIN-04",
                "description": "Провести антивирусную проверку WS-FIN-04",
                "assigned_to": sys_login["user"]["id"],
                "due_date": "2026-11-30T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(t_open.status_code, 200, t_open.text)
        self.assertEqual(t_open.json()["assigned_to"], sys_login["user"]["id"])

        t_pdn = self.client.post(
            "/api/incidents/2/tasks",
            json={
                "title": "Ограничить доступ к CRM",
                "description": "Отозвать токены и заблокировать выгрузку из CRM",
                "assigned_to": sys_login["user"]["id"],
                "due_date": "2026-11-30T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(t_pdn.status_code, 200, t_pdn.text)
        pdn_task_id = t_pdn.json()["id"]

        sys_tasks = self.client.get("/api/tasks", headers=sys_hdr)
        self.assertEqual(sys_tasks.status_code, 200)
        sys_task_ids = {t["id"] for t in sys_tasks.json()}
        self.assertIn(t_open.json()["id"], sys_task_ids)
        self.assertNotIn(pdn_task_id, sys_task_ids)
        self.assertEqual(
            self.client.patch(
                f"/api/tasks/{pdn_task_id}",
                json={"status": "Выполнена"},
                headers=sys_hdr,
            ).status_code,
            403,
        )

        # Escalations use Role enum values and labels
        esc = self.client.post("/api/escalations/check", headers=head_hdr)
        self.assertEqual(esc.status_code, 200, esc.text)
        by_kind = {(n["incident_id"], n["kind"]): n for n in esc.json()}
        self.assertEqual(by_kind[(1, "escalation_30m")]["recipient_role"], Role.IT_HEAD.value)
        self.assertEqual(by_kind[(2, "pdn_lawyer_notice")]["recipient_role"], Role.LAWYER.value)
        self.assertEqual(by_kind[(2, "pdn_accounting_notice")]["recipient_role"], Role.ACCOUNTANT.value)
        self.assertEqual(by_kind[(2, "pdn_accounting_notice")]["recipient_name"], Role.ACCOUNTANT.label)


if __name__ == "__main__":
    unittest.main()
