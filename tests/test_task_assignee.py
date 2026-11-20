import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.container import get_container
from app.enums import Role, TaskStatus
from app.repositories import hash_password
from app.services import NotFoundError, ValidationError
from main import app


class TestTaskAssigneePickerAndEnrichment(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_task_assignee.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()
        self.container = get_container()

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _login(self, username: str, password: str = "password123") -> tuple[dict[str, str], dict]:
        resp = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        return {"Authorization": f"Bearer {body['token']}"}, body["user"]

    @staticmethod
    def _expected_user_summary(user_row) -> dict:
        role_val = user_row.role.value if isinstance(user_row.role, Role) else str(user_row.role)
        role_lbl = Role(role_val).label
        return {
            "id": user_row.id,
            "username": user_row.username,
            "full_name": user_row.full_name,
            "role": role_val,
            "role_label": role_lbl,
            "label": f"{user_row.full_name} — {role_lbl}",
        }

    def test_get_users_auth_filters_and_labels(self) -> None:
        self.assertEqual(self.client.get("/api/users").status_code, 401)

        inactive_sys = self.container.user_repo.create(
            "sysadmin_off",
            hash_password("password123"),
            "Орлов Пётр (Уволен)",
            Role.SYS_ADMIN,
            active=False,
        )
        director = self.container.user_repo.create(
            "director_1",
            hash_password("password123"),
            "Воронов Сергей (Директор)",
            Role.DIRECTOR,
            active=True,
        )
        employee = self.container.user_repo.create(
            "employee_1",
            hash_password("password123"),
            "Новикова Ольга (Сотрудник)",
            Role.EMPLOYEE,
            active=True,
        )
        extra_sys = self.container.user_repo.create(
            "sysadmin_2",
            hash_password("password123"),
            "Громов Артём (Сисадмин 2)",
            Role.SYS_ADMIN,
            active=True,
        )

        ib_hdr, _ = self._login("ib")

        # Full list returns all active and inactive users with exact schema & labels
        all_resp = self.client.get("/api/users", headers=ib_hdr)
        self.assertEqual(all_resp.status_code, 200, all_resp.text)
        all_users = all_resp.json()
        by_username = {u["username"]: u for u in all_users}
        self.assertIn("ib", by_username)
        self.assertIn("sysadmin", by_username)
        self.assertIn("it_head", by_username)
        self.assertIn("lawyer", by_username)
        self.assertIn(inactive_sys.username, by_username)
        self.assertIn(director.username, by_username)
        self.assertIn(employee.username, by_username)
        self.assertIn(extra_sys.username, by_username)

        expected_keys = {"id", "username", "full_name", "role", "role_label", "label", "active"}
        for item in all_users:
            self.assertEqual(set(item.keys()), expected_keys)
            role_label = Role(item["role"]).label
            self.assertEqual(item["role_label"], role_label)
            self.assertEqual(item["label"], f"{item['full_name']} — {role_label}")

        self.assertFalse(by_username[inactive_sys.username]["active"])
        self.assertEqual(
            by_username["sysadmin"]["label"],
            "Петров Дмитрий (Сисадмин) — Системный администратор",
        )

        # assignable=true filters to active operational roles only
        assignable_resp = self.client.get("/api/users", params={"assignable": True}, headers=ib_hdr)
        self.assertEqual(assignable_resp.status_code, 200, assignable_resp.text)
        assignable_users = assignable_resp.json()
        assignable_usernames = {u["username"] for u in assignable_users}
        self.assertEqual(
            assignable_usernames,
            {"ib", "sysadmin", "it_head", "lawyer", "sysadmin_2"},
        )
        self.assertTrue(all(u["active"] is True for u in assignable_users))
        self.assertTrue(
            all(
                u["role"] in {Role.SYS_ADMIN.value, Role.SECURITY_SPECIALIST.value, Role.IT_HEAD.value, Role.LAWYER.value}
                for u in assignable_users
            )
        )

        # Filter by role alone includes active and inactive users of that role
        sys_all_resp = self.client.get("/api/users", params={"role": "sysadmin"}, headers=ib_hdr)
        self.assertEqual(sys_all_resp.status_code, 200)
        self.assertEqual(
            {u["username"] for u in sys_all_resp.json()},
            {"sysadmin", "sysadmin_off", "sysadmin_2"},
        )

        # Combined role + assignable=true excludes inactive sysadmin
        sys_assignable_resp = self.client.get(
            "/api/users",
            params={"role": "sysadmin", "assignable": True},
            headers=ib_hdr,
        )
        self.assertEqual(sys_assignable_resp.status_code, 200)
        self.assertEqual(
            {u["username"] for u in sys_assignable_resp.json()},
            {"sysadmin", "sysadmin_2"},
        )

        # Non-operational role with assignable=true returns empty list
        dir_assignable = self.client.get(
            "/api/users",
            params={"role": "director", "assignable": True},
            headers=ib_hdr,
        )
        self.assertEqual(dir_assignable.status_code, 200)
        self.assertEqual(dir_assignable.json(), [])

    def test_task_assignee_validation_on_create_and_update(self) -> None:
        ib_hdr, ib_user = self._login("ib")
        sys_user = self.container.user_repo.get_by_username("sysadmin")
        head_user = self.container.user_repo.get_by_username("it_head")
        assert sys_user is not None and head_user is not None

        inactive_user = self.container.user_repo.create(
            "inactive_op",
            hash_password("password123"),
            "Неактивный Оператор",
            Role.SYS_ADMIN,
            active=False,
        )

        # Nonexistent assignee rejected on create (HTTP 404 / NotFoundError)
        missing_create = self.client.post(
            "/api/incidents/1/tasks",
            json={"title": "Несуществующий исполнитель", "assigned_to": 999999},
            headers=ib_hdr,
        )
        self.assertEqual(missing_create.status_code, 404, missing_create.text)
        with self.assertRaises(NotFoundError):
            self.container.task_service.create_task(
                ib_user,
                1,
                {"title": "Direct check", "assigned_to": 999999},
            )

        # Inactive assignee rejected on create (HTTP 400 / ValidationError)
        inactive_create = self.client.post(
            "/api/incidents/1/tasks",
            json={"title": "Уволенный исполнитель", "assigned_to": inactive_user.id},
            headers=ib_hdr,
        )
        self.assertEqual(inactive_create.status_code, 400, inactive_create.text)
        with self.assertRaises(ValidationError):
            self.container.task_service.create_task(
                ib_user,
                1,
                {"title": "Direct inactive", "assigned_to": inactive_user.id},
            )

        # Non-integer assigned_to rejected cleanly in service layer
        with self.assertRaises(ValidationError):
            self.container.task_service.create_task(
                ib_user,
                1,
                {"title": "Bad type", "assigned_to": True},
            )

        # Valid create -> default sysadmin
        created = self.client.post(
            "/api/incidents/1/tasks",
            json={"title": "Проверить логи WS-FIN-04", "description": "Полная проверка"},
            headers=ib_hdr,
        )
        self.assertEqual(created.status_code, 200, created.text)
        task_id = created.json()["id"]
        self.assertEqual(created.json()["assigned_to"], sys_user.id)

        # Reassignment to nonexistent user fails (HTTP 404 / NotFoundError)
        missing_patch = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"assigned_to": 888888},
            headers=ib_hdr,
        )
        self.assertEqual(missing_patch.status_code, 404, missing_patch.text)
        with self.assertRaises(NotFoundError):
            self.container.task_service.update_task(
                ib_user,
                task_id,
                {"assigned_to": 888888},
            )

        # Reassignment to inactive user fails (HTTP 400 / ValidationError)
        inactive_patch = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"assigned_to": inactive_user.id},
            headers=ib_hdr,
        )
        self.assertEqual(inactive_patch.status_code, 400, inactive_patch.text)
        with self.assertRaises(ValidationError):
            self.container.task_service.update_task(
                ib_user,
                task_id,
                {"assigned_to": inactive_user.id},
            )

        # Valid reassignment to it_head succeeds and leaves status untouched
        reassigned = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"assigned_to": head_user.id},
            headers=ib_hdr,
        )
        self.assertEqual(reassigned.status_code, 200, reassigned.text)
        reassigned_data = reassigned.json()
        self.assertEqual(reassigned_data["assigned_to"], head_user.id)
        self.assertEqual(reassigned_data["status"], TaskStatus.OPEN.value)
        self.assertEqual(
            reassigned_data["assigned_to_user"],
            self._expected_user_summary(head_user),
        )

        # Status update without assigned_to preserves current assignee
        done_resp = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"status": "Выполнена", "result": "Логи собраны"},
            headers=ib_hdr,
        )
        self.assertEqual(done_resp.status_code, 200, done_resp.text)
        self.assertEqual(done_resp.json()["assigned_to"], head_user.id)
        self.assertEqual(
            done_resp.json()["assigned_to_user"],
            self._expected_user_summary(head_user),
        )

    def test_task_user_enrichment_across_all_task_and_incident_endpoints(self) -> None:
        ib_hdr, _ = self._login("ib")
        head_hdr, _ = self._login("it_head")

        ib_user = self.container.user_repo.get_by_username("ib")
        sys_user = self.container.user_repo.get_by_username("sysadmin")
        head_user = self.container.user_repo.get_by_username("it_head")
        assert ib_user and sys_user and head_user

        expected_ib = self._expected_user_summary(ib_user)
        expected_sys = self._expected_user_summary(sys_user)
        expected_head = self._expected_user_summary(head_user)

        # 1. POST /api/incidents/{id}/tasks
        create_resp = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Изолировать узел",
                "description": "Отключить от локальной сети",
                "assigned_to": head_user.id,
            },
            headers=ib_hdr,
        )
        self.assertEqual(create_resp.status_code, 200, create_resp.text)
        created_task = create_resp.json()
        task_id = created_task["id"]
        self.assertEqual(created_task["assigned_to"], head_user.id)
        self.assertEqual(created_task["created_by"], ib_user.id)
        self.assertEqual(created_task["assigned_to_user"], expected_head)
        self.assertEqual(created_task["created_by_user"], expected_ib)
        self.assertEqual(
            set(created_task["assigned_to_user"].keys()),
            {"id", "username", "full_name", "role", "role_label", "label"},
        )

        # Create a task with NULL assigned_to & created_by directly via repo to test None safety
        unassigned_task = self.container.task_repo.create(
            incident_id=1,
            title="Задача без исполнителя",
            assigned_to=None,
            created_by=None,
        )

        # 2. GET /api/tasks
        list_resp = self.client.get("/api/tasks", headers=head_hdr)
        self.assertEqual(list_resp.status_code, 200, list_resp.text)
        tasks_by_id = {t["id"]: t for t in list_resp.json()}
        self.assertIn(task_id, tasks_by_id)
        listed_task = tasks_by_id[task_id]
        self.assertEqual(listed_task["assigned_to"], head_user.id)
        self.assertEqual(listed_task["created_by"], ib_user.id)
        self.assertEqual(listed_task["assigned_to_user"], expected_head)
        self.assertEqual(listed_task["created_by_user"], expected_ib)
        self.assertIn("incident_title", listed_task)

        listed_unassigned = tasks_by_id[unassigned_task.id]
        self.assertIsNone(listed_unassigned["assigned_to"])
        self.assertIsNone(listed_unassigned["created_by"])
        self.assertIsNone(listed_unassigned["assigned_to_user"])
        self.assertIsNone(listed_unassigned["created_by_user"])

        # 3. PATCH /api/tasks/{id} (reassign head -> sysadmin)
        patch_resp = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"assigned_to": sys_user.id},
            headers=head_hdr,
        )
        self.assertEqual(patch_resp.status_code, 200, patch_resp.text)
        patched_task = patch_resp.json()
        self.assertEqual(patched_task["assigned_to"], sys_user.id)
        self.assertEqual(patched_task["created_by"], ib_user.id)
        self.assertEqual(patched_task["assigned_to_user"], expected_sys)
        self.assertEqual(patched_task["created_by_user"], expected_ib)

        # Explicit unassignment via assigned_to=null
        unassign_resp = self.client.patch(
            f"/api/tasks/{unassigned_task.id}",
            json={"assigned_to": None},
            headers=head_hdr,
        )
        self.assertEqual(unassign_resp.status_code, 200, unassign_resp.text)
        self.assertIsNone(unassign_resp.json()["assigned_to"])
        self.assertIsNone(unassign_resp.json()["assigned_to_user"])

        # 4. GET /api/incidents/{id} -> tasks list inside incident card
        inc_resp = self.client.get("/api/incidents/1", headers=ib_hdr)
        self.assertEqual(inc_resp.status_code, 200, inc_resp.text)
        inc_tasks = {t["id"]: t for t in inc_resp.json()["tasks"]}
        self.assertEqual(inc_tasks[task_id]["assigned_to"], sys_user.id)
        self.assertEqual(inc_tasks[task_id]["created_by"], ib_user.id)
        self.assertEqual(inc_tasks[task_id]["assigned_to_user"], expected_sys)
        self.assertEqual(inc_tasks[task_id]["created_by_user"], expected_ib)
        self.assertIsNone(inc_tasks[unassigned_task.id]["assigned_to_user"])
        self.assertIsNone(inc_tasks[unassigned_task.id]["created_by_user"])


if __name__ == "__main__":
    unittest.main()
