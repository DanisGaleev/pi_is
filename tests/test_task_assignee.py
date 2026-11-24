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
            json={
                "title": "Несуществующий исполнитель",
                "description": "Проверка несуществующего исполнителя",
                "assigned_to": 999999,
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(missing_create.status_code, 404, missing_create.text)
        with self.assertRaises(NotFoundError):
            self.container.task_service.create_task(
                ib_user,
                1,
                {
                    "title": "Direct check",
                    "description": "Проверка сервиса",
                    "assigned_to": 999999,
                    "due_date": "2026-12-01T12:00:00+00:00",
                },
            )

        # Inactive assignee rejected on create (HTTP 400 / ValidationError)
        inactive_create = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Уволенный исполнитель",
                "description": "Проверка неактивного исполнителя",
                "assigned_to": inactive_user.id,
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(inactive_create.status_code, 400, inactive_create.text)
        with self.assertRaises(ValidationError):
            self.container.task_service.create_task(
                ib_user,
                1,
                {
                    "title": "Direct inactive",
                    "description": "Проверка сервиса",
                    "assigned_to": inactive_user.id,
                    "due_date": "2026-12-01T12:00:00+00:00",
                },
            )

        # Non-integer assigned_to rejected cleanly in service layer
        with self.assertRaises(ValidationError):
            self.container.task_service.create_task(
                ib_user,
                1,
                {
                    "title": "Bad type",
                    "description": "Проверка типа",
                    "assigned_to": True,
                    "due_date": "2026-12-01T12:00:00+00:00",
                },
            )

        # Valid create with explicit sysadmin
        created = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Проверить логи WS-FIN-04",
                "description": "Полная проверка",
                "assigned_to": sys_user.id,
                "due_date": "2026-12-01T12:00:00+00:00",
            },
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
                "due_date": "2026-12-01T12:00:00+00:00",
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
        self.assertEqual(inc_tasks[task_id]["assignee_ids"], [sys_user.id])
        self.assertEqual(inc_tasks[task_id]["assignees"], [expected_sys])
        self.assertEqual(inc_tasks[task_id]["created_by"], ib_user.id)
        self.assertEqual(inc_tasks[task_id]["assigned_to_user"], expected_sys)
        self.assertEqual(inc_tasks[task_id]["created_by_user"], expected_ib)
        self.assertIsNone(inc_tasks[unassigned_task.id]["assigned_to_user"])
        self.assertEqual(inc_tasks[unassigned_task.id]["assignee_ids"], [])
        self.assertEqual(inc_tasks[unassigned_task.id]["assignees"], [])
        self.assertIsNone(inc_tasks[unassigned_task.id]["created_by_user"])

    def test_multi_assignees_create_add_remove_replace_filter_and_rbac(self) -> None:
        ib_hdr, ib_user = self._login("ib")
        sys_hdr, sys_user = self._login("sysadmin")
        head_hdr, head_user = self._login("it_head")
        lawyer_hdr, _ = self._login("lawyer")

        extra_sys = self.container.user_repo.create(
            "sysadmin_extra",
            hash_password("password123"),
            "Сидоров Максим (Сисадмин 2)",
            Role.SYS_ADMIN,
            active=True,
        )
        inactive_user = self.container.user_repo.create(
            "sysadmin_retired",
            hash_password("password123"),
            "Уволенный Сотрудник",
            Role.SYS_ADMIN,
            active=False,
        )

        # Reject > 3 assignees on create (HTTP 400 / ValidationError)
        too_many_resp = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Слишком много исполнителей",
                "description": "Проверка лимита в 3 исполнителя",
                "assignee_ids": [ib_user["id"], sys_user["id"], head_user["id"], extra_sys.id],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(too_many_resp.status_code, 400, too_many_resp.text)

        # Reject empty assignee_ids on create (HTTP 422)
        empty_resp = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Пустой список исполнителей",
                "description": "Проверка валидации",
                "assignee_ids": [],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(empty_resp.status_code, 422, empty_resp.text)

        # Reject conflicting assigned_to and assignee_ids
        conflict_resp = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Конфликт полей",
                "description": "assigned_to не входит в assignee_ids",
                "assigned_to": extra_sys.id,
                "assignee_ids": [sys_user["id"], head_user["id"]],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(conflict_resp.status_code, 400, conflict_resp.text)

        # Create task with 2 assignees (duplicates deduplicated preserving order)
        create_resp = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Совместная проверка хоста",
                "description": "Проверить логи и сетевые подключения",
                "assignee_ids": [sys_user["id"], head_user["id"], sys_user["id"]],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(create_resp.status_code, 200, create_resp.text)
        task = create_resp.json()
        task_id = task["id"]
        self.assertEqual(task["assignee_ids"], [sys_user["id"], head_user["id"]])
        self.assertEqual(task["assigned_to"], sys_user["id"])
        self.assertEqual([u["id"] for u in task["assignees"]], [sys_user["id"], head_user["id"]])

        # Both assignees see the task under GET /api/tasks?assigned_to=me
        sys_me = self.client.get("/api/tasks", params={"assigned_to": "me"}, headers=sys_hdr).json()
        head_me = self.client.get("/api/tasks", params={"assigned_to": "me"}, headers=head_hdr).json()
        ib_me = self.client.get("/api/tasks", params={"assigned_to": "me"}, headers=ib_hdr).json()
        self.assertIn(task_id, {t["id"] for t in sys_me})
        self.assertIn(task_id, {t["id"] for t in head_me})
        self.assertNotIn(task_id, {t["id"] for t in ib_me})

        # Add 3rd assignee via POST /api/tasks/{id}/assignees
        add_3rd = self.client.post(
            f"/api/tasks/{task_id}/assignees",
            json={"user_id": extra_sys.id},
            headers=ib_hdr,
        )
        self.assertEqual(add_3rd.status_code, 200, add_3rd.text)
        self.assertEqual(
            add_3rd.json()["assignee_ids"],
            [sys_user["id"], head_user["id"], extra_sys.id],
        )

        # Idempotent add of existing assignee succeeds without exceeding limit
        add_dup = self.client.post(
            f"/api/tasks/{task_id}/assignees",
            json={"user_id": head_user["id"]},
            headers=ib_hdr,
        )
        self.assertEqual(add_dup.status_code, 200, add_dup.text)
        self.assertEqual(len(add_dup.json()["assignee_ids"]), 3)

        # Adding a 4th distinct assignee fails (HTTP 400)
        add_4th = self.client.post(
            f"/api/tasks/{task_id}/assignees",
            json={"user_id": ib_user["id"]},
            headers=ib_hdr,
        )
        self.assertEqual(add_4th.status_code, 400, add_4th.text)

        # Remove primary assignee via DELETE -> primary shifts to head_user
        del_primary = self.client.delete(
            f"/api/tasks/{task_id}/assignees/{sys_user['id']}",
            headers=ib_hdr,
        )
        self.assertEqual(del_primary.status_code, 200, del_primary.text)
        self.assertEqual(del_primary.json()["assignee_ids"], [head_user["id"], extra_sys.id])
        self.assertEqual(del_primary.json()["assigned_to"], head_user["id"])

        # Removing user not assigned to the task returns 404
        del_missing = self.client.delete(
            f"/api/tasks/{task_id}/assignees/{sys_user['id']}",
            headers=ib_hdr,
        )
        self.assertEqual(del_missing.status_code, 404, del_missing.text)

        # Replace assignees via PUT /api/tasks/{id}/assignees (and reject inactive / >3)
        put_inactive = self.client.put(
            f"/api/tasks/{task_id}/assignees",
            json={"assignee_ids": [inactive_user.id]},
            headers=ib_hdr,
        )
        self.assertEqual(put_inactive.status_code, 400, put_inactive.text)

        put_too_many = self.client.put(
            f"/api/tasks/{task_id}/assignees",
            json={"assignee_ids": [ib_user["id"], sys_user["id"], head_user["id"], extra_sys.id]},
            headers=ib_hdr,
        )
        self.assertEqual(put_too_many.status_code, 400, put_too_many.text)

        put_ok = self.client.put(
            f"/api/tasks/{task_id}/assignees",
            json={"assignee_ids": [ib_user["id"], sys_user["id"], extra_sys.id]},
            headers=ib_hdr,
        )
        self.assertEqual(put_ok.status_code, 200, put_ok.text)
        self.assertEqual(
            put_ok.json()["assignee_ids"],
            [ib_user["id"], sys_user["id"], extra_sys.id],
        )
        self.assertEqual(put_ok.json()["assigned_to"], ib_user["id"])

        # Clear all assignees via PATCH /api/tasks/{id} with assignee_ids=[]
        clear_patch = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"assignee_ids": []},
            headers=ib_hdr,
        )
        self.assertEqual(clear_patch.status_code, 200, clear_patch.text)
        self.assertEqual(clear_patch.json()["assignee_ids"], [])
        self.assertEqual(clear_patch.json()["assignees"], [])
        self.assertIsNone(clear_patch.json()["assigned_to"])
        self.assertIsNone(clear_patch.json()["assigned_to_user"])

        # Re-assign 2 people via PATCH /api/tasks/{id}
        patch_two = self.client.patch(
            f"/api/tasks/{task_id}",
            json={"assignee_ids": [sys_user["id"], ib_user["id"]]},
            headers=ib_hdr,
        )
        self.assertEqual(patch_two.status_code, 200, patch_two.text)
        self.assertEqual(patch_two.json()["assignee_ids"], [sys_user["id"], ib_user["id"]])

        # RBAC: lawyer cannot manage assignees; sysadmin cannot manage assignees on PDn task
        self.assertEqual(
            self.client.put(
                f"/api/tasks/{task_id}/assignees",
                json={"assignee_ids": [sys_user["id"]]},
                headers=lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                f"/api/tasks/{task_id}/assignees",
                json={"user_id": head_user["id"]},
                headers=lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.delete(
                f"/api/tasks/{task_id}/assignees/{sys_user['id']}",
                headers=lawyer_hdr,
            ).status_code,
            403,
        )

        pdn_task = self.client.post(
            "/api/incidents/2/tasks",
            json={
                "title": "ПДн совместная задача",
                "description": "Проверка ПДн",
                "assignee_ids": [ib_user["id"], head_user["id"]],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=ib_hdr,
        )
        self.assertEqual(pdn_task.status_code, 200, pdn_task.text)
        pdn_task_id = pdn_task.json()["id"]
        self.assertEqual(
            self.client.post(
                f"/api/tasks/{pdn_task_id}/assignees",
                json={"user_id": sys_user["id"]},
                headers=sys_hdr,
            ).status_code,
            403,
        )

        # Incident card shows enriched multi-assignee list
        card_tasks = {
            t["id"]: t
            for t in self.client.get("/api/incidents/1", headers=ib_hdr).json()["tasks"]
        }
        self.assertEqual(card_tasks[task_id]["assignee_ids"], [sys_user["id"], ib_user["id"]])
        self.assertEqual(
            [u["id"] for u in card_tasks[task_id]["assignees"]],
            [sys_user["id"], ib_user["id"]],
        )


if __name__ == "__main__":
    unittest.main()
