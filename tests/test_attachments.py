import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.container import AppContainer, container
from app.repositories import Database
from app.services.attachments import MAX_ATTACHMENT_SIZE_BYTES
from main import app


class TestAttachmentsApi(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        self._prev_upload_dir = os.environ.get("UPLOAD_DIR")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "test_attachments.db")
        os.environ["UPLOAD_DIR"] = str(Path(self._tmp_dir.name) / "uploads")

        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

        self.ib_hdr, self.ib_user = self._login("ib")
        self.sys_hdr, self.sys_user = self._login("sysadmin")
        self.head_hdr, self.head_user = self._login("it_head")
        self.lawyer_hdr, self.lawyer_user = self._login("lawyer")

        # Non-PDn task on incident #1 and PDn task on incident #2
        t_non_pdn = self.client.post(
            "/api/incidents/1/tasks",
            json={
                "title": "Проверить WS-FIN-04",
                "description": "Собрать скриншоты и логи",
                "assigned_to": self.sys_user["id"],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(t_non_pdn.status_code, 200, t_non_pdn.text)
        self.task_id = t_non_pdn.json()["id"]

        t_other = self.client.post(
            "/api/incidents/3/tasks",
            json={
                "title": "Проверить письмо",
                "description": "Сохранить заголовки",
                "assigned_to": self.sys_user["id"],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(t_other.status_code, 200, t_other.text)
        self.other_task_id = t_other.json()["id"]

        t_pdn = self.client.post(
            "/api/incidents/2/tasks",
            json={
                "title": "Проверить выгрузку ПДн",
                "description": "Выгрузка CRM",
                "assigned_to": self.head_user["id"],
                "due_date": "2026-12-01T12:00:00+00:00",
            },
            headers=self.ib_hdr,
        )
        self.assertEqual(t_pdn.status_code, 200, t_pdn.text)
        self.pdn_task_id = t_pdn.json()["id"]

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        if self._prev_upload_dir is None:
            os.environ.pop("UPLOAD_DIR", None)
        else:
            os.environ["UPLOAD_DIR"] = self._prev_upload_dir
        self._tmp_dir.cleanup()

    def _login(self, username: str, password: str = "password123") -> tuple[dict[str, str], dict]:
        resp = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        return {"Authorization": f"Bearer {body['token']}"}, body["user"]

    def test_upload_image_text_and_table_to_incident_and_download(self) -> None:
        files_to_upload = [
            ("screenshot.png", b"\x89PNG\r\n\x1a\nfake-png-bytes", "image/png", "image"),
            ("av_scan.log", b"2026-11-24 TROJAN detected\n", "text/plain", "text"),
            ("affected_hosts.csv", b"host,status\nWS-FIN-04,quarantined\n", "text/csv", "table"),
            (
                "report.xlsx",
                b"PK\x03\x04fake-xlsx-content",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "table",
            ),
        ]

        uploaded_ids: list[int] = []
        for fname, raw_bytes, ctype, expected_cat in files_to_upload:
            resp = self.client.post(
                "/api/incidents/1/attachments",
                files={"file": (fname, raw_bytes, ctype)},
                headers=self.ib_hdr,
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            item = resp.json()
            self.assertEqual(item["incident_id"], 1)
            self.assertIsNone(item["task_id"])
            self.assertEqual(item["filename"], fname)
            self.assertEqual(item["file_category"], expected_cat)
            self.assertEqual(item["size_bytes"], len(raw_bytes))
            self.assertEqual(item["uploaded_by"], self.ib_user["id"])
            self.assertEqual(item["uploaded_by_user"]["username"], "ib")
            self.assertEqual(item["download_url"], f"/api/attachments/{item['id']}/download")

            disk_path = Path(os.environ["UPLOAD_DIR"]) / item["path"]
            self.assertTrue(disk_path.is_file())
            self.assertEqual(disk_path.read_bytes(), raw_bytes)

            dl = self.client.get(item["download_url"], headers=self.sys_hdr)
            self.assertEqual(dl.status_code, 200, dl.text)
            self.assertEqual(dl.content, raw_bytes)
            self.assertIn(fname, dl.headers.get("content-disposition", ""))
            uploaded_ids.append(item["id"])

        listed = self.client.get("/api/incidents/1/attachments", headers=self.sys_hdr)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual([a["id"] for a in listed.json()], uploaded_ids)

        card = self.client.get("/api/incidents/1", headers=self.sys_hdr)
        self.assertEqual(card.status_code, 200, card.text)
        self.assertEqual([a["id"] for a in card.json()["attachments"]], uploaded_ids)
        self.assertIn("attachment_uploaded", [h["action"] for h in card.json()["history"]])

    def test_task_file_management_upload_link_detach_and_delete(self) -> None:
        # 1. Upload a file directly to a task
        task_upload = self.client.post(
            f"/api/tasks/{self.task_id}/attachments",
            files={"file": ("evidence.txt", b"task log line 1\n", "text/plain")},
            headers=self.sys_hdr,
        )
        self.assertEqual(task_upload.status_code, 200, task_upload.text)
        att_task = task_upload.json()
        self.assertEqual(att_task["incident_id"], 1)
        self.assertEqual(att_task["task_id"], self.task_id)
        att_task_path = Path(os.environ["UPLOAD_DIR"]) / att_task["path"]
        self.assertTrue(att_task_path.is_file())

        # Verify task listing & incident card reflect the attachment on the task
        task_atts = self.client.get(f"/api/tasks/{self.task_id}/attachments", headers=self.sys_hdr)
        self.assertEqual(task_atts.status_code, 200, task_atts.text)
        self.assertEqual([a["id"] for a in task_atts.json()], [att_task["id"]])

        tasks_list = self.client.get("/api/tasks", params={"incident_id": 1}, headers=self.ib_hdr)
        self.assertEqual(tasks_list.status_code, 200, tasks_list.text)
        t_row = next(t for t in tasks_list.json() if t["id"] == self.task_id)
        self.assertEqual([a["id"] for a in t_row["attachments"]], [att_task["id"]])

        # 2. Upload an incident-level table file and link it to the task
        inc_upload = self.client.post(
            "/api/incidents/1/attachments",
            files={"file": ("iocs.csv", b"ip,action\n1.2.3.4,block\n", "text/csv")},
            headers=self.ib_hdr,
        )
        self.assertEqual(inc_upload.status_code, 200, inc_upload.text)
        att_inc_id = inc_upload.json()["id"]
        self.assertIsNone(inc_upload.json()["task_id"])

        link_resp = self.client.post(
            f"/api/tasks/{self.task_id}/attachments/{att_inc_id}",
            headers=self.sys_hdr,
        )
        self.assertEqual(link_resp.status_code, 200, link_resp.text)
        self.assertEqual(link_resp.json()["task_id"], self.task_id)

        # Cannot link a file from incident #1 to a task of incident #3
        cross_link = self.client.post(
            f"/api/tasks/{self.other_task_id}/attachments/{att_inc_id}",
            headers=self.ib_hdr,
        )
        self.assertEqual(cross_link.status_code, 400, cross_link.text)

        # 3. Detach from task without deleting the file ("убрать" из задачи)
        detach_resp = self.client.delete(
            f"/api/tasks/{self.task_id}/attachments/{att_inc_id}",
            headers=self.sys_hdr,
        )
        self.assertEqual(detach_resp.status_code, 200, detach_resp.text)
        self.assertTrue(detach_resp.json()["detached"])
        self.assertFalse(detach_resp.json()["deleted"])
        self.assertIsNone(detach_resp.json()["attachment"]["task_id"])

        # Task now has only att_task, while incident still has both files on disk & DB
        task_atts_after_detach = self.client.get(
            f"/api/tasks/{self.task_id}/attachments", headers=self.sys_hdr
        ).json()
        self.assertEqual([a["id"] for a in task_atts_after_detach], [att_task["id"]])

        inc_atts_after_detach = self.client.get(
            "/api/incidents/1/attachments", headers=self.ib_hdr
        ).json()
        self.assertEqual({a["id"] for a in inc_atts_after_detach}, {att_task["id"], att_inc_id})

        # 4. Delete permanently via task endpoint (?delete_file=true)
        del_from_task = self.client.delete(
            f"/api/tasks/{self.task_id}/attachments/{att_task['id']}",
            params={"delete_file": True},
            headers=self.sys_hdr,
        )
        self.assertEqual(del_from_task.status_code, 200, del_from_task.text)
        self.assertTrue(del_from_task.json()["deleted"])
        self.assertFalse(att_task_path.exists())
        self.assertEqual(
            self.client.get(f"/api/attachments/{att_task['id']}", headers=self.ib_hdr).status_code,
            404,
        )

        # 5. Delete remaining incident attachment via /api/incidents/{id}/attachments/{att_id}
        att_inc_path = Path(os.environ["UPLOAD_DIR"]) / inc_upload.json()["path"]
        self.assertTrue(att_inc_path.is_file())
        del_inc_att = self.client.delete(
            f"/api/incidents/1/attachments/{att_inc_id}",
            headers=self.ib_hdr,
        )
        self.assertEqual(del_inc_att.status_code, 200, del_inc_att.text)
        self.assertFalse(att_inc_path.exists())
        self.assertEqual(
            self.client.get("/api/incidents/1/attachments", headers=self.ib_hdr).json(),
            [],
        )

    def test_validation_rejects_disallowed_types_empty_oversized_and_bad_mime(self) -> None:
        # Disallowed extensions (executables/scripts/html)
        for bad_name, content_type in (
            ("payload.exe", "application/octet-stream"),
            ("script.ps1", "text/plain"),
            ("page.html", "text/html"),
            ("noext", "text/plain"),
        ):
            resp = self.client.post(
                "/api/incidents/1/attachments",
                files={"file": (bad_name, b"data", content_type)},
                headers=self.ib_hdr,
            )
            self.assertEqual(resp.status_code, 400, f"{bad_name}: {resp.text}")

        # Empty file rejected
        empty_resp = self.client.post(
            "/api/tasks/{}/attachments".format(self.task_id),
            files={"file": ("empty.txt", b"", "text/plain")},
            headers=self.ib_hdr,
        )
        self.assertEqual(empty_resp.status_code, 400, empty_resp.text)

        # Oversized file rejected
        oversized = b"x" * (MAX_ATTACHMENT_SIZE_BYTES + 1)
        big_resp = self.client.post(
            "/api/incidents/1/attachments",
            files={"file": ("huge.txt", oversized, "text/plain")},
            headers=self.ib_hdr,
        )
        self.assertEqual(big_resp.status_code, 400, big_resp.text)

        # Mismatched MIME type rejected
        bad_mime = self.client.post(
            "/api/incidents/1/attachments",
            files={"file": ("photo.png", b"png", "application/x-msdownload")},
            headers=self.ib_hdr,
        )
        self.assertEqual(bad_mime.status_code, 400, bad_mime.text)

    def test_rbac_on_incident_and_task_attachments(self) -> None:
        # Upload a PDn attachment (incident #2) and a non-PDn attachment (incident #1)
        pdn_up = self.client.post(
            f"/api/tasks/{self.pdn_task_id}/attachments",
            files={"file": ("pdn_dump.csv", b"fio\nIvanov\n", "text/csv")},
            headers=self.ib_hdr,
        )
        self.assertEqual(pdn_up.status_code, 200, pdn_up.text)
        pdn_att_id = pdn_up.json()["id"]

        non_pdn_up = self.client.post(
            f"/api/tasks/{self.task_id}/attachments",
            files={"file": ("scan.txt", b"clean", "text/plain")},
            headers=self.ib_hdr,
        )
        self.assertEqual(non_pdn_up.status_code, 200, non_pdn_up.text)
        non_pdn_att_id = non_pdn_up.json()["id"]

        # Sysadmin cannot access, download, upload, or delete PDn incident/task attachments
        self.assertEqual(
            self.client.get("/api/incidents/2/attachments", headers=self.sys_hdr).status_code, 403
        )
        self.assertEqual(
            self.client.get(f"/api/tasks/{self.pdn_task_id}/attachments", headers=self.sys_hdr).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(f"/api/attachments/{pdn_att_id}/download", headers=self.sys_hdr).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/incidents/2/attachments",
                files={"file": ("x.txt", b"x", "text/plain")},
                headers=self.sys_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.delete(f"/api/attachments/{pdn_att_id}", headers=self.sys_hdr).status_code,
            403,
        )

        # Lawyer can view/download PDn incident attachments, but cannot mutate or access task endpoints
        self.assertEqual(
            self.client.get("/api/incidents/2/attachments", headers=self.lawyer_hdr).status_code, 200
        )
        self.assertEqual(
            self.client.get(f"/api/attachments/{pdn_att_id}/download", headers=self.lawyer_hdr).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(f"/api/tasks/{self.pdn_task_id}/attachments", headers=self.lawyer_hdr).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/incidents/2/attachments",
                files={"file": ("legal.txt", b"note", "text/plain")},
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.delete(
                f"/api/tasks/{self.pdn_task_id}/attachments/{pdn_att_id}",
                headers=self.lawyer_hdr,
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.delete(f"/api/attachments/{pdn_att_id}", headers=self.lawyer_hdr).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(f"/api/attachments/{non_pdn_att_id}/download", headers=self.lawyer_hdr).status_code,
            403,
        )

        # Audit log recorded upload, download, and access_denied entries
        audits = {(r.user_id, r.object_type, r.action) for r in container.audit_repo.list_recent(limit=50)}
        self.assertIn((self.ib_user["id"], "attachment", "upload"), audits)
        self.assertIn((self.lawyer_user["id"], "attachment", "download"), audits)

    def test_migration_adds_missing_attachment_columns_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "partial_attachments.db")
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, full_name TEXT NOT NULL, role TEXT NOT NULL);
                CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE instructions (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, incident_type TEXT NOT NULL, steps_json TEXT NOT NULL);
                CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', incident_type TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Новый', outcome TEXT NOT NULL DEFAULT '', computer TEXT NOT NULL DEFAULT '', employee TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', incident_key TEXT NOT NULL DEFAULT '', has_personal_data INTEGER NOT NULL DEFAULT 0, instruction_id INTEGER, rkn_draft TEXT NOT NULL DEFAULT '', detected_at TEXT NOT NULL, taken_at TEXT, closed_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', sender TEXT NOT NULL DEFAULT '', body TEXT NOT NULL, incident_key TEXT NOT NULL DEFAULT '', received_at TEXT NOT NULL);
                CREATE TABLE history (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, user_id INTEGER, action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
                CREATE TABLE step_progress (incident_id INTEGER NOT NULL, step_index INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0, updated_by INTEGER, updated_at TEXT NOT NULL, PRIMARY KEY (incident_id, step_index));
                CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', assigned_to INTEGER, status TEXT NOT NULL DEFAULT 'Открыта', result TEXT NOT NULL DEFAULT '', created_by INTEGER, created_at TEXT NOT NULL, completed_at TEXT);
                CREATE TABLE notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, recipient_role TEXT NOT NULL, recipient_name TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    uploaded_by INTEGER,
                    uploaded_at TEXT NOT NULL
                );
                """
            )
            conn.commit()
            conn.close()

            db = Database(db_path)
            db.init_schema()
            db.init_schema()

            with db.connection() as migrated:
                cols = {r["name"] for r in migrated.execute("PRAGMA table_info(attachments)").fetchall()}
                self.assertTrue({"task_id", "size_bytes"}.issubset(cols))

            c = AppContainer(db_path=db_path)
            self.assertEqual(c.attachment_repo.list_by_incident(1), [])


if __name__ == "__main__":
    unittest.main()
