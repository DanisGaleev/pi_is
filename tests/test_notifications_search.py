import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.container import AppContainer
from app.enums import Role
from app.services.exceptions import ValidationError
from main import app


class TestNotificationSearchAndFiltering(unittest.TestCase):
    """Test search and multi-facet filtering across repository, service, and API layers."""

    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        self.db_path = str(Path(self._tmp_dir.name) / "test_notifications_search.db")
        os.environ["DB_PATH"] = self.db_path

        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()
        self.container = AppContainer(self.db_path)

        # Seed diverse notifications across dates, roles, kinds, incidents, and languages
        self.n1 = self.container.notification_repo.create(
            incident_id=1,
            recipient_role=Role.IT_HEAD.value,
            recipient_name="Сидорова Елена",
            kind="escalation_30m",
            message="Эскалация: вирус Trojan.Win32 обнаружен на WS-FIN-01",
            created_at="2026-11-18T09:15:00+00:00",
        )
        self.n2 = self.container.notification_repo.create(
            incident_id=2,
            recipient_role=Role.LAWYER.value,
            recipient_name="Смирнов Алексей",
            kind="pdn_lawyer_notice",
            message="Срочно (ПДн): утечка таблицы clients_pdn требует уведомления РКН",
            created_at="2026-11-19T00:00:00+00:00",
        )
        self.n3 = self.container.notification_repo.create(
            incident_id=2,
            recipient_role=Role.ACCOUNTANT.value,
            recipient_name="Петрова Светлана",
            kind="pdn_accounting_notice",
            message="Уведомление ПДН и платёжные реквизиты: оценка финансовых рисков",
            created_at="2026-11-19T23:59:59+00:00",
        )
        self.n4 = self.container.notification_repo.create(
            incident_id=1,
            recipient_role=Role.DIRECTOR.value,
            recipient_name="Alice Cooper",
            kind="escalation_director",
            message="Critical Ransomware Alert on Server-DB-02",
            created_at="2026-11-20T12:30:00+00:00",
        )
        self.n5 = self.container.notification_repo.create(
            incident_id=None,
            recipient_role=Role.FOREMAN.value,
            recipient_name="Ёжиков Пётр",
            kind="warning_broadcast",
            message="Внимание: массовая фишинговая рассылка (Phishing Campaign)",
            created_at="2026-11-20T18:45:00Z",
        )
        self.n6 = self.container.notification_repo.create(
            incident_id=2,
            recipient_role=Role.LAWYER.value,
            recipient_name="Смирнов Алексей",
            kind="pdn_lawyer_notice",
            message="Повторное напоминание по ПДн: срок 24ч истекает",
            created_at="2026-11-21T01:00:00+03:00",  # 2026-11-20T22:00:00+00:00
        )
        self.all_ids_desc = [self.n6.id, self.n5.id, self.n4.id, self.n3.id, self.n2.id, self.n1.id]

        resp = self.client.post(
            "/api/auth/login",
            json={"username": "ib", "password": "password123"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.headers = {"Authorization": f"Bearer {resp.json()['token']}"}

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _api_ids(self, **params: str | int) -> list[int]:
        resp = self.client.get("/api/notifications", params=params, headers=self.headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        return [item["id"] for item in resp.json()]

    def test_requires_auth(self) -> None:
        resp = self.client.get("/api/notifications")
        self.assertEqual(resp.status_code, 401)

    def test_backwards_compatible_unfiltered_and_role_only(self) -> None:
        # Repository default & role-only
        self.assertEqual([n.id for n in self.container.notification_repo.list_all()], self.all_ids_desc)
        self.assertEqual(
            [n.id for n in self.container.notification_repo.list_all(Role.LAWYER.value)],
            [self.n6.id, self.n2.id],
        )

        # Service default & Role enum / string
        self.assertEqual(
            [n["id"] for n in self.container.notification_service.list_notifications()],
            self.all_ids_desc,
        )
        self.assertEqual(
            [n["id"] for n in self.container.notification_service.list_notifications(Role.LAWYER)],
            [self.n6.id, self.n2.id],
        )

        # API default, empty params, and recipient_role
        self.assertEqual(self._api_ids(), self.all_ids_desc)
        self.assertEqual(
            self._api_ids(q="", recipient_role="", kind="", date_from="", date_to=""),
            self.all_ids_desc,
        )
        self.assertEqual(self._api_ids(recipient_role="lawyer"), [self.n6.id, self.n2.id])

    def test_case_insensitive_cyrillic_search_in_message_and_recipient_name(self) -> None:
        # Cyrillic mixed case in message
        self.assertEqual(self._api_ids(q="пдн"), [self.n6.id, self.n3.id, self.n2.id])
        self.assertEqual(self._api_ids(q="ПдН"), [self.n6.id, self.n3.id, self.n2.id])
        self.assertEqual(self._api_ids(q="УТЕЧКА"), [self.n2.id])
        self.assertEqual(self._api_ids(q="  фишинговая  "), [self.n5.id])

        # Cyrillic mixed case in recipient_name
        self.assertEqual(self._api_ids(q="СИДОРОВА"), [self.n1.id])
        self.assertEqual(self._api_ids(q="смирнов"), [self.n6.id, self.n2.id])
        self.assertEqual(self._api_ids(q="ёжиков"), [self.n5.id])
        self.assertEqual(self._api_ids(q="ЁЖИКОВ"), [self.n5.id])

    def test_case_insensitive_latin_search_in_message_and_recipient_name(self) -> None:
        # Latin mixed case in message
        self.assertEqual(self._api_ids(q="ransomware"), [self.n4.id])
        self.assertEqual(self._api_ids(q="TROJAN.win32"), [self.n1.id])
        self.assertEqual(self._api_ids(q="phishing"), [self.n5.id])

        # Latin mixed case in recipient_name
        self.assertEqual(self._api_ids(q="alice"), [self.n4.id])
        self.assertEqual(self._api_ids(q="COOPER"), [self.n4.id])

        # q searches only message & recipient_name, not kind or recipient_role
        self.assertEqual(self._api_ids(q="escalation_30m"), [])
        self.assertEqual(self._api_ids(q="it_head"), [])

    def test_facet_filters_role_kind_incident_id(self) -> None:
        self.assertEqual(self._api_ids(recipient_role="it_head"), [self.n1.id])
        self.assertEqual(self._api_ids(recipient_role="chief_accountant"), [self.n3.id])

        self.assertEqual(self._api_ids(kind="pdn_lawyer_notice"), [self.n6.id, self.n2.id])
        self.assertEqual(self._api_ids(kind="warning_broadcast"), [self.n5.id])

        self.assertEqual(self._api_ids(incident_id=1), [self.n4.id, self.n1.id])
        self.assertEqual(self._api_ids(incident_id=2), [self.n6.id, self.n3.id, self.n2.id])
        self.assertEqual(self._api_ids(incident_id=999), [])

    def test_date_from_and_date_to_filtering(self) -> None:
        # Date-only date_to includes full day up to 23:59:59+00:00
        self.assertEqual(self._api_ids(date_to="2026-11-18"), [self.n1.id])
        self.assertEqual(self._api_ids(date_to="2026-11-19"), [self.n3.id, self.n2.id, self.n1.id])

        # Date-only date_from starts inclusively at 00:00:00+00:00
        self.assertEqual(
            self._api_ids(date_from="2026-11-19"),
            [self.n6.id, self.n5.id, self.n4.id, self.n3.id, self.n2.id],
        )
        self.assertEqual(
            self._api_ids(date_from="2026-11-20"),
            [self.n6.id, self.n5.id, self.n4.id],
        )

        # Single-day range (2026-11-19 00:00:00 through 23:59:59+00:00)
        self.assertEqual(
            self._api_ids(date_from="2026-11-19", date_to="2026-11-19"),
            [self.n3.id, self.n2.id],
        )

        # Single-day range on 2026-11-20 includes Z and +03:00 -> 22:00Z timestamps
        self.assertEqual(
            self._api_ids(date_from="2026-11-20", date_to="2026-11-20"),
            [self.n6.id, self.n5.id, self.n4.id],
        )

        # Exact ISO datetime bounds (with and without explicit offset)
        self.assertEqual(
            self._api_ids(
                date_from="2026-11-20T12:30:00+00:00",
                date_to="2026-11-20T18:45:00+00:00",
            ),
            [self.n5.id, self.n4.id],
        )
        self.assertEqual(
            self._api_ids(
                date_from="2026-11-19T23:59:59",
                date_to="2026-11-20T12:30:00",
            ),
            [self.n4.id, self.n3.id],
        )

        # Inverted date range returns empty list
        self.assertEqual(self._api_ids(date_from="2026-11-21", date_to="2026-11-18"), [])

    def test_invalid_date_returns_400_and_validation_error(self) -> None:
        with self.assertRaises(ValidationError):
            self.container.notification_service.list_notifications(date_from="not-a-date")

        resp_from = self.client.get(
            "/api/notifications",
            params={"date_from": "2026-99-99"},
            headers=self.headers,
        )
        self.assertEqual(resp_from.status_code, 400)

        resp_to = self.client.get(
            "/api/notifications",
            params={"date_to": "invalid"},
            headers=self.headers,
        )
        self.assertEqual(resp_to.status_code, 400)

    def test_combined_filters_and_descending_order(self) -> None:
        # Combine q + recipient_role + kind + incident_id + date_from + date_to
        self.assertEqual(
            self._api_ids(
                q="пдн",
                recipient_role="lawyer",
                kind="pdn_lawyer_notice",
                incident_id=2,
                date_from="2026-11-19",
                date_to="2026-11-20",
            ),
            [self.n6.id, self.n2.id],
        )

        # Narrow further by date_to to isolate n2
        self.assertEqual(
            self._api_ids(
                q="пдн",
                recipient_role="lawyer",
                kind="pdn_lawyer_notice",
                incident_id=2,
                date_from="2026-11-19",
                date_to="2026-11-19",
            ),
            [self.n2.id],
        )

        # Combine Latin q + incident_id + role
        self.assertEqual(
            self._api_ids(q="server-db-02", recipient_role="director", incident_id=1),
            [self.n4.id],
        )

        # Mismatched combination yields empty list
        self.assertEqual(
            self._api_ids(q="ransomware", recipient_role="lawyer", incident_id=1),
            [],
        )


if __name__ == "__main__":
    unittest.main()
