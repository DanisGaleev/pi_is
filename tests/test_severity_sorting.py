import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.container import AppContainer
from app.domain import Incident
from app.enums import IncidentStatus, IncidentType, Severity
from app.services import ValidationError
from main import app


class TestIncidentSortingRepositoryAndService(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp_dir.name) / "sorting_unit.db")
        self.container = AppContainer(self.db_path)
        self.container.init_db()
        with self.container.db.connection() as conn:
            conn.execute("DELETE FROM incidents")
            conn.commit()
        self.ib_user = self.container.user_repo.get_by_username("ib")
        assert self.ib_user is not None

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def _insert_incident(
        self,
        title: str,
        severity: str,
        detected_at: str,
        created_at: str,
        has_personal_data: int = 0,
    ) -> Incident:
        return self.container.incident_repo.create(
            Incident(
                title=title,
                description=f"desc: {title}",
                incident_type=IncidentType.VIRUS.value,
                severity=severity,
                status=IncidentStatus.NEW.value,
                computer="WS-SORT-01",
                has_personal_data=has_personal_data,
                detected_at=detected_at,
                created_at=created_at,
                updated_at=created_at,
            )
        )

    def test_default_severity_sorting_ignores_insertion_id_and_uses_id_desc_tiebreaker(self) -> None:
        # Insert in ascending priority + unrecognized severity and duplicate tiers.
        inc_other = self._insert_incident("other-1", "unknown_tier", "2026-11-20T10:00:00+00:00", "2026-11-20T10:00:00+00:00")
        inc_low_1 = self._insert_incident("low-1", Severity.LOW.value, "2026-11-20T11:00:00+00:00", "2026-11-20T11:00:00+00:00")
        inc_med = self._insert_incident("med-1", Severity.MEDIUM.value, "2026-11-20T12:00:00+00:00", "2026-11-20T12:00:00+00:00")
        inc_high_1 = self._insert_incident("high-1", Severity.HIGH.value, "2026-11-20T13:00:00+00:00", "2026-11-20T13:00:00+00:00")
        inc_crit_1 = self._insert_incident("crit-1", Severity.CRITICAL.value, "2026-11-20T09:00:00+00:00", "2026-11-20T09:00:00+00:00")
        inc_low_2 = self._insert_incident("low-2", Severity.LOW.value, "2026-11-20T14:00:00+00:00", "2026-11-20T14:00:00+00:00")
        inc_high_2 = self._insert_incident("high-2", Severity.HIGH.value, "2026-11-20T08:00:00+00:00", "2026-11-20T08:00:00+00:00")
        inc_crit_2 = self._insert_incident("crit-2", Severity.CRITICAL.value, "2026-11-20T07:00:00+00:00", "2026-11-20T07:00:00+00:00")

        expected_ids = [
            inc_crit_2.id,
            inc_crit_1.id,
            inc_high_2.id,
            inc_high_1.id,
            inc_med.id,
            inc_low_2.id,
            inc_low_1.id,
            inc_other.id,
        ]

        repo_ids = [inc.id for inc in self.container.incident_repo.list_filtered()]
        svc_ids = [inc["id"] for inc in self.container.incident_service.list_incidents(self.ib_user)]
        self.assertEqual(repo_ids, expected_ids)
        self.assertEqual(svc_ids, expected_ids)

    def test_explicit_sort_by_and_sort_order_options(self) -> None:
        # Insertion order, detected_at order, created_at order, and severity order all differ.
        inc1 = self._insert_incident("inc-1", Severity.LOW.value, "2026-11-20T12:00:00+00:00", "2026-11-20T15:00:00+00:00")
        inc2 = self._insert_incident("inc-2", Severity.CRITICAL.value, "2026-11-20T08:00:00+00:00", "2026-11-20T11:00:00+00:00")
        inc3 = self._insert_incident("inc-3", Severity.MEDIUM.value, "2026-11-20T16:00:00+00:00", "2026-11-20T10:00:00+00:00")
        inc4 = self._insert_incident("inc-4", Severity.HIGH.value, "2026-11-20T10:00:00+00:00", "2026-11-20T13:00:00+00:00")

        cases = [
            ("severity", "desc", [inc2.id, inc4.id, inc3.id, inc1.id]),
            ("severity", "asc", [inc1.id, inc3.id, inc4.id, inc2.id]),
            ("detected_at", "desc", [inc3.id, inc1.id, inc4.id, inc2.id]),
            ("detected_at", "asc", [inc2.id, inc4.id, inc1.id, inc3.id]),
            ("created_at", "desc", [inc1.id, inc4.id, inc2.id, inc3.id]),
            ("created_at", "asc", [inc3.id, inc2.id, inc4.id, inc1.id]),
            ("id", "desc", [inc4.id, inc3.id, inc2.id, inc1.id]),
            ("id", "asc", [inc1.id, inc2.id, inc3.id, inc4.id]),
        ]
        for sort_by, sort_order, expected_ids in cases:
            with self.subTest(sort_by=sort_by, sort_order=sort_order):
                result = self.container.incident_service.list_incidents(
                    self.ib_user,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.assertEqual([item["id"] for item in result], expected_ids)

    def test_invalid_sort_params_raise_validation_error_and_prevent_sql_injection(self) -> None:
        self._insert_incident("keep-me", Severity.HIGH.value, "2026-11-20T10:00:00+00:00", "2026-11-20T10:00:00+00:00")

        invalid_sort_by = [
            "",
            "   ",
            "title",
            "updated_at",
            "severity; DROP TABLE incidents--",
            "id DESC, (SELECT 1)",
        ]
        for bad_field in invalid_sort_by:
            with self.subTest(bad_sort_by=bad_field):
                with self.assertRaises(ValueError):
                    self.container.incident_repo.list_filtered(sort_by=bad_field)
                with self.assertRaises(ValidationError):
                    self.container.incident_service.list_incidents(self.ib_user, sort_by=bad_field)

        invalid_sort_order = [
            "",
            "   ",
            "up",
            "descending",
            "desc; DROP TABLE incidents--",
            "asc UNION SELECT 1",
        ]
        for bad_order in invalid_sort_order:
            with self.subTest(bad_sort_order=bad_order):
                with self.assertRaises(ValueError):
                    self.container.incident_repo.list_filtered(sort_order=bad_order)
                with self.assertRaises(ValidationError):
                    self.container.incident_service.list_incidents(self.ib_user, sort_order=bad_order)

        # Ensure incidents table was untouched by injection attempts.
        remaining = self.container.incident_repo.list_filtered()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].title, "keep-me")


class TestIncidentSortingApi(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._prev_db_path = os.environ.get("DB_PATH")
        os.environ["DB_PATH"] = str(Path(self._tmp_dir.name) / "sorting_api.db")
        self._client_cm = TestClient(app)
        self.client = self._client_cm.__enter__()

    def tearDown(self) -> None:
        self._client_cm.__exit__(None, None, None)
        if self._prev_db_path is None:
            os.environ.pop("DB_PATH", None)
        else:
            os.environ["DB_PATH"] = self._prev_db_path
        self._tmp_dir.cleanup()

    def _login(self, username: str) -> dict[str, str]:
        resp = self.client.post("/api/auth/login", json={"username": username, "password": "password123"})
        self.assertEqual(resp.status_code, 200, resp.text)
        return {"Authorization": f"Bearer {resp.json()['token']}"}

    def _create_incident(
        self,
        headers: dict[str, str],
        *,
        title: str,
        severity: str,
        detected_at: str,
        has_personal_data: int = 0,
    ) -> dict:
        resp = self.client.post(
            "/api/incidents",
            json={
                "title": title,
                "incident_type": "virus",
                "severity": severity,
                "computer": "WS-API-01",
                "has_personal_data": has_personal_data,
                "detected_at": detected_at,
            },
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def test_seeded_and_created_incidents_default_to_severity_desc_then_id_desc(self) -> None:
        ib_hdr = self._login("ib")

        # Seeded incidents: id=1 (high), id=2 (critical), id=3 (medium).
        seeded = self.client.get("/api/incidents", headers=ib_hdr)
        self.assertEqual(seeded.status_code, 200, seeded.text)
        self.assertEqual([item["id"] for item in seeded.json()], [2, 1, 3])

        # Create low (id=4), medium (id=5), high (id=6), critical (id=7), low (id=8).
        inc4 = self._create_incident(ib_hdr, title="low-4", severity="low", detected_at="2026-11-20T14:00:00+00:00")
        inc5 = self._create_incident(ib_hdr, title="med-5", severity="medium", detected_at="2026-11-20T13:00:00+00:00")
        inc6 = self._create_incident(ib_hdr, title="high-6", severity="high", detected_at="2026-11-20T12:00:00+00:00")
        inc7 = self._create_incident(ib_hdr, title="crit-7", severity="critical", detected_at="2026-11-20T11:00:00+00:00")
        inc8 = self._create_incident(ib_hdr, title="low-8", severity="low", detected_at="2026-11-20T15:00:00+00:00")

        listed = self.client.get("/api/incidents", headers=ib_hdr)
        self.assertEqual(listed.status_code, 200, listed.text)
        items = listed.json()

        self.assertEqual(
            [item["severity"] for item in items],
            ["critical", "critical", "high", "high", "medium", "medium", "low", "low"],
        )
        self.assertEqual(
            [item["id"] for item in items],
            [inc7["id"], 2, inc6["id"], 1, inc5["id"], 3, inc8["id"], inc4["id"]],
        )

        # Sysadmin must still see PDn filtered out (id=2 excluded), sorted by severity desc.
        sys_hdr = self._login("sysadmin")
        sys_listed = self.client.get("/api/incidents", headers=sys_hdr)
        self.assertEqual(sys_listed.status_code, 200, sys_listed.text)
        self.assertEqual(
            [item["id"] for item in sys_listed.json()],
            [inc7["id"], inc6["id"], 1, inc5["id"], 3, inc8["id"], inc4["id"]],
        )

    def test_query_parameters_sort_by_and_sort_order(self) -> None:
        ib_hdr = self._login("ib")

        # Update created_at on seeded rows? Keep deterministic by inserting fresh rows and filtering q="WS-API-01".
        inc_a = self._create_incident(ib_hdr, title="A-low", severity="low", detected_at="2026-11-20T05:00:00+00:00")
        inc_b = self._create_incident(ib_hdr, title="B-crit", severity="critical", detected_at="2026-11-20T02:00:00+00:00")
        inc_c = self._create_incident(ib_hdr, title="C-med", severity="medium", detected_at="2026-11-20T09:00:00+00:00")

        # Give distinct created_at timestamps decoupled from id and detected_at.
        from app.container import container

        with container.db.connection() as conn:
            conn.execute("UPDATE incidents SET created_at = ? WHERE id = ?", ("2026-11-20T04:00:00+00:00", inc_a["id"]))
            conn.execute("UPDATE incidents SET created_at = ? WHERE id = ?", ("2026-11-20T06:00:00+00:00", inc_b["id"]))
            conn.execute("UPDATE incidents SET created_at = ? WHERE id = ?", ("2026-11-20T01:00:00+00:00", inc_c["id"]))
            conn.commit()

        api_cases = [
            ({"q": "WS-API-01", "sort_by": "severity", "sort_order": "asc"}, [inc_a["id"], inc_c["id"], inc_b["id"]]),
            ({"q": "WS-API-01", "sort_by": "severity", "sort_order": "desc"}, [inc_b["id"], inc_c["id"], inc_a["id"]]),
            ({"q": "WS-API-01", "sort_by": "detected_at", "sort_order": "asc"}, [inc_b["id"], inc_a["id"], inc_c["id"]]),
            ({"q": "WS-API-01", "sort_by": "detected_at", "sort_order": "desc"}, [inc_c["id"], inc_a["id"], inc_b["id"]]),
            ({"q": "WS-API-01", "sort_by": "created_at", "sort_order": "asc"}, [inc_c["id"], inc_a["id"], inc_b["id"]]),
            ({"q": "WS-API-01", "sort_by": "created_at", "sort_order": "desc"}, [inc_b["id"], inc_a["id"], inc_c["id"]]),
            ({"q": "WS-API-01", "sort_by": "id", "sort_order": "asc"}, [inc_a["id"], inc_b["id"], inc_c["id"]]),
            ({"q": "WS-API-01", "sort_by": "id", "sort_order": "desc"}, [inc_c["id"], inc_b["id"], inc_a["id"]]),
        ]
        for params, expected_ids in api_cases:
            with self.subTest(params=params):
                resp = self.client.get("/api/incidents", params=params, headers=ib_hdr)
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual([item["id"] for item in resp.json()], expected_ids)

    def test_invalid_query_parameters_return_400_or_422(self) -> None:
        ib_hdr = self._login("ib")

        bad_queries = [
            {"sort_by": "title"},
            {"sort_by": "unknown"},
            {"sort_by": ""},
            {"sort_by": "severity; DROP TABLE incidents--"},
            {"sort_order": "invalid"},
            {"sort_order": ""},
            {"sort_order": "desc; DROP TABLE incidents--"},
        ]
        for params in bad_queries:
            with self.subTest(params=params):
                resp = self.client.get("/api/incidents", params=params, headers=ib_hdr)
                self.assertIn(resp.status_code, (400, 422), resp.text)

        # Table remains intact and queryable.
        ok = self.client.get("/api/incidents", headers=ib_hdr)
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(len(ok.json()), 3)
