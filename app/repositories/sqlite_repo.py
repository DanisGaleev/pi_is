import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Collection, Iterable, Iterator
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Any

from app.domain.models import (
    AuditRecord,
    HistoryRecord,
    Incident,
    IncomingMessage,
    IngestionError,
    Instruction,
    InstructionProgress,
    Notification,
    Task,
    User,
)
from app.enums import (
    SEVERITY_WEIGHTS,
    AccessCategory,
    Channel,
    CheckResult,
    DeliveryStatus,
    IncidentStatus,
    IncidentType,
    Role,
    Severity,
    SourceType,
    TaskStatus,
)


_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _to_utc_iso(text: str) -> str:
    """Parse an ISO-8601 date/datetime string into a fixed-width UTC ISO-8601 string."""
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds")


def _iso_utc_key(value: str) -> str:
    """Normalize a stored timestamp for chronological SQL comparison, falling back safely."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    try:
        return _to_utc_iso(text)
    except ValueError:
        return text


def _parse_date_bound(value: str, *, end_of_day: bool) -> str:
    """Parse a YYYY-MM-DD date or ISO-8601 datetime into a fixed-width UTC ISO bound."""
    text = value.strip()
    if end_of_day and _DATE_ONLY_RE.fullmatch(text):
        day = date.fromisoformat(text)
        dt = datetime(day.year, day.month, day.day, 23, 59, 59, 999999, tzinfo=timezone.utc)
        return dt.isoformat(timespec="microseconds")
    return _to_utc_iso(text)


def utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format without microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def hash_password(password: str) -> str:
    """Return SHA-256 hex digest of a plain-text password."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


_sha256 = hash_password


SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS instructions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    incident_type TEXT NOT NULL,
    steps_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '{IncidentStatus.NEW.value}',
    outcome TEXT NOT NULL DEFAULT '',
    computer TEXT NOT NULL DEFAULT '',
    employee TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    incident_key TEXT NOT NULL DEFAULT '',
    has_personal_data INTEGER NOT NULL DEFAULT 0,
    instruction_id INTEGER REFERENCES instructions(id),
    rkn_draft TEXT NOT NULL DEFAULT '',
    detected_at TEXT NOT NULL,
    taken_at TEXT,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    access_category TEXT NOT NULL DEFAULT '',
    assigned_to INTEGER REFERENCES users(id),
    rkn_sent_at TEXT,
    rkn_confirmation TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    source TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    incident_key TEXT NOT NULL DEFAULT '',
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS step_progress (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    updated_by INTEGER REFERENCES users(id),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, step_index)
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    assigned_to INTEGER REFERENCES users(id),
    status TEXT NOT NULL DEFAULT '{TaskStatus.OPEN.value}',
    result TEXT NOT NULL DEFAULT '',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    due_date TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    recipient_role TEXT NOT NULL,
    recipient_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT '{Channel.INTERNAL.value}',
    status TEXT NOT NULL DEFAULT '{DeliveryStatus.SENT.value}'
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    object_type TEXT NOT NULL,
    object_id INTEGER,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingestion_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL DEFAULT '',
    error_text TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0
);
"""

_COLUMN_MIGRATIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "users": (
        ("active", "INTEGER NOT NULL DEFAULT 1"),
    ),
    "tasks": (
        ("due_date", "TEXT"),
    ),
    "incidents": (
        ("access_category", "TEXT NOT NULL DEFAULT ''"),
        ("assigned_to", "INTEGER REFERENCES users(id)"),
        ("rkn_sent_at", "TEXT"),
        ("rkn_confirmation", "TEXT NOT NULL DEFAULT ''"),
    ),
    "notifications": (
        ("channel", f"TEXT NOT NULL DEFAULT '{Channel.INTERNAL.value}'"),
        ("status", f"TEXT NOT NULL DEFAULT '{DeliveryStatus.SENT.value}'"),
    ),
}


def _apply_migrations(conn: sqlite3.Connection) -> None:
    """Safely add missing UML columns to pre-existing SQLite tables."""
    for table, columns in _COLUMN_MIGRATIONS.items():
        existing = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for col_name, col_def in columns:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")


def _seed(conn: sqlite3.Connection) -> None:
    """Populate initial demo users, instructions, incidents, messages, and history."""
    pw_hash = hash_password("password123")
    users = [
        ("ib", pw_hash, "Иванов Алексей (ИБ)", Role.SECURITY_SPECIALIST.value),
        ("sysadmin", pw_hash, "Петров Дмитрий (Сисадмин)", Role.SYS_ADMIN.value),
        ("it_head", pw_hash, "Сидорова Елена (Руководитель ИТ)", Role.IT_HEAD.value),
        ("lawyer", pw_hash, "Козлова Анна (Юрист)", Role.LAWYER.value),
    ]
    conn.executemany(
        "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
        users,
    )

    instructions = [
        (
            "Реагирование на вредоносное ПО",
            IncidentType.VIRUS.value,
            json.dumps(
                [
                    "Изолировать рабочую станцию от сети",
                    "Запустить полную антивирусную проверку",
                    "Проверить журналы авторизации и сетевую активность",
                    "Сменить скомпрометированные учетные данные",
                ],
                ensure_ascii=False,
            ),
        ),
        (
            "Реагирование на утечку ПДн",
            IncidentType.DATA_LEAK.value,
            json.dumps(
                [
                    "Зафиксировать объем и категории персональных данных",
                    "Ограничить доступ к источнику утечки",
                    "Подготовить первичное уведомление в РКН (24 часа)",
                    "Уведомить юриста и руководство",
                ],
                ensure_ascii=False,
            ),
        ),
        (
            "Реагирование на фишинг",
            IncidentType.PHISHING.value,
            json.dumps(
                [
                    "Заблокировать домен/отправителя в почтовом шлюзе",
                    "Проверить переходы сотрудников по ссылке",
                    "Принудительно сбросить пароли затронутых учетных записей",
                ],
                ensure_ascii=False,
            ),
        ),
        (
            "Несанкционированный доступ",
            IncidentType.UNAUTHORIZED_ACCESS.value,
            json.dumps(
                [
                    "Заблокировать подозрительную учетную запись/сессию",
                    "Собрать логи доступа и IP-адреса источника",
                    "Проверить целостность критичных систем",
                ],
                ensure_ascii=False,
            ),
        ),
    ]
    conn.executemany(
        "INSERT INTO instructions (title, incident_type, steps_json) VALUES (?, ?, ?)",
        instructions,
    )

    now = datetime.now(timezone.utc).replace(microsecond=0)
    t_45m_ago = (now - timedelta(minutes=45)).isoformat()
    t_2h_ago = (now - timedelta(hours=2)).isoformat()
    t_1d_ago = (now - timedelta(days=1)).isoformat()
    now_iso = now.isoformat()

    incidents = [
        (
            "Обнаружен троян на WS-FIN-04",
            "Антивирус зафиксировал попытку запуска Trojan.GenericKD на рабочей станции.",
            IncidentType.VIRUS.value,
            Severity.HIGH.value,
            IncidentStatus.NEW.value,
            "",
            "WS-FIN-04",
            "Смирнова О.В.",
            SourceType.KASPERSKY.value,
            "av-ws-fin-04-trojan",
            0,
            1,
            "",
            t_45m_ago,
            None,
            None,
            t_45m_ago,
            t_45m_ago,
            AccessCategory.EMPLOYEE_INVOLVED.value,
        ),
        (
            "Подозрение на выгрузку базы клиентов",
            "DLP-система зафиксировала выгрузку архива с ПДн клиентов на внешний ресурс.",
            IncidentType.DATA_LEAK.value,
            Severity.CRITICAL.value,
            IncidentStatus.IN_PROGRESS.value,
            "",
            "SRV-CRM-01",
            "Волков И.П.",
            SourceType.DLP.value,
            "dlp-crm-export-01",
            1,
            2,
            "",
            t_2h_ago,
            t_2h_ago,
            None,
            t_2h_ago,
            t_2h_ago,
            AccessCategory.PERSONAL_DATA.value,
        ),
        (
            "Фишинговая рассылка на бухгалтерию",
            "Получено письмо с поддельным счетом и вредоносной ссылкой.",
            IncidentType.PHISHING.value,
            Severity.MEDIUM.value,
            IncidentStatus.CLOSED.value,
            CheckResult.FALSE_POSITIVE.value,
            "WS-ACC-02",
            "Морозова Т.А.",
            SourceType.EMAIL.value,
            "mail-phish-acc-02",
            0,
            3,
            "",
            t_1d_ago,
            t_1d_ago,
            now_iso,
            t_1d_ago,
            now_iso,
            AccessCategory.EMPLOYEE_INVOLVED.value,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO incidents (
            title, description, incident_type, severity, status, outcome,
            computer, employee, source, incident_key, has_personal_data,
            instruction_id, rkn_draft, detected_at, taken_at, closed_at,
            created_at, updated_at, access_category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        incidents,
    )

    conn.execute(
        "INSERT INTO messages (incident_id, source, sender, body, incident_key, received_at) VALUES (?, ?, ?, ?, ?, ?)",
        (1, SourceType.KASPERSKY.value, "AV-Agent", "Обнаружен Trojan.GenericKD на WS-FIN-04", "av-ws-fin-04-trojan", t_45m_ago),
    )
    conn.execute(
        "INSERT INTO messages (incident_id, source, sender, body, incident_key, received_at) VALUES (?, ?, ?, ?, ?, ?)",
        (2, SourceType.DLP.value, "DLP-Sensor", "Выгрузка файла clients_pdn.zip с SRV-CRM-01", "dlp-crm-export-01", t_2h_ago),
    )
    conn.execute(
        "INSERT INTO history (incident_id, user_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (1, None, "created", f"Инцидент создан по сигналу {SourceType.KASPERSKY.value}", t_45m_ago),
    )
    conn.execute(
        "INSERT INTO history (incident_id, user_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (2, 1, "status_changed", f"Статус изменен на {IncidentStatus.IN_PROGRESS.value}", t_2h_ago),
    )


class Database:
    """SQLite database connection factory and schema/migration manager."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path

    def resolve_path(self) -> str:
        """Resolve the configured or current DB_PATH environment value."""
        if self._db_path is not None:
            return self._db_path
        return os.environ.get("DB_PATH", "incidents.db")

    def connect(self) -> sqlite3.Connection:
        """Open a fresh SQLite connection with Row factory, foreign keys, and cfold()."""
        conn = sqlite3.connect(self.resolve_path(), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.create_function(
            "cfold",
            1,
            lambda s: s.casefold() if isinstance(s, str) else s,
        )
        conn.create_function("iso_utc", 1, _iso_utc_key)
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a SQLite connection and guarantee closure afterwards."""
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Create missing tables, safely migrate existing schemas, and seed empty DBs."""
        with self.connection() as conn:
            conn.executescript(SCHEMA_SQL)
            _apply_migrations(conn)
            if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
                _seed(conn)
            conn.commit()


_DEFAULT_DB = Database()


def get_conn() -> sqlite3.Connection:
    """Return a SQLite connection for the active DB_PATH."""
    return _DEFAULT_DB.connect()


def init_db() -> None:
    """Initialize and migrate the database for the active DB_PATH."""
    _DEFAULT_DB.init_schema()


class _BaseRepository:
    """Shared base for SQLite-backed repositories."""

    def __init__(self, db: Database) -> None:
        self.db = db


def _row_to_user(row: sqlite3.Row) -> User:
    keys = row.keys()
    active = bool(row["active"]) if "active" in keys else True
    return User(
        id=row["id"],
        username=row["username"],
        full_name=row["full_name"],
        role=row["role"],
        active=active,
    )


def _row_to_incident(row: sqlite3.Row) -> Incident:
    keys = row.keys()
    return Incident(
        id=row["id"],
        title=row["title"],
        description=row["description"],
        incident_type=row["incident_type"],
        severity=row["severity"],
        status=row["status"],
        outcome=row["outcome"],
        computer=row["computer"],
        employee=row["employee"],
        source=row["source"],
        incident_key=row["incident_key"],
        has_personal_data=row["has_personal_data"],
        instruction_id=row["instruction_id"],
        rkn_draft=row["rkn_draft"],
        detected_at=row["detected_at"],
        taken_at=row["taken_at"],
        closed_at=row["closed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        access_category=row["access_category"] if "access_category" in keys else "",
        assigned_to=row["assigned_to"] if "assigned_to" in keys else None,
        rkn_sent_at=row["rkn_sent_at"] if "rkn_sent_at" in keys else None,
        rkn_confirmation=row["rkn_confirmation"] if "rkn_confirmation" in keys else "",
    )


def _row_to_task(row: sqlite3.Row) -> Task:
    keys = row.keys()
    return Task(
        id=row["id"],
        incident_id=row["incident_id"],
        title=row["title"],
        description=row["description"],
        assigned_to=row["assigned_to"],
        status=row["status"],
        result=row["result"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        completed_at=row["completed_at"],
        due_date=row["due_date"] if "due_date" in keys else None,
    )


def _row_to_notification(row: sqlite3.Row) -> Notification:
    keys = row.keys()
    return Notification(
        id=row["id"],
        incident_id=row["incident_id"],
        recipient_role=row["recipient_role"],
        recipient_name=row["recipient_name"],
        kind=row["kind"],
        message=row["message"],
        created_at=row["created_at"],
        channel=(row["channel"] if "channel" in keys and row["channel"] else Channel.INTERNAL.value),
        status=(row["status"] if "status" in keys and row["status"] else DeliveryStatus.SENT.value),
    )


class UserRepository(_BaseRepository):
    """Persistence operations for system users."""

    def get_by_id(self, user_id: int) -> User | None:
        """Fetch a user by primary key."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id, username, full_name, role, active FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            return _row_to_user(row) if row is not None else None

    def get_by_username(self, username: str) -> User | None:
        """Fetch a user by login name."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id, username, full_name, role, active FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return _row_to_user(row) if row is not None else None

    def find_with_password(self, username: str) -> tuple[User, str] | None:
        """Fetch a user and their stored password hash for credential verification."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, full_name, role, active FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return None
            return _row_to_user(row), row["password_hash"]

    def find_first_by_role(self, role: Role | str) -> User | None:
        """Return the first active user matching the specified role."""
        role_val = role.value if isinstance(role, Role) else str(role)
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id, username, full_name, role, active FROM users WHERE role = ? AND active = 1 ORDER BY id LIMIT 1",
                (role_val,),
            ).fetchone()
            return _row_to_user(row) if row is not None else None

    def list_all(self) -> list[User]:
        """Return all users ordered by id."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, username, full_name, role, active FROM users ORDER BY id"
            ).fetchall()
            return [_row_to_user(r) for r in rows]

    def list_filtered(
        self,
        role: Role | str | None = None,
        roles: Collection[Role | str] | None = None,
        active_only: bool = False,
    ) -> list[User]:
        """Return users filtered by optional role, allowed roles, and active flag."""
        clauses: list[str] = []
        params: list[Any] = []

        if active_only:
            clauses.append("active = 1")
        if role is not None:
            role_val = role.value if isinstance(role, Role) else str(role).strip()
            if role_val:
                clauses.append("role = ?")
                params.append(role_val)
        if roles is not None:
            role_vals = [r.value if isinstance(r, Role) else str(r) for r in roles]
            if not role_vals:
                return []
            placeholders = ", ".join("?" for _ in role_vals)
            clauses.append(f"role IN ({placeholders})")
            params.extend(role_vals)

        sql = "SELECT id, username, full_name, role, active FROM users"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id"

        with self.db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_user(r) for r in rows]

    def get_by_ids(self, user_ids: Iterable[int]) -> dict[int, User]:
        """Batch-fetch users keyed by primary key ID."""
        unique_ids = sorted({int(uid) for uid in user_ids if uid is not None})
        if not unique_ids:
            return {}
        placeholders = ", ".join("?" for _ in unique_ids)
        with self.db.connection() as conn:
            rows = conn.execute(
                f"SELECT id, username, full_name, role, active FROM users WHERE id IN ({placeholders})",
                unique_ids,
            ).fetchall()
            return {row["id"]: _row_to_user(row) for row in rows}

    def get_names_by_role(self) -> dict[str, str]:
        """Return a mapping of role code to user full name."""
        with self.db.connection() as conn:
            rows = conn.execute("SELECT role, full_name FROM users").fetchall()
            return {r["role"]: r["full_name"] for r in rows}

    def create(
        self,
        username: str,
        password_hash: str,
        full_name: str,
        role: Role | str,
        active: bool = True,
    ) -> User:
        """Insert a new user record and return the persisted domain model."""
        role_val = role.value if isinstance(role, Role) else str(role)
        with self.db.connection() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, full_name, role, active) VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, full_name, role_val, 1 if active else 0),
            )
            conn.commit()
            row = conn.execute(
                "SELECT id, username, full_name, role, active FROM users WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
            return _row_to_user(row)


class SessionRepository(_BaseRepository):
    """Persistence operations for bearer authentication sessions."""

    def create(self, token: str, user_id: int, created_at: str) -> None:
        """Persist a new session token for a user."""
        with self.db.connection() as conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                (token, user_id, created_at),
            )
            conn.commit()

    def get_user_by_token(self, token: str) -> User | None:
        """Resolve an active user from a bearer session token."""
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT u.id, u.username, u.full_name, u.role, u.active
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = ? AND u.active = 1
                """,
                (token,),
            ).fetchone()
            return _row_to_user(row) if row is not None else None

    def delete(self, token: str) -> None:
        """Delete a session token."""
        with self.db.connection() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()


DEFAULT_INCIDENT_SORT_BY = "severity"
DEFAULT_INCIDENT_SORT_ORDER = "desc"

_SEVERITY_WHEN_CLAUSES = " ".join(
    f"WHEN '{sev.value}' THEN {weight}"
    for sev, weight in sorted(SEVERITY_WEIGHTS.items(), key=lambda item: item[1], reverse=True)
)
_SEVERITY_PRIORITY_SQL = f"CASE LOWER(severity) {_SEVERITY_WHEN_CLAUSES} ELSE 0 END"

_INCIDENT_SORT_EXPRESSIONS: dict[str, str] = {
    "severity": _SEVERITY_PRIORITY_SQL,
    "detected_at": "detected_at",
    "created_at": "created_at",
    "id": "id",
}

_SORT_DIRECTIONS: dict[str, str] = {
    "desc": "DESC",
    "asc": "ASC",
}


def resolve_incident_sort(
    sort_by: str | None = DEFAULT_INCIDENT_SORT_BY,
    sort_order: str | None = DEFAULT_INCIDENT_SORT_ORDER,
) -> tuple[str, str]:
    """Validate and normalize incident sort field and direction against allowlists."""
    field_key = (
        DEFAULT_INCIDENT_SORT_BY
        if sort_by is None
        else (sort_by.strip().lower() if isinstance(sort_by, str) else "")
    )
    if field_key not in _INCIDENT_SORT_EXPRESSIONS:
        allowed_fields = ", ".join(_INCIDENT_SORT_EXPRESSIONS)
        raise ValueError(f"Недопустимое поле сортировки {sort_by!r}; разрешены: {allowed_fields}")

    order_key = (
        DEFAULT_INCIDENT_SORT_ORDER
        if sort_order is None
        else (sort_order.strip().lower() if isinstance(sort_order, str) else "")
    )
    if order_key not in _SORT_DIRECTIONS:
        allowed_orders = ", ".join(_SORT_DIRECTIONS)
        raise ValueError(
            f"Недопустимое направление сортировки {sort_order!r}; разрешены: {allowed_orders}"
        )

    return field_key, order_key


def _build_incident_order_by(
    sort_by: str | None = DEFAULT_INCIDENT_SORT_BY,
    sort_order: str | None = DEFAULT_INCIDENT_SORT_ORDER,
) -> str:
    """Build a safe SQL ORDER BY clause using allowlisted expressions only."""
    field_key, order_key = resolve_incident_sort(sort_by, sort_order)
    expr = _INCIDENT_SORT_EXPRESSIONS[field_key]
    direction = _SORT_DIRECTIONS[order_key]
    if field_key == "id":
        return f"id {direction}"
    return f"{expr} {direction}, id {direction}"


class IncidentRepository(_BaseRepository):
    """Persistence operations for incidents."""

    def get_by_id(self, incident_id: int) -> Incident | None:
        """Fetch an incident by ID."""
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            return _row_to_incident(row) if row is not None else None

    def list_filtered(
        self,
        q: str | None = None,
        incident_type: str | None = None,
        status: str | None = None,
        exclude_personal_data: bool = False,
        sort_by: str | None = DEFAULT_INCIDENT_SORT_BY,
        sort_order: str | None = DEFAULT_INCIDENT_SORT_ORDER,
    ) -> list[Incident]:
        """List incidents matching optional search, filter, and sort criteria."""
        order_by = _build_incident_order_by(sort_by, sort_order)
        clauses: list[str] = []
        params: list[Any] = []

        if exclude_personal_data:
            clauses.append("has_personal_data = 0")
        if q:
            clauses.append("(cfold(computer) LIKE ? OR cfold(employee) LIKE ?)")
            like = f"%{q.casefold()}%"
            params.extend([like, like])
        if incident_type:
            resolved_type = IncidentType.resolve(incident_type)
            clauses.append("incident_type = ?")
            params.append(resolved_type.value if resolved_type is not None else incident_type)
        if status:
            resolved_status = IncidentStatus.resolve(status)
            clauses.append("status = ?")
            params.append(resolved_status.value if resolved_status is not None else status)

        sql = "SELECT * FROM incidents"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += f" ORDER BY {order_by}"

        with self.db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_incident(r) for r in rows]

    def find_open_by_key(self, incident_key: str) -> Incident | None:
        """Find the latest non-closed incident sharing an external incident key."""
        if not incident_key:
            return None
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE status != ? AND incident_key = ? ORDER BY id DESC LIMIT 1",
                (IncidentStatus.CLOSED.value, incident_key),
            ).fetchone()
            return _row_to_incident(row) if row is not None else None

    def find_open_by_computer_and_type(self, computer: str, incident_type: str) -> Incident | None:
        """Find the latest non-closed incident matching host and incident type."""
        if not computer or not incident_type:
            return None
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM incidents
                WHERE status != ? AND computer = ? AND incident_type = ?
                ORDER BY id DESC LIMIT 1
                """,
                (IncidentStatus.CLOSED.value, computer, incident_type),
            ).fetchone()
            return _row_to_incident(row) if row is not None else None

    def list_open(self) -> list[Incident]:
        """List all non-closed incidents."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status != ? ORDER BY id DESC",
                (IncidentStatus.CLOSED.value,),
            ).fetchall()
            return [_row_to_incident(r) for r in rows]

    def list_by_month(self, year: int, month: int) -> list[Incident]:
        """List incidents detected in a given year and month."""
        prefix = f"{year:04d}-{month:02d}"
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE substr(detected_at, 1, 7) = ? ORDER BY id DESC",
                (prefix,),
            ).fetchall()
            return [_row_to_incident(r) for r in rows]

    def list_by_year(self, year: int) -> list[Incident]:
        """List incidents detected in a given calendar year."""
        prefix = f"{year:04d}"
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE substr(detected_at, 1, 4) = ? ORDER BY id DESC",
                (prefix,),
            ).fetchall()
            return [_row_to_incident(r) for r in rows]

    def create(self, incident: Incident) -> Incident:
        """Insert a new incident and return the persisted domain model."""
        now = utc_now()
        detected_at = incident.detected_at or now
        created_at = incident.created_at or now
        updated_at = incident.updated_at or now
        access_category = incident.access_category or incident.resolve_access_category().value

        with self.db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO incidents (
                    title, description, incident_type, severity, status, outcome,
                    computer, employee, source, incident_key, has_personal_data,
                    instruction_id, rkn_draft, detected_at, taken_at, closed_at,
                    created_at, updated_at, access_category, assigned_to,
                    rkn_sent_at, rkn_confirmation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.title,
                    incident.description,
                    incident.incident_type,
                    incident.severity,
                    incident.status,
                    incident.outcome,
                    incident.computer,
                    incident.employee,
                    incident.source,
                    incident.incident_key,
                    incident.has_personal_data,
                    incident.instruction_id,
                    incident.rkn_draft,
                    detected_at,
                    incident.taken_at,
                    incident.closed_at,
                    created_at,
                    updated_at,
                    access_category,
                    incident.assigned_to,
                    incident.rkn_sent_at,
                    incident.rkn_confirmation,
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (cur.lastrowid,)).fetchone()
            return _row_to_incident(row)

    def update(self, incident: Incident) -> Incident:
        """Persist updates to an existing incident and return the reloaded model."""
        if incident.id is None:
            raise ValueError("Incident id is required for update")
        updated_at = incident.updated_at or utc_now()
        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE incidents
                SET title = ?, description = ?, incident_type = ?, severity = ?,
                    status = ?, outcome = ?, computer = ?, employee = ?, source = ?,
                    incident_key = ?, has_personal_data = ?, instruction_id = ?,
                    rkn_draft = ?, detected_at = ?, taken_at = ?, closed_at = ?,
                    updated_at = ?, access_category = ?, assigned_to = ?,
                    rkn_sent_at = ?, rkn_confirmation = ?
                WHERE id = ?
                """,
                (
                    incident.title,
                    incident.description,
                    incident.incident_type,
                    incident.severity,
                    incident.status,
                    incident.outcome,
                    incident.computer,
                    incident.employee,
                    incident.source,
                    incident.incident_key,
                    incident.has_personal_data,
                    incident.instruction_id,
                    incident.rkn_draft,
                    incident.detected_at,
                    incident.taken_at,
                    incident.closed_at,
                    updated_at,
                    incident.access_category,
                    incident.assigned_to,
                    incident.rkn_sent_at,
                    incident.rkn_confirmation,
                    incident.id,
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident.id,)).fetchone()
            return _row_to_incident(row)

    def touch_updated_at(self, incident_id: int, updated_at: str) -> None:
        """Update the updated_at timestamp on an incident."""
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE incidents SET updated_at = ? WHERE id = ?",
                (updated_at, incident_id),
            )
            conn.commit()


class MessageRepository(_BaseRepository):
    """Persistence operations for incoming incident messages."""

    def list_by_incident(self, incident_id: int) -> list[IncomingMessage]:
        """List messages attached to an incident in chronological order."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE incident_id = ? ORDER BY id ASC",
                (incident_id,),
            ).fetchall()
            return [
                IncomingMessage(
                    id=r["id"],
                    incident_id=r["incident_id"],
                    source=r["source"],
                    sender=r["sender"],
                    body=r["body"],
                    incident_key=r["incident_key"],
                    received_at=r["received_at"],
                )
                for r in rows
            ]

    def create(
        self,
        incident_id: int,
        source: str,
        sender: str,
        body: str,
        incident_key: str = "",
        received_at: str | None = None,
    ) -> IncomingMessage:
        """Attach a new incoming message to an incident."""
        ts = received_at or utc_now()
        with self.db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO messages (incident_id, source, sender, body, incident_key, received_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (incident_id, source, sender, body, incident_key, ts),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM messages WHERE id = ?", (cur.lastrowid,)).fetchone()
            return IncomingMessage(
                id=row["id"],
                incident_id=row["incident_id"],
                source=row["source"],
                sender=row["sender"],
                body=row["body"],
                incident_key=row["incident_key"],
                received_at=row["received_at"],
            )


class HistoryRepository(_BaseRepository):
    """Persistence operations for incident history logs."""

    def list_by_incident(self, incident_id: int) -> list[HistoryRecord]:
        """List incident history entries joined with actor names."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT h.*, u.username, u.full_name
                FROM history h
                LEFT JOIN users u ON u.id = h.user_id
                WHERE h.incident_id = ?
                ORDER BY h.id ASC
                """,
                (incident_id,),
            ).fetchall()
            return [
                HistoryRecord(
                    id=r["id"],
                    incident_id=r["incident_id"],
                    user_id=r["user_id"],
                    action=r["action"],
                    details=r["details"],
                    created_at=r["created_at"],
                    username=r["username"],
                    full_name=r["full_name"],
                )
                for r in rows
            ]

    def add(
        self,
        incident_id: int,
        user_id: int | None,
        action: str,
        details: str = "",
        created_at: str | None = None,
    ) -> HistoryRecord:
        """Append a history record to an incident timeline."""
        ts = created_at or utc_now()
        with self.db.connection() as conn:
            cur = conn.execute(
                "INSERT INTO history (incident_id, user_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
                (incident_id, user_id, action, details, ts),
            )
            conn.commit()
            row = conn.execute(
                """
                SELECT h.*, u.username, u.full_name
                FROM history h
                LEFT JOIN users u ON u.id = h.user_id
                WHERE h.id = ?
                """,
                (cur.lastrowid,),
            ).fetchone()
            return HistoryRecord(
                id=row["id"],
                incident_id=row["incident_id"],
                user_id=row["user_id"],
                action=row["action"],
                details=row["details"],
                created_at=row["created_at"],
                username=row["username"],
                full_name=row["full_name"],
            )


class InstructionRepository(_BaseRepository):
    """Persistence operations for response playbooks and step progress."""

    def list_all(self) -> list[Instruction]:
        """Return all instruction templates ordered by id."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, title, incident_type, steps_json FROM instructions ORDER BY id"
            ).fetchall()
            return [
                Instruction(
                    id=r["id"],
                    title=r["title"],
                    incident_type=r["incident_type"],
                    steps=json.loads(r["steps_json"]),
                )
                for r in rows
            ]

    def get_by_id(self, instruction_id: int) -> Instruction | None:
        """Fetch an instruction template by ID."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id, title, incident_type, steps_json FROM instructions WHERE id = ?",
                (instruction_id,),
            ).fetchone()
            if row is None:
                return None
            return Instruction(
                id=row["id"],
                title=row["title"],
                incident_type=row["incident_type"],
                steps=json.loads(row["steps_json"]),
            )

    def find_default_id(self, incident_type: str) -> int | None:
        """Find the default instruction ID for an incident type."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT id FROM instructions WHERE incident_type = ? ORDER BY id ASC LIMIT 1",
                (incident_type,),
            ).fetchone()
            return row["id"] if row else None

    def list_progress(self, incident_id: int) -> list[InstructionProgress]:
        """Return step completion records for an incident."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM step_progress WHERE incident_id = ? ORDER BY step_index ASC",
                (incident_id,),
            ).fetchall()
            return [
                InstructionProgress(
                    incident_id=r["incident_id"],
                    step_index=r["step_index"],
                    completed=bool(r["completed"]),
                    updated_by=r["updated_by"],
                    updated_at=r["updated_at"],
                )
                for r in rows
            ]

    def upsert_progress(
        self,
        incident_id: int,
        step_index: int,
        completed: bool,
        updated_by: int | None,
        updated_at: str | None = None,
    ) -> InstructionProgress:
        """Create or update completion state for an instruction step."""
        ts = updated_at or utc_now()
        completed_int = 1 if completed else 0
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO step_progress (incident_id, step_index, completed, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(incident_id, step_index) DO UPDATE SET
                    completed = excluded.completed,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (incident_id, step_index, completed_int, updated_by, ts),
            )
            conn.commit()
        return InstructionProgress(
            incident_id=incident_id,
            step_index=step_index,
            completed=bool(completed),
            updated_by=updated_by,
            updated_at=ts,
        )


class TaskRepository(_BaseRepository):
    """Persistence operations for incident tasks."""

    def get_by_id(self, task_id: int) -> Task | None:
        """Fetch a task by ID."""
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            return _row_to_task(row) if row is not None else None

    def get_with_incident_pdn(self, task_id: int) -> tuple[Task, int] | None:
        """Fetch a task together with its parent incident's has_personal_data flag."""
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT t.*, i.has_personal_data
                FROM tasks t
                JOIN incidents i ON i.id = t.incident_id
                WHERE t.id = ?
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                return None
            return _row_to_task(row), int(row["has_personal_data"])

    def list_by_incident(self, incident_id: int) -> list[Task]:
        """List tasks attached to an incident ordered by creation."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE incident_id = ? ORDER BY id ASC",
                (incident_id,),
            ).fetchall()
            return [_row_to_task(r) for r in rows]

    def _query_filtered_rows(
        self,
        assigned_to: int | None = None,
        status: str | None = None,
        incident_id: int | None = None,
        exclude_personal_data: bool = False,
    ) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []

        if exclude_personal_data:
            clauses.append("i.has_personal_data = 0")
        if assigned_to is not None:
            clauses.append("t.assigned_to = ?")
            params.append(assigned_to)
        if status:
            resolved_status = TaskStatus.resolve(status)
            clauses.append("t.status = ?")
            params.append(resolved_status.value if resolved_status is not None else status)
        if incident_id is not None:
            clauses.append("t.incident_id = ?")
            params.append(incident_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT t.*, i.title AS incident_title, i.has_personal_data
            FROM tasks t
            JOIN incidents i ON i.id = t.incident_id
            {where_sql}
            ORDER BY t.id DESC
        """
        with self.db.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def list_filtered(
        self,
        assigned_to: int | None = None,
        status: str | None = None,
        incident_id: int | None = None,
        exclude_personal_data: bool = False,
    ) -> list[Task]:
        """List filtered tasks as domain Task objects."""
        rows = self._query_filtered_rows(
            assigned_to=assigned_to,
            status=status,
            incident_id=incident_id,
            exclude_personal_data=exclude_personal_data,
        )
        return [_row_to_task(r) for r in rows]

    def list_filtered_with_meta(
        self,
        assigned_to: int | None = None,
        status: str | None = None,
        incident_id: int | None = None,
        exclude_personal_data: bool = False,
    ) -> list[dict[str, Any]]:
        """List filtered tasks enriched with incident_title and has_personal_data."""
        rows = self._query_filtered_rows(
            assigned_to=assigned_to,
            status=status,
            incident_id=incident_id,
            exclude_personal_data=exclude_personal_data,
        )
        return [dict(r) for r in rows]

    def create(
        self,
        incident_id: int,
        title: str,
        description: str = "",
        assigned_to: int | None = None,
        created_by: int | None = None,
        created_at: str | None = None,
        due_date: str | None = None,
        status: str = TaskStatus.OPEN.value,
    ) -> Task:
        """Create a new task and return the persisted Task model."""
        ts = created_at or utc_now()
        with self.db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO tasks (
                    incident_id, title, description, assigned_to,
                    status, result, created_by, created_at, due_date
                ) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?)
                """,
                (incident_id, title, description, assigned_to, status, created_by, ts, due_date),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (cur.lastrowid,)).fetchone()
            return _row_to_task(row)

    def update(self, task: Task) -> Task:
        """Persist task updates and return the reloaded Task model."""
        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET title = ?, description = ?, assigned_to = ?,
                    status = ?, result = ?, completed_at = ?, due_date = ?
                WHERE id = ?
                """,
                (
                    task.title,
                    task.description,
                    task.assigned_to,
                    task.status,
                    task.result,
                    task.completed_at,
                    task.due_date,
                    task.id,
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task.id,)).fetchone()
            return _row_to_task(row)


class NotificationRepository(_BaseRepository):
    """Persistence operations for escalation and urgent notifications."""

    def exists(self, incident_id: int, kind: str) -> bool:
        """Return True if a notification of the given kind already exists for the incident."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM notifications WHERE incident_id = ? AND kind = ?",
                (incident_id, kind),
            ).fetchone()
            return row is not None

    def create(
        self,
        incident_id: int | None,
        recipient_role: str,
        recipient_name: str,
        kind: str,
        message: str,
        created_at: str | None = None,
        channel: str = Channel.INTERNAL.value,
        status: str = DeliveryStatus.SENT.value,
    ) -> Notification:
        """Insert a notification record and return the Notification domain model."""
        ts = created_at or utc_now()
        channel_val = channel.value if isinstance(channel, Channel) else str(channel)
        status_val = status.value if isinstance(status, DeliveryStatus) else str(status)
        with self.db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO notifications (
                    incident_id, recipient_role, recipient_name,
                    kind, message, created_at, channel, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    recipient_role,
                    recipient_name,
                    kind,
                    message,
                    ts,
                    channel_val,
                    status_val,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM notifications WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
            return _row_to_notification(row)

    def create_if_new(
        self,
        incident_id: int,
        recipient_role: str,
        recipient_name: str,
        kind: str,
        message: str,
        created_at: str | None = None,
        channel: str = Channel.INTERNAL.value,
        status: str = DeliveryStatus.SENT.value,
    ) -> Notification | None:
        """Insert a notification only if no prior notification shares (incident_id, kind)."""
        ts = created_at or utc_now()
        channel_val = channel.value if isinstance(channel, Channel) else str(channel)
        status_val = status.value if isinstance(status, DeliveryStatus) else str(status)
        with self.db.connection() as conn:
            exists = conn.execute(
                "SELECT 1 FROM notifications WHERE incident_id = ? AND kind = ?",
                (incident_id, kind),
            ).fetchone()
            if exists is not None:
                return None
            cur = conn.execute(
                """
                INSERT INTO notifications (
                    incident_id, recipient_role, recipient_name,
                    kind, message, created_at, channel, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    recipient_role,
                    recipient_name,
                    kind,
                    message,
                    ts,
                    channel_val,
                    status_val,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM notifications WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
            return _row_to_notification(row)

    def list_all(
        self,
        recipient_role: str | None = None,
        q: str | None = None,
        kind: str | None = None,
        incident_id: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[Notification]:
        """List notifications ordered newest first, with optional search and filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if recipient_role and recipient_role.strip():
            clauses.append("recipient_role = ?")
            params.append(recipient_role.strip())
        if q and q.strip():
            clauses.append("(cfold(message) LIKE ? OR cfold(recipient_name) LIKE ?)")
            like = f"%{q.strip().casefold()}%"
            params.extend([like, like])
        if kind and kind.strip():
            clauses.append("kind = ?")
            params.append(kind.strip())
        if incident_id is not None:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        if date_from and date_from.strip():
            clauses.append("iso_utc(created_at) >= ?")
            params.append(_parse_date_bound(date_from, end_of_day=False))
        if date_to and date_to.strip():
            clauses.append("iso_utc(created_at) <= ?")
            params.append(_parse_date_bound(date_to, end_of_day=True))

        sql = "SELECT * FROM notifications"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"

        with self.db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [_row_to_notification(r) for r in rows]


class AuditRepository(_BaseRepository):
    """Persistence operations for access-control audit records."""

    def log(
        self,
        user_id: int | None,
        object_type: str,
        object_id: int | None,
        action: str,
        created_at: str | None = None,
    ) -> AuditRecord:
        """Insert an audit_log record and return the AuditRecord model."""
        ts = created_at or utc_now()
        with self.db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO audit_log (user_id, object_type, object_id, action, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, object_type, object_id, action, ts),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM audit_log WHERE id = ?", (cur.lastrowid,)).fetchone()
            return AuditRecord(
                id=row["id"],
                user_id=row["user_id"],
                object_type=row["object_type"],
                object_id=row["object_id"],
                action=row["action"],
                created_at=row["created_at"],
            )

    def list_recent(self, limit: int = 100) -> list[AuditRecord]:
        """Return recent audit log entries ordered newest first."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                AuditRecord(
                    id=r["id"],
                    user_id=r["user_id"],
                    object_type=r["object_type"],
                    object_id=r["object_id"],
                    action=r["action"],
                    created_at=r["created_at"],
                )
                for r in rows
            ]


class IngestionErrorRepository(_BaseRepository):
    """Persistence operations for signal ingestion failures."""

    def create(
        self,
        source: str,
        error_text: str,
        occurred_at: str | None = None,
        resolved: bool = False,
    ) -> IngestionError:
        """Record a malformed signal or adapter ingestion error."""
        ts = occurred_at or utc_now()
        with self.db.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO ingestion_errors (source, error_text, occurred_at, resolved)
                VALUES (?, ?, ?, ?)
                """,
                (source, error_text, ts, 1 if resolved else 0),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM ingestion_errors WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
            return IngestionError(
                id=row["id"],
                source=row["source"],
                error_text=row["error_text"],
                occurred_at=row["occurred_at"],
                resolved=bool(row["resolved"]),
            )

    def list_all(self, resolved: bool | None = None) -> list[IngestionError]:
        """List ingestion errors, optionally filtered by resolution flag."""
        with self.db.connection() as conn:
            if resolved is None:
                rows = conn.execute(
                    "SELECT * FROM ingestion_errors ORDER BY id DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM ingestion_errors WHERE resolved = ? ORDER BY id DESC",
                    (1 if resolved else 0,),
                ).fetchall()
            return [
                IngestionError(
                    id=r["id"],
                    source=r["source"],
                    error_text=r["error_text"],
                    occurred_at=r["occurred_at"],
                    resolved=bool(r["resolved"]),
                )
                for r in rows
            ]

    def mark_resolved(self, error_id: int) -> IngestionError | None:
        """Mark an ingestion error record as resolved."""
        with self.db.connection() as conn:
            conn.execute(
                "UPDATE ingestion_errors SET resolved = 1 WHERE id = ?",
                (error_id,),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM ingestion_errors WHERE id = ?",
                (error_id,),
            ).fetchone()
            if row is None:
                return None
            return IngestionError(
                id=row["id"],
                source=row["source"],
                error_text=row["error_text"],
                occurred_at=row["occurred_at"],
                resolved=bool(row["resolved"]),
            )
