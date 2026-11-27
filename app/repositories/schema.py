import json
import sqlite3
from typing import Any

from app.enums import (
    ROLE_LABELS,
    SEVERITY_LABELS,
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


LOOKUP_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS severities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL,
    weight INTEGER NOT NULL UNIQUE CHECK (weight > 0)
);

CREATE TABLE IF NOT EXISTS incident_statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS check_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS access_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS task_statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_kinds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS history_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_object_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS mime_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL
);
"""

ENTITY_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role_id INTEGER NOT NULL REFERENCES roles(id),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS computers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS instructions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    incident_type_id INTEGER NOT NULL REFERENCES incident_types(id),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE TABLE IF NOT EXISTS instruction_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instruction_id INTEGER NOT NULL REFERENCES instructions(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL CHECK (step_index >= 0),
    step_text TEXT NOT NULL,
    UNIQUE (instruction_id, step_index)
);

CREATE TABLE IF NOT EXISTS dispatch_rules (
    incident_type_id INTEGER PRIMARY KEY REFERENCES incident_types(id) ON DELETE CASCADE,
    default_severity_id INTEGER NOT NULL REFERENCES severities(id),
    access_category_id INTEGER NOT NULL REFERENCES access_categories(id),
    responsible_role_id INTEGER NOT NULL REFERENCES roles(id),
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dispatch_rule_urgent_roles (
    incident_type_id INTEGER NOT NULL REFERENCES dispatch_rules(incident_type_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id),
    PRIMARY KEY (incident_type_id, role_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    incident_type_id INTEGER NOT NULL REFERENCES incident_types(id),
    severity_id INTEGER REFERENCES severities(id),
    status_id INTEGER NOT NULL REFERENCES incident_statuses(id),
    check_result_id INTEGER REFERENCES check_results(id),
    outcome_note TEXT NOT NULL DEFAULT '',
    computer_id INTEGER REFERENCES computers(id),
    employee_id INTEGER REFERENCES employees(id),
    source_id INTEGER REFERENCES sources(id),
    incident_key TEXT NOT NULL DEFAULT '',
    has_personal_data INTEGER NOT NULL DEFAULT 0 CHECK (has_personal_data IN (0, 1)),
    instruction_id INTEGER REFERENCES instructions(id),
    detected_at TEXT NOT NULL,
    taken_at TEXT,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    access_category_id INTEGER NOT NULL REFERENCES access_categories(id),
    assigned_to INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS regulator_notices (
    incident_id INTEGER PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
    draft TEXT NOT NULL DEFAULT '',
    sent_at TEXT,
    confirmation TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    source_id INTEGER REFERENCES sources(id),
    sender TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    incident_key TEXT NOT NULL DEFAULT '',
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    action_id INTEGER NOT NULL REFERENCES history_actions(id),
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS step_progress (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL CHECK (step_index >= 0),
    instruction_step_id INTEGER REFERENCES instruction_steps(id) ON DELETE SET NULL,
    completed INTEGER NOT NULL DEFAULT 0 CHECK (completed IN (0, 1)),
    updated_by INTEGER REFERENCES users(id),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, step_index)
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status_id INTEGER NOT NULL REFERENCES task_statuses(id),
    result TEXT NOT NULL DEFAULT '',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    due_date TEXT
);

CREATE TABLE IF NOT EXISTS task_assignees (
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0 CHECK (position >= 0 AND position < 3),
    assigned_at TEXT NOT NULL,
    PRIMARY KEY (task_id, user_id),
    UNIQUE (task_id, position)
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    mime_type_id INTEGER NOT NULL REFERENCES mime_types(id),
    path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    uploaded_by INTEGER REFERENCES users(id),
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    recipient_role_id INTEGER REFERENCES roles(id),
    recipient_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    recipient_name TEXT NOT NULL,
    kind_id INTEGER NOT NULL REFERENCES notification_kinds(id),
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    channel_id INTEGER NOT NULL REFERENCES notification_channels(id),
    status_id INTEGER NOT NULL REFERENCES delivery_statuses(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    object_type_id INTEGER NOT NULL REFERENCES audit_object_types(id),
    object_id INTEGER,
    action_id INTEGER NOT NULL REFERENCES audit_actions(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingestion_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER REFERENCES sources(id),
    raw_source TEXT NOT NULL DEFAULT '',
    error_text TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0 CHECK (resolved IN (0, 1))
);

CREATE TABLE IF NOT EXISTS telegram_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    bot_token TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    webhook_secret TEXT NOT NULL DEFAULT '',
    app_base_url TEXT NOT NULL DEFAULT '',
    notify_on_create INTEGER NOT NULL DEFAULT 1 CHECK (notify_on_create IN (0, 1)),
    notify_on_status INTEGER NOT NULL DEFAULT 1 CHECK (notify_on_status IN (0, 1)),
    notify_on_escalation INTEGER NOT NULL DEFAULT 1 CHECK (notify_on_escalation IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS telegram_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    role_id INTEGER REFERENCES roles(id),
    min_severity_id INTEGER NOT NULL REFERENCES severities(id),
    notify_on_create INTEGER NOT NULL DEFAULT 1 CHECK (notify_on_create IN (0, 1)),
    notify_on_status INTEGER NOT NULL DEFAULT 1 CHECK (notify_on_status IN (0, 1)),
    notify_on_escalation INTEGER NOT NULL DEFAULT 1 CHECK (notify_on_escalation IN (0, 1)),
    include_pdn INTEGER NOT NULL DEFAULT 0 CHECK (include_pdn IN (0, 1)),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_instructions_incident_type_id ON instructions(incident_type_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status_id ON incidents(status_id);
CREATE INDEX IF NOT EXISTS idx_incidents_type_id ON incidents(incident_type_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity_id ON incidents(severity_id);
CREATE INDEX IF NOT EXISTS idx_incidents_access_category_id ON incidents(access_category_id);
CREATE INDEX IF NOT EXISTS idx_incidents_incident_key ON incidents(incident_key);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents(assigned_to);
CREATE INDEX IF NOT EXISTS idx_messages_incident_id ON messages(incident_id);
CREATE INDEX IF NOT EXISTS idx_history_incident_id ON history(incident_id);
CREATE INDEX IF NOT EXISTS idx_tasks_incident_id ON tasks(incident_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status_id ON tasks(status_id);
CREATE INDEX IF NOT EXISTS idx_task_assignees_user_id ON task_assignees(user_id);
CREATE INDEX IF NOT EXISTS idx_attachments_incident_id ON attachments(incident_id);
CREATE INDEX IF NOT EXISTS idx_attachments_task_id ON attachments(task_id);
CREATE INDEX IF NOT EXISTS idx_attachments_mime_type_id ON attachments(mime_type_id);
CREATE INDEX IF NOT EXISTS idx_notifications_incident_id ON notifications(incident_id);
CREATE INDEX IF NOT EXISTS idx_notifications_role_id ON notifications(recipient_role_id);
CREATE INDEX IF NOT EXISTS idx_notifications_kind_id ON notifications(kind_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_telegram_subscriptions_role_id ON telegram_subscriptions(role_id);
CREATE INDEX IF NOT EXISTS idx_telegram_subscriptions_min_severity_id ON telegram_subscriptions(min_severity_id);
CREATE INDEX IF NOT EXISTS idx_telegram_subscriptions_active ON telegram_subscriptions(active);
"""

SCHEMA_SQL = f"{LOOKUP_TABLES_SQL}\n{ENTITY_TABLES_SQL}\n{INDEXES_SQL}"

_DEFAULT_NOTIFICATION_KINDS = (
    "escalation_30m",
    "escalation_director",
    "pdn_lawyer_notice",
    "pdn_accounting_notice",
    "warning_broadcast",
    "tg_incident_created",
    "tg_incident_status",
    "tg_test",
    "tg_escalation_30m",
    "tg_escalation_director",
    "tg_pdn_lawyer_notice",
    "tg_pdn_accounting_notice",
    *(f"urgent_dispatch_{role.value}" for role in Role),
)

_DEFAULT_HISTORY_ACTIONS = (
    "created",
    "signal_created",
    "signal_deduplicated",
    "create",
    "update",
    "status_change",
    "status_changed",
    "classify",
    "step_updated",
    "task_created",
    "task_updated",
    "rkn_draft_updated",
    "rkn_sent",
    "escalation_stopped",
    "attachment_uploaded",
    "attachment_linked",
    "attachment_detached",
    "attachment_deleted",
)

_DEFAULT_AUDIT_OBJECT_TYPES = (
    "incident",
    "task",
    "regulator_notice",
    "attachment",
    "telegram_config",
    "telegram_subscription",
)

_DEFAULT_AUDIT_ACTIONS = (
    "view",
    "create",
    "update",
    "delete",
    "upsert",
    "upload",
    "download",
    "link_task",
    "detach_task",
    "setup_webhook",
    "status_change",
    "classify",
    "step_updated",
    "update_draft",
    "mark_sent",
    "access_denied",
    "edit_denied",
    "create_denied",
    "upload_denied",
    "delete_denied",
    "update_denied",
)

_DEFAULT_MIME_TYPES = (
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "text/plain",
    "text/markdown",
    "text/x-markdown",
    "text/json",
    "application/json",
    "text/xml",
    "application/xml",
    "text/yaml",
    "text/x-yaml",
    "application/yaml",
    "application/x-yaml",
    "text/csv",
    "application/csv",
    "text/tab-separated-values",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel",
    "application/vnd.oasis.opendocument.spreadsheet",
)

_CODE_TABLES = frozenset(
    {
        "notification_kinds",
        "history_actions",
        "audit_object_types",
        "audit_actions",
        "mime_types",
    }
)

_LEGACY_TABLES_ORDER = (
    "users",
    "sessions",
    "instructions",
    "incidents",
    "messages",
    "history",
    "step_progress",
    "tasks",
    "task_assignees",
    "attachments",
    "notifications",
    "audit_log",
    "ingestion_errors",
    "telegram_settings",
    "telegram_subscriptions",
)

_EXPECTED_NORMALIZED_COLUMNS: dict[str, tuple[str, ...]] = {
    "users": ("role_id",),
    "instructions": ("incident_type_id", "version"),
    "incidents": ("incident_type_id", "severity_id", "status_id", "access_category_id"),
    "messages": ("source_id",),
    "history": ("action_id",),
    "step_progress": ("instruction_step_id",),
    "tasks": ("status_id",),
    "attachments": ("task_id", "mime_type_id", "size_bytes"),
    "notifications": ("recipient_role_id", "kind_id", "channel_id", "status_id"),
    "audit_log": ("object_type_id", "action_id"),
    "ingestion_errors": ("source_id",),
    "telegram_subscriptions": ("role_id", "min_severity_id"),
}


def _existing_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {row["name"] for row in rows}


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _lookup_id(conn: sqlite3.Connection, table: str, column: str, value: str) -> int:
    row = conn.execute(
        f"SELECT id FROM {table} WHERE {column} = ?",
        (value,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Lookup value {value!r} not found in {table}.{column}")
    return int(row["id"])


def get_or_create_code_id(conn: sqlite3.Connection, table: str, code: str) -> int:
    """Resolve or insert a code row in an allowlisted single-code lookup table."""
    if table not in _CODE_TABLES:
        raise ValueError(f"Unsupported code table: {table!r}")
    cleaned = str(code or "").strip()
    if not cleaned:
        raise ValueError(f"Code must not be empty for {table}")
    conn.execute(f"INSERT OR IGNORE INTO {table} (code) VALUES (?)", (cleaned,))
    return _lookup_id(conn, table, "code", cleaned)


def seed_lookups(conn: sqlite3.Connection) -> None:
    """Idempotently populate all enum reference tables."""
    conn.executemany(
        "INSERT OR IGNORE INTO roles (code, label) VALUES (?, ?)",
        [(role.value, ROLE_LABELS[role]) for role in Role],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO incident_types (code, name) VALUES (?, ?)",
        [(inc_type.name, inc_type.value) for inc_type in IncidentType],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO severities (code, label, weight) VALUES (?, ?, ?)",
        [
            (sev.value, SEVERITY_LABELS[sev], SEVERITY_WEIGHTS[sev])
            for sev in Severity
        ],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO incident_statuses (code, name) VALUES (?, ?)",
        [(status.name, status.value) for status in IncidentStatus],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO check_results (code, name) VALUES (?, ?)",
        [(res.name, res.value) for res in CheckResult],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO sources (code, name) VALUES (?, ?)",
        [(src.name, src.value) for src in SourceType],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO access_categories (code, name) VALUES (?, ?)",
        [(cat.name, cat.value) for cat in AccessCategory],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO task_statuses (code, name) VALUES (?, ?)",
        [(status.name, status.value) for status in TaskStatus],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO notification_channels (code, name) VALUES (?, ?)",
        [(ch.name, ch.value) for ch in Channel],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO delivery_statuses (code, name) VALUES (?, ?)",
        [(ds.name, ds.value) for ds in DeliveryStatus],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO notification_kinds (code) VALUES (?)",
        [(k,) for k in _DEFAULT_NOTIFICATION_KINDS],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO history_actions (code) VALUES (?)",
        [(a,) for a in _DEFAULT_HISTORY_ACTIONS],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO audit_object_types (code) VALUES (?)",
        [(t,) for t in _DEFAULT_AUDIT_OBJECT_TYPES],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO audit_actions (code) VALUES (?)",
        [(a,) for a in _DEFAULT_AUDIT_ACTIONS],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO mime_types (code) VALUES (?)",
        [(m,) for m in _DEFAULT_MIME_TYPES],
    )


def seed_dispatch_rules(conn: sqlite3.Connection) -> None:
    """Idempotently populate dispatch_rules and dispatch_rule_urgent_roles."""
    from app.services.dispatch import DEFAULT_DISPATCH_RULES

    for inc_type, rule in DEFAULT_DISPATCH_RULES.items():
        inc_type_id = _lookup_id(conn, "incident_types", "code", inc_type.name)
        sev_id = _lookup_id(conn, "severities", "code", rule.default_severity.value)
        cat_id = _lookup_id(conn, "access_categories", "name", rule.access_category.value)
        role_id = _lookup_id(conn, "roles", "code", rule.responsible_role.value)
        conn.execute(
            """
            INSERT OR IGNORE INTO dispatch_rules (
                incident_type_id, default_severity_id, access_category_id,
                responsible_role_id, description
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (inc_type_id, sev_id, cat_id, role_id, rule.description),
        )
        for urgent_role in rule.urgent_notify_roles:
            urgent_role_id = _lookup_id(conn, "roles", "code", urgent_role.value)
            conn.execute(
                """
                INSERT OR IGNORE INTO dispatch_rule_urgent_roles (incident_type_id, role_id)
                VALUES (?, ?)
                """,
                (inc_type_id, urgent_role_id),
            )


def _needs_normalization_migration(conn: sqlite3.Connection) -> bool:
    existing = _existing_tables(conn)
    for table, required_cols in _EXPECTED_NORMALIZED_COLUMNS.items():
        if table in existing:
            cols = _table_columns(conn, table)
            if any(col not in cols for col in required_cols):
                return True
    if "instructions" in existing and "steps_json" in _table_columns(conn, "instructions"):
        return True
    if "incidents" in existing and "rkn_draft" in _table_columns(conn, "incidents"):
        return True
    if "tasks" in existing and "assigned_to" in _table_columns(conn, "tasks"):
        return True
    return False


def _resolve_role_id_for_migration(conn: sqlite3.Connection, raw_role: str) -> int:
    code = str(raw_role or "").strip() or Role.EMPLOYEE.value
    conn.execute(
        "INSERT OR IGNORE INTO roles (code, label) VALUES (?, ?)",
        (code, code),
    )
    return _lookup_id(conn, "roles", "code", code)


def _resolve_optional_role_id_for_migration(conn: sqlite3.Connection, raw_role: str | None) -> int | None:
    cleaned = str(raw_role or "").strip()
    if not cleaned or cleaned.lower() == "telegram":
        return None
    return _resolve_role_id_for_migration(conn, cleaned)


def _resolve_source_id_for_migration(conn: sqlite3.Connection, raw_source: str | None) -> int | None:
    cleaned = str(raw_source or "").strip()
    if not cleaned:
        return None
    norm = SourceType.normalize(cleaned)
    return _lookup_id(conn, "sources", "name", norm.value)


def _resolve_outcome_for_migration(conn: sqlite3.Connection, raw_outcome: str | None) -> tuple[int | None, str]:
    cleaned = str(raw_outcome or "").strip()
    if not cleaned:
        return None, ""
    try:
        res = CheckResult.normalize(cleaned)
        return _lookup_id(conn, "check_results", "name", res.value), ""
    except ValueError:
        return None, cleaned


def _get_or_create_entity_id(conn: sqlite3.Connection, table: str, column: str, value: str | None) -> int | None:
    cleaned = str(value or "").strip()
    if not cleaned:
        return None
    conn.execute(f"INSERT OR IGNORE INTO {table} ({column}) VALUES (?)", (cleaned,))
    return _lookup_id(conn, table, column, cleaned)


def _resolve_access_category_for_migration(
    conn: sqlite3.Connection,
    raw_cat: str | None,
    has_pdn: int,
    employee: str,
) -> int:
    if has_pdn:
        cat = AccessCategory.PERSONAL_DATA
    elif raw_cat and raw_cat.strip():
        try:
            parsed = AccessCategory(raw_cat.strip())
            cat = AccessCategory.EMPLOYEE_INVOLVED if employee.strip() else parsed
        except ValueError:
            cat = AccessCategory.EMPLOYEE_INVOLVED if employee.strip() else AccessCategory.TECHNICAL
    elif employee.strip():
        cat = AccessCategory.EMPLOYEE_INVOLVED
    else:
        cat = AccessCategory.TECHNICAL
    return _lookup_id(conn, "access_categories", "name", cat.value)


def _migrate_row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _copy_legacy_data(conn: sqlite3.Connection, migrated_legacy: set[str]) -> None:
    if "users" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_users ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            role_id = (
                int(r["role_id"])
                if "role_id" in r and r["role_id"] is not None
                else _resolve_role_id_for_migration(conn, r["role"])
            )
            active = int(r["active"]) if "active" in r and r["active"] is not None else 1
            conn.execute(
                """
                INSERT INTO users (id, username, password_hash, full_name, role_id, active)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (r["id"], r["username"], r["password_hash"], r["full_name"], role_id, active),
            )

    if "sessions" in migrated_legacy:
        conn.execute(
            """
            INSERT INTO sessions (token, user_id, created_at)
            SELECT s.token, s.user_id, s.created_at
            FROM _legacy_sessions s
            JOIN users u ON u.id = s.user_id
            """
        )

    if "instructions" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_instructions ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            if "incident_type_id" in r and r["incident_type_id"] is not None:
                inc_type_id = int(r["incident_type_id"])
            else:
                inc_type = IncidentType.normalize(r["incident_type"])
                inc_type_id = _lookup_id(conn, "incident_types", "name", inc_type.value)
            version = int(r.get("version") or 1)
            conn.execute(
                "INSERT INTO instructions (id, title, incident_type_id, version) VALUES (?, ?, ?, ?)",
                (r["id"], r["title"], inc_type_id, version),
            )
            raw_steps = r.get("steps_json")
            if raw_steps:
                steps = json.loads(raw_steps)
                for idx, step_text in enumerate(steps):
                    conn.execute(
                        """
                        INSERT INTO instruction_steps (instruction_id, step_index, step_text)
                        VALUES (?, ?, ?)
                        """,
                        (r["id"], idx, str(step_text)),
                    )

    if "incidents" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_incidents ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            if "incident_type_id" in r and r["incident_type_id"] is not None:
                inc_type_id = int(r["incident_type_id"])
            else:
                inc_type = IncidentType.normalize(r["incident_type"])
                inc_type_id = _lookup_id(conn, "incident_types", "name", inc_type.value)

            if "severity_id" in r:
                severity_id = r["severity_id"]
            else:
                severity_id = None
                raw_sev = str(r.get("severity") or "").strip()
                if raw_sev:
                    try:
                        sev = Severity.normalize(raw_sev)
                        severity_id = _lookup_id(conn, "severities", "code", sev.value)
                    except ValueError:
                        severity_id = None

            if "status_id" in r and r["status_id"] is not None:
                status_id = int(r["status_id"])
            else:
                status_enum = IncidentStatus.resolve(r.get("status")) or IncidentStatus.NEW
                status_id = _lookup_id(conn, "incident_statuses", "name", status_enum.value)

            if "check_result_id" in r:
                check_result_id = r["check_result_id"]
                outcome_note = r.get("outcome_note", "")
            else:
                check_result_id, outcome_note = _resolve_outcome_for_migration(conn, r.get("outcome"))

            if "computer_id" in r:
                computer_id = r["computer_id"]
            else:
                computer_id = _get_or_create_entity_id(conn, "computers", "hostname", r.get("computer"))

            if "employee_id" in r:
                employee_id = r["employee_id"]
                employee_text = ""
            else:
                employee_text = str(r.get("employee") or "").strip()
                employee_id = _get_or_create_entity_id(conn, "employees", "full_name", employee_text)

            if "source_id" in r:
                source_id = r["source_id"]
            else:
                source_id = _resolve_source_id_for_migration(conn, r.get("source"))

            has_pdn = 1 if r.get("has_personal_data") else 0
            if "access_category_id" in r and r["access_category_id"] is not None:
                access_category_id = int(r["access_category_id"])
            else:
                access_category_id = _resolve_access_category_for_migration(
                    conn,
                    r.get("access_category"),
                    has_pdn,
                    employee_text,
                )

            conn.execute(
                """
                INSERT INTO incidents (
                    id, title, description, incident_type_id, severity_id, status_id,
                    check_result_id, outcome_note, computer_id, employee_id, source_id,
                    incident_key, has_personal_data, instruction_id, detected_at,
                    taken_at, closed_at, created_at, updated_at, access_category_id, assigned_to
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    r["title"],
                    r.get("description", ""),
                    inc_type_id,
                    severity_id,
                    status_id,
                    check_result_id,
                    outcome_note,
                    computer_id,
                    employee_id,
                    source_id,
                    r.get("incident_key", ""),
                    has_pdn,
                    r.get("instruction_id"),
                    r["detected_at"],
                    r.get("taken_at"),
                    r.get("closed_at"),
                    r["created_at"],
                    r["updated_at"],
                    access_category_id,
                    r.get("assigned_to"),
                ),
            )
            rkn_draft = str(r.get("rkn_draft") or "")
            rkn_sent_at = r.get("rkn_sent_at")
            rkn_confirmation = str(r.get("rkn_confirmation") or "")
            if rkn_draft or rkn_sent_at is not None or rkn_confirmation:
                conn.execute(
                    """
                    INSERT INTO regulator_notices (incident_id, draft, sent_at, confirmation)
                    VALUES (?, ?, ?, ?)
                    """,
                    (r["id"], rkn_draft, rkn_sent_at, rkn_confirmation),
                )

    if "messages" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_messages ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            source_id = (
                r["source_id"]
                if "source_id" in r
                else _resolve_source_id_for_migration(conn, r.get("source"))
            )
            conn.execute(
                """
                INSERT INTO messages (id, incident_id, source_id, sender, body, incident_key, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    r["incident_id"],
                    source_id,
                    r.get("sender", ""),
                    r["body"],
                    r.get("incident_key", ""),
                    r["received_at"],
                ),
            )

    if "history" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_history ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            action_id = (
                int(r["action_id"])
                if "action_id" in r and r["action_id"] is not None
                else get_or_create_code_id(conn, "history_actions", r["action"])
            )
            conn.execute(
                """
                INSERT INTO history (id, incident_id, user_id, action_id, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (r["id"], r["incident_id"], r.get("user_id"), action_id, r.get("details", ""), r["created_at"]),
            )

    if "step_progress" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_step_progress").fetchall():
            r = _migrate_row_dict(row)
            if "instruction_step_id" in r:
                step_id = r["instruction_step_id"]
            else:
                step_row = conn.execute(
                    """
                    SELECT s.id
                    FROM incidents i
                    JOIN instruction_steps s
                        ON s.instruction_id = i.instruction_id
                       AND s.step_index = ?
                    WHERE i.id = ?
                    """,
                    (r["step_index"], r["incident_id"]),
                ).fetchone()
                step_id = int(step_row["id"]) if step_row is not None else None
            conn.execute(
                """
                INSERT INTO step_progress (
                    incident_id, step_index, instruction_step_id, completed, updated_by, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    r["incident_id"],
                    r["step_index"],
                    step_id,
                    1 if r["completed"] else 0,
                    r.get("updated_by"),
                    r["updated_at"],
                ),
            )

    if "tasks" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_tasks ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            if "status_id" in r and r["status_id"] is not None:
                status_id = int(r["status_id"])
            else:
                task_status = TaskStatus.resolve(r.get("status")) or TaskStatus.OPEN
                status_id = _lookup_id(conn, "task_statuses", "name", task_status.value)
            conn.execute(
                """
                INSERT INTO tasks (
                    id, incident_id, title, description,
                    status_id, result, created_by, created_at, completed_at, due_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    r["incident_id"],
                    r["title"],
                    r.get("description", ""),
                    status_id,
                    r.get("result", ""),
                    r.get("created_by"),
                    r["created_at"],
                    r.get("completed_at"),
                    r.get("due_date"),
                ),
            )

    if "task_assignees" in migrated_legacy:
        positions_by_task: dict[int, int] = {}
        for row in conn.execute(
            "SELECT * FROM _legacy_task_assignees ORDER BY task_id ASC, position ASC, user_id ASC"
        ).fetchall():
            r = _migrate_row_dict(row)
            tid = int(r["task_id"])
            pos = positions_by_task.get(tid, 0)
            if pos >= 3:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO task_assignees (task_id, user_id, position, assigned_at)
                VALUES (?, ?, ?, ?)
                """,
                (tid, int(r["user_id"]), pos, r["assigned_at"]),
            )
            positions_by_task[tid] = pos + 1

    if "tasks" in migrated_legacy:
        legacy_task_cols = _table_columns(conn, "_legacy_tasks")
        if "assigned_to" in legacy_task_cols:
            conn.execute(
                """
                INSERT OR IGNORE INTO task_assignees (task_id, user_id, position, assigned_at)
                SELECT lt.id, lt.assigned_to, 0, lt.created_at
                FROM _legacy_tasks lt
                WHERE lt.assigned_to IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM task_assignees ta WHERE ta.task_id = lt.id
                  )
                """
            )

    if "attachments" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_attachments ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            mime_type_id = (
                int(r["mime_type_id"])
                if "mime_type_id" in r and r["mime_type_id"] is not None
                else get_or_create_code_id(conn, "mime_types", r.get("mime_type") or "application/octet-stream")
            )
            size_bytes = int(r["size_bytes"]) if "size_bytes" in r and r["size_bytes"] is not None else 0
            conn.execute(
                """
                INSERT INTO attachments (
                    id, incident_id, task_id, filename, mime_type_id, path,
                    size_bytes, uploaded_by, uploaded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    r["incident_id"],
                    r.get("task_id"),
                    r["filename"],
                    mime_type_id,
                    r["path"],
                    max(0, size_bytes),
                    r.get("uploaded_by"),
                    r["uploaded_at"],
                ),
            )

    if "notifications" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_notifications ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            if "recipient_role_id" in r:
                role_id = r["recipient_role_id"]
            else:
                role_id = _resolve_optional_role_id_for_migration(conn, r.get("recipient_role"))
            kind_id = (
                int(r["kind_id"])
                if "kind_id" in r and r["kind_id"] is not None
                else get_or_create_code_id(conn, "notification_kinds", r["kind"])
            )
            if "channel_id" in r and r["channel_id"] is not None:
                channel_id = int(r["channel_id"])
            else:
                raw_channel = str(r.get("channel") or Channel.INTERNAL.value).strip().lower()
                try:
                    ch_val = Channel(raw_channel).value
                except ValueError:
                    ch_val = Channel.INTERNAL.value
                channel_id = _lookup_id(conn, "notification_channels", "name", ch_val)

            if "status_id" in r and r["status_id"] is not None:
                status_id = int(r["status_id"])
            else:
                raw_status = str(r.get("status") or DeliveryStatus.SENT.value).strip().lower()
                try:
                    st_val = DeliveryStatus(raw_status).value
                except ValueError:
                    st_val = DeliveryStatus.SENT.value
                status_id = _lookup_id(conn, "delivery_statuses", "name", st_val)

            conn.execute(
                """
                INSERT INTO notifications (
                    id, incident_id, recipient_role_id, recipient_user_id, recipient_name,
                    kind_id, message, created_at, channel_id, status_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    r.get("incident_id"),
                    role_id,
                    r.get("recipient_user_id"),
                    r["recipient_name"],
                    kind_id,
                    r["message"],
                    r["created_at"],
                    channel_id,
                    status_id,
                ),
            )

    if "audit_log" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_audit_log ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            obj_type_id = (
                int(r["object_type_id"])
                if "object_type_id" in r and r["object_type_id"] is not None
                else get_or_create_code_id(conn, "audit_object_types", r["object_type"])
            )
            action_id = (
                int(r["action_id"])
                if "action_id" in r and r["action_id"] is not None
                else get_or_create_code_id(conn, "audit_actions", r["action"])
            )
            conn.execute(
                """
                INSERT INTO audit_log (id, user_id, object_type_id, object_id, action_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (r["id"], r.get("user_id"), obj_type_id, r.get("object_id"), action_id, r["created_at"]),
            )

    if "ingestion_errors" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_ingestion_errors ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            if "source_id" in r:
                source_id = r["source_id"]
                raw_source_val = r.get("raw_source", "")
            else:
                raw_src = str(r.get("source") or "").strip()
                src_row = conn.execute(
                    "SELECT id FROM sources WHERE name = ? OR code = ?",
                    (raw_src, raw_src.upper()),
                ).fetchone()
                source_id = int(src_row["id"]) if src_row is not None else None
                raw_source_val = "" if source_id is not None else raw_src
            conn.execute(
                """
                INSERT INTO ingestion_errors (id, source_id, raw_source, error_text, occurred_at, resolved)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    source_id,
                    raw_source_val,
                    r["error_text"],
                    r["occurred_at"],
                    1 if r.get("resolved") else 0,
                ),
            )

    if "telegram_settings" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_telegram_settings").fetchall():
            r = _migrate_row_dict(row)
            conn.execute(
                """
                INSERT INTO telegram_settings (
                    id, bot_token, enabled, webhook_secret, app_base_url,
                    notify_on_create, notify_on_status, notify_on_escalation, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    r.get("bot_token", ""),
                    1 if r.get("enabled", 1) else 0,
                    r.get("webhook_secret", ""),
                    r.get("app_base_url", ""),
                    1 if r.get("notify_on_create", 1) else 0,
                    1 if r.get("notify_on_status", 1) else 0,
                    1 if r.get("notify_on_escalation", 1) else 0,
                    r.get("updated_at", ""),
                ),
            )

    if "telegram_subscriptions" in migrated_legacy:
        for row in conn.execute("SELECT * FROM _legacy_telegram_subscriptions ORDER BY id").fetchall():
            r = _migrate_row_dict(row)
            if "role_id" in r:
                role_id = r["role_id"]
            else:
                role_id = _resolve_optional_role_id_for_migration(conn, r.get("role"))

            if "min_severity_id" in r and r["min_severity_id"] is not None:
                min_sev_id = int(r["min_severity_id"])
            else:
                raw_sev = str(r.get("min_severity") or Severity.LOW.value).strip()
                try:
                    sev = Severity.normalize(raw_sev)
                except ValueError:
                    sev = Severity.LOW
                min_sev_id = _lookup_id(conn, "severities", "code", sev.value)

            conn.execute(
                """
                INSERT INTO telegram_subscriptions (
                    id, chat_id, label, role_id, min_severity_id,
                    notify_on_create, notify_on_status, notify_on_escalation,
                    include_pdn, active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"],
                    r["chat_id"],
                    r.get("label", ""),
                    role_id,
                    min_sev_id,
                    1 if r.get("notify_on_create", 1) else 0,
                    1 if r.get("notify_on_status", 1) else 0,
                    1 if r.get("notify_on_escalation", 1) else 0,
                    1 if r.get("include_pdn", 0) else 0,
                    1 if r.get("active", 1) else 0,
                    r["created_at"],
                    r["updated_at"],
                ),
            )


def apply_migrations(conn: sqlite3.Connection) -> None:
    """Migrate legacy or pre-normalization SQLite tables to the normalized schema."""
    if not _needs_normalization_migration(conn):
        return

    if conn.in_transaction:
        conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")

    existing = _existing_tables(conn)
    migrated_legacy: set[str] = set()
    try:
        conn.execute("BEGIN")
        for table in _LEGACY_TABLES_ORDER:
            if table in existing:
                conn.execute(f"ALTER TABLE {table} RENAME TO _legacy_{table}")
                migrated_legacy.add(table)

        for stmt in ENTITY_TABLES_SQL.strip().split(";"):
            cleaned = stmt.strip()
            if cleaned:
                conn.execute(cleaned)

        _copy_legacy_data(conn, migrated_legacy)

        for table in reversed(_LEGACY_TABLES_ORDER):
            if table in migrated_legacy:
                conn.execute(f"DROP TABLE _legacy_{table}")

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")

    fk_errors = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk_errors:
        raise RuntimeError(f"Foreign key violations after migration: {[dict(r) for r in fk_errors]}")
