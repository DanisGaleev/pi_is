import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone


def _db_path() -> str:
    return os.environ.get("DB_PATH", "incidents.db")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL
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
    status TEXT NOT NULL DEFAULT 'Новый',
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
    updated_at TEXT NOT NULL
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
    status TEXT NOT NULL DEFAULT 'Открыта',
    result TEXT NOT NULL DEFAULT '',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    recipient_role TEXT NOT NULL,
    recipient_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def init_db() -> None:
    conn = get_conn()
    try:
        conn.executescript(SCHEMA_SQL)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            _seed(conn)
        conn.commit()
    finally:
        conn.close()


def _seed(conn: sqlite3.Connection) -> None:
    pw_hash = _sha256("password123")
    users = [
        ("ib", pw_hash, "Иванов Алексей (ИБ)", "ib_specialist"),
        ("sysadmin", pw_hash, "Петров Дмитрий (Сисадмин)", "sysadmin"),
        ("it_head", pw_hash, "Сидорова Елена (Руководитель ИТ)", "it_head"),
        ("lawyer", pw_hash, "Козлова Анна (Юрист)", "lawyer"),
    ]
    conn.executemany(
        "INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
        users,
    )

    instructions = [
        (
            "Реагирование на вредоносное ПО",
            "Вирус / Вредоносное ПО",
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
            "Утечка ПДн",
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
            "Фишинг",
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
            "Несанкционированный доступ",
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
            "Вирус / Вредоносное ПО",
            "high",
            "Новый",
            "",
            "WS-FIN-04",
            "Смирнова О.В.",
            "antivirus",
            "av-ws-fin-04-trojan",
            0,
            1,
            "",
            t_45m_ago,
            None,
            None,
            t_45m_ago,
            t_45m_ago,
        ),
        (
            "Подозрение на выгрузку базы клиентов",
            "DLP-система зафиксировала выгрузку архива с ПДн клиентов на внешний ресурс.",
            "Утечка ПДн",
            "critical",
            "В работе",
            "",
            "SRV-CRM-01",
            "Волков И.П.",
            "dlp",
            "dlp-crm-export-01",
            1,
            2,
            "",
            t_2h_ago,
            t_2h_ago,
            None,
            t_2h_ago,
            t_2h_ago,
        ),
        (
            "Фишинговая рассылка на бухгалтерию",
            "Получено письмо с поддельным счетом и вредоносной ссылкой.",
            "Фишинг",
            "medium",
            "Закрыт",
            "Ложное срабатывание",
            "WS-ACC-02",
            "Морозова Т.А.",
            "mail_gateway",
            "mail-phish-acc-02",
            0,
            3,
            "",
            t_1d_ago,
            t_1d_ago,
            now_iso,
            t_1d_ago,
            now_iso,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO incidents (
            title, description, incident_type, severity, status, outcome,
            computer, employee, source, incident_key, has_personal_data,
            instruction_id, rkn_draft, detected_at, taken_at, closed_at,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        incidents,
    )

    conn.execute(
        "INSERT INTO messages (incident_id, source, sender, body, incident_key, received_at) VALUES (?, ?, ?, ?, ?, ?)",
        (1, "antivirus", "AV-Agent", "Обнаружен Trojan.GenericKD на WS-FIN-04", "av-ws-fin-04-trojan", t_45m_ago),
    )
    conn.execute(
        "INSERT INTO messages (incident_id, source, sender, body, incident_key, received_at) VALUES (?, ?, ?, ?, ?, ?)",
        (2, "dlp", "DLP-Sensor", "Выгрузка файла clients_pdn.zip с SRV-CRM-01", "dlp-crm-export-01", t_2h_ago),
    )
    conn.execute(
        "INSERT INTO history (incident_id, user_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (1, None, "created", "Инцидент создан по сигналу antivirus", t_45m_ago),
    )
    conn.execute(
        "INSERT INTO history (incident_id, user_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (2, 1, "status_changed", "Статус изменен на В работе", t_2h_ago),
    )
