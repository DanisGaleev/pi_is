import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, BeforeValidator

from app.enums import IncidentStatus, PdnFlag, Role, TaskStatus
from auth import get_current_user
from db import get_conn, utc_now

router = APIRouter(prefix="/api", tags=["ops"])

NormalizedTaskStatus = Annotated[TaskStatus, BeforeValidator(TaskStatus.normalize)]


class StepUpdate(BaseModel):
    completed: bool


class TaskCreate(BaseModel):
    title: str
    description: str = ""
    assigned_to: int | None = None


class TaskUpdate(BaseModel):
    status: NormalizedTaskStatus | None = None
    result: str | None = None


class RknDraftUpdate(BaseModel):
    rkn_draft: str


def _parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _get_incident(
    conn: sqlite3.Connection,
    incident_id: int,
    user: dict,
    *,
    forbid_sysadmin_pdn: bool = True,
) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    if forbid_sysadmin_pdn and user["role"] == Role.SYS_ADMIN and PdnFlag.from_bool_int(row["has_personal_data"]) is PdnFlag.YES:
        raise HTTPException(status_code=403, detail="Доступ к инцидентам с ПДн запрещен")
    return row


def _log_history(
    conn: sqlite3.Connection,
    incident_id: int,
    user_id: int | None,
    action: str,
    details: str,
    created_at: str,
) -> None:
    conn.execute(
        "INSERT INTO history (incident_id, user_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (incident_id, user_id, action, details, created_at),
    )


def _build_rkn_draft(row: sqlite3.Row, deadline_24h: datetime, deadline_72h: datetime) -> str:
    pdn_flag = "Да" if PdnFlag.from_bool_int(row["has_personal_data"]) is PdnFlag.YES else "Нет"
    return (
        f"УВЕДОМЛЕНИЕ В РОСКОМНАДЗОР (первичное / 24 часа)\n"
        f"Инцидент #{row['id']}: {row['title']}\n"
        f"Тип инцидента: {row['incident_type']}\n"
        f"Дата и время выявления: {row['detected_at']}\n"
        f"Крайний срок первичного уведомления (24ч): {deadline_24h.isoformat()}\n"
        f"Крайний срок дополнительного уведомления (72ч): {deadline_72h.isoformat()}\n"
        f"Наличие ПДн: {pdn_flag}\n"
        f"Затронутый узел / сотрудник: {row['computer'] or '-'} / {row['employee'] or '-'}\n"
        f"Описание: {row['description'] or '-'}\n"
        f"Принимаемые меры: проводится локализация и расследование инцидента ИБ."
    )


def _rkn_payload(row: sqlite3.Row) -> dict:
    detected_dt = _parse_iso(row["detected_at"])
    deadline_24h = (detected_dt + timedelta(hours=24)).replace(microsecond=0)
    deadline_72h = (detected_dt + timedelta(hours=72)).replace(microsecond=0)
    now = datetime.now(timezone.utc)
    stored_draft = row["rkn_draft"] or ""
    is_auto = not bool(stored_draft.strip())
    draft = _build_rkn_draft(row, deadline_24h, deadline_72h) if is_auto else stored_draft
    return {
        "incident_id": row["id"],
        "detected_at": row["detected_at"],
        "deadline_24h": deadline_24h.isoformat(),
        "deadline_72h": deadline_72h.isoformat(),
        "overdue_24h": now > deadline_24h,
        "overdue_72h": now > deadline_72h,
        "rkn_draft": draft,
        "is_auto_generated": is_auto,
    }


@router.get("/instructions")
def list_instructions(_user: dict = Depends(get_current_user)) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, title, incident_type, steps_json FROM instructions ORDER BY id"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "title": r["title"],
                "incident_type": r["incident_type"],
                "steps": json.loads(r["steps_json"]),
            }
            for r in rows
        ]
    finally:
        conn.close()


@router.put("/incidents/{incident_id}/steps/{step_index}")
def update_step_progress(
    incident_id: int,
    step_index: int,
    payload: StepUpdate,
    user: dict = Depends(get_current_user),
) -> dict:
    conn = get_conn()
    try:
        _get_incident(conn, incident_id, user, forbid_sysadmin_pdn=True)
        now = utc_now()
        completed_int = 1 if payload.completed else 0
        conn.execute(
            """
            INSERT INTO step_progress (incident_id, step_index, completed, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(incident_id, step_index) DO UPDATE SET
                completed = excluded.completed,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            (incident_id, step_index, completed_int, user["id"], now),
        )
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        state_label = "выполнен" if payload.completed else "снят"
        _log_history(
            conn,
            incident_id,
            user["id"],
            "step_updated",
            f"Шаг {step_index}: {state_label}",
            now,
        )
        conn.commit()
        return {
            "incident_id": incident_id,
            "step_index": step_index,
            "completed": payload.completed,
            "updated_by": user["id"],
            "updated_at": now,
        }
    finally:
        conn.close()


@router.post("/incidents/{incident_id}/tasks")
def create_task(
    incident_id: int,
    payload: TaskCreate,
    user: dict = Depends(get_current_user),
) -> dict:
    conn = get_conn()
    try:
        _get_incident(conn, incident_id, user, forbid_sysadmin_pdn=True)
        assigned_to = payload.assigned_to
        if assigned_to is None:
            sysadmin_row = conn.execute(
                "SELECT id FROM users WHERE role = ? ORDER BY id LIMIT 1",
                (Role.SYS_ADMIN.value,),
            ).fetchone()
            assigned_to = sysadmin_row["id"] if sysadmin_row else None

        now = utc_now()
        cur = conn.execute(
            """
            INSERT INTO tasks (incident_id, title, description, assigned_to, status, result, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, '', ?, ?)
            """,
            (incident_id, payload.title, payload.description, assigned_to, TaskStatus.OPEN.value, user["id"], now),
        )
        task_id = cur.lastrowid
        _log_history(
            conn,
            incident_id,
            user["id"],
            "task_created",
            f"Создана задача #{task_id}: {payload.title}",
            now,
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return dict(row)
    finally:
        conn.close()


@router.get("/tasks")
def list_tasks(
    assigned_to: str | None = Query(default=None),
    status: str | None = Query(default=None),
    incident_id: int | None = Query(default=None),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    conn = get_conn()
    try:
        clauses = []
        params: list = []

        if user["role"] == Role.SYS_ADMIN:
            clauses.append("i.has_personal_data = 0")

        if assigned_to == "me":
            clauses.append("t.assigned_to = ?")
            params.append(user["id"])
        elif assigned_to is not None and assigned_to.isdigit():
            clauses.append("t.assigned_to = ?")
            params.append(int(assigned_to))

        if status:
            resolved_status = TaskStatus.resolve(status)
            clauses.append("t.status = ?")
            params.append(resolved_status.value if resolved_status is not None else status)

        if incident_id is not None:
            clauses.append("t.incident_id = ?")
            params.append(incident_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            f"""
            SELECT t.*, i.title AS incident_title, i.has_personal_data
            FROM tasks t
            JOIN incidents i ON i.id = t.incident_id
            {where_sql}
            ORDER BY t.id DESC
            """,
            params,
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.patch("/tasks/{task_id}")
def update_task(
    task_id: int,
    payload: TaskUpdate,
    user: dict = Depends(get_current_user),
) -> dict:
    conn = get_conn()
    try:
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
            raise HTTPException(status_code=404, detail="Задача не найдена")
        if user["role"] == Role.SYS_ADMIN and PdnFlag.from_bool_int(row["has_personal_data"]) is PdnFlag.YES:
            raise HTTPException(status_code=403, detail="Доступ к задачам по инцидентам с ПДн запрещен")

        new_status = payload.status.value if payload.status is not None else row["status"]
        new_result = payload.result if payload.result is not None else row["result"]
        now = utc_now()

        if payload.status is not None:
            if TaskStatus.is_done(payload.status):
                completed_at = row["completed_at"] or now
            else:
                completed_at = None
        else:
            completed_at = row["completed_at"]

        conn.execute(
            "UPDATE tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?",
            (new_status, new_result, completed_at, task_id),
        )
        _log_history(
            conn,
            row["incident_id"],
            user["id"],
            "task_updated",
            f"Задача #{task_id}: статус '{new_status}'",
            now,
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return dict(updated)
    finally:
        conn.close()


@router.get("/incidents/{incident_id}/rkn")
def get_rkn_info(
    incident_id: int,
    user: dict = Depends(get_current_user),
) -> dict:
    if user["role"] == Role.SYS_ADMIN:
        raise HTTPException(status_code=403, detail="Доступ к данным РКН запрещен")
    conn = get_conn()
    try:
        row = _get_incident(conn, incident_id, user, forbid_sysadmin_pdn=False)
        return _rkn_payload(row)
    finally:
        conn.close()


@router.put("/incidents/{incident_id}/rkn")
def update_rkn_draft(
    incident_id: int,
    payload: RknDraftUpdate,
    user: dict = Depends(get_current_user),
) -> dict:
    if user["role"] == Role.SYS_ADMIN:
        raise HTTPException(status_code=403, detail="Доступ к данным РКН запрещен")
    conn = get_conn()
    try:
        _get_incident(conn, incident_id, user, forbid_sysadmin_pdn=False)
        now = utc_now()
        conn.execute(
            "UPDATE incidents SET rkn_draft = ?, updated_at = ? WHERE id = ?",
            (payload.rkn_draft, now, incident_id),
        )
        _log_history(
            conn,
            incident_id,
            user["id"],
            "rkn_draft_updated",
            "Обновлен черновик уведомления в РКН",
            now,
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return _rkn_payload(updated)
    finally:
        conn.close()


def _insert_notification_if_new(
    conn: sqlite3.Connection,
    incident_id: int,
    recipient_role: str,
    recipient_name: str,
    kind: str,
    message: str,
    created_at: str,
) -> dict | None:
    exists = conn.execute(
        "SELECT 1 FROM notifications WHERE incident_id = ? AND kind = ?",
        (incident_id, kind),
    ).fetchone()
    if exists is not None:
        return None
    cur = conn.execute(
        """
        INSERT INTO notifications (incident_id, recipient_role, recipient_name, kind, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (incident_id, recipient_role, recipient_name, kind, message, created_at),
    )
    row = conn.execute("SELECT * FROM notifications WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


@router.post("/escalations/check")
def check_escalations(_user: dict = Depends(get_current_user)) -> list[dict]:
    conn = get_conn()
    try:
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.replace(microsecond=0).isoformat()
        threshold = now_dt - timedelta(minutes=30)

        users_by_role = {
            r["role"]: r["full_name"]
            for r in conn.execute("SELECT role, full_name FROM users").fetchall()
        }
        it_head_name = users_by_role.get(Role.IT_HEAD.value, Role.IT_HEAD.label)
        lawyer_name = users_by_role.get(Role.LAWYER.value, Role.LAWYER.label)

        open_incidents = conn.execute(
            "SELECT * FROM incidents WHERE status != ?",
            (IncidentStatus.CLOSED.value,),
        ).fetchall()

        created: list[dict] = []
        for inc in open_incidents:
            detected_dt = _parse_iso(inc["detected_at"])
            if inc["taken_at"] is None and inc["status"] == IncidentStatus.NEW and detected_dt < threshold:
                msg = (
                    f"Эскалация: инцидент #{inc['id']} «{inc['title']}» "
                    f"(критичность: {inc['severity']}) не взят в работу более 30 минут."
                )
                notif = _insert_notification_if_new(
                    conn,
                    inc["id"],
                    Role.IT_HEAD.value,
                    it_head_name,
                    "escalation_30m",
                    msg,
                    now_iso,
                )
                if notif:
                    created.append(notif)

            if PdnFlag.from_bool_int(inc["has_personal_data"]) is PdnFlag.YES:
                lawyer_msg = (
                    f"Срочно (ПДн): инцидент #{inc['id']} «{inc['title']}» требует правовой оценки "
                    f"и подготовки уведомления в РКН (24ч/72ч)."
                )
                lawyer_notif = _insert_notification_if_new(
                    conn,
                    inc["id"],
                    Role.LAWYER.value,
                    lawyer_name,
                    "pdn_lawyer_notice",
                    lawyer_msg,
                    now_iso,
                )
                if lawyer_notif:
                    created.append(lawyer_notif)

                acc_msg = (
                    f"Уведомление (ПДн): инцидент #{inc['id']} «{inc['title']}» затрагивает ПДн — "
                    f"оценить риски и возможные регуляторные последствия."
                )
                acc_notif = _insert_notification_if_new(
                    conn,
                    inc["id"],
                    Role.ACCOUNTANT.value,
                    users_by_role.get(Role.ACCOUNTANT.value, Role.ACCOUNTANT.label),
                    "pdn_accounting_notice",
                    acc_msg,
                    now_iso,
                )
                if acc_notif:
                    created.append(acc_notif)

        conn.commit()
        return created
    finally:
        conn.close()


@router.get("/notifications")
def list_notifications(
    recipient_role: str | None = Query(default=None),
    _user: dict = Depends(get_current_user),
) -> list[dict]:
    conn = get_conn()
    try:
        if recipient_role:
            rows = conn.execute(
                "SELECT * FROM notifications WHERE recipient_role = ? ORDER BY id DESC",
                (recipient_role,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM notifications ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/reports/monthly")
def monthly_report(
    year: int | None = Query(default=None),
    month: int | None = Query(default=None, ge=1, le=12),
    _user: dict = Depends(get_current_user),
) -> dict:
    now_dt = datetime.now(timezone.utc)
    target_year = year if year is not None else now_dt.year
    target_month = month if month is not None else now_dt.month
    prefix = f"{target_year:04d}-{target_month:02d}"

    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT incident_type, status, outcome, severity, has_personal_data
            FROM incidents
            WHERE substr(detected_at, 1, 7) = ?
            """,
            (prefix,),
        ).fetchall()

        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        pdn_count = 0

        for r in rows:
            by_type[r["incident_type"]] = by_type.get(r["incident_type"], 0) + 1
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            outcome_key = r["outcome"] or "Без итога"
            by_outcome[outcome_key] = by_outcome.get(outcome_key, 0) + 1
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
            if PdnFlag.from_bool_int(r["has_personal_data"]) is PdnFlag.YES:
                pdn_count += 1

        return {
            "year": target_year,
            "month": target_month,
            "total": len(rows),
            "personal_data_count": pdn_count,
            "by_incident_type": by_type,
            "by_status": by_status,
            "by_outcome": by_outcome,
            "by_severity": by_severity,
        }
    finally:
        conn.close()
