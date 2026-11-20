from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, BeforeValidator

from app.enums import (
    AccessCategory,
    CheckResult,
    IncidentStatus,
    IncidentType,
    PdnFlag,
    Role,
    Severity,
    SourceType,
)
from auth import get_current_user
from db import get_conn, utc_now

router = APIRouter(prefix="/api", tags=["incidents"])


def _normalize_signal_source(raw: str | SourceType | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, SourceType):
        return raw.value
    if not str(raw).strip():
        return ""
    return SourceType.normalize(raw).value


def _normalize_outcome(raw: str | CheckResult | None) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, CheckResult):
        return raw.value
    cleaned = str(raw).strip()
    if not cleaned:
        return ""
    try:
        return CheckResult.normalize(cleaned).value
    except ValueError:
        return cleaned


def _pdn_to_int(val: bool | int | PdnFlag) -> int:
    return PdnFlag.from_bool_int(val).to_bool_int()


NormalizedIncidentType = Annotated[IncidentType, BeforeValidator(IncidentType.normalize)]
NormalizedSeverity = Annotated[Severity, BeforeValidator(Severity.normalize)]
NormalizedIncidentStatus = Annotated[IncidentStatus, BeforeValidator(IncidentStatus.normalize)]
NormalizedSourceType = Annotated[SourceType, BeforeValidator(SourceType.normalize)]
SignalSource = Annotated[str, BeforeValidator(_normalize_signal_source)]
NormalizedOutcome = Annotated[str | None, BeforeValidator(_normalize_outcome)]


class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    incident_type: NormalizedIncidentType
    severity: NormalizedSeverity = Severity.MEDIUM
    computer: str = ""
    employee: str = ""
    source: NormalizedSourceType = SourceType.MANUAL
    incident_key: str = ""
    has_personal_data: bool | int | PdnFlag = 0
    instruction_id: int | None = None
    detected_at: str | None = None


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    incident_type: NormalizedIncidentType | None = None
    severity: NormalizedSeverity | None = None
    has_personal_data: bool | int | PdnFlag | None = None
    instruction_id: int | None = None
    rkn_draft: str | None = None


class StatusTransition(BaseModel):
    status: NormalizedIncidentStatus
    outcome: NormalizedOutcome = None


class SignalIn(BaseModel):
    source: SignalSource = ""
    sender: str = ""
    body: str
    computer: str = ""
    employee: str = ""
    incident_type: NormalizedIncidentType = IncidentType.OTHER
    severity: NormalizedSeverity = Severity.MEDIUM
    incident_key: str = ""
    has_personal_data: bool | int | PdnFlag = 0
    title: str | None = None


def _get_incident_or_404(conn, incident_id: int):
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    return row


def _incident_access_category(incident) -> AccessCategory:
    if PdnFlag.from_bool_int(incident["has_personal_data"]) is PdnFlag.YES:
        return AccessCategory.PERSONAL_DATA
    if str(incident["employee"] or "").strip():
        return AccessCategory.EMPLOYEE_INVOLVED
    return AccessCategory.TECHNICAL


def _assert_access(user: dict, incident) -> None:
    if user["role"] == Role.SYS_ADMIN and _incident_access_category(incident) is AccessCategory.PERSONAL_DATA:
        raise HTTPException(status_code=403, detail="Доступ к инцидентам с ПДн запрещен")


def _log_history(
    conn,
    incident_id: int,
    user_id: int | None,
    action: str,
    details: str = "",
    created_at: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO history (incident_id, user_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (incident_id, user_id, action, details, created_at or utc_now()),
    )


def _default_instruction_id(conn, incident_type: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM instructions WHERE incident_type = ? ORDER BY id ASC LIMIT 1",
        (incident_type,),
    ).fetchone()
    return row["id"] if row else None


@router.get("/incidents")
def list_incidents(
    q: str | None = None,
    incident_type: str | None = None,
    status: str | None = None,
    user: dict = Depends(get_current_user),
) -> list[dict]:
    clauses: list[str] = []
    params: list[object] = []

    if user["role"] == Role.SYS_ADMIN:
        clauses.append("has_personal_data = 0")
    if q:
        clauses.append("(computer LIKE ? OR employee LIKE ?)")
        like = f"%{q}%"
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
    sql += " ORDER BY id DESC"

    conn = get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.post("/incidents")
def create_incident(
    payload: IncidentCreate,
    user: dict = Depends(get_current_user),
) -> dict:
    has_pd = _pdn_to_int(payload.has_personal_data)
    if user["role"] == Role.SYS_ADMIN and has_pd:
        raise HTTPException(status_code=403, detail="Доступ к инцидентам с ПДн запрещен")

    now = utc_now()
    detected_at = payload.detected_at or now

    conn = get_conn()
    try:
        instruction_id = payload.instruction_id
        if instruction_id is None:
            instruction_id = _default_instruction_id(conn, payload.incident_type.value)

        cur = conn.execute(
            """
            INSERT INTO incidents (
                title, description, incident_type, severity, status, outcome,
                computer, employee, source, incident_key, has_personal_data,
                instruction_id, detected_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.title,
                payload.description,
                payload.incident_type.value,
                payload.severity.value,
                IncidentStatus.NEW.value,
                payload.computer,
                payload.employee,
                payload.source.value,
                payload.incident_key,
                has_pd,
                instruction_id,
                detected_at,
                now,
                now,
            ),
        )
        incident_id = cur.lastrowid
        _log_history(conn, incident_id, user["id"], "create", f"Создан инцидент: {payload.title}", now)
        conn.commit()
        row = _get_incident_or_404(conn, incident_id)
        return dict(row)
    finally:
        conn.close()


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    user: dict = Depends(get_current_user),
) -> dict:
    conn = get_conn()
    try:
        incident = _get_incident_or_404(conn, incident_id)
        _assert_access(user, incident)

        messages = conn.execute(
            "SELECT * FROM messages WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        ).fetchall()
        history = conn.execute(
            """
            SELECT h.*, u.username, u.full_name
            FROM history h
            LEFT JOIN users u ON u.id = h.user_id
            WHERE h.incident_id = ?
            ORDER BY h.id ASC
            """,
            (incident_id,),
        ).fetchall()
        step_progress = conn.execute(
            "SELECT * FROM step_progress WHERE incident_id = ? ORDER BY step_index ASC",
            (incident_id,),
        ).fetchall()
        tasks = conn.execute(
            "SELECT * FROM tasks WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        ).fetchall()

        data = dict(incident)
        data["messages"] = [dict(r) for r in messages]
        data["history"] = [dict(r) for r in history]
        data["step_progress"] = [dict(r) for r in step_progress]
        data["tasks"] = [dict(r) for r in tasks]
        return data
    finally:
        conn.close()


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    user: dict = Depends(get_current_user),
) -> dict:
    conn = get_conn()
    try:
        incident = _get_incident_or_404(conn, incident_id)
        _assert_access(user, incident)

        updates = payload.model_dump(exclude_unset=True)
        if updates.get("incident_type") is not None:
            updates["incident_type"] = updates["incident_type"].value
        if updates.get("severity") is not None:
            updates["severity"] = updates["severity"].value
        if "has_personal_data" in updates:
            updates["has_personal_data"] = _pdn_to_int(updates["has_personal_data"])
            if user["role"] == Role.SYS_ADMIN and updates["has_personal_data"]:
                raise HTTPException(status_code=403, detail="Доступ к инцидентам с ПДн запрещен")

        if updates:
            now = utc_now()
            set_sql = ", ".join(f"{col} = ?" for col in updates) + ", updated_at = ?"
            params = list(updates.values()) + [now, incident_id]
            conn.execute(f"UPDATE incidents SET {set_sql} WHERE id = ?", params)
            _log_history(
                conn,
                incident_id,
                user["id"],
                "update",
                "Обновлены поля: " + ", ".join(updates.keys()),
                now,
            )
            conn.commit()

        return dict(_get_incident_or_404(conn, incident_id))
    finally:
        conn.close()


@router.post("/incidents/{incident_id}/status")
def change_status(
    incident_id: int,
    payload: StatusTransition,
    user: dict = Depends(get_current_user),
) -> dict:
    conn = get_conn()
    try:
        incident = _get_incident_or_404(conn, incident_id)
        _assert_access(user, incident)

        now = utc_now()
        taken_at = incident["taken_at"]
        if payload.status == IncidentStatus.IN_PROGRESS and not taken_at:
            taken_at = now

        closed_at = incident["closed_at"]
        if payload.status == IncidentStatus.CLOSED:
            closed_at = now

        outcome = payload.outcome if payload.outcome is not None else incident["outcome"]

        conn.execute(
            """
            UPDATE incidents
            SET status = ?, outcome = ?, taken_at = ?, closed_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (payload.status.value, outcome, taken_at, closed_at, now, incident_id),
        )
        details = f"{incident['status']} -> {payload.status.value}"
        if outcome:
            details += f" ({outcome})"
        _log_history(conn, incident_id, user["id"], "status_change", details, now)
        conn.commit()
        return dict(_get_incident_or_404(conn, incident_id))
    finally:
        conn.close()


@router.post("/signals")
def ingest_signal(payload: SignalIn) -> dict:
    now = utc_now()
    key = payload.incident_key.strip()
    computer = payload.computer.strip()
    incident_type = payload.incident_type.value

    conn = get_conn()
    try:
        existing = None
        if key:
            existing = conn.execute(
                "SELECT * FROM incidents WHERE status != ? AND incident_key = ? ORDER BY id DESC LIMIT 1",
                (IncidentStatus.CLOSED.value, key),
            ).fetchone()
        if existing is None and computer and incident_type:
            existing = conn.execute(
                """
                SELECT * FROM incidents
                WHERE status != ? AND computer = ? AND incident_type = ?
                ORDER BY id DESC LIMIT 1
                """,
                (IncidentStatus.CLOSED.value, computer, incident_type),
            ).fetchone()

        if existing is not None:
            incident_id = existing["id"]
            deduplicated = True
            conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        else:
            deduplicated = False
            title = payload.title or f"{incident_type}: {computer or payload.sender or payload.source or 'Сигнал'}"
            instruction_id = _default_instruction_id(conn, incident_type)
            cur = conn.execute(
                """
                INSERT INTO incidents (
                    title, description, incident_type, severity, status, outcome,
                    computer, employee, source, incident_key, has_personal_data,
                    instruction_id, detected_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    title,
                    payload.body,
                    incident_type,
                    payload.severity.value,
                    IncidentStatus.NEW.value,
                    computer,
                    payload.employee.strip(),
                    payload.source,
                    key,
                    _pdn_to_int(payload.has_personal_data),
                    instruction_id,
                    now,
                    now,
                    now,
                ),
            )
            incident_id = cur.lastrowid

        msg_cur = conn.execute(
            """
            INSERT INTO messages (incident_id, source, sender, body, incident_key, received_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (incident_id, payload.source, payload.sender, payload.body, key, now),
        )
        message_id = msg_cur.lastrowid

        action = "signal_deduplicated" if deduplicated else "signal_created"
        origin = payload.source or payload.sender or "external"
        details = (
            f"Повторный сигнал ({origin}) привязан к инциденту"
            if deduplicated
            else f"Инцидент создан по сигналу ({origin})"
        )
        _log_history(conn, incident_id, None, action, details, now)
        conn.commit()

        return {
            "incident_id": incident_id,
            "deduplicated": deduplicated,
            "message_id": message_id,
        }
    finally:
        conn.close()
