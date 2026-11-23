import { useEffect, useState } from "react";
import {
  changeIncidentStatus,
  confirmRkn,
  createTask,
  getIncident,
  getRkn,
  listInstructions,
  listUsers,
  updateIncident,
  updateRkn,
  updateStep,
} from "../api";

const INCIDENT_TYPES = [
  "Вирус / Вредоносное ПО",
  "Утечка ПДн",
  "Фишинг",
  "Несанкционированный доступ",
  "Подбор пароля",
  "Обман с платежами",
  "Уязвимость (CVE)",
  "Прочее",
];

const SEVERITIES = [
  { value: "critical", label: "Критический" },
  { value: "high", label: "Высокий" },
  { value: "medium", label: "Средний" },
  { value: "low", label: "Низкий" },
];

const OUTCOMES = [
  "Устранен",
  "Ложное срабатывание",
  "Передано в СК/РКН",
  "Прочее",
];

const SEVERITY_LABELS = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
};

const STATUS_CLASSES = {
  "Новый": "status-new",
  "В работе": "status-progress",
  "На проверке": "status-review",
  "Закрыт": "status-closed",
};

function formatDateTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ru-RU", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatCountdown(deadlineIso, nowMs) {
  if (!deadlineIso) return { text: "-", overdue: false };
  const targetMs = new Date(deadlineIso).getTime();
  if (Number.isNaN(targetMs)) return { text: deadlineIso, overdue: false };

  const diffMs = targetMs - nowMs;
  const overdue = diffMs < 0;
  const absSec = Math.floor(Math.abs(diffMs) / 1000);
  const days = Math.floor(absSec / 86400);
  const hours = Math.floor((absSec % 86400) / 3600);
  const minutes = Math.floor((absSec % 3600) / 60);
  const seconds = absSec % 60;

  const pad = (n) => String(n).padStart(2, "0");
  const hms = `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
  const durationText = days > 0 ? `${days} дн. ${hms}` : hms;

  return {
    text: overdue ? `Просрочено на ${durationText}` : `Осталось ${durationText}`,
    overdue,
  };
}

function isOverdueNew(incident) {
  if (!incident || incident.status !== "Новый" || !incident.detected_at) {
    return false;
  }
  const detectedMs = new Date(incident.detected_at).getTime();
  if (Number.isNaN(detectedMs)) return false;
  return Date.now() - detectedMs > 30 * 60 * 1000;
}

export default function IncidentDetailPage({ incidentId, user, onBack }) {
  const [incident, setIncident] = useState(null);
  const [instructions, setInstructions] = useState([]);
  const [rkn, setRkn] = useState(null);
  const [rknDraft, setRknDraft] = useState("");
  const [nowMs, setNowMs] = useState(() => Date.now());

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [outcome, setOutcome] = useState(OUTCOMES[0]);
  const [classForm, setClassForm] = useState({
    incident_type: INCIDENT_TYPES[0],
    severity: "medium",
    has_personal_data: false,
  });

  const [taskTitle, setTaskTitle] = useState("");
  const [taskDesc, setTaskDesc] = useState("");
  const [taskAssignee, setTaskAssignee] = useState("");
  const [taskDueDate, setTaskDueDate] = useState("");
  const [assignableUsers, setAssignableUsers] = useState([]);
  const [saving, setSaving] = useState(false);

  const isSysadmin = user?.role === "sysadmin";
  const isLawyer = user?.role === "lawyer";
  const [rknConfirmText, setRknConfirmText] = useState("");

  async function loadAll() {
    setLoading(true);
    setError("");
    try {
      const [incData, instrData, usersData] = await Promise.all([
        getIncident(incidentId),
        listInstructions(),
        listUsers({ assignable: true }),
      ]);
      setIncident(incData);
      setInstructions(instrData);
      setAssignableUsers(usersData);
      setClassForm({
        incident_type: incData.incident_type || INCIDENT_TYPES[0],
        severity: incData.severity || "medium",
        has_personal_data: Boolean(incData.has_personal_data),
      });
      if (incData.outcome) {
        setOutcome(incData.outcome);
      }

      if (incData.has_personal_data === 1 && !isSysadmin) {
        const rknData = await getRkn(incidentId);
        setRkn(rknData);
        setRknDraft(rknData.rkn_draft || "");
      } else {
        setRkn(null);
        setRknDraft("");
      }
    } catch (err) {
      setError(err.message || "Не удалось загрузить карточку инцидента");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
  }, [incidentId]);

  useEffect(() => {
    if (!rkn) return undefined;
    const timer = setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, [rkn]);

  async function handleStatusChange(nextStatus, selectedOutcome) {
    if (nextStatus === "Закрыт" && !selectedOutcome?.trim()) {
      setError("Укажите итог закрытия инцидента");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      await changeIncidentStatus(incidentId, nextStatus, selectedOutcome);
      setNotice(`Статус изменен на «${nextStatus}»`);
      await loadAll();
    } catch (err) {
      setError(err.message || "Не удалось изменить статус");
    } finally {
      setSaving(false);
    }
  }

  async function handleSaveClassification(e) {
    e.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const payload = isLawyer
        ? { has_personal_data: classForm.has_personal_data ? 1 : 0 }
        : {
            incident_type: classForm.incident_type,
            severity: classForm.severity,
            ...(isSysadmin
              ? {}
              : { has_personal_data: classForm.has_personal_data ? 1 : 0 }),
          };
      await updateIncident(incidentId, payload);
      setNotice("Классификация сохранена");
      await loadAll();
    } catch (err) {
      setError(err.message || "Не удалось обновить классификацию");
    } finally {
      setSaving(false);
    }
  }

  async function handleSaveRknDraft() {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const updated = await updateRkn(incidentId, rknDraft);
      setRkn(updated);
      setRknDraft(updated.rkn_draft || "");
      setNotice("Черновик уведомления РКН сохранен");
    } catch (err) {
      setError(err.message || "Не удалось сохранить черновик РКН");
    } finally {
      setSaving(false);
    }
  }

  async function handleConfirmRkn() {
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const updated = await confirmRkn(incidentId, rknConfirmText.trim());
      setRkn(updated);
      setRknConfirmText("");
      setNotice("Отправка уведомления РКН подтверждена");
    } catch (err) {
      setError(err.message || "Не удалось подтвердить отправку уведомления РКН");
    } finally {
      setSaving(false);
    }
  }

  async function handleInstructionChange(e) {
    const val = e.target.value;
    const instructionId = val ? Number(val) : null;
    setSaving(true);
    setError("");
    setNotice("");
    try {
      await updateIncident(incidentId, { instruction_id: instructionId });
      setNotice("Инструкция обновлена");
      await loadAll();
    } catch (err) {
      setError(err.message || "Не удалось обновить инструкцию");
    } finally {
      setSaving(false);
    }
  }

  async function handleStepToggle(stepIndex, completed) {
    setError("");
    try {
      await updateStep(incidentId, stepIndex, completed);
      await loadAll();
    } catch (err) {
      setError(err.message || "Не удалось обновить шаг инструкции");
    }
  }

  async function handleCreateTask(e) {
    e.preventDefault();
    if (!taskTitle.trim()) return;
    if (!taskDesc.trim()) {
      setError("Укажите детали задачи");
      return;
    }
    if (!taskAssignee) {
      setError("Выберите исполнителя задачи");
      return;
    }
    if (!taskDueDate) {
      setError("Укажите срок выполнения задачи");
      return;
    }
    setSaving(true);
    setError("");
    setNotice("");
    try {
      await createTask(incidentId, {
        title: taskTitle.trim(),
        description: taskDesc.trim(),
        assigned_to: Number(taskAssignee),
        due_date: new Date(taskDueDate).toISOString(),
      });
      setTaskTitle("");
      setTaskDesc("");
      setTaskAssignee("");
      setTaskDueDate("");
      setNotice("Задача создана");
      await loadAll();
    } catch (err) {
      setError(err.message || "Не удалось создать задачу");
    } finally {
      setSaving(false);
    }
  }

  if (loading && !incident) {
    return <div className="muted">Загрузка карточки инцидента...</div>;
  }

  if (!incident) {
    return (
      <div>
        <button type="button" className="btn" onClick={onBack}>
          Назад к списку
        </button>
        {error && (
          <div className="alert alert-error" style={{ marginTop: "12px" }}>
            {error}
          </div>
        )}
      </div>
    );
  }

  const overdueNew = isOverdueNew(incident);
  const selectedInstruction = instructions.find(
    (inst) => inst.id === incident.instruction_id
  );
  const stepMap = new Map(
    (incident.step_progress || []).map((sp) => [sp.step_index, sp.completed === 1])
  );

  const timer24 = rkn ? formatCountdown(rkn.deadline_24h, nowMs) : null;
  const timer72 = rkn ? formatCountdown(rkn.deadline_72h, nowMs) : null;

  return (
    <div>
      <div className="page-header">
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "6px" }}>
            <button type="button" className="btn btn-sm" onClick={onBack}>
              Назад к списку
            </button>
            <span className="muted">Инцидент #{incident.id}</span>
            <span className={`badge severity-${incident.severity || "medium"}`}>
              {SEVERITY_LABELS[incident.severity] || incident.severity}
            </span>
            <span className={`badge ${STATUS_CLASSES[incident.status] || ""}`}>
              {incident.status}
            </span>
            {incident.has_personal_data === 1 && (
              <span className="badge badge-pdn">ПДн</span>
            )}
            {overdueNew && (
              <span className="badge badge-overdue">Просрочен (&gt;30 мин)</span>
            )}
          </div>
          <h1>{incident.title}</h1>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
          {!isLawyer && incident.status !== "В работе" && incident.status !== "Закрыт" && (
            <button
              type="button"
              className="btn btn-primary"
              disabled={saving}
              onClick={() => handleStatusChange("В работе")}
            >
              Взять в работу
            </button>
          )}
          {!isLawyer && incident.status !== "На проверке" && incident.status !== "Закрыт" && (
            <button
              type="button"
              className="btn btn-dark"
              disabled={saving}
              onClick={() => handleStatusChange("На проверке")}
            >
              На проверку
            </button>
          )}
          {!isLawyer && incident.status !== "Закрыт" && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <select
                value={outcome}
                onChange={(e) => setOutcome(e.target.value)}
                style={{ width: "auto" }}
                aria-label="Итог закрытия"
              >
                {OUTCOMES.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="btn btn-danger"
                disabled={saving}
                onClick={() => handleStatusChange("Закрыт", outcome)}
              >
                Закрыть
              </button>
            </div>
          )}
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {notice && <div className="alert alert-ok">{notice}</div>}

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2>Сведения об инциденте</h2>
          </div>
          <p style={{ marginTop: 0 }}>{incident.description || "Описание отсутствует."}</p>
          <div className="grid-2" style={{ gap: "8px", fontSize: "13px" }}>
            <div>
              <span className="muted">Компьютер:</span>{" "}
              <strong>{incident.computer || "-"}</strong>
            </div>
            <div>
              <span className="muted">Сотрудник:</span>{" "}
              <strong>{incident.employee || "-"}</strong>
            </div>
            <div>
              <span className="muted">Источник:</span>{" "}
              <strong>{incident.source || "-"}</strong>
            </div>
            <div>
              <span className="muted">Ключ дедупликации:</span>{" "}
              <strong>{incident.incident_key || "-"}</strong>
            </div>
            <div>
              <span className="muted">Обнаружен:</span>{" "}
              <strong>{formatDateTime(incident.detected_at)}</strong>
            </div>
            <div>
              <span className="muted">Взят в работу:</span>{" "}
              <strong>{formatDateTime(incident.taken_at)}</strong>
            </div>
            <div>
              <span className="muted">Закрыт:</span>{" "}
              <strong>{formatDateTime(incident.closed_at)}</strong>
            </div>
            {incident.outcome && (
              <div>
                <span className="muted">Итог:</span>{" "}
                <strong>{incident.outcome}</strong>
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2>Классификация</h2>
          </div>
          <form onSubmit={handleSaveClassification}>
            {!isLawyer && (
              <>
                <div className="form-field">
                  <label htmlFor="cls-type">Тип инцидента</label>
                  <select
                    id="cls-type"
                    value={classForm.incident_type}
                    onChange={(e) =>
                      setClassForm({ ...classForm, incident_type: e.target.value })
                    }
                  >
                    {INCIDENT_TYPES.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-field">
                  <label htmlFor="cls-severity">Важность</label>
                  <select
                    id="cls-severity"
                    value={classForm.severity}
                    onChange={(e) =>
                      setClassForm({ ...classForm, severity: e.target.value })
                    }
                  >
                    {SEVERITIES.map((s) => (
                      <option key={s.value} value={s.value}>
                        {s.label}
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}
            {!isSysadmin && (
              <div className="form-field">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={classForm.has_personal_data}
                    onChange={(e) =>
                      setClassForm({
                        ...classForm,
                        has_personal_data: e.target.checked,
                      })
                    }
                  />
                  <span>Утечка / затрагивание ПДн</span>
                </label>
              </div>
            )}
            <button
              type="submit"
              className="btn btn-primary"
              disabled={saving}
            >
              Сохранить классификацию
            </button>
          </form>
        </div>
      </div>

      {incident.has_personal_data === 1 && !isSysadmin && rkn && (
        <div className="card rkn-box">
          <div className="card-header">
            <h2>Контроль сроков РКН (152-ФЗ)</h2>
            <span className="badge badge-pdn">Инцидент с ПДн</span>
          </div>
          <div className="timer-grid">
            <div
              className={`timer-card ${
                timer24?.overdue ? "timer-overdue" : ""
              }`}
            >
              <div className="timer-title">
                Первичное уведомление (24 часа) — до{" "}
                {formatDateTime(rkn.deadline_24h)}
              </div>
              <div className="timer-value">{timer24?.text}</div>
            </div>
            <div
              className={`timer-card ${
                timer72?.overdue ? "timer-overdue" : ""
              }`}
            >
              <div className="timer-title">
                Дополнительное уведомление (72 часа) — до{" "}
                {formatDateTime(rkn.deadline_72h)}
              </div>
              <div className="timer-value">{timer72?.text}</div>
            </div>
          </div>
          <div className="form-field">
            <label htmlFor="rkn-draft">Черновик уведомления в Роскомнадзор</label>
            <textarea
              id="rkn-draft"
              rows={7}
              value={rknDraft}
              onChange={(e) => setRknDraft(e.target.value)}
            />
          </div>
          <button
            type="button"
            className="btn btn-dark"
            disabled={saving}
            onClick={handleSaveRknDraft}
          >
            Сохранить черновик РКН
          </button>

          <div style={{ marginTop: "16px", borderTop: "1px solid var(--border, #e2e2e2)", paddingTop: "12px" }}>
            {rkn.sent_at ? (
              <div>
                <div>
                  <span className="muted">Отправлено:</span>{" "}
                  <strong>{formatDateTime(rkn.sent_at)}</strong>
                </div>
                {rkn.confirmation && (
                  <div>
                    <span className="muted">Подтверждение:</span> {rkn.confirmation}
                  </div>
                )}
              </div>
            ) : (
              <>
                <div className="form-field">
                  <label htmlFor="rkn-confirm">Подтверждение фактической отправки (номер письма, скрин и т.п.)</label>
                  <input
                    id="rkn-confirm"
                    type="text"
                    value={rknConfirmText}
                    onChange={(e) => setRknConfirmText(e.target.value)}
                    placeholder="Например, исх. №12 от 01.01.2026"
                  />
                </div>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={saving}
                  onClick={handleConfirmRkn}
                >
                  Подтвердить отправку в РКН
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {!isLawyer && (
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2>Инструкция и чек-лист реагирования</h2>
          </div>
          <div className="form-field">
            <label htmlFor="instr-select">Шаблон инструкции</label>
            <select
              id="instr-select"
              value={incident.instruction_id || ""}
              onChange={handleInstructionChange}
            >
              <option value="">Без инструкции</option>
              {instructions.map((inst) => (
                <option key={inst.id} value={inst.id}>
                  {inst.title} ({inst.incident_type})
                </option>
              ))}
            </select>
          </div>
          {selectedInstruction ? (
            <ul className="checklist">
              {selectedInstruction.steps.map((stepText, idx) => {
                const done = Boolean(stepMap.get(idx));
                return (
                  <li
                    key={idx}
                    className={`checklist-item ${done ? "done" : ""}`}
                  >
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={done}
                        onChange={(e) =>
                          handleStepToggle(idx, e.target.checked)
                        }
                      />
                      <span>
                        {idx + 1}. {stepText}
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="muted">Выберите шаблон инструкции для работы по шагам.</div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h2>Задачи по инциденту</h2>
          </div>
          <form onSubmit={handleCreateTask} style={{ marginBottom: "14px" }}>
            <div className="form-field">
              <label htmlFor="task-title">Поручение *</label>
              <input
                id="task-title"
                type="text"
                value={taskTitle}
                onChange={(e) => setTaskTitle(e.target.value)}
                placeholder="Например, изолировать хост и снять дамп"
                required
              />
            </div>
            <div className="form-field">
              <label htmlFor="task-desc">Детали *</label>
              <input
                id="task-desc"
                type="text"
                value={taskDesc}
                onChange={(e) => setTaskDesc(e.target.value)}
                placeholder="Дополнительные указания"
                required
              />
            </div>
            <div className="form-field">
              <label htmlFor="task-assignee">Исполнитель *</label>
              <select
                id="task-assignee"
                value={taskAssignee}
                onChange={(e) => setTaskAssignee(e.target.value)}
                required
              >
                <option value="">Выберите сотрудника...</option>
                {assignableUsers.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="task-due">Срок выполнения *</label>
              <input
                id="task-due"
                type="datetime-local"
                value={taskDueDate}
                onChange={(e) => setTaskDueDate(e.target.value)}
                required
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary btn-sm"
              disabled={saving}
            >
              Поставить задачу
            </button>
          </form>

          {(!incident.tasks || incident.tasks.length === 0) ? (
            <div className="muted">Задачи по этому инциденту отсутствуют.</div>
          ) : (
            <ul className="timeline">
              {incident.tasks.map((t) => (
                <li key={t.id} className="timeline-item">
                  <div className="timeline-meta">
                    Задача #{t.id} | Статус: <strong>{t.status}</strong> |{" "}
                    {formatDateTime(t.created_at)}
                  </div>
                  <div style={{ fontWeight: 600 }}>{t.title}</div>
                  {t.description && (
                    <div className="muted">{t.description}</div>
                  )}
                  <div className="muted">
                    Исполнитель: {t.assigned_to_user?.label || "-"} | Поставил:{" "}
                    {t.created_by_user?.label || "-"}
                  </div>
                  {t.result && (
                    <div style={{ marginTop: "4px" }}>
                      Результат: {t.result}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      )}

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2>Входящие сообщения ({incident.messages?.length || 0})</h2>
          </div>
          {!incident.messages || incident.messages.length === 0 ? (
            <div className="muted">Входящих сообщений нет.</div>
          ) : (
            <ul className="timeline">
              {incident.messages.map((m) => (
                <li key={m.id} className="timeline-item">
                  <div className="timeline-meta">
                    {m.source || "Источник"} | {m.sender || "Отправитель не указан"} |{" "}
                    {formatDateTime(m.received_at)}
                  </div>
                  <div>{m.body}</div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h2>История действий ({incident.history?.length || 0})</h2>
          </div>
          {!incident.history || incident.history.length === 0 ? (
            <div className="muted">История действий пуста.</div>
          ) : (
            <ul className="timeline">
              {incident.history.map((h) => (
                <li key={h.id} className="timeline-item">
                  <div className="timeline-meta">
                    {formatDateTime(h.created_at)} |{" "}
                    {h.full_name || h.username || "Система"} | {h.action}
                  </div>
                  <div>{h.details}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
