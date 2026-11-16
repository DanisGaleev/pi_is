import { useEffect, useState } from "react";
import { createIncident, listIncidents } from "../api";

const INCIDENT_TYPES = [
  "Вирус / Вредоносное ПО",
  "Утечка ПДн",
  "Фишинг",
  "Несанкционированный доступ",
  "Прочее",
];

const SEVERITIES = [
  { value: "critical", label: "Критический" },
  { value: "high", label: "Высокий" },
  { value: "medium", label: "Средний" },
  { value: "low", label: "Низкий" },
];

const STATUSES = ["Новый", "В работе", "На проверке", "Закрыт"];

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

function isOverdueNew(incident) {
  if (incident.status !== "Новый" || !incident.detected_at) return false;
  const detectedMs = new Date(incident.detected_at).getTime();
  if (Number.isNaN(detectedMs)) return false;
  return Date.now() - detectedMs > 30 * 60 * 1000;
}

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

export default function IncidentsPage({ user, onOpenIncident }) {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [q, setQ] = useState("");
  const [incidentType, setIncidentType] = useState("");
  const [status, setStatus] = useState("");

  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");
  const [form, setForm] = useState({
    title: "",
    description: "",
    incident_type: INCIDENT_TYPES[0],
    severity: "medium",
    computer: "",
    employee: "",
    has_personal_data: false,
  });

  const isSysadmin = user?.role === "sysadmin";

  async function loadIncidents(filters = { q, incident_type: incidentType, status }) {
    setLoading(true);
    setError("");
    try {
      const data = await listIncidents(filters);
      setIncidents(data);
    } catch (err) {
      setError(err.message || "Не удалось загрузить инциденты");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncidents({ q, incident_type: incidentType, status });
  }, [incidentType, status]);

  function handleSearchSubmit(e) {
    e.preventDefault();
    loadIncidents({ q, incident_type: incidentType, status });
  }

  function handleResetFilters() {
    setQ("");
    setIncidentType("");
    setStatus("");
    loadIncidents({ q: "", incident_type: "", status: "" });
  }

  async function handleCreateSubmit(e) {
    e.preventDefault();
    if (!form.title.trim()) {
      setFormError("Укажите заголовок инцидента");
      return;
    }
    setSubmitting(true);
    setFormError("");
    try {
      await createIncident({
        ...form,
        title: form.title.trim(),
        description: form.description.trim(),
        computer: form.computer.trim(),
        employee: form.employee.trim(),
        has_personal_data: isSysadmin ? 0 : form.has_personal_data ? 1 : 0,
      });
      setForm({
        title: "",
        description: "",
        incident_type: INCIDENT_TYPES[0],
        severity: "medium",
        computer: "",
        employee: "",
        has_personal_data: false,
      });
      setShowForm(false);
      await loadIncidents({ q, incident_type: incidentType, status });
    } catch (err) {
      setFormError(err.message || "Ошибка регистрации инцидента");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Инциденты ИБ</h1>
          <div className="muted">
            Реестр инцидентов информационной безопасности
          </div>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setShowForm((v) => !v)}
        >
          {showForm ? "Скрыть форму" : "Зарегистрировать инцидент"}
        </button>
      </div>

      {showForm && (
        <div className="card">
          <div className="card-header">
            <h2>Ручная регистрация инцидента</h2>
          </div>
          {formError && <div className="alert alert-error">{formError}</div>}
          <form onSubmit={handleCreateSubmit}>
            <div className="form-grid">
              <div className="form-field">
                <label htmlFor="inc-title">Заголовок *</label>
                <input
                  id="inc-title"
                  type="text"
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  placeholder="Краткое описание инцидента"
                  required
                />
              </div>
              <div className="form-field">
                <label htmlFor="inc-type">Тип инцидента</label>
                <select
                  id="inc-type"
                  value={form.incident_type}
                  onChange={(e) =>
                    setForm({ ...form, incident_type: e.target.value })
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
                <label htmlFor="inc-severity">Важность</label>
                <select
                  id="inc-severity"
                  value={form.severity}
                  onChange={(e) =>
                    setForm({ ...form, severity: e.target.value })
                  }
                >
                  {SEVERITIES.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-field">
                <label htmlFor="inc-computer">Компьютер / Хост</label>
                <input
                  id="inc-computer"
                  type="text"
                  value={form.computer}
                  onChange={(e) =>
                    setForm({ ...form, computer: e.target.value })
                  }
                  placeholder="Например, PC-FIN-01"
                />
              </div>
              <div className="form-field">
                <label htmlFor="inc-employee">Сотрудник</label>
                <input
                  id="inc-employee"
                  type="text"
                  value={form.employee}
                  onChange={(e) =>
                    setForm({ ...form, employee: e.target.value })
                  }
                  placeholder="ФИО сотрудника"
                />
              </div>
              {!isSysadmin && (
                <div className="form-field" style={{ justifyContent: "flex-end" }}>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={form.has_personal_data}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          has_personal_data: e.target.checked,
                        })
                      }
                    />
                    <span>Связано с персональными данными (ПДн)</span>
                  </label>
                </div>
              )}
            </div>
            <div className="form-field">
              <label htmlFor="inc-desc">Описание</label>
              <textarea
                id="inc-desc"
                value={form.description}
                onChange={(e) =>
                  setForm({ ...form, description: e.target.value })
                }
                placeholder="Подробности обнаружения и контекст"
              />
            </div>
            <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={submitting}
              >
                {submitting ? "Сохранение..." : "Создать инцидент"}
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => setShowForm(false)}
              >
                Отмена
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="card">
        <form className="toolbar" onSubmit={handleSearchSubmit}>
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Поиск по компьютеру или сотруднику..."
            style={{ maxWidth: "280px" }}
          />
          <select
            value={incidentType}
            onChange={(e) => setIncidentType(e.target.value)}
            style={{ maxWidth: "220px" }}
          >
            <option value="">Все типы</option>
            {INCIDENT_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            style={{ maxWidth: "180px" }}
          >
            <option value="">Все статусы</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <button type="submit" className="btn btn-dark">
            Найти
          </button>
          {(q || incidentType || status) && (
            <button type="button" className="btn" onClick={handleResetFilters}>
              Сбросить
            </button>
          )}
        </form>

        {error && <div className="alert alert-error">{error}</div>}

        {loading ? (
          <div className="muted">Загрузка инцидентов...</div>
        ) : incidents.length === 0 ? (
          <div className="muted">Инциденты не найдены.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Заголовок</th>
                  <th>Тип</th>
                  <th>Важность</th>
                  <th>Статус</th>
                  <th>Узел / Сотрудник</th>
                  <th>Обнаружен</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => {
                  const overdue = isOverdueNew(inc);
                  return (
                    <tr
                      key={inc.id}
                      className="clickable"
                      onClick={() => onOpenIncident(inc.id)}
                    >
                      <td>#{inc.id}</td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{inc.title}</div>
                        <div style={{ display: "flex", gap: "6px", marginTop: "4px", flexWrap: "wrap" }}>
                          {inc.has_personal_data === 1 && (
                            <span className="badge badge-pdn">ПДн</span>
                          )}
                          {overdue && (
                            <span className="badge badge-overdue">
                              Просрочен (&gt;30 мин)
                            </span>
                          )}
                        </div>
                      </td>
                      <td>{inc.incident_type}</td>
                      <td>
                        <span
                          className={`badge severity-${inc.severity || "medium"}`}
                        >
                          {SEVERITY_LABELS[inc.severity] || inc.severity}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`badge ${
                            STATUS_CLASSES[inc.status] || ""
                          }`}
                        >
                          {inc.status}
                        </span>
                      </td>
                      <td>
                        <div>{inc.computer || "-"}</div>
                        <div className="muted">{inc.employee || "-"}</div>
                      </td>
                      <td>{formatDateTime(inc.detected_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
