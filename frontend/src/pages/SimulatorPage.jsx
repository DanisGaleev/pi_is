import { useEffect, useState } from 'react';
import { getDispatchRules, sendSignal } from '../api';

const PRESETS = [
  {
    label: 'Kaspersky',
    data: {
      source: 'Kaspersky Endpoint Security',
      sender: 'ksc-server@corp.local',
      computer: 'WS-FIN-04',
      employee: 'Иванова М.А.',
      incident_type: 'Вирус / Вредоносное ПО',
      severity: 'high',
      incident_key: 'ksc-ws-fin-04-trojan',
      has_personal_data: true,
      error_code: '',
      body: 'Обнаружен и заблокирован объект Trojan.Win32.Agent в каталоге Загрузки пользователя.',
    },
  },
  {
    label: 'Zabbix',
    data: {
      source: 'Zabbix',
      sender: 'zabbix@corp.local',
      computer: 'SRV-DB-01',
      employee: '',
      incident_type: 'Сбой / Доступность',
      severity: 'critical',
      incident_key: 'zbx-srv-db-01-high-load',
      has_personal_data: false,
      error_code: '',
      body: 'Аномальная загрузка CPU (98%) и всплеск сетевых соединений на SRV-DB-01.',
    },
  },
  {
    label: 'Почта',
    data: {
      source: 'Почта',
      sender: 'security-report@corp.local',
      computer: 'WS-HR-12',
      employee: 'Петров С.В.',
      incident_type: 'Фишинг',
      severity: 'medium',
      incident_key: 'mail-phish-hr-12',
      has_personal_data: true,
      error_code: '',
      body: 'Сотрудник переслал подозрительное письмо с вложением Счет_оплата.html и запросом пароля.',
    },
  },
  {
    label: 'Telegram',
    data: {
      source: 'Telegram',
      sender: '@helpdesk_bot',
      computer: 'WS-SALES-07',
      employee: 'Сидоров К.Н.',
      incident_type: 'Несанкционированный доступ',
      severity: 'high',
      incident_key: 'tg-sales-07-rdp',
      has_personal_data: false,
      error_code: '',
      body: 'Зафиксированы множественные неудачные попытки входа по RDP с внешнего адреса.',
    },
  },
  {
    label: 'CVE',
    data: {
      source: 'Сканер уязвимостей',
      sender: 'vuln-scanner@corp.local',
      computer: 'SRV-WEB-02',
      employee: '',
      incident_type: '',
      severity: 'high',
      incident_key: 'scanner-srv-web-02-cve',
      has_personal_data: false,
      error_code: 'CVE-2024-3400',
      body: 'Сканер уязвимостей обнаружил критическую уязвимость CVE-2024-3400 на SRV-WEB-02, требуется обновление.',
    },
  },
  {
    label: 'Подбор пароля',
    data: {
      source: 'AD',
      sender: 'ad-monitor@corp.local',
      computer: 'SRV-AD-01',
      employee: '',
      incident_type: '',
      severity: 'high',
      incident_key: 'ad-srv-ad-01-bruteforce',
      has_personal_data: false,
      error_code: 'AUTH_BRUTEFORCE',
      body: 'Зафиксирован подбор пароля (bruteforce) учётной записи администратора домена, 200+ неудачных попыток входа.',
    },
  },
  {
    label: 'Обман с платежами',
    data: {
      source: 'Бухгалтерия',
      sender: 'buh@corp.local',
      computer: '',
      employee: 'Кузнецова О.И.',
      incident_type: '',
      severity: 'high',
      incident_key: 'buh-payment-fraud',
      has_personal_data: false,
      error_code: '',
      body: 'Получено письмо с измененными платежными реквизитами поставщика, подозрение на обман с платежами (BEC).',
    },
  },
];

const INCIDENT_TYPES = [
  'Вирус / Вредоносное ПО',
  'Фишинг',
  'Несанкционированный доступ',
  'Утечка ПДн',
  'Подбор пароля',
  'Обман с платежами',
  'Уязвимость (CVE)',
  'Прочее',
];

const SEVERITIES = [
  { value: 'low', label: 'Низкий' },
  { value: 'medium', label: 'Средний' },
  { value: 'high', label: 'Высокий' },
  { value: 'critical', label: 'Критический' },
];

export default function SimulatorPage({ onOpenIncident }) {
  const [form, setForm] = useState(PRESETS[0].data);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [dispatchRules, setDispatchRules] = useState([]);

  useEffect(() => {
    getDispatchRules()
      .then((rules) => setDispatchRules(Array.isArray(rules) ? rules : []))
      .catch(() => {});
  }, []);

  function applyPreset(preset) {
    setForm({ ...preset.data });
    setResult(null);
    setError('');
  }

  function updateField(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    setResult(null);
    try {
      const res = await sendSignal(form);
      setResult(res);
    } catch (err) {
      setError(err.message || 'Не удалось отправить сигнал');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Симулятор сигналов</h1>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 style={{ margin: 0 }}>Быстрые пресеты источников</h2>
        </div>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          {PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              className="btn"
              onClick={() => applyPreset(preset)}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {result && (
        <div className={`alert ${result.deduplicated ? 'alert-info' : 'alert-ok'}`}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <strong>
                {result.deduplicated
                  ? 'Объединено с существующей карточкой'
                  : 'Создана новая карточка'}
              </strong>
              {' — '}
              инцидент #{result.incident_id} (сообщение #{result.message_id})
            </div>
            {onOpenIncident && (
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => onOpenIncident(result.incident_id)}
              >
                Открыть инцидент #{result.incident_id}
              </button>
            )}
          </div>
        </div>
      )}

      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-grid">
            <div className="form-field">
              <label htmlFor="sig-source">Источник (source)</label>
              <input
                id="sig-source"
                type="text"
                value={form.source}
                onChange={(e) => updateField('source', e.target.value)}
                required
              />
            </div>

            <div className="form-field">
              <label htmlFor="sig-sender">Отправитель (sender)</label>
              <input
                id="sig-sender"
                type="text"
                value={form.sender}
                onChange={(e) => updateField('sender', e.target.value)}
              />
            </div>

            <div className="form-field">
              <label htmlFor="sig-computer">Компьютер / узел (computer)</label>
              <input
                id="sig-computer"
                type="text"
                value={form.computer}
                onChange={(e) => updateField('computer', e.target.value)}
              />
            </div>

            <div className="form-field">
              <label htmlFor="sig-employee">Сотрудник (employee)</label>
              <input
                id="sig-employee"
                type="text"
                value={form.employee}
                onChange={(e) => updateField('employee', e.target.value)}
              />
            </div>

            <div className="form-field">
              <label htmlFor="sig-type">Тип инцидента (incident_type)</label>
              <select
                id="sig-type"
                value={form.incident_type}
                onChange={(e) => updateField('incident_type', e.target.value)}
              >
                <option value="">— Автоклассификация по error_code/тексту —</option>
                {INCIDENT_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div className="form-field">
              <label htmlFor="sig-error-code">Код ошибки (error_code)</label>
              <input
                id="sig-error-code"
                type="text"
                value={form.error_code || ''}
                onChange={(e) => updateField('error_code', e.target.value)}
                placeholder="Например, CVE-2024-3400 или AUTH_BRUTEFORCE"
              />
            </div>

            <div className="form-field">
              <label htmlFor="sig-severity">Важность (severity)</label>
              <select
                id="sig-severity"
                value={form.severity}
                onChange={(e) => updateField('severity', e.target.value)}
              >
                {SEVERITIES.map((s) => (
                  <option key={s.value} value={s.value}>
                    {s.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="form-field">
              <label htmlFor="sig-key">Ключ дедупликации (incident_key)</label>
              <input
                id="sig-key"
                type="text"
                value={form.incident_key}
                onChange={(e) => updateField('incident_key', e.target.value)}
              />
            </div>

            <div className="form-field" style={{ justifyContent: 'flex-end' }}>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={Boolean(form.has_personal_data)}
                  onChange={(e) => updateField('has_personal_data', e.target.checked)}
                />
                <span>Затрагивает персональные данные (ПДн)</span>
              </label>
            </div>
          </div>

          <div className="form-field">
            <label htmlFor="sig-body">Текст сигнала (body)</label>
            <textarea
              id="sig-body"
              value={form.body}
              onChange={(e) => updateField('body', e.target.value)}
              required
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Отправка...' : 'Отправить сигнал'}
          </button>
        </form>
      </div>

      {dispatchRules.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0 }}>Правила автодиспетчеризации</h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Тип инцидента</th>
                  <th>Важность по умолчанию</th>
                  <th>Ответственная роль</th>
                  <th>Описание</th>
                </tr>
              </thead>
              <tbody>
                {dispatchRules.map((rule) => {
                  const sevLabel =
                    SEVERITIES.find((s) => s.value === rule.default_severity)?.label ||
                    rule.default_severity;
                  return (
                    <tr key={rule.incident_type}>
                      <td>{rule.incident_type}</td>
                      <td>
                        <span className={`badge severity-${rule.default_severity || 'medium'}`}>
                          {sevLabel}
                        </span>
                      </td>
                      <td>{rule.responsible_role_label || rule.responsible_role}</td>
                      <td className="muted">{rule.description}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
