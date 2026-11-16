import { useEffect, useState } from 'react';
import { getMonthlyReport } from '../api';

const MONTHS = [
  { value: 1, label: 'Январь' },
  { value: 2, label: 'Февраль' },
  { value: 3, label: 'Март' },
  { value: 4, label: 'Апрель' },
  { value: 5, label: 'Май' },
  { value: 6, label: 'Июнь' },
  { value: 7, label: 'Июль' },
  { value: 8, label: 'Август' },
  { value: 9, label: 'Сентябрь' },
  { value: 10, label: 'Октябрь' },
  { value: 11, label: 'Ноябрь' },
  { value: 12, label: 'Декабрь' },
];

function BreakdownTable({ title, data }) {
  const entries = Object.entries(data || {});
  return (
    <div className="card">
      <div className="card-header">
        <h2 style={{ margin: 0 }}>{title}</h2>
      </div>
      {entries.length === 0 ? (
        <div className="muted">Нет данных за выбранный период.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Категория</th>
                <th style={{ textAlign: 'right' }}>Количество</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(([key, count]) => (
                <tr key={key}>
                  <td>{key}</td>
                  <td style={{ textAlign: 'right', fontWeight: 600 }}>{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function ReportPage() {
  const now = new Date();
  const [year, setYear] = useState(now.getFullYear());
  const [month, setMonth] = useState(now.getMonth() + 1);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function loadReport(y = year, m = month) {
    setLoading(true);
    setError('');
    try {
      const data = await getMonthlyReport(y, m);
      setReport(data);
    } catch (err) {
      setError(err.message || 'Не удалось сформировать отчёт');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReport(year, month);
  }, [year, month]);

  const monthName = MONTHS.find((m) => m.value === Number(month))?.label || month;

  return (
    <div>
      <div className="page-header">
        <h1>
          Отчёт за {monthName} {year}
        </h1>
        <button
          type="button"
          className="btn btn-primary no-print"
          onClick={() => window.print()}
        >
          Печать / Экспорт в PDF
        </button>
      </div>

      <div className="toolbar no-print">
        <div style={{ width: 120 }}>
          <input
            type="number"
            min="2000"
            max="2100"
            value={year}
            onChange={(e) => setYear(Number(e.target.value) || now.getFullYear())}
            aria-label="Год"
          />
        </div>
        <div style={{ width: 160 }}>
          <select
            value={month}
            onChange={(e) => setMonth(Number(e.target.value))}
            aria-label="Месяц"
          >
            {MONTHS.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </div>
        <button type="button" className="btn" onClick={() => loadReport(year, month)}>
          Обновить
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {loading ? (
        <div className="card">
          <div className="muted">Формирование отчёта...</div>
        </div>
      ) : (
        report && (
          <>
            <div className="grid-2" style={{ marginBottom: 16 }}>
              <div className="kpi-card">
                <div className="kpi-label">Всего инцидентов</div>
                <div className="kpi-value">{report.total}</div>
              </div>
              <div className="kpi-card">
                <div className="kpi-label">С ПДн</div>
                <div className="kpi-value">{report.personal_data_count}</div>
              </div>
            </div>

            <div className="grid-2">
              <BreakdownTable title="По типам" data={report.by_incident_type} />
              <BreakdownTable title="По статусам" data={report.by_status} />
              <BreakdownTable title="По итогам проверки" data={report.by_outcome} />
              <BreakdownTable title="По важности" data={report.by_severity} />
            </div>
          </>
        )
      )}
    </div>
  );
}
