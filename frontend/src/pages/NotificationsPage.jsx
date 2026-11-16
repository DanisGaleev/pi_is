import { useEffect, useState } from 'react';
import { checkEscalations, listNotifications } from '../api';

const ROLE_LABELS = {
  ib_specialist: 'Специалист ИБ',
  sysadmin: 'Системный администратор',
  it_head: 'Руководитель ИТ',
  lawyer: 'Юрист',
  chief_accountant: 'Главный бухгалтер',
};

const KIND_LABELS = {
  escalation_30m: 'Просрочка 30 мин',
  pdn_lawyer_notice: 'ПДн: уведомление юристу',
  pdn_accounting_notice: 'ПДн: уведомление бухгалтерии',
};

export default function NotificationsPage({ onOpenIncident }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [info, setInfo] = useState('');
  const [error, setError] = useState('');

  async function loadNotifications() {
    setLoading(true);
    setError('');
    try {
      const data = await listNotifications();
      setItems(data);
    } catch (err) {
      setError(err.message || 'Не удалось загрузить уведомления');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadNotifications();
  }, []);

  async function handleCheckEscalations() {
    setChecking(true);
    setError('');
    setInfo('');
    try {
      const created = await checkEscalations();
      const count = Array.isArray(created) ? created.length : 0;
      setInfo(
        count > 0
          ? `Создано новых уведомлений: ${count}`
          : 'Новых просрочек и неуведомлённых инцидентов с ПДн не найдено.'
      );
      await loadNotifications();
    } catch (err) {
      setError(err.message || 'Ошибка при проверке просрочек');
    } finally {
      setChecking(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Журнал уведомлений</h1>
        <button
          type="button"
          className="btn btn-primary"
          onClick={handleCheckEscalations}
          disabled={checking}
        >
          {checking ? 'Проверка...' : 'Проверить просрочки'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {info && <div className="alert alert-info">{info}</div>}

      <div className="card">
        {loading ? (
          <div className="muted">Загрузка журнала...</div>
        ) : items.length === 0 ? (
          <div className="muted">Уведомлений пока нет.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Дата и время</th>
                  <th>Тип</th>
                  <th>Получатель</th>
                  <th>Роль</th>
                  <th>Инцидент</th>
                  <th>Сообщение</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{item.created_at}</td>
                    <td>
                      <span className="badge">{KIND_LABELS[item.kind] || item.kind}</span>
                    </td>
                    <td>{item.recipient_name}</td>
                    <td>{ROLE_LABELS[item.recipient_role] || item.recipient_role}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => onOpenIncident && onOpenIncident(item.incident_id)}
                      >
                        #{item.incident_id}
                      </button>
                    </td>
                    <td>{item.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
