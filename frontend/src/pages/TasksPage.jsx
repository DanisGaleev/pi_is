import { useEffect, useState } from 'react';
import { listTasks, updateTask } from '../api';

const DONE_STATUSES = new Set(['выполнена', 'завершена', 'закрыта', 'done']);

function isDone(status) {
  return DONE_STATUSES.has(String(status || '').trim().toLowerCase());
}

export default function TasksPage({ onOpenIncident }) {
  const [scope, setScope] = useState('me');
  const [tasks, setTasks] = useState([]);
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState(null);
  const [error, setError] = useState('');

  async function loadTasks(currentScope = scope) {
    setLoading(true);
    setError('');
    try {
      const params = currentScope === 'me' ? { assigned_to: 'me' } : {};
      const data = await listTasks(params);
      setTasks(data);
      const initialResults = {};
      for (const t of data) {
        initialResults[t.id] = t.result || '';
      }
      setResults(initialResults);
    } catch (err) {
      setError(err.message || 'Не удалось загрузить задачи');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadTasks(scope);
  }, [scope]);

  async function handleComplete(task) {
    setSavingId(task.id);
    setError('');
    try {
      await updateTask(task.id, {
        status: 'Выполнена',
        result: results[task.id] || '',
      });
      await loadTasks(scope);
    } catch (err) {
      setError(err.message || 'Не удалось завершить задачу');
    } finally {
      setSavingId(null);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Мои задачи</h1>
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <button
            type="button"
            className={`btn ${scope === 'me' ? 'btn-primary' : ''}`}
            onClick={() => setScope('me')}
          >
            Мои
          </button>
          <button
            type="button"
            className={`btn ${scope === 'all' ? 'btn-primary' : ''}`}
            onClick={() => setScope('all')}
          >
            Все
          </button>
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        {loading ? (
          <div className="muted">Загрузка задач...</div>
        ) : tasks.length === 0 ? (
          <div className="muted">Задач нет.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Инцидент</th>
                  <th>Задача</th>
                  <th>Статус</th>
                  <th>Результат выполнения</th>
                  <th>Действие</th>
                </tr>
              </thead>
              <tbody>
                {tasks.map((task) => {
                  const done = isDone(task.status);
                  return (
                    <tr key={task.id}>
                      <td>#{task.id}</td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => onOpenIncident && onOpenIncident(task.incident_id)}
                        >
                          #{task.incident_id} {task.incident_title || 'Открыть'}
                        </button>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{task.title}</div>
                        {task.description && <div className="muted">{task.description}</div>}
                      </td>
                      <td>
                        <span className={`badge ${done ? 'status-closed' : 'status-progress'}`}>
                          {task.status}
                        </span>
                      </td>
                      <td style={{ minWidth: 220 }}>
                        <input
                          type="text"
                          value={results[task.id] ?? ''}
                          onChange={(e) =>
                            setResults((prev) => ({ ...prev, [task.id]: e.target.value }))
                          }
                          placeholder="Краткий итог выполнения"
                          disabled={done}
                        />
                      </td>
                      <td>
                        {done ? (
                          <span className="muted">Завершена</span>
                        ) : (
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            disabled={savingId === task.id}
                            onClick={() => handleComplete(task)}
                          >
                            {savingId === task.id ? 'Сохранение...' : 'Завершить задачу'}
                          </button>
                        )}
                      </td>
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
