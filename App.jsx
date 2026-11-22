import { useEffect, useState } from 'react';
import { clearToken, getMe, getToken, login, setToken } from './api';
import IncidentDetailPage from './pages/IncidentDetailPage';
import IncidentsPage from './pages/IncidentsPage';
import NotificationsPage from './pages/NotificationsPage';
import ReportPage from './pages/ReportPage';
import SimulatorPage from './pages/SimulatorPage';
import TasksPage from './pages/TasksPage';

const ROLE_LABELS = {
  ib_specialist: 'Специалист ИБ',
  sysadmin: 'Системный администратор',
  it_head: 'Руководитель ИТ',
  lawyer: 'Юрист',
};

const DEMO_ROLES = [
  { username: 'ib', label: 'Специалист ИБ (ib)' },
  { username: 'sysadmin', label: 'Сисадмин (sysadmin)' },
  { username: 'it_head', label: 'Руководитель ИТ (it_head)' },
  { username: 'lawyer', label: 'Юрист (lawyer)' },
];

const NAV_ITEMS = [
  { id: 'incidents', label: 'Инциденты' },
  { id: 'tasks', label: 'Мои задачи' },
  { id: 'simulator', label: 'Симулятор сигналов' },
  { id: 'notifications', label: 'Журнал уведомлений' },
  { id: 'report', label: 'Отчёт' },
];

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('incidents');
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }
    getMe()
      .then((me) => setUser(me))
      .catch(() => {
        clearToken();
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  async function handleLogin(e) {
    e.preventDefault();
    setAuthError('');
    setSubmitting(true);
    try {
      const res = await login(username.trim(), password);
      setToken(res.token);
      setUser(res.user);
      setActiveTab('incidents');
      setSelectedIncidentId(null);
    } catch (err) {
      setAuthError(err.message || 'Ошибка входа');
    } finally {
      setSubmitting(false);
    }
  }

  function handleQuickFill(demoUsername) {
    setUsername(demoUsername);
    setPassword('password123');
    setAuthError('');
  }

  function handleLogout() {
    clearToken();
    setUser(null);
    setSelectedIncidentId(null);
    setActiveTab('incidents');
    setUsername('');
    setPassword('');
  }

  function openIncident(id) {
    setSelectedIncidentId(id);
    setActiveTab('incidents');
  }

  if (loading) {
    return (
      <div className="login-wrap">
        <div className="card">Загрузка...</div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="login-wrap">
        <div className="login-card">
          <h1>Учёт инцидентов ИБ</h1>
          <p className="muted" style={{ marginBottom: 16 }}>
            Войдите в систему для работы с инцидентами и задачами.
          </p>

          {authError && <div className="alert alert-error">{authError}</div>}

          <form onSubmit={handleLogin}>
            <div className="form-field">
              <label htmlFor="login-username">Логин</label>
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Например, ib"
                required
              />
            </div>

            <div className="form-field">
              <label htmlFor="login-password">Пароль</label>
              <input
                id="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Введите пароль"
                required
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', marginTop: 6 }}
              disabled={submitting}
            >
              {submitting ? 'Вход...' : 'Войти'}
            </button>
          </form>

          <div style={{ marginTop: 18, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
            <div className="muted">Демо-учётные записи (пароль password123):</div>
            <div className="quick-roles">
              {DEMO_ROLES.map((item) => (
                <button
                  key={item.username}
                  type="button"
                  className="btn btn-sm"
                  onClick={() => handleQuickFill(item.username)}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar no-print">
        <div className="topbar-inner">
          <div className="brand">Учёт инцидентов ИБ</div>

          <nav className="nav">
            {NAV_ITEMS.filter((item) => item.id !== 'tasks' || user.role !== 'lawyer').map((item) => (
              <button
                key={item.id}
                type="button"
                className={`nav-btn ${activeTab === item.id ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab(item.id);
                  if (item.id === 'incidents') {
                    setSelectedIncidentId(null);
                  }
                }}
              >
                {item.label}
              </button>
            ))}
          </nav>

          <div className="user-bar">
            <span>{user.full_name}</span>
            <span className="user-role">{ROLE_LABELS[user.role] || user.role}</span>
            <button type="button" className="btn btn-sm" onClick={handleLogout}>
              Выйти
            </button>
          </div>
        </div>
      </header>

      <main className="container">
        {activeTab === 'incidents' &&
          (selectedIncidentId !== null ? (
            <IncidentDetailPage
              incidentId={selectedIncidentId}
              user={user}
              onBack={() => setSelectedIncidentId(null)}
            />
          ) : (
            <IncidentsPage
              user={user}
              onOpenIncident={(id) => setSelectedIncidentId(id)}
            />
          ))}

        {activeTab === 'tasks' && user.role !== 'lawyer' && (
          <TasksPage user={user} onOpenIncident={openIncident} />
        )}
        {activeTab === 'simulator' && <SimulatorPage onOpenIncident={openIncident} />}
        {activeTab === 'notifications' && <NotificationsPage onOpenIncident={openIncident} />}
        {activeTab === 'report' && <ReportPage />}
      </main>
    </div>
  );
}
