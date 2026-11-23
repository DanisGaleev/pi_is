
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

function ShieldMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    </span>
  );
}

function NavIcon({ id }) {
  const props = { width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2, 'aria-hidden': true };
  if (id === 'incidents') {
    return <svg {...props}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 10h18" /></svg>;
  }
  if (id === 'tasks') {
    return <svg {...props}><path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></svg>;
  }
  if (id === 'simulator') {
    return <svg {...props}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>;
  }
  if (id === 'notifications') {
    return <svg {...props}><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" /></svg>;
  }
  return <svg {...props}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>;
}

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
          <div className="login-brand">
            <ShieldMark />
            <h1 style={{ margin: 0, fontSize: 19 }}>Учёт инцидентов ИБ</h1>
          </div>
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
      <aside className="sidebar no-print">
        <div className="sidebar-top">
          <div className="brand">
            <ShieldMark />
            <span>Инциденты ИБ</span>
          </div>

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
                <NavIcon id={item.id} />
                <span>{item.label}</span>
              </button>
            ))}
          </nav>
        </div>

        <div className="user-card">
          <div className="user-meta">
            <span className="user-name">{user.full_name}</span>
            <span className="user-role">{ROLE_LABELS[user.role] || user.role}</span>
          </div>
          <button type="button" className="btn btn-sm btn-logout" onClick={handleLogout}>
            Выйти
          </button>
        </div>
      </aside>

      <div className="main-workspace">
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
    </div>
  );
}
