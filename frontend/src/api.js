const TOKEN_KEY = 'pi_is_token';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function toQuery(params = {}) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      sp.set(k, String(v));
    }
  }
  const qs = sp.toString();
  return qs ? `?${qs}` : '';
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const token = getToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  let body = options.body;
  if (body !== undefined && typeof body !== 'string') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  const res = await fetch(path, { ...options, headers, body });
  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    const detail = data && typeof data === 'object' ? data.detail || data.message : null;
    const err = new Error(detail || `Ошибка HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }

  return data;
}

export function login(username, password) {
  return request('/api/auth/login', {
    method: 'POST',
    body: { username, password },
  });
}

export function getMe() {
  return request('/api/auth/me');
}

export function listIncidents(params = {}) {
  return request(`/api/incidents${toQuery(params)}`);
}

export function createIncident(data) {
  return request('/api/incidents', {
    method: 'POST',
    body: data,
  });
}

export function getIncident(id) {
  return request(`/api/incidents/${id}`);
}

export function updateIncident(id, data) {
  return request(`/api/incidents/${id}`, {
    method: 'PATCH',
    body: data,
  });
}

export function changeIncidentStatus(id, status, outcome) {
  const payload = outcome !== undefined ? { status, outcome } : { status };
  return request(`/api/incidents/${id}/status`, {
    method: 'POST',
    body: payload,
  });
}

export function sendSignal(data) {
  return request('/api/signals', {
    method: 'POST',
    body: data,
  });
}

export function listInstructions() {
  return request('/api/instructions');
}

export function updateStep(incidentId, stepIndex, completed) {
  return request(`/api/incidents/${incidentId}/steps/${stepIndex}`, {
    method: 'PUT',
    body: { completed },
  });
}

export function listUsers(params = {}) {
  return request(`/api/users${toQuery(params)}`);
}

export function createTask(incidentId, data) {
  return request(`/api/incidents/${incidentId}/tasks`, {
    method: 'POST',
    body: data,
  });
}

export function listTasks(params = {}) {
  return request(`/api/tasks${toQuery(params)}`);
}

export function updateTask(taskId, data) {
  return request(`/api/tasks/${taskId}`, {
    method: 'PATCH',
    body: data,
  });
}

export function getRkn(incidentId) {
  return request(`/api/incidents/${incidentId}/rkn`);
}

export function updateRkn(incidentId, rknDraft) {
  return request(`/api/incidents/${incidentId}/rkn`, {
    method: 'PUT',
    body: { rkn_draft: rknDraft },
  });
}

export function confirmRkn(incidentId, confirmation) {
  return request(`/api/incidents/${incidentId}/rkn/confirm`, {
    method: 'POST',
    body: { confirmation: confirmation || '' },
  });
}

export function getDispatchRules() {
  return request('/api/incidents/dispatch-rules');
}

export function checkEscalations() {
  return request('/api/escalations/check', {
    method: 'POST',
  });
}

export function listNotifications(params = {}) {
  return request(`/api/notifications${toQuery(params)}`);
}

export function getMonthlyReport(year, month) {
  return request(`/api/reports/monthly${toQuery({ year, month })}`);
}

export function getByTypeReport(year, month) {
  return request(`/api/reports/by-type${toQuery({ year, month })}`);
}
