const BASE_URL = 'http://localhost:8000';

// ── Token & user management ───────────────────────────────────
function getToken()    { return localStorage.getItem('cyberai_token'); }
function setToken(t)   { localStorage.setItem('cyberai_token', t); }
function getUser()     { const u = localStorage.getItem('cyberai_user'); return u ? JSON.parse(u) : null; }
function setUser(u)    { localStorage.setItem('cyberai_user', JSON.stringify(u)); }
function logout()      { localStorage.removeItem('cyberai_token'); localStorage.removeItem('cyberai_user'); window.location.href = '../pages/login.html'; }
function requireAuth() { if (!getToken()) window.location.href = '../pages/login.html'; }

// ── Base fetch ────────────────────────────────────────────────
async function apiCall(endpoint, options = {}) {
    const token = getToken();
    const headers = {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
    };
    const res  = await fetch(`${BASE_URL}${endpoint}`, { ...options, headers });
    if (res.status === 401) { logout(); return; }
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'API error');
    return data;
}

// ── Auth ──────────────────────────────────────────────────────
async function login(email, password) {
    const body = new URLSearchParams({ username: email, password });
    const res  = await fetch(`${BASE_URL}/auth/login`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Login failed');
    setToken(data.access_token);
    setUser({ name: data.name, role: data.role, email: data.email, avatar: data.avatar });
    return data;
}

async function register(name, email, password, role = 'analyst', department = '') {
    const res  = await fetch(`${BASE_URL}/auth/register`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name, email, password, role, department }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Registration failed');
    setToken(data.access_token);
    setUser({ name: data.name, role: data.role, email: data.email, avatar: data.avatar });
    return data;
}

async function updateProfile(name, department = '') {
    const data = await apiCall('/auth/profile', {
        method: 'PUT',
        body:   JSON.stringify({ name, department }),
    });
    const user = getUser();
    if (user) {
        user.name   = name || user.name;
        user.avatar = name ? name[0].toUpperCase() : user.avatar;
        setUser(user);
    }
    return data;
}

// ── Logs ──────────────────────────────────────────────────────
async function uploadLogs(file) {
    const token = getToken();
    const form  = new FormData();
    form.append('file', file);
    const res  = await fetch(`${BASE_URL}/logs/upload`, {
        method:  'POST',
        headers: { Authorization: `Bearer ${token}` },
        body:    form,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Upload failed');
    return data;
}

async function getUploadHistory() {
    return apiCall('/logs/history');
}

// ── Threats ───────────────────────────────────────────────────
// ✅ FIXED: added uploadId parameter — scopes threats to a specific upload
async function getThreats(severity = '', attackType = '', limit = 50, uploadId = '') {
    let q = `?limit=${limit}`;
    if (severity)   q += `&severity=${severity}`;
    if (attackType) q += `&attack_type=${attackType}`;
    if (uploadId)   q += `&upload_id=${uploadId}`;   // ✅ KEY FIX
    return apiCall(`/threats/${q}`);
}

async function getThreatsSummary() {
    return apiCall('/threats/summary');
}

async function getThreat(id) {
    return apiCall(`/threats/${id}`);
}

async function resolveThreat(id) {
    return apiCall(`/threats/${id}/resolve`, { method: 'POST' });
}

// ── Reports ───────────────────────────────────────────────────
async function getReports() {
    return apiCall('/reports/');
}

async function generateReport(threatIds, title = '', uploadId = '') {
    return apiCall('/reports/generate', {
        method: 'POST',
        body:   JSON.stringify({ threat_ids: threatIds, title, upload_id: uploadId || null }),
    });
}

async function getReport(id) {
    return apiCall(`/reports/${id}`);
}

// ── Chat ──────────────────────────────────────────────────────
async function sendChat(message) {
    return apiCall('/chat/', {
        method: 'POST',
        body:   JSON.stringify({ message }),
    });
}

async function clearChatHistory() {
    return apiCall('/chat/history', { method: 'DELETE' });
}

// ── Health ────────────────────────────────────────────────────
async function getRiskScore() {
    const res = await fetch(`${BASE_URL}/risk-score`);
    return res.json();
}

async function getHealth() {
    const res = await fetch(`${BASE_URL}/health`);
    return res.json();
}

// ── Remediation (R10) ─────────────────────────────────────────
async function getPlaybooks(uploadId = '') {
    const url = uploadId ? `/remediation/playbooks?upload_id=${uploadId}` : '/remediation/playbooks';
    return apiCall(url);
}

async function runDeepAnalysis(uploadId = '') {
    return apiCall('/remediation/deep-analysis', {
        method: 'POST',
        body:   JSON.stringify({ upload_id: uploadId || null }),
    });
}