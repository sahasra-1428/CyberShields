```javascript
/**
 * CYBERSHIELD - Central API Client & Authentication Management
 */

// ============================================================
// BACKEND API URL
// Frontend: Vercel
// Backend: Render
// ============================================================
const API_BASE_URL = 'https://cybershields-backend.onrender.com';

const STORAGE_KEYS = {
  TOKEN: 'cybershield_auth_token',
  USER: 'cybershield_auth_user'
};

// ============================================================
// AUTHENTICATION MANAGEMENT
// ============================================================
const Auth = {
  getToken() {
    return localStorage.getItem(STORAGE_KEYS.TOKEN);
  },

  setToken(token) {
    localStorage.setItem(STORAGE_KEYS.TOKEN, token);
  },

  getUser() {
    try {
      const user = localStorage.getItem(STORAGE_KEYS.USER);
      return user ? JSON.parse(user) : null;
    } catch {
      return null;
    }
  },

  setUser(user) {
    localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
  },

  isAuthenticated() {
    return Boolean(this.getToken());
  },

  isAdmin() {
    const user = this.getUser();
    return Boolean(user && user.role === 'admin');
  },

  logout(redirectUrl = 'login.html') {
    localStorage.removeItem(STORAGE_KEYS.TOKEN);
    localStorage.removeItem(STORAGE_KEYS.USER);
    window.location.href = redirectUrl;
  },

  requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href =
        'login.html?redirect=' +
        encodeURIComponent(window.location.pathname);

      return false;
    }

    return true;
  },

  requireAdmin() {
    if (!this.isAuthenticated()) {
      window.location.href =
        'login.html?redirect=' +
        encodeURIComponent(window.location.pathname);

      return false;
    }

    if (!this.isAdmin()) {
      window.location.href = 'user-dashboard.html';
      return false;
    }

    return true;
  }
};

// ============================================================
// TOAST NOTIFICATION
// ============================================================
function showToast(message, type = 'info', duration = 4000) {
  let container = document.getElementById('toast-container');

  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type}`;

  const iconMap = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ'
  };

  toast.innerHTML = `
    <span class="toast-icon">${iconMap[type] || 'ℹ'}</span>
    <span class="toast-message">${escapeHtml(message)}</span>
    <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
  `;

  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.add('toast-show');
  });

  setTimeout(() => {
    toast.classList.remove('toast-show');

    setTimeout(() => {
      toast.remove();
    }, 300);
  }, duration);
}

// ============================================================
// HTML ESCAPE
// ============================================================
function escapeHtml(str) {
  if (typeof str !== 'string') return '';

  return str.replace(/[&<>"']/g, function (m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m];
  });
}

// ============================================================
// CORE API REQUEST FUNCTION
// ============================================================
async function apiFetch(endpoint, options = {}) {
  const url = endpoint.startsWith('http')
    ? endpoint
    : `${API_BASE_URL}${endpoint}`;

  const token = Auth.getToken();

  const headers = {
    'Accept': 'application/json',
    ...(options.headers || {})
  };

  if (
    options.body &&
    !(options.body instanceof FormData) &&
    typeof options.body === 'object'
  ) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const res = await fetch(url, {
      ...options,
      headers
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      // Handle expired session
      if (res.status === 401 && Auth.isAuthenticated()) {
        Auth.logout();

        throw new Error(
          'Your session has expired. Please log in again.'
        );
      }

      const errorMsg =
        data?.error?.message ||
        data?.message ||
        `Request failed with status ${res.status}`;

      const err = new Error(errorMsg);

      err.status = res.status;
      err.code = data?.error?.code;

      throw err;
    }

    return data;

  } catch (err) {

    if (
      err.name === 'TypeError' &&
      err.message.includes('fetch')
    ) {
      throw new Error(
        'CyberShield server is currently unavailable. Please try again.'
      );
    }

    throw err;
  }
}

// ============================================================
// SCANNERS API
// ============================================================
const ScannersAPI = {

  scanUrl: (url) =>
    apiFetch('/api/scan/url', {
      method: 'POST',
      body: { url }
    }),

  scanMessage: (message) =>
    apiFetch('/api/scan/message', {
      method: 'POST',
      body: { message }
    }),

  scanEmail: (email) =>
    apiFetch('/api/scan/email', {
      method: 'POST',
      body: { email }
    }),

  scanPhone: (phone) =>
    apiFetch('/api/scan/phone', {
      method: 'POST',
      body: { phone }
    }),

  scanQr: (content) =>
    apiFetch('/api/scan/qr', {
      method: 'POST',
      body: { content }
    })
};

// ============================================================
// SCAN HISTORY API
// ============================================================
const HistoryAPI = {

  getScans: (params = {}) => {
    const qs = new URLSearchParams(params).toString();

    return apiFetch(`/api/scans?${qs}`);
  },

  getScanById: (id) =>
    apiFetch(`/api/scans/${id}`),

  deleteScan: (id) =>
    apiFetch(`/api/scans/${id}`, {
      method: 'DELETE'
    }),

  getDashboardStats: () =>
    apiFetch('/api/scans/dashboard-stats')
};

// ============================================================
// REPORTS API
// ============================================================
const ReportsAPI = {

  submitReport: (data) =>
    apiFetch('/api/reports', {
      method: 'POST',
      body: data
    }),

  getReports: (params = {}) => {
    const qs = new URLSearchParams(params).toString();

    return apiFetch(`/api/reports?${qs}`);
  },

  getReportById: (id) =>
    apiFetch(`/api/reports/${id}`),

  getReportByDocket: (docketNo) =>
    apiFetch(
      `/api/reports/docket/${encodeURIComponent(docketNo)}`
    )
};

// ============================================================
// AWARENESS API
// ============================================================
const AwarenessAPI = {

  getModules: () =>
    apiFetch('/api/awareness'),

  getModuleById: (id) =>
    apiFetch(`/api/awareness/${id}`),

  completeModule: (id) =>
    apiFetch(`/api/awareness/${id}/complete`, {
      method: 'POST'
    }),

  getQuizQuestions: () =>
    apiFetch('/api/awareness/quiz/questions'),

  submitQuiz: (answers) =>
    apiFetch('/api/awareness/quiz/submit', {
      method: 'POST',
      body: { answers }
    })
};

// ============================================================
// ADMIN API
// ============================================================
const AdminAPI = {

  getDashboard: () =>
    apiFetch('/api/admin/dashboard'),

  getUsers: (params = {}) => {
    const qs = new URLSearchParams(params).toString();

    return apiFetch(`/api/admin/users?${qs}`);
  },

  updateUserStatus: (id, data) =>
    apiFetch(`/api/admin/users/${id}`, {
      method: 'PATCH',
      body: data
    }),

  getScans: (params = {}) => {
    const qs = new URLSearchParams(params).toString();

    return apiFetch(`/api/admin/scans?${qs}`);
  },

  getReports: (params = {}) => {
    const qs = new URLSearchParams(params).toString();

    return apiFetch(`/api/admin/reports?${qs}`);
  },

  updateReport: (id, data) =>
    apiFetch(`/api/admin/reports/${id}`, {
      method: 'PATCH',
      body: data
    })
};

// ============================================================
// GLOBAL ACCESS
// ============================================================
window.API_BASE_URL = API_BASE_URL;
window.Auth = Auth;
window.showToast = showToast;
window.apiFetch = apiFetch;
window.ScannersAPI = ScannersAPI;
window.HistoryAPI = HistoryAPI;
window.ReportsAPI = ReportsAPI;
window.AwarenessAPI = AwarenessAPI;
window.AdminAPI = AdminAPI;
```
