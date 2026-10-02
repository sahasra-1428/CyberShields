```javascript
/**
 * CYBERSHIELD - API Client & Authentication
 */

const API_BASE_URL = 'https://cybershields-backend.onrender.com';

/* =========================
   API REQUEST FUNCTION
========================= */

async function apiFetch(endpoint, options = {}) {
    const url = endpoint.startsWith('http')
        ? endpoint
        : `${API_BASE_URL}${endpoint}`;

    const token = localStorage.getItem('cybershield_token');

    const config = {
        method: options.method || 'GET',
        headers: {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        }
    };

    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }

    if (options.body !== undefined) {
        config.body =
            typeof options.body === 'string'
                ? options.body
                : JSON.stringify(options.body);
    }

    try {
        const response = await fetch(url, config);

        const text = await response.text();

        let data;

        try {
            data = text ? JSON.parse(text) : {};
        } catch {
            data = {
                success: false,
                message: text || 'Invalid server response'
            };
        }

        if (!response.ok) {
            throw new Error(
                data?.message ||
                data?.error?.message ||
                `Request failed with status ${response.status}`
            );
        }

        return data;

    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/* =========================
   TOAST MESSAGE
========================= */

function showToast(message, type = 'info') {
    alert(message);
}

/* =========================
   AUTHENTICATION
========================= */

const Auth = {
    setToken(token) {
        localStorage.setItem('cybershield_token', token);
    },

    getToken() {
        return localStorage.getItem('cybershield_token');
    },

    removeToken() {
        localStorage.removeItem('cybershield_token');
    },

    setUser(user) {
        localStorage.setItem(
            'cybershield_user',
            JSON.stringify(user)
        );
    },

    getUser() {
        const user = localStorage.getItem('cybershield_user');

        if (!user) {
            return null;
        }

        try {
            return JSON.parse(user);
        } catch {
            return null;
        }
    },

    removeUser() {
        localStorage.removeItem('cybershield_user');
    },

    isAuthenticated() {
        return !!this.getToken();
    },

    logout() {
        this.removeToken();
        this.removeUser();
        window.location.href = 'login.html';
    }
};

/* =========================
   SCAN FUNCTIONS
========================= */

async function scanURL(url) {
    return await apiFetch('/api/scan/url', {
        method: 'POST',
        body: { url }
    });
}

async function scanMessage(message) {
    return await apiFetch('/api/scan/message', {
        method: 'POST',
        body: { message }
    });
}

async function scanEmail(email) {
    return await apiFetch('/api/scan/email', {
        method: 'POST',
        body: { email }
    });
}

async function scanPhone(phone) {
    return await apiFetch('/api/scan/phone', {
        method: 'POST',
        body: { phone }
    });
}

/* =========================
   SCANNERS API
========================= */

const ScannersAPI = {

    scanUrl(url) {
        return scanURL(url);
    },

    url(url) {
        return scanURL(url);
    },

    scanMessage(message) {
        return scanMessage(message);
    },

    scanEmail(email) {
        return scanEmail(email);
    },

    scanPhone(phone) {
        return scanPhone(phone);
    }
};

/* =========================
   HISTORY API
========================= */

const HistoryAPI = {
    getHistory() {
        return apiFetch('/api/scans/history');
    }
};

/* =========================
   REPORTS API
========================= */

const ReportsAPI = {
    submit(reportData) {
        return apiFetch('/api/reports', {
            method: 'POST',
            body: reportData
        });
    },

    getAll() {
        return apiFetch('/api/reports');
    }
};

/* =========================
   AWARENESS API
========================= */

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

/* =========================
   ADMIN API
========================= */

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

/* =========================
   GLOBAL EXPOSE
========================= */

window.API_BASE_URL = API_BASE_URL;

window.Auth = Auth;
window.showToast = showToast;
window.apiFetch = apiFetch;

window.scanURL = scanURL;
window.scanMessage = scanMessage;
window.scanEmail = scanEmail;
window.scanPhone = scanPhone;

window.ScannersAPI = ScannersAPI;
window.HistoryAPI = HistoryAPI;
window.ReportsAPI = ReportsAPI;
window.AwarenessAPI = AwarenessAPI;
window.AdminAPI = AdminAPI;
```
