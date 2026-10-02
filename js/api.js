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
   SCAN API
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
   SCAN HISTORY
========================= */

async function getScanHistory() {
    return await apiFetch('/api/scans/history');
}


/* =========================
   REPORTS
========================= */

async function submitReport(reportData) {
    return await apiFetch('/api/reports', {
        method: 'POST',
        body: reportData
    });
}

async function getReports() {
    return await apiFetch('/api/reports');
}


/* =========================
   AWARENESS
========================= */

async function getAwarenessContent() {
    return await apiFetch('/api/awareness');
}


/* =========================
   ADMIN
========================= */

async function getAdminUsers() {
    return await apiFetch('/api/admin/users');
}

async function getAdminReports() {
    return await apiFetch('/api/admin/reports');
}

async function getAdminScans() {
    return await apiFetch('/api/admin/scans');
}


/* =========================
   GLOBAL ACCESS
========================= */

window.API_BASE_URL = API_BASE_URL;
window.apiFetch = apiFetch;
window.Auth = Auth;

window.scanURL = scanURL;
window.scanMessage = scanMessage;
window.scanEmail = scanEmail;
window.scanPhone = scanPhone;

window.getScanHistory = getScanHistory;

window.submitReport = submitReport;
window.getReports = getReports;

window.getAwarenessContent = getAwarenessContent;

window.getAdminUsers = getAdminUsers;
window.getAdminReports = getAdminReports;
window.getAdminScans = getAdminScans;
/* =========================
   TOAST MESSAGE
========================= */

function showToast(message, type = 'info') {
    alert(message);
}

window.showToast = showToast;

/* =========================
   SCANNERS API
========================= */

const ScannersAPI = {
    url: async function (url) {
        return await scanURL(url);
    },

    message: async function (message) {
        return await scanMessage(message);
    },

    email: async function (email) {
        return await scanEmail(email);
    },

    phone: async function (phone) {
        return await scanPhone(phone);
    }
};

window.ScannersAPI = ScannersAPI;
