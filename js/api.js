```javascript
const AwarenessAPI = {
  getModules: () => apiFetch('/api/awareness'),
  getModuleById: (id) => apiFetch(`/api/awareness/${id}`),
  completeModule: (id) => apiFetch(`/api/awareness/${id}/complete`, { method: 'POST' }),
  getQuizQuestions: () => apiFetch('/api/awareness/quiz/questions'),
  submitQuiz: (answers) => apiFetch('/api/awareness/quiz/submit', {
    method: 'POST',
    body: { answers }
  })
};

// Scanner API
ScannersAPI.scanUrl = (url) => apiFetch('/api/scan/url', {
  method: 'POST',
  body: { url }
});

// Admin API
const AdminAPI = {
  getDashboard: () => apiFetch('/api/admin/dashboard'),

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

// Global expose
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
