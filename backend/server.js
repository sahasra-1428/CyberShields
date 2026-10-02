**
 * CYBERSHIELD - Central API Client & Authentication Management
 */
// Production Render Backend API URL
let API_BASE_URL = 'https://cybershields-backend.onrender.com';
if (typeof window !== 'undefined') {
  if (window.CYBERSHIELD_API_URL) {
    API_BASE_URL = window.CYBERSHIELD_API_URL;
  } else if (window.location.search && window.location.search.includes('local=true')) {
    API_BASE_URL = 'http://localhost:5000';
  } else {
    API_BASE_URL = 'https://cybershields-backend.onrender.com';
  }
}
const STORAGE_KEYS = {
  TOKEN: 'cybershield_auth_token',
  USER: 'cybershield_auth_user'
};
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
