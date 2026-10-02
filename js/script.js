/**
 * CYBERSHIELD - Public Landing Page Scripts
 */

document.addEventListener('DOMContentLoaded', () => {
  // Update Navbar based on authentication state
  const authNav = document.getElementById('navbar-auth-action');
  if (authNav && window.Auth) {
    if (Auth.isAuthenticated()) {
      const user = Auth.getUser();
      const targetPage = user?.role === 'admin' ? 'admin-dashboard.html' : 'user-dashboard.html';
      authNav.innerHTML = `
        <a href="${targetPage}" class="btn btn-primary btn-sm">
          <span>Dashboard</span>
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </a>
      `;
    } else {
      authNav.innerHTML = `
        <a href="login.html" class="btn btn-outline btn-sm">Login</a>
        <a href="signup.html" class="btn btn-primary btn-sm">Get Started</a>
      `;
    }
  }

  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
});
