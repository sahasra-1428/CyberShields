/**
 * CYBERSHIELD - Admin Portal Controller (Dashboard, Users, Scans, Reports)
 */

document.addEventListener('DOMContentLoaded', () => {
  if (!Auth.requireAdmin()) return;

  const currentPath = window.location.pathname;

  // Initialize view specific logic
  if (currentPath.includes('admin-dashboard.html') || currentPath.endsWith('admin-dashboard.html')) {
    initAdminDashboard();
  } else if (currentPath.includes('admin-users.html')) {
    initAdminUsers();
  } else if (currentPath.includes('admin-scans.html')) {
    initAdminScans();
  } else if (currentPath.includes('admin-reports.html')) {
    initAdminReports();
  }

  // Admin mobile toggle
  const toggleBtn = document.getElementById('mobile-sidebar-toggle');
  const sidebar = document.querySelector('.sidebar');
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => sidebar.classList.toggle('open'));
  }

  // Logout button
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      Auth.logout();
    });
  }
});

/**
 * Admin Dashboard View
 */
async function initAdminDashboard() {
  try {
    const res = await AdminAPI.getDashboard();
    if (!res.success) throw new Error(res.error?.message || 'Failed to fetch admin stats.');

    const stats = res.stats;

    // Populate Real Database Numbers
    const elUsers = document.getElementById('admin-stat-users');
    const elScans = document.getElementById('admin-stat-scans');
    const elScansToday = document.getElementById('admin-stat-scans-today');
    const elSuspicious = document.getElementById('admin-stat-suspicious');
    const elHigh = document.getElementById('admin-stat-high');
    const elMalicious = document.getElementById('admin-stat-malicious');
    const elReports = document.getElementById('admin-stat-reports');

    if (elUsers) elUsers.textContent = stats.totalUsers || 0;
    if (elScans) elScans.textContent = stats.totalScans || 0;
    if (elScansToday) elScansToday.textContent = stats.scansToday || 0;
    if (elSuspicious) elSuspicious.textContent = stats.suspicious || 0;
    if (elHigh) elHigh.textContent = stats.highRisk || 0;
    if (elMalicious) elMalicious.textContent = stats.malicious || 0;
    if (elReports) elReports.textContent = stats.totalReports || 0;

    // Render Recent Scans Across All Users
    const tbody = document.getElementById('admin-recent-scans-tbody');
    if (tbody) {
      const scans = stats.recentScans || [];
      if (scans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><p>No scans in system yet.</p></td></tr>`;
      } else {
        tbody.innerHTML = scans.map(s => {
          const riskClass = getRiskCssClass(s.risk_level);
          const dateStr = new Date(s.created_at).toLocaleString();
          return `
            <tr>
              <td>${dateStr}</td>
              <td>${s.user_name ? escapeHtml(s.user_name) : '<em style="color:#64748b;">Guest Scan</em>'}</td>
              <td><span style="color:var(--cyan-accent); font-weight:700; font-size:0.75rem; text-transform:uppercase;">${s.scan_type}</span></td>
              <td class="truncate-cell" title="${escapeHtml(s.input_value)}">${escapeHtml(s.input_value)}</td>
              <td><span class="badge-risk ${riskClass}">${s.risk_level}</span></td>
              <td><strong>${s.risk_score}</strong>/100</td>
            </tr>
          `;
        }).join('');
      }
    }

    // Render Recent Audit Logs
    const auditContainer = document.getElementById('admin-audit-log-list');
    if (auditContainer) {
      const logs = stats.auditLogs || [];
      if (logs.length === 0) {
        auditContainer.innerHTML = `<div style="color:var(--text-muted); padding:16px;">No audit logs recorded yet.</div>`;
      } else {
        auditContainer.innerHTML = logs.map(l => {
          const time = new Date(l.created_at).toLocaleTimeString();
          return `
            <div style="padding:10px 14px; border-bottom:1px solid rgba(255,255,255,0.04); font-size:0.85rem; display:flex; justify-content:space-between;">
              <div>
                <strong style="color:var(--cyan-accent);">${escapeHtml(l.action)}</strong>: ${escapeHtml(l.details || '')}
              </div>
              <span style="color:var(--text-muted); font-size:0.78rem;">${time}</span>
            </div>
          `;
        }).join('');
      }
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

/**
 * Admin Users Management View
 */
async function initAdminUsers() {
  let currentPage = 1;
  const tbody = document.getElementById('admin-users-tbody');
  const searchInput = document.getElementById('admin-user-search');
  const roleFilter = document.getElementById('admin-user-role-filter');
  const statusFilter = document.getElementById('admin-user-status-filter');

  await loadUsers();

  if (roleFilter) roleFilter.addEventListener('change', () => { currentPage = 1; loadUsers(); });
  if (statusFilter) statusFilter.addEventListener('change', () => { currentPage = 1; loadUsers(); });
  if (searchInput) {
    let debounce;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => { currentPage = 1; loadUsers(); }, 350);
    });
  }

  async function loadUsers() {
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">Fetching citizen directory from MySQL...</td></tr>`;

    try {
      const res = await AdminAPI.getUsers({
        search: searchInput?.value || '',
        role: roleFilter?.value || 'all',
        status: statusFilter?.value || 'all',
        page: currentPage,
        limit: 20
      });

      if (!res.success) throw new Error(res.error?.message);

      const users = res.users || [];
      if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><p>No users found matching query.</p></td></tr>`;
        return;
      }

      tbody.innerHTML = users.map(u => {
        const regDate = new Date(u.created_at).toLocaleDateString();
        const lastLogin = u.last_login ? new Date(u.last_login).toLocaleString() : 'Never';
        const statusBadge = u.status === 'active'
          ? `<span class="admin-badge-active">Active</span>`
          : `<span class="admin-badge-inactive">${u.status}</span>`;
        const roleBadge = u.role === 'admin'
          ? `<span class="admin-badge-admin">Admin</span>`
          : `<span style="color:#94a3b8; font-size:0.8rem;">User</span>`;

        return `
          <tr>
            <td>#${u.id}</td>
            <td><strong>${escapeHtml(u.name)}</strong></td>
            <td>${escapeHtml(u.email)}</td>
            <td>${roleBadge}</td>
            <td>${statusBadge}</td>
            <td>${regDate}</td>
            <td style="font-size:0.8rem; color:#94a3b8;">${lastLogin}</td>
            <td><strong style="color:var(--cyan-accent);">${u.scan_count || 0}</strong></td>
            <td>
              <div style="display:flex; gap:6px;">
                ${u.status === 'active'
                  ? `<button class="btn btn-outline btn-sm" style="color:#ef4444; border-color:rgba(239,68,68,0.3);" onclick="changeUserStatus(${u.id}, 'inactive')">Deactivate</button>`
                  : `<button class="btn btn-outline btn-sm" style="color:#10b981; border-color:rgba(16,185,129,0.3);" onclick="changeUserStatus(${u.id}, 'active')">Activate</button>`
                }
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  window.changeUserStatus = async (id, newStatus) => {
    if (!confirm(`Are you sure you want to set user #${id} status to ${newStatus}?`)) return;
    try {
      const res = await AdminAPI.updateUserStatus(id, { status: newStatus });
      if (res.success) {
        showToast(`User status updated to ${newStatus}.`, 'success');
        loadUsers();
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
}

/**
 * Admin Scans Management View
 */
async function initAdminScans() {
  let currentPage = 1;
  const tbody = document.getElementById('admin-scans-tbody');
  const typeFilter = document.getElementById('admin-scan-type-filter');
  const riskFilter = document.getElementById('admin-scan-risk-filter');
  const searchInput = document.getElementById('admin-scan-search');

  await loadScans();

  if (typeFilter) typeFilter.addEventListener('change', () => { currentPage = 1; loadScans(); });
  if (riskFilter) riskFilter.addEventListener('change', () => { currentPage = 1; loadScans(); });
  if (searchInput) {
    let debounce;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => { currentPage = 1; loadScans(); }, 350);
    });
  }

  async function loadScans() {
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Querying global scan registry...</td></tr>`;

    try {
      const res = await AdminAPI.getScans({
        type: typeFilter?.value || 'all',
        risk: riskFilter?.value || 'all',
        search: searchInput?.value || '',
        page: currentPage,
        limit: 25
      });

      if (!res.success) throw new Error(res.error?.message);

      const scans = res.scans || [];
      if (scans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><p>No scans match current query.</p></td></tr>`;
        return;
      }

      tbody.innerHTML = scans.map(s => {
        const riskClass = getRiskCssClass(s.risk_level);
        const dateStr = new Date(s.created_at).toLocaleString();
        return `
          <tr>
            <td>${dateStr}</td>
            <td>${s.user_email ? escapeHtml(s.user_email) : '<span style="color:#64748b;">Anonymous</span>'}</td>
            <td><span style="color:var(--cyan-accent); font-weight:700; font-size:0.75rem; text-transform:uppercase;">${s.scan_type}</span></td>
            <td class="truncate-cell" title="${escapeHtml(s.input_value)}">${escapeHtml(s.input_value)}</td>
            <td><span class="badge-risk ${riskClass}">${s.risk_level}</span></td>
            <td><strong>${s.risk_score}</strong>/100</td>
            <td style="font-size:0.8rem; color:#94a3b8;">${escapeHtml(s.source || 'local')}</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
}

/**
 * Admin Reports Review View
 */
async function initAdminReports() {
  let currentPage = 1;
  const tbody = document.getElementById('admin-reports-tbody');
  const statusFilter = document.getElementById('admin-report-status-filter');
  const categoryFilter = document.getElementById('admin-report-category-filter');
  const searchInput = document.getElementById('admin-report-search');
  const modal = document.getElementById('report-detail-modal');

  await loadReports();

  if (statusFilter) statusFilter.addEventListener('change', () => { currentPage = 1; loadReports(); });
  if (categoryFilter) categoryFilter.addEventListener('change', () => { currentPage = 1; loadReports(); });
  if (searchInput) {
    let debounce;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => { currentPage = 1; loadReports(); }, 350);
    });
  }

  document.querySelectorAll('.modal-close-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (modal) modal.classList.remove('active');
    });
  });

  async function loadReports() {
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Fetching citizen scam incidents...</td></tr>`;

    try {
      const res = await AdminAPI.getReports({
        status: statusFilter?.value || 'all',
        category: categoryFilter?.value || 'all',
        search: searchInput?.value || '',
        page: currentPage,
        limit: 25
      });

      if (!res.success) throw new Error(res.error?.message);

      const reports = res.reports || [];
      if (reports.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state"><p>No incident reports found.</p></td></tr>`;
        return;
      }

      tbody.innerHTML = reports.map(r => {
        const docketCode = r.docket_no || `CAD-2026-${String(r.id).padStart(6, '0')}`;
        const urgencyClassMap = {
          'CRITICAL': 'urgency-critical',
          'HIGH': 'urgency-high',
          'MEDIUM': 'urgency-medium',
          'LOW': 'urgency-low'
        };
        const statusMap = {
          'Submitted': 'unknown',
          'Under Review': 'suspicious',
          'Verified': 'malicious',
          'Resolved': 'low-risk',
          'Rejected': 'invalid'
        };
        const badgeClass = statusMap[r.status] || 'unknown';
        const urgencyBadge = `<span style="font-size:0.72rem; font-weight:700; padding:2px 6px; border-radius:3px; background:rgba(239,68,68,0.15); color:#f87171;">${escapeHtml(r.urgency || 'HIGH')}</span>`;
        const agentName = r.assigned_agent ? r.assigned_agent.split('(')[0] : 'Unassigned';

        return `
          <tr>
            <td><strong style="color:var(--cyan); font-family:var(--font-mono);">${escapeHtml(docketCode)}</strong></td>
            <td>${r.reporter_email ? escapeHtml(r.reporter_email) : 'Citizen'}</td>
            <td><span style="color:var(--cyan-accent); font-weight:700; font-size:0.75rem; text-transform:uppercase;">${r.category}</span></td>
            <td class="truncate-cell" title="${escapeHtml(r.target)}" style="max-width:140px;">${escapeHtml(r.target)}</td>
            <td>${urgencyBadge}</td>
            <td style="font-size:0.82rem; color:#cbd5e1;">${escapeHtml(agentName)}</td>
            <td><span class="badge-risk ${badgeClass}">${r.status}</span></td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="reviewReport(${r.id})">Triage</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  window.reviewReport = async (id) => {
    try {
      const res = await ReportsAPI.getReportById(id);
      if (!res.success) throw new Error(res.error?.message);

      const r = res.report;
      const modalBody = document.getElementById('report-modal-body');
      const modalTitle = document.getElementById('report-modal-title');
      const docketCode = r.docket_no || `CAD-2026-${String(r.id).padStart(6, '0')}`;

      if (modalTitle) modalTitle.textContent = `Cyber Agent Incident Triage [${docketCode}]`;

      if (modalBody) {
        modalBody.innerHTML = `
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px; font-size:0.85rem;">
            <div>
              <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Target / Entity</span>
              <div style="font-family:var(--font-mono); font-size:0.95rem; color:#fff; word-break:break-all; margin-top:2px;">${escapeHtml(r.target)}</div>
            </div>
            <div>
              <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Cyber Agency Unit</span>
              <div style="font-size:0.85rem; color:#38bdf8; margin-top:2px;">${escapeHtml(r.agent_unit || 'National Cybercrime Operations')}</div>
            </div>
            <div>
              <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Requested Enforcement</span>
              <div style="font-size:0.85rem; color:#cbd5e1; margin-top:2px;">${escapeHtml(r.action_requested || 'Domain / SIM Takedown')}</div>
            </div>
            <div>
              <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Reported Loss</span>
              <div style="font-size:0.9rem; font-weight:700; color:${r.loss_amount > 0 ? '#ef4444' : '#10b981'}; margin-top:2px;">
                ${r.loss_amount > 0 ? `₹${parseFloat(r.loss_amount).toLocaleString()} (🚨 Golden Hour Alert)` : '₹0.00'}
              </div>
            </div>
            ${r.suspect_upi ? `
              <div>
                <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Suspect UPI</span>
                <div style="font-family:var(--font-mono); font-size:0.85rem; color:#facc15; margin-top:2px;">${escapeHtml(r.suspect_upi)}</div>
              </div>
            ` : ''}
            ${r.suspect_phone ? `
              <div>
                <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Suspect Phone</span>
                <div style="font-family:var(--font-mono); font-size:0.85rem; color:#facc15; margin-top:2px;">${escapeHtml(r.suspect_phone)}</div>
              </div>
            ` : ''}
          </div>

          <div style="margin-bottom:14px;">
            <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Citizen Incident Narrative</span>
            <div style="background:rgba(0,0,0,0.3); padding:10px 12px; border-radius:6px; font-size:0.88rem; color:#e2e8f0; margin-top:4px;">${escapeHtml(r.description)}</div>
          </div>

          ${r.evidence ? `
            <div style="margin-bottom:14px;">
              <span style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Technical Evidence Log</span>
              <div style="background:rgba(0,0,0,0.3); padding:10px 12px; border-radius:6px; font-size:0.82rem; font-family:var(--font-mono); color:#a5f3fc; margin-top:4px; max-height:120px; overflow-y:auto;">${escapeHtml(r.evidence)}</div>
            </div>
          ` : ''}

          <div style="margin-top:16px; border-top:1px solid rgba(255,255,255,0.08); padding-top:14px;">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
              <div>
                <label class="form-label">Triage Status</label>
                <select class="form-input" id="update-report-status" style="margin-bottom:0;">
                  <option value="Submitted" ${r.status === 'Submitted' ? 'selected' : ''}>Submitted (New)</option>
                  <option value="Under Review" ${r.status === 'Under Review' ? 'selected' : ''}>Under Review</option>
                  <option value="Verified" ${r.status === 'Verified' ? 'selected' : ''}>Verified (Confirmed Fraud)</option>
                  <option value="Resolved" ${r.status === 'Resolved' ? 'selected' : ''}>Resolved (Takedown Complete)</option>
                  <option value="Rejected" ${r.status === 'Rejected' ? 'selected' : ''}>Rejected (Inconclusive)</option>
                </select>
              </div>
              <div>
                <label class="form-label">Assigned Cyber Agent</label>
                <input type="text" class="form-input" id="update-report-agent" value="${escapeHtml(r.assigned_agent || '')}" placeholder="Officer Name and Badge" style="margin-bottom:0;">
              </div>
            </div>

            <label class="form-label">Cyber Agent Investigation &amp; Forensics Notes</label>
            <textarea class="form-input" id="update-report-notes" rows="3" placeholder="Enter registrar notice details, bank freezing ticket, or forensic findings...">${escapeHtml(r.admin_notes || '')}</textarea>
          </div>
          <div style="margin-top:16px; display:flex; justify-content:flex-end;">
            <button class="btn btn-primary" onclick="saveReportUpdate(${r.id})">Save Cyber Assessment</button>
          </div>
        `;
      }

      if (modal) modal.classList.add('active');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window.saveReportUpdate = async (id) => {
    const status = document.getElementById('update-report-status')?.value;
    const notes = document.getElementById('update-report-notes')?.value;
    const assignedAgent = document.getElementById('update-report-agent')?.value;

    try {
      const res = await AdminAPI.updateReport(id, { 
        status, 
        admin_notes: notes,
        assigned_agent: assignedAgent 
      });
      if (res.success) {
        showToast('Cyber Agent investigation docket updated in audit log.', 'success');
        if (modal) modal.classList.remove('active');
        loadReports();
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
}

function getRiskCssClass(riskLevel) {
  switch (riskLevel) {
    case 'LOW RISK': return 'low-risk';
    case 'SUSPICIOUS': return 'suspicious';
    case 'HIGH RISK': return 'high-risk';
    case 'MALICIOUS': return 'malicious';
    case 'INVALID': return 'invalid';
    default: return 'unknown';
  }
}
