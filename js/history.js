/**
 * CYBERSHIELD - Scan History Manager
 */

document.addEventListener('DOMContentLoaded', () => {
  if (!Auth.requireAuth()) return;

  let currentPage = 1;
  const limit = 15;

  const typeFilter = document.getElementById('filter-type');
  const riskFilter = document.getElementById('filter-risk');
  const searchInput = document.getElementById('filter-search');
  const tbody = document.getElementById('history-tbody');
  const modal = document.getElementById('scan-detail-modal');

  // Load initial scans
  loadScans();

  // Filter change handlers
  if (typeFilter) typeFilter.addEventListener('change', () => { currentPage = 1; loadScans(); });
  if (riskFilter) riskFilter.addEventListener('change', () => { currentPage = 1; loadScans(); });
  if (searchInput) {
    let debounce;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => { currentPage = 1; loadScans(); }, 350);
    });
  }

  // Modal close
  document.querySelectorAll('.modal-close-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (modal) modal.classList.remove('active');
    });
  });

  async function loadScans() {
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Loading scans from CyberShield database...</td></tr>`;

    try {
      const res = await HistoryAPI.getScans({
        type: typeFilter?.value || 'all',
        risk: riskFilter?.value || 'all',
        search: searchInput?.value || '',
        page: currentPage,
        limit
      });

      if (!res.success) throw new Error(res.error?.message || 'Could not load history.');

      renderScans(res.scans || []);
      renderPagination(res.pagination);
    } catch (err) {
      showToast(err.message, 'error');
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:#ef4444;">${err.message}</td></tr>`;
    }
  }

  function renderScans(scans) {
    if (!scans || scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-state">
            <div class="empty-icon">📂</div>
            <p>No scans match your current filter criteria.</p>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const riskClass = getRiskCssClass(s.risk_level);
      const dateFormatted = new Date(s.created_at).toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });

      return `
        <tr>
          <td>${dateFormatted}</td>
          <td><span style="text-transform:uppercase; font-size:0.75rem; font-weight:700; color:var(--cyan-accent);">${s.scan_type}</span></td>
          <td class="truncate-cell" title="${escapeHtml(s.input_value)}">${escapeHtml(s.input_value)}</td>
          <td><span class="badge-risk ${riskClass}">${s.risk_level}</span></td>
          <td><strong style="color: #fff;">${s.risk_score}</strong>/100</td>
          <td>${s.verified ? '<span style="color:#10b981;">✓ Verified</span>' : '<span style="color:#94a3b8;">○ Unverified</span>'}</td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-secondary btn-sm" onclick="viewScanDetails(${s.id})">View</button>
              <button class="btn btn-outline btn-sm" style="color:#ef4444; border-color:rgba(239,68,68,0.3);" onclick="deleteScanRecord(${s.id})">Delete</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderPagination(pagination) {
    const container = document.getElementById('pagination-container');
    if (!container || !pagination) return;

    const { page, totalPages, total } = pagination;
    container.innerHTML = `
      <div>Showing page <strong>${page}</strong> of <strong>${totalPages || 1}</strong> (${total} total scans)</div>
      <div class="pagination-buttons">
        <button class="btn btn-secondary btn-sm" ${page <= 1 ? 'disabled' : ''} id="btn-prev-page">Previous</button>
        <button class="btn btn-secondary btn-sm" ${page >= totalPages ? 'disabled' : ''} id="btn-next-page">Next</button>
      </div>
    `;

    document.getElementById('btn-prev-page')?.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        loadScans();
      }
    });

    document.getElementById('btn-next-page')?.addEventListener('click', () => {
      if (currentPage < totalPages) {
        currentPage++;
        loadScans();
      }
    });
  }

  // Expose global methods for row actions
  window.viewScanDetails = async (id) => {
    try {
      const res = await HistoryAPI.getScanById(id);
      if (!res.success) throw new Error(res.error?.message);

      const s = res.scan;
      const modalBody = document.getElementById('scan-modal-body');
      const modalTitle = document.getElementById('scan-modal-title');
      const riskClass = getRiskCssClass(s.risk_level);

      if (modalTitle) modalTitle.textContent = `Security Scan Record #${s.id} (${s.scan_type.toUpperCase()})`;

      if (modalBody) {
        modalBody.innerHTML = `
          <div style="margin-bottom: 16px; display:flex; justify-content:space-between; align-items:center;">
            <span class="badge-risk ${riskClass}">${s.risk_level}</span>
            <span style="font-size: 1.2rem; font-weight:800; color:#fff;">Risk Score: ${s.risk_score}/100</span>
          </div>
          <div style="margin-bottom: 16px;">
            <div style="font-size:0.78rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Scanned Target</div>
            <div style="font-family:var(--font-mono); font-size:0.9rem; word-break:break-all; background:rgba(0,0,0,0.3); padding:10px; border-radius:6px; margin-top:4px;">${escapeHtml(s.input_value)}</div>
          </div>
          <div style="margin-bottom: 16px;">
            <div style="font-size:0.78rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Indicators Detected</div>
            <div class="indicators-list" style="margin-top:6px;">
              ${(s.indicators || []).map(ind => `
                <div class="indicator-item ${ind.type || 'info'}">
                  <span class="indicator-icon">${ind.type === 'alert' ? '⚠' : 'ℹ'}</span>
                  <span>${escapeHtml(ind.text)}</span>
                </div>
              `).join('')}
            </div>
          </div>
          <div>
            <div style="font-size:0.78rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Safety Recommendations</div>
            <ul style="padding-left:18px; margin-top:6px; font-size:0.9rem; color:#e2e8f0;">
              ${(s.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
            </ul>
          </div>
        `;
      }

      if (modal) modal.classList.add('active');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window.deleteScanRecord = async (id) => {
    if (!confirm('Are you sure you want to delete this scan record from your history?')) return;
    try {
      const res = await HistoryAPI.deleteScan(id);
      if (res.success) {
        showToast('Scan record deleted.', 'success');
        loadScans();
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
});

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
