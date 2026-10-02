/**
 * CYBERSHIELD - User Dashboard Scripts (Live MySQL Analytics & Visualizations)
 */

document.addEventListener('DOMContentLoaded', async () => {
  if (!Auth.requireAuth()) return;

  const user = Auth.getUser();

  // Populate user header elements
  const userNameEl = document.getElementById('user-display-name');
  const userEmailEl = document.getElementById('user-display-email');
  const userAvatarEl = document.getElementById('user-avatar-initials');

  if (userNameEl && user) userNameEl.textContent = user.name || 'Citizen User';
  if (userEmailEl && user) userEmailEl.textContent = user.email || '';
  if (userAvatarEl && user) userAvatarEl.textContent = (user.name || 'U').charAt(0).toUpperCase();

  // Mobile sidebar toggle
  const toggleBtn = document.getElementById('mobile-sidebar-toggle');
  const sidebar = document.querySelector('.sidebar');
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }

  // Logout button
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      Auth.logout();
    });
  }

  await loadDashboardData();
});

async function loadDashboardData() {
  try {
    const res = await HistoryAPI.getDashboardStats();
    if (!res.success) throw new Error('Failed to retrieve analytics.');

    const stats = res.stats;

    // 1. Populate Metric Cards from MySQL
    const totalScansEl = document.getElementById('stat-total-scans');
    const lowRiskEl = document.getElementById('stat-low-risk');
    const suspiciousEl = document.getElementById('stat-suspicious');
    const highRiskEl = document.getElementById('stat-high-risk');
    const maliciousEl = document.getElementById('stat-malicious');

    if (totalScansEl) totalScansEl.textContent = stats.totalScans || 0;
    if (lowRiskEl) lowRiskEl.textContent = stats.lowRisk || 0;
    if (suspiciousEl) suspiciousEl.textContent = stats.suspicious || 0;
    if (highRiskEl) highRiskEl.textContent = stats.highRisk || 0;
    if (maliciousEl) maliciousEl.textContent = stats.malicious || 0;

    // 2. Render Charts using HTML Canvas
    renderActivityChart(stats.activity || []);
    renderRiskDonutChart(stats);
    renderScanTypesBar(stats.types || {});

    // 3. Render Recent Scans Table
    renderRecentScans(stats.recentScans || []);
  } catch (err) {
    console.error('Dashboard load error:', err);
    showToast('Unable to load latest security metrics: ' + err.message, 'error');
  }
}

/**
 * Activity Bar/Line Chart (Daily Scans)
 */
function renderActivityChart(activityData) {
  const canvas = document.getElementById('activityChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width = canvas.parentElement.clientWidth;
  const height = canvas.height = canvas.parentElement.clientHeight || 240;

  ctx.clearRect(0, 0, width, height);

  // If no data yet
  if (!activityData || activityData.length === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '14px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No scan activity recorded in the past 7 days.', width / 2, height / 2);
    return;
  }

  // Prepare points
  const padding = 40;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;

  const maxVal = Math.max(...activityData.map(d => d.count), 5);
  const stepX = chartWidth / Math.max(activityData.length - 1, 1);

  // Draw grid lines
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding + (chartHeight / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();

    const valLabel = Math.round(maxVal - (maxVal / 4) * i);
    ctx.fillStyle = '#64748b';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.fillText(valLabel, padding - 8, y + 3);
  }

  // Gradient fill for area
  const gradient = ctx.createLinearGradient(0, padding, 0, height - padding);
  gradient.addColorStop(0, 'rgba(14, 165, 233, 0.35)');
  gradient.addColorStop(1, 'rgba(14, 165, 233, 0.0)');

  // Line path
  ctx.beginPath();
  activityData.forEach((d, idx) => {
    const x = padding + idx * stepX;
    const y = padding + chartHeight - (d.count / maxVal) * chartHeight;
    if (idx === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });

  ctx.strokeStyle = '#0ea5e9';
  ctx.lineWidth = 2.5;
  ctx.stroke();

  // Close path for gradient fill
  ctx.lineTo(padding + (activityData.length - 1) * stepX, height - padding);
  ctx.lineTo(padding, height - padding);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  // Draw point dots and x-labels
  activityData.forEach((d, idx) => {
    const x = padding + idx * stepX;
    const y = padding + chartHeight - (d.count / maxVal) * chartHeight;

    ctx.fillStyle = '#06b6d4';
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fill();

    // Date label
    const dateStr = new Date(d.scanDate).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    ctx.fillStyle = '#94a3b8';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(dateStr, x, height - padding + 18);
  }
  );
}

/**
 * Risk Distribution Donut Chart
 */
function renderRiskDonutChart(stats) {
  const canvas = document.getElementById('riskDonutChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width = canvas.parentElement.clientWidth;
  const height = canvas.height = canvas.parentElement.clientHeight || 240;

  ctx.clearRect(0, 0, width, height);

  const total = stats.totalScans || 0;
  if (total === 0) {
    ctx.fillStyle = '#64748b';
    ctx.font = '14px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No scan records to display.', width / 2, height / 2);
    return;
  }

  const data = [
    { label: 'Low Risk', value: stats.lowRisk || 0, color: '#10b981' },
    { label: 'Suspicious', value: stats.suspicious || 0, color: '#f59e0b' },
    { label: 'High Risk', value: stats.highRisk || 0, color: '#f97316' },
    { label: 'Malicious', value: stats.malicious || 0, color: '#ef4444' },
    { label: 'Unknown', value: stats.unknownRisk || 0, color: '#818cf8' }
  ].filter(d => d.value > 0);

  const centerX = width / 2;
  const centerY = height / 2 - 10;
  const radius = Math.min(centerX, centerY) - 25;
  const innerRadius = radius * 0.65;

  let currentAngle = -Math.PI / 2;

  data.forEach(slice => {
    const sliceAngle = (slice.value / total) * Math.PI * 2;

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
    ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
    ctx.closePath();
    ctx.fillStyle = slice.color;
    ctx.fill();

    currentAngle += sliceAngle;
  });

  // Center text
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 20px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(total, centerX, centerY + 2);

  ctx.fillStyle = '#94a3b8';
  ctx.font = '11px Inter, sans-serif';
  ctx.fillText('Total Scans', centerX, centerY + 18);
}

/**
 * Scan Types Bar Indicators
 */
function renderScanTypesBar(types) {
  const container = document.getElementById('scan-types-progress');
  if (!container) return;

  const total = Object.values(types).reduce((a, b) => a + b, 0) || 1;
  const mapping = [
    { key: 'url', name: 'Web URLs', icon: '🌐', count: types.url || 0, color: '#0ea5e9' },
    { key: 'message', name: 'Messages / SMS', icon: '💬', count: types.message || 0, color: '#06b6d4' },
    { key: 'email', name: 'Email Addresses', icon: '✉️', count: types.email || 0, color: '#6366f1' },
    { key: 'phone', name: 'Phone Numbers', icon: '📞', count: types.phone || 0, color: '#f59e0b' },
    { key: 'qr', name: 'QR Codes', icon: '📷', count: types.qr || 0, color: '#10b981' }
  ];

  container.innerHTML = mapping.map(item => {
    const pct = Math.round((item.count / total) * 100);
    return `
      <div style="margin-bottom: 12px;">
        <div style="display:flex; justify-content:space-between; font-size: 0.82rem; margin-bottom: 4px;">
          <span>${item.icon} ${item.name}</span>
          <strong style="color: #fff;">${item.count} (${pct}%)</strong>
        </div>
        <div style="height: 6px; background: rgba(255,255,255,0.06); border-radius: 3px; overflow:hidden;">
          <div style="width: ${pct}%; height:100%; background: ${item.color}; border-radius: 3px;"></div>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Recent Scans Table Rendering
 */
function renderRecentScans(scans) {
  const tbody = document.getElementById('recent-scans-tbody');
  if (!tbody) return;

  if (!scans || scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">
          <div class="empty-icon">🛡️</div>
          <p>No scans performed yet. Submit a URL or message to analyze your first threat.</p>
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
      </tr>
    `;
  }).join('');
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
