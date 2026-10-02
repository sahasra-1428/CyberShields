/**
/**
 * CYBERSHIELD - Report to Cyber Agents & Incident Dispatch Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('report-form');
  const categorySelect = document.getElementById('report-category');
  const targetInput = document.getElementById('report-target');
  const unitSelect = document.getElementById('report-unit');
  const urgencySelect = document.getElementById('report-urgency');
  const upiInput = document.getElementById('report-upi');
  const suspectPhoneInput = document.getElementById('report-suspect-phone');
  const lossInput = document.getElementById('report-loss');
  const lossWarning = document.getElementById('loss-warning');
  const actionSelect = document.getElementById('report-action');
  const descInput = document.getElementById('report-description');
  const evidenceInput = document.getElementById('report-evidence');
  const submitBtn = document.getElementById('btn-submit-report');
  const recentReportsTbody = document.getElementById('user-reports-tbody');

  // Docket Modal Elements
  const docketModal = document.getElementById('docket-modal');
  const modalDocketId = document.getElementById('modal-docket-id');
  const modalAssignedAgent = document.getElementById('modal-assigned-agent');
  const modalAgentUnit = document.getElementById('modal-agent-unit');
  const modalTarget = document.getElementById('modal-target');
  const modalStatus = document.getElementById('modal-status');
  const modalAction = document.getElementById('modal-action');
  const modalCreated = document.getElementById('modal-created');
  const modalAdvisory = document.getElementById('modal-advisory');
  const btnCloseDocketModal = document.getElementById('btn-close-docket-modal');
  const btnCopyDocket = document.getElementById('btn-copy-docket');

  // Track Docket Elements
  const trackDocketInput = document.getElementById('track-docket-input');
  const btnTrackDocket = document.getElementById('btn-track-docket');

  // Monitor loss input for Golden Hour alert
  if (lossInput && lossWarning) {
    lossInput.addEventListener('input', () => {
      const val = parseFloat(lossInput.value) || 0;
      lossWarning.style.display = val > 0 ? 'block' : 'none';
    });
  }

  // Pre-fill from URL parameters (e.g. from Scanner "Report to Cyber Agents" redirect)
  const urlParams = new URLSearchParams(window.location.search);
  const paramCategory = urlParams.get('category');
  const paramTarget = urlParams.get('target');
  const paramEvidence = urlParams.get('evidence');
  const paramUrgency = urlParams.get('urgency');
  const paramAction = urlParams.get('action');

  if (categorySelect && paramCategory) categorySelect.value = paramCategory;
  if (targetInput && paramTarget) targetInput.value = paramTarget;
  if (evidenceInput && paramEvidence) evidenceInput.value = paramEvidence;
  if (urgencySelect && paramUrgency) urgencySelect.value = paramUrgency;
  if (actionSelect && paramAction) actionSelect.value = paramAction;

  // Track Docket Search
  if (btnTrackDocket && trackDocketInput) {
    btnTrackDocket.addEventListener('click', async () => {
      const query = trackDocketInput.value.trim().toUpperCase();
      if (!query) {
        showToast('Please enter a Cyber Agent Docket Number (e.g. CAD-2026-XXXXXX).', 'error');
        return;
      }

      btnTrackDocket.disabled = true;
      btnTrackDocket.innerHTML = 'Searching...';

      try {
        const res = await ReportsAPI.getReportByDocket(query);
        if (!res.success || !res.report) {
          throw new Error('Docket not found. Please check the reference code.');
        }

        openDocketModal({
          docketNo: res.report.docket_no,
          assignedAgent: res.report.assigned_agent || 'Officer On-Duty (Active Assignment)',
          agentUnit: res.report.agent_unit || 'National Cyber Crime Bureau',
          target: res.report.target,
          status: res.report.status,
          actionRequested: res.report.action_requested || 'Evidence Forensics & Domain Takedown',
          createdAt: res.report.created_at,
          advisory: `Current Triage Status: ${res.report.status}. Monitored under ${res.report.agent_unit || '1930 Cyber Cell'}.`
        });
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        btnTrackDocket.disabled = false;
        btnTrackDocket.innerHTML = 'Track Docket';
      }
    });
  }

  // Load user's previous reports if authenticated
  if (Auth.isAuthenticated()) {
    loadUserReports();
  } else if (recentReportsTbody) {
    recentReportsTbody.innerHTML = `
      <tr>
        <td colspan="7" class="empty-state">
          <p><a href="login.html" style="color:var(--cyan-accent); font-weight:700;">Log in</a> to track all your dispatched Cyber Agent dockets in real-time.</p>
        </td>
      </tr>
    `;
  }

  // Submit Incident Dispatch to Cyber Agents
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const category = categorySelect.value;
      const target = targetInput.value.trim();
      const description = descInput.value.trim();
      const evidence = evidenceInput?.value.trim() || '';
      const agent_unit = unitSelect?.value || '';
      const urgency = urgencySelect?.value || 'HIGH';
      const loss_amount = parseFloat(lossInput?.value) || 0;
      const suspect_upi = upiInput?.value.trim() || '';
      const suspect_phone = suspectPhoneInput?.value.trim() || '';
      const action_requested = actionSelect?.value || 'Domain / SIM Takedown & Evidence Forensics';

      if (!category || !target || !description) {
        showToast('Please fill out all required incident fields.', 'error');
        return;
      }

      const origText = submitBtn.innerHTML;
      submitBtn.disabled = true;
      submitBtn.innerHTML = '🚨 Dispatching to Cyber Agents...';

      try {
        const res = await ReportsAPI.submitReport({
          category,
          target,
          description,
          evidence,
          agent_unit,
          urgency,
          loss_amount,
          suspect_upi,
          suspect_phone,
          action_requested
        });

        if (!res.success) throw new Error(res.error?.message || 'Report submission failed.');

        showToast(`Incident dispatched! Assigned to ${res.report.assignedAgent}`, 'success');
        form.reset();
        if (lossWarning) lossWarning.style.display = 'none';

        // Open Docket Confirmation Modal
        openDocketModal({
          docketNo: res.report.docketNo,
          assignedAgent: res.report.assignedAgent,
          agentUnit: res.report.agentUnit,
          target: res.report.target,
          status: res.report.status,
          actionRequested: res.report.actionRequested,
          createdAt: res.report.createdAt,
          advisory: res.report.emergencyAdvisory?.advice || 'Dispatched to Cyber Defense operations.'
        });

        if (Auth.isAuthenticated()) {
          loadUserReports();
        }
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = origText;
      }
    });
  }

  // Open Docket Modal Helper
  function openDocketModal(data) {
    if (!docketModal) return;

    modalDocketId.textContent = data.docketNo || 'CAD-2026-N/A';
    modalAssignedAgent.textContent = data.assignedAgent || 'Cyber Defense Officer Assigned';
    modalAgentUnit.textContent = data.agentUnit || 'National Cybercrime Operations';
    modalTarget.textContent = data.target || '-';
    modalAction.textContent = data.actionRequested || '-';
    modalCreated.textContent = new Date(data.createdAt || Date.now()).toLocaleString();
    modalAdvisory.textContent = data.advisory || 'Evidence secured and logged in cyber crime telemetry.';

    const statusClassMap = {
      'Submitted': 'unknown',
      'Under Review': 'suspicious',
      'Verified': 'malicious',
      'Resolved': 'low-risk',
      'Rejected': 'invalid'
    };
    const badgeClass = statusClassMap[data.status] || 'unknown';
    modalStatus.innerHTML = `<span class="badge-risk ${badgeClass}">${escapeHtml(data.status || 'Submitted')}</span>`;

    docketModal.classList.add('active');
  }

  // Close Docket Modal
  if (btnCloseDocketModal) {
    btnCloseDocketModal.addEventListener('click', () => {
      docketModal.classList.remove('active');
    });
  }

  // Copy Docket ID
  if (btnCopyDocket) {
    btnCopyDocket.addEventListener('click', () => {
      const code = modalDocketId.textContent;
      navigator.clipboard.writeText(code).then(() => {
        showToast(`Copied Docket ID: ${code}`, 'success');
      }).catch(() => {
        showToast(code, 'info');
      });
    });
  }

  // Print Official Incident Dossier
  const btnPrintDocket = document.getElementById('btn-print-docket');
  if (btnPrintDocket) {
    btnPrintDocket.addEventListener('click', () => {
      const docketId = modalDocketId.textContent;
      const agent = modalAssignedAgent.textContent;
      const unit = modalAgentUnit.textContent;
      const target = modalTarget.textContent;
      const action = modalAction.textContent;
      const created = modalCreated.textContent;
      const advisory = modalAdvisory.textContent;

      const printWin = window.open('', '_blank');
      printWin.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Official Cyber Crime Incident Dossier - ${docketId}</title>
          <style>
            body { font-family: 'Arial', sans-serif; line-height: 1.5; color: #111; margin: 30px; font-size: 11pt; }
            .header-table { width: 100%; border-bottom: 3px double #000; padding-bottom: 12px; margin-bottom: 20px; }
            .docket-badge { font-family: monospace; font-size: 14pt; font-weight: bold; background: #eee; padding: 4px 8px; border: 1px solid #999; }
            table.meta-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            table.meta-table td { padding: 8px 12px; border: 1px solid #ccc; }
            table.meta-table td.label { font-weight: bold; background: #f8f9fa; width: 30%; }
            .section-title { font-size: 12pt; font-weight: bold; text-transform: uppercase; border-bottom: 1px solid #000; padding-bottom: 4px; margin-top: 24px; margin-bottom: 12px; }
            .legal-box { background: #fdf2e9; border: 1px solid #f39c12; padding: 12px; font-size: 10pt; line-height: 1.5; margin-bottom: 20px; }
            .footer-sign { margin-top: 50px; display: flex; justify-content: space-between; }
            @media print { body { margin: 15mm; } }
          </style>
        </head>
        <body>
          <table class="header-table">
            <tr>
              <td>
                <div style="font-size: 16pt; font-weight: bold; letter-spacing: 0.05em;">CYBERSHIELD DEFENSE NETWORK</div>
                <div style="font-size: 10pt; color: #555;">National Threat Intelligence & Incident Response Telemetry</div>
              </td>
              <td style="text-align: right;">
                <span class="docket-badge">${docketId}</span>
                <div style="font-size: 9pt; color: #666; margin-top: 4px;">DATE: ${created}</div>
              </td>
            </tr>
          </table>

          <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 15pt;">OFFICIAL CYBER INCIDENT INVESTIGATION DOSSIER</h2>
            <div style="font-size: 10pt; color: #444;">DISPATCHED UNDER NATIONAL FINANCIAL FRAUD & CYBER CRIME PROTOCOLS</div>
          </div>

          <div class="legal-box">
            <strong>STATUTORY JURISDICTION & CITATION:</strong><br>
            This incident has been logged with digital forensic telemetry under <strong>Section 66C (Identity Theft)</strong> and <strong>Section 66D (Cheating by Personation using Computer Resource)</strong> of the Information Technology Act, 2000, and <strong>RBI Circular DBR.No.Leg.BC.78/09.07.005/2017-18</strong> on unauthorized electronic banking transactions.
          </div>

          <div class="section-title">1. INCIDENT &amp; CYBER AGENT ASSIGNMENT PARTICULARS</div>
          <table class="meta-table">
            <tr>
              <td class="label">Docket Reference</td>
              <td><strong>${docketId}</strong></td>
            </tr>
            <tr>
              <td class="label">On-Duty Cyber Agent</td>
              <td><strong>${agent}</strong></td>
            </tr>
            <tr>
              <td class="label">Assigned Agency Unit</td>
              <td>${unit}</td>
            </tr>
            <tr>
              <td class="label">Target Entity / Suspect IOC</td>
              <td><code style="font-size:11pt; font-weight:bold;">${target}</code></td>
            </tr>
            <tr>
              <td class="label">Requested Action</td>
              <td>${action}</td>
            </tr>
            <tr>
              <td class="label">Dispatched Timestamp</td>
              <td>${created}</td>
            </tr>
          </table>

          <div class="section-title">2. EMERGENCY DIRECTIVES &amp; MANDATORY REQUISITIONS</div>
          <div style="font-size: 10.5pt; line-height: 1.6;">
            <strong>A. FOR RECIPIENT / BENEFICIARY BANK MANAGERS:</strong><br>
            Under NPCI and CFCFRMS Golden Hour protocols, you are formally requested to place an immediate debit freeze / lien on the account or UPI VPA associated with <code>${target}</code> to prevent subsequent fund dissipation.<br><br>
            <strong>B. FOR DOMAIN REGISTRARS &amp; TELECOM OPERATORS:</strong><br>
            Initiate immediate WHOIS suspension, DNS sinkholing, and SIM blacklisting under DoT Sanchar Saathi guidelines.<br><br>
            <strong>C. ADVISORY TO CITIZEN:</strong><br>
            ${advisory}
          </div>

          <div class="footer-sign">
            <div>
              <div>____________________________________</div>
              <div style="font-size: 9pt; font-weight: bold; margin-top: 4px;">Complainant Signature</div>
            </div>
            <div style="text-align: right;">
              <div>____________________________________</div>
              <div style="font-size: 9pt; font-weight: bold; margin-top: 4px;">Cyber Crime Operations Cell</div>
              <div style="font-size: 8pt; color: #666;">National Cyber Helpline: 1930</div>
            </div>
          </div>

          <script>
            window.onload = function() { window.print(); };
          </script>
        </body>
        </html>
      `);
      printWin.document.close();
    });
  }

  // Load User Reports
  async function loadUserReports() {
    if (!recentReportsTbody) return;
    try {
      const res = await ReportsAPI.getReports({ limit: 15 });
      if (!res.success) return;

      const reports = res.reports || [];
      if (reports.length === 0) {
        recentReportsTbody.innerHTML = `
          <tr>
            <td colspan="7" class="empty-state">
              <div class="empty-icon">🛡️</div>
              <p>No incidents dispatched by your account yet.</p>
            </td>
          </tr>
        `;
        return;
      }

      const urgencyClassMap = {
        'CRITICAL': 'urgency-critical',
        'HIGH': 'urgency-high',
        'MEDIUM': 'urgency-medium',
        'LOW': 'urgency-low'
      };

      const statusClassMap = {
        'Submitted': 'unknown',
        'Under Review': 'suspicious',
        'Verified': 'malicious',
        'Resolved': 'low-risk',
        'Rejected': 'invalid'
      };

      recentReportsTbody.innerHTML = reports.map(r => {
        const dateFormatted = new Date(r.created_at).toLocaleDateString(undefined, {
          month: 'short',
          day: 'numeric',
          year: 'numeric'
        });

        const docketCode = r.docket_no || `CAD-2026-${String(r.id).padStart(6, '0')}`;
        const urgencyClass = urgencyClassMap[r.urgency] || 'urgency-high';
        const statusBadge = statusClassMap[r.status] || 'unknown';
        const assignedAgentDisplay = r.assigned_agent ? r.assigned_agent.split(',')[0] : 'Officer Assigned';

        return `
          <tr>
            <td><strong style="color:var(--cyan); font-family:var(--font-mono);">${escapeHtml(docketCode)}</strong></td>
            <td>
              <div style="font-weight:600; color:#fff; font-size:0.85rem;">${escapeHtml(assignedAgentDisplay)}</div>
              <div style="font-size:0.72rem; color:var(--text-muted);">${escapeHtml(r.agent_unit || 'National Cyber Cell')}</div>
            </td>
            <td class="truncate-cell" title="${escapeHtml(r.target)}" style="max-width:160px;">${escapeHtml(r.target)}</td>
            <td><span class="urgency-badge ${urgencyClass}">${escapeHtml(r.urgency || 'HIGH')}</span></td>
            <td><span class="badge-risk ${statusBadge}">${escapeHtml(r.status)}</span></td>
            <td style="font-size:0.82rem; color:var(--text-muted);">${dateFormatted}</td>
            <td>
              <button class="btn btn-secondary btn-sm view-docket-btn" 
                data-docket="${escapeHtml(docketCode)}"
                data-agent="${escapeHtml(r.assigned_agent || 'Cyber Agent')}"
                data-unit="${escapeHtml(r.agent_unit || 'National Cyber Cell')}"
                data-target="${escapeHtml(r.target)}"
                data-status="${escapeHtml(r.status)}"
                data-action="${escapeHtml(r.action_requested || 'Forensic Takedown')}"
                data-created="${escapeHtml(r.created_at)}"
                data-notes="${escapeHtml(r.admin_notes || 'Case under continuous cyber intelligence monitoring.')}"
                style="padding:3px 8px; font-size:0.75rem;">
                View
              </button>
            </td>
          </tr>
        `;
      }).join('');

      // Wire View Docket buttons in table
      document.querySelectorAll('.view-docket-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          openDocketModal({
            docketNo: btn.dataset.docket,
            assignedAgent: btn.dataset.agent,
            agentUnit: btn.dataset.unit,
            target: btn.dataset.target,
            status: btn.dataset.status,
            actionRequested: btn.dataset.action,
            createdAt: btn.dataset.created,
            advisory: btn.dataset.notes
          });
        });
      });

    } catch (err) {
      console.error('Failed to load user reports:', err);
    }
  }
});
