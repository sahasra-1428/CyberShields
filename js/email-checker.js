/**
 * CYBERSHIELD - Email Security Checker Frontend Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('email-scan-form');
  const input = document.getElementById('email-input');
  const loadingBox = document.getElementById('scanner-loading');
  const loadingStep = document.getElementById('loading-step-text');
  const resultCard = document.getElementById('scanner-result');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = input.value.trim();

      if (!email) {
        showToast('Please enter an email address to analyze.', 'error');
        return;
      }

      resultCard.style.display = 'none';
      loadingBox.style.display = 'block';

      const steps = [
        'Validating RFC 5322 email syntax and mailbox format...',
        'Extracting domain and checking MX record indicators...',
        'Scanning for disposable/temporary email services...',
        'Checking typosquatting and homoglyph brand impersonation...',
        'Synthesizing email address security score...'
      ];

      let stepIdx = 0;
      loadingStep.textContent = steps[0];
      const stepInterval = setInterval(() => {
        stepIdx = (stepIdx + 1) % steps.length;
        loadingStep.textContent = steps[stepIdx];
      }, 600);

      try {
        const res = await ScannersAPI.scanEmail(email);
        clearInterval(stepInterval);
        loadingBox.style.display = 'none';

        if (!res.success) {
          throw new Error(res.error?.message || 'Email analysis failed.');
        }

        renderScanResult(res.analysis, email);
        showToast('Email address analysis complete.', 'success');
      } catch (err) {
        clearInterval(stepInterval);
        loadingBox.style.display = 'none';
        showToast(err.message, 'error');
      }
    });
  }

  // Sample email test buttons
  document.querySelectorAll('.sample-email-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      input.value = btn.getAttribute('data-email');
      form.dispatchEvent(new Event('submit'));
    });
  });
});

function renderScanResult(analysis, originalInput) {
  const card = document.getElementById('scanner-result');
  if (!card) return;

  const colorMap = {
    'LOW RISK': '#10b981',
    'SUSPICIOUS': '#f59e0b',
    'HIGH RISK': '#f97316',
    'MALICIOUS': '#ef4444',
    'INVALID': '#64748b',
    'UNKNOWN / UNABLE TO VERIFY': '#818cf8'
  };
  const themeColor = colorMap[analysis.riskLevel] || '#818cf8';

  const riskClass = getRiskCssClass(analysis.riskLevel);
  const riskTagEl = document.getElementById('result-risk-tag');
  const scoreNumEl = document.getElementById('result-score-num');
  const scoreBarEl = document.getElementById('result-score-bar');

  if (riskTagEl) {
    riskTagEl.className = `risk-level-tag badge-risk ${riskClass}`;
    riskTagEl.textContent = analysis.riskLevel;
  }
  if (scoreNumEl) {
    scoreNumEl.textContent = analysis.riskScore;
    scoreNumEl.style.color = themeColor;
  }
  if (scoreBarEl) {
    scoreBarEl.style.width = analysis.riskScore + '%';
    scoreBarEl.style.backgroundColor = themeColor;
  }

  const explanationEl = document.getElementById('result-explanation');
  if (explanationEl) {
    explanationEl.textContent = analysis.explanation;
  }

  const indicatorsListEl = document.getElementById('result-indicators-list');
  if (indicatorsListEl) {
    indicatorsListEl.innerHTML = (analysis.indicators || []).map(ind => {
      const icon = ind.type === 'alert' ? '⚠' : (ind.type === 'warning' ? '⚠' : (ind.type === 'success' ? '✓' : 'ℹ'));
      return `
        <div class="indicator-item ${ind.type}">
          <span class="indicator-icon">${icon}</span>
          <span>${escapeHtml(ind.text)}</span>
        </div>
      `;
    }).join('');
  }

  const recListEl = document.getElementById('result-recommendations-list');
  if (recListEl) {
    recListEl.innerHTML = (analysis.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
  }

  // Configure Cyber Agent Escalation Button
  const escalateBtn = document.getElementById('btn-escalate-cyber-agent');
  if (escalateBtn) {
    const urgency = ['HIGH RISK', 'MALICIOUS'].includes(analysis.riskLevel) ? 'CRITICAL' : 'HIGH';
    const evidenceSummary = `Threat Score: ${analysis.riskScore}/100. Risk Level: ${analysis.riskLevel}. Analysis: ${analysis.explanation || ''}. Flags: ${(analysis.indicators || []).map(i => i.text).join('; ')}`;
    escalateBtn.href = `report.html?category=email&target=${encodeURIComponent(originalInput)}&urgency=${urgency}&evidence=${encodeURIComponent(evidenceSummary)}`;
  }

  card.style.display = 'block';
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
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
