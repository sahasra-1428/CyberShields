/**
 * CYBERSHIELD - Scam Message Detector Frontend Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('message-scan-form');
  const textarea = document.getElementById('message-input');
  const charCounter = document.getElementById('char-count');
  const loadingBox = document.getElementById('scanner-loading');
  const loadingStep = document.getElementById('loading-step-text');
  const resultCard = document.getElementById('scanner-result');

  if (textarea && charCounter) {
    textarea.addEventListener('input', () => {
      charCounter.textContent = `${textarea.value.length} characters`;
    });
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const message = textarea.value.trim();

      if (!message) {
        showToast('Please paste a message to analyze.', 'error');
        return;
      }

      resultCard.style.display = 'none';
      loadingBox.style.display = 'block';

      const steps = [
        'Parsing message text and detecting embedded links...',
        'Checking urgency, coercion, and fear-inducing language...',
        'Analyzing unsolicited prize, lottery, and investment claims...',
        'Scanning for credential harvesting, OTP requests, and bank impersonation...',
        'Evaluating authority affiliation claims (Government/Police/RBI)...',
        'Synthesizing risk assessment report...'
      ];

      let stepIdx = 0;
      loadingStep.textContent = steps[0];
      const stepInterval = setInterval(() => {
        stepIdx = (stepIdx + 1) % steps.length;
        loadingStep.textContent = steps[stepIdx];
      }, 650);

      try {
        const res = await ScannersAPI.scanMessage(message);
        clearInterval(stepInterval);
        loadingBox.style.display = 'none';

        if (!res.success) {
          throw new Error(res.error?.message || 'Message security analysis failed.');
        }

        renderScanResult(res.analysis, message);
        showToast('Scam message analysis complete.', 'success');
      } catch (err) {
        clearInterval(stepInterval);
        loadingBox.style.display = 'none';
        showToast(err.message, 'error');
      }
    });
  }

  // Preset sample scam messages for interactive testing
  document.querySelectorAll('.sample-msg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      textarea.value = btn.getAttribute('data-msg');
      if (charCounter) charCounter.textContent = `${textarea.value.length} characters`;
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

  // Explanation
  const explanationEl = document.getElementById('result-explanation');
  if (explanationEl) {
    explanationEl.textContent = analysis.explanation;
  }

  // Render Structured Pattern Chips if detected
  const patternsBox = document.getElementById('result-patterns-box');
  const patternsChips = document.getElementById('result-patterns-chips');
  const detected = analysis.details?.detectedPatterns || [];

  if (patternsBox && patternsChips) {
    if (detected.length > 0) {
      patternsChips.innerHTML = detected.map(p => `
        <span style="background:rgba(239, 68, 68, 0.2); border:1px solid #ef4444; color:#fca5a5; padding:4px 10px; border-radius:6px; font-size:0.8rem; font-weight:600; display:inline-flex; align-items:center; gap:6px;">
          <span style="background:#ef4444; color:#fff; padding:1px 5px; border-radius:3px; font-family:var(--font-mono); font-size:0.75rem;">${escapeHtml(p.prefix)}</span>
          <span>${escapeHtml(p.meaning)}</span>
        </span>
      `).join('');
      patternsBox.style.display = 'block';
    } else {
      patternsBox.style.display = 'none';
    }
  }

  // Indicators
  const indicatorsListEl = document.getElementById('result-indicators-list');
  if (indicatorsListEl) {
    if (!analysis.indicators || analysis.indicators.length === 0) {
      indicatorsListEl.innerHTML = `<div class="indicator-item info"><span>ℹ</span><span>No overt scam signatures flagged.</span></div>`;
    } else {
      indicatorsListEl.innerHTML = analysis.indicators.map(ind => {
        const icon = ind.type === 'alert' ? '⚠' : (ind.type === 'warning' ? '⚠' : (ind.type === 'success' ? '✓' : 'ℹ'));
        return `
          <div class="indicator-item ${ind.type}">
            <span class="indicator-icon">${icon}</span>
            <span>${escapeHtml(ind.text)}</span>
          </div>
        `;
      }).join('');
    }
  }

  // Recommendations
  const recListEl = document.getElementById('result-recommendations-list');
  if (recListEl) {
    if (!analysis.recommendations || analysis.recommendations.length === 0) {
      recListEl.innerHTML = `<li>Do not reply with sensitive personal information.</li>`;
    } else {
      recListEl.innerHTML = analysis.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');
    }
  }

  // Configure Cyber Agent Escalation Button
  const escalateBtn = document.getElementById('btn-escalate-cyber-agent');
  if (escalateBtn) {
    const urgency = ['HIGH RISK', 'MALICIOUS'].includes(analysis.riskLevel) ? 'CRITICAL' : 'HIGH';
    const excerpt = (originalInput || '').slice(0, 150);
    const evidenceSummary = `Threat Score: ${analysis.riskScore}/100. Severity: ${analysis.riskLevel}. Full Text: ${originalInput || ''}. Reason: ${analysis.explanation || ''}. Flags: ${(analysis.indicators || []).map(i => i.text).join('; ')}`;
    escalateBtn.href = `report.html?category=message&target=${encodeURIComponent(excerpt)}&urgency=${urgency}&evidence=${encodeURIComponent(evidenceSummary)}`;
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
