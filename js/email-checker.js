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

        const analysis = applyClientEmailDefenses(res.analysis || {}, email);
        renderScanResult(analysis, email);
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

const FAKE_SAMPLE_DOMAINS = ['demo.com', 'fake.com', 'test.com', 'dummy.com', 'sample.com', 'example.com', 'phish.com', 'mock.com'];
const FREE_MAIL_PROVIDERS = ['gmail.com', 'yahoo.com', 'yahoo.co.in', 'outlook.com', 'hotmail.com', 'rediffmail.com'];
const AUTHORITY_KEYWORDS = ['sbi', 'rbi', 'hdfc', 'icici', 'police', 'support', 'customercare', 'customer.care', 'helpdesk', 'security', 'cbi', 'court', 'bank', 'verify', 'tax', 'income.tax', 'kyc'];

function applyClientEmailDefenses(analysis, email) {
  const result = { ...(analysis || {}) };
  const parts = (email || '').toLowerCase().trim().split('@');
  if (parts.length !== 2) return result;

  const [username, domain] = parts;
  const isSynthetic = FAKE_SAMPLE_DOMAINS.includes(domain) || domain.split('.').some(p => ['demo', 'fake', 'dummy', 'mock', 'sample'].includes(p));
  const isFreeMail = FREE_MAIL_PROVIDERS.includes(domain);
  const hasAuthorityKeyword = AUTHORITY_KEYWORDS.some(kw => username.includes(kw));

  if (isSynthetic) {
    result.riskScore = 100;
    result.riskLevel = 'MALICIOUS';
    result.verified = false;
    result.indicators = Array.isArray(result.indicators) ? [...result.indicators] : [];
    if (!result.indicators.some(i => i.text && i.text.includes('SYNTHETIC / MOCK DOMAIN'))) {
      result.indicators.unshift({
        type: 'alert',
        text: `🚨 SYNTHETIC / MOCK DOMAIN DETECTED: "${domain}" is a synthetic test domain frequently employed in phishing simulation exercises or deceptive setups.`
      });
    }
    result.explanation = 'CRITICAL MALICIOUS THREAT: Synthetic domain flagged. Never exchange authentic credentials or financial details with simulated/mock domain addresses.';
    return result;
  }

  if (isFreeMail && hasAuthorityKeyword) {
    result.riskScore = Math.max(result.riskScore || 0, 75);
    result.riskLevel = 'MALICIOUS';
    result.verified = false;
    result.indicators = Array.isArray(result.indicators) ? [...result.indicators] : [];
    if (!result.indicators.some(i => i.text && i.text.includes('FREE WEBMAIL AUTHORITY IMPERSONATION'))) {
      result.indicators.unshift({
        type: 'alert',
        text: `🚨 FREE WEBMAIL AUTHORITY IMPERSONATION: The sender uses free public email (@${domain}) while claiming institutional/authority identity ("${username}"). Official banks, police, and government departments operate exclusively on verified enterprise domains, never free public webmail accounts.`
      });
    }
    result.explanation = 'CRITICAL FRAUD INDICATOR: High-probability social engineering impersonation. Legitimate banking and law enforcement agencies never communicate from consumer Gmail or Yahoo accounts.';
    return result;
  }

  if (result.riskScore === 0 || result.riskLevel === 'UNKNOWN / UNABLE TO VERIFY' || result.riskLevel === 'LOW RISK') {
    if (!isFreeMail) {
      result.riskScore = 30;
      result.riskLevel = 'SUSPICIOUS';
      result.verified = false;
      result.indicators = Array.isArray(result.indicators) ? [...result.indicators] : [];
      if (!result.indicators.some(i => i.text && i.text.includes('UNVERIFIED CUSTOM DOMAIN'))) {
        result.indicators.push({
          type: 'warning',
          text: `⚠️ UNVERIFIED CUSTOM DOMAIN: Domain "${domain}" is not in the certified registry of accredited government or banking organizations.`
        });
      }
      result.explanation = 'SUSPICIOUS: Unverified custom email domain. Exercise caution before trusting payment instructions or clicking links.';
    }
  }
  return result;
}

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
