/**
 * CYBERSHIELD - Phone Number Security Checker
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('phone-scan-form');
  const input = document.getElementById('phone-input');
  const loadingBox = document.getElementById('scanner-loading');
  const loadingStep = document.getElementById('loading-step-text');
  const resultCard = document.getElementById('scanner-result');

  let lastCheckedPhone = '';

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const phone = input.value.trim();

      if (!phone) {
        showToast('Please enter a phone number to analyze.', 'error');
        return;
      }

      lastCheckedPhone = phone;
      resultCard.style.display = 'none';
      loadingBox.style.display = 'block';

      const steps = [
        'Normalizing phone digits and parsing international dial code...',
        'Checking against known high-risk Wangiri fraud country codes...',
        'Cross-referencing reported scam numbers in CyberShield database...',
        'Analyzing caller ID pattern spoofing indicators...',
        'Compiling citizen protection advisory...'
      ];

      let stepIdx = 0;
      loadingStep.textContent = steps[0];
      const stepInterval = setInterval(() => {
        stepIdx = (stepIdx + 1) % steps.length;
        loadingStep.textContent = steps[stepIdx];
      }, 600);

      try {
        const res = await ScannersAPI.scanPhone(phone);
        clearInterval(stepInterval);
        loadingBox.style.display = 'none';

        if (!res.success) {
          throw new Error(res.error?.message || 'Phone analysis failed.');
        }

        const analysis = applyClientPhoneDefenses(res.analysis || {}, phone);
        renderScanResult(analysis, phone);
        showToast('Phone number verification completed.', 'success');
      } catch (err) {
        clearInterval(stepInterval);
        loadingBox.style.display = 'none';
        showToast(err.message, 'error');
      }
    });
  }

  // Setup "Report this number" action button
  const reportBtn = document.getElementById('btn-report-phone');
  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      const targetPhone = lastCheckedPhone || input.value.trim();
      window.location.href = `report.html?category=phone&target=${encodeURIComponent(targetPhone)}`;
    });
  }

  // Sample phone test buttons
  document.querySelectorAll('.sample-phone-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      input.value = btn.getAttribute('data-phone');
      form.dispatchEvent(new Event('submit'));
    });
  });
});

const VERIFIED_INSTITUTIONS = [
  '1930', '112', '100', '1091', '1098', '1075',
  '1800112211', '18004253800', '18002026161', '18001080',
  '18002584455', '18001031906', '14440'
];

function applyClientPhoneDefenses(analysis, phone) {
  const result = { ...(analysis || {}) };
  const digits = (phone || '').replace(/\D/g, '');
  const cleanDigits = digits.length > 10 && digits.startsWith('91') ? digits.slice(2) : digits;
  const isVerified = VERIFIED_INSTITUTIONS.includes(cleanDigits) || VERIFIED_INSTITUTIONS.includes(digits);

  if (isVerified) {
    result.riskLevel = 'LOW RISK';
    result.riskScore = 0;
    result.verified = true;
    return result;
  }

  // If unverified 10-digit mobile number or server returned 0 / UNKNOWN
  if (!isVerified && (result.riskScore === 0 || result.riskLevel === 'UNKNOWN / UNABLE TO VERIFY' || result.riskLevel === 'LOW RISK')) {
    const isStandard10Digit = cleanDigits.length === 10;
    result.riskScore = isStandard10Digit ? 35 : 30;
    result.riskLevel = 'SUSPICIOUS';
    result.verified = false;
    result.indicators = Array.isArray(result.indicators) ? [...result.indicators] : [];

    if (isStandard10Digit) {
      if (!result.indicators.some(i => i.text && i.text.includes('UNVERIFIED PERSONAL MOBILE LINE'))) {
        result.indicators.unshift({
          type: 'warning',
          text: '⚠️ UNVERIFIED PERSONAL MOBILE LINE: Standard 10-digit personal cellular number. Not registered as an institutional bank, police, or government helpline.'
        });
      }
      if (!result.indicators.some(i => i.text && i.text.includes('AUTHORITY CHECK WARNING'))) {
        result.indicators.push({
          type: 'alert',
          text: '🚨 AUTHORITY CHECK WARNING: Scammers frequently use unverified mobile numbers to impersonate banks, police, courier agents, and tax officers.'
        });
      }
      result.explanation = 'SUSPICIOUS: Unverified personal cellular number. Official government authorities, banks, and law enforcement agencies never conduct official operations or demand money transfers via private 10-digit mobile numbers.';
    } else {
      if (!result.indicators.some(i => i.text && i.text.includes('UNVERIFIED ORIGIN'))) {
        result.indicators.unshift({
          type: 'warning',
          text: '⚠️ UNVERIFIED ORIGIN: Number has no public enterprise or institutional verification credentials.'
        });
      }
      result.explanation = 'SUSPICIOUS: Unverified communication origin. Proceed with caution and do not disclose sensitive financial credentials.';
    }

    if (!result.recommendations || result.recommendations.length === 0) {
      result.recommendations = [
        'Do not share OTPs, PINs, or net banking passwords over this call or SMS.',
        'If the caller claims to represent an official authority, hang up and dial their official published helpline directly.',
        'Report fraudulent calls immediately to 1930 or cybercrime.gov.in.'
      ];
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
    const evidenceSummary = `Threat Score: ${analysis.riskScore}/100. Risk Level: ${analysis.riskLevel}. Number: ${originalInput}. Notes: ${analysis.explanation || ''}. Flags: ${(analysis.indicators || []).map(i => i.text).join('; ')}`;
    escalateBtn.href = `report.html?category=phone&target=${encodeURIComponent(originalInput)}&urgency=${urgency}&evidence=${encodeURIComponent(evidenceSummary)}`;
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
