/**
 * CYBERSHIELD - URL Scanner Frontend Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('url-scan-form');
  const input = document.getElementById('url-input');
  const loadingBox = document.getElementById('scanner-loading');
  const loadingStep = document.getElementById('loading-step-text');
  const resultCard = document.getElementById('scanner-result');

  const autoScanCheckbox = document.getElementById('chk-auto-scan');
  const liveInspector = document.getElementById('live-url-inspector');
  const liveChips = document.getElementById('live-anatomy-chips');
  const liveRiskIndicator = document.getElementById('live-risk-indicator');
  const liveTypingStatus = document.getElementById('live-typing-status');

  let debounceTimer = null;
  let isScanning = false;

  async function executeScan(rawUrl) {
    if (!rawUrl || isScanning) return;
    isScanning = true;

    if (liveTypingStatus) {
      liveTypingStatus.innerHTML = '<span style="width:7px; height:7px; border-radius:50%; background:#38bdf8; display:inline-block; animation:pulse 1s infinite;"></span> Live Probing Host...';
      liveTypingStatus.style.color = '#38bdf8';
    }

    // Hide previous result, show animated loader
    resultCard.style.display = 'none';
    loadingBox.style.display = 'block';

    const steps = [
      'Performing real-time DNS resolution & bogon probe...',
      'Analyzing domain hierarchy & subdomain stacking...',
      'Inspecting homoglyphs, Punycode & credential traps...',
      'Verifying live public reputation & SSL protocol...',
      'Computing multi-factor risk assessment...'
    ];

    let stepIdx = 0;
    loadingStep.textContent = steps[0];
    const stepInterval = setInterval(() => {
      stepIdx = (stepIdx + 1) % steps.length;
      loadingStep.textContent = steps[stepIdx];
    }, 500);

    try {
      const res = await ScannersAPI.scanUrl(rawUrl);
      clearInterval(stepInterval);
      loadingBox.style.display = 'none';

      if (!res.success) {
        throw new Error(res.error?.message || 'Security engine analysis failed.');
      }

      const analysis = applyClientUrlDefenses(res.analysis || {}, rawUrl);
      renderScanResult(analysis, rawUrl);
      if (liveTypingStatus) {
        liveTypingStatus.innerHTML = '<span style="width:7px; height:7px; border-radius:50%; background:#10b981; display:inline-block;"></span> Live Analysis Active';
        liveTypingStatus.style.color = '#10b981';
      }
    } catch (err) {
      clearInterval(stepInterval);
      loadingBox.style.display = 'none';
      showToast(err.message, 'error');
      if (liveTypingStatus) {
        liveTypingStatus.innerHTML = '<span style="width:7px; height:7px; border-radius:50%; background:#ef4444; display:inline-block;"></span> Evaluation Error';
        liveTypingStatus.style.color = '#ef4444';
      }
    } finally {
      isScanning = false;
    }
  }

  // Real-time Lexical Decomposition Helper
  function inspectUrlRealtime(val) {
    if (!val || val.length < 3) {
      if (liveInspector) liveInspector.style.display = 'none';
      return;
    }

    let urlObj = null;
    let testUrl = val.trim();
    let hasMalformedProto = false;
    let malformedProtoText = '';

    const malformedMatch = testUrl.match(/^(https?p?|htps?|hppt|htpp|htttp)[:/]+/i);
    if (malformedMatch && !/^https?:\/\//i.test(testUrl)) {
      hasMalformedProto = true;
      malformedProtoText = malformedMatch[0];
      testUrl = 'https://' + testUrl.slice(malformedProtoText.length);
    } else if (!/^https?:\/\//i.test(testUrl)) {
      testUrl = 'https://' + testUrl;
    }

    try {
      urlObj = new URL(testUrl);
    } catch {
      if (liveInspector) liveInspector.style.display = 'none';
      return;
    }

    const host = urlObj.hostname.toLowerCase();
    const parts = host.split('.');
    const protocol = urlObj.protocol.replace(':', '').toUpperCase();
    const isHttps = protocol === 'HTTPS';
    const isPunycode = host.includes('xn--');
    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host);
    const highRiskTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.buzz', '.click', '.live'];
    const matchedTld = highRiskTlds.find(t => host.endsWith(t));
    const syntheticKeywords = ['demo', 'fake', 'dummy', 'sample', 'test', 'temp', 'staging', 'mock', 'sandbox', 'phish', 'spoof'];
    const hasSyntheticKeyword = syntheticKeywords.some(k => host.split('.').some(p => p === k || p.includes(k)));

    const chips = [];

    if (hasMalformedProto) {
      chips.push(`<span style="background:rgba(239,68,68,0.25); color:#ef4444; padding:2px 8px; border-radius:4px; border:1px solid #ef4444; font-weight:700;">⚠️ Malformed Protocol (${escapeHtml(malformedProtoText)})</span>`);
    } else {
      chips.push(`<span style="background:${isHttps ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}; color:${isHttps ? '#10b981' : '#f87171'}; padding:2px 8px; border-radius:4px; border:1px solid ${isHttps ? '#10b981' : '#ef4444'};">${isHttps ? '🔒 HTTPS' : '⚠️ HTTP (Unencrypted)'}</span>`);
    }

    if (hasSyntheticKeyword) {
      chips.push(`<span style="background:rgba(239,68,68,0.25); color:#ef4444; padding:2px 8px; border-radius:4px; border:1px solid #ef4444; font-weight:700;">🚨 Synthetic / Fake Test Domain</span>`);
    }

    if (isIp) {
      chips.push('<span style="background:rgba(239,68,68,0.2); color:#f87171; padding:2px 8px; border-radius:4px; border:1px solid #ef4444;">🚨 Raw IP Hosting</span>');
    } else {
      chips.push(`<span style="background:rgba(0,229,255,0.15); color:var(--cyan); padding:2px 8px; border-radius:4px; border:1px solid rgba(0,229,255,0.4);">Host: ${escapeHtml(host)}</span>`);
    }

    if (parts.length > 3) {
      chips.push('<span style="background:rgba(245,158,11,0.2); color:#fbbf24; padding:2px 8px; border-radius:4px; border:1px solid #f59e0b;">⚠️ Subdomain Stacking</span>');
    }

    if (isPunycode) {
      chips.push('<span style="background:rgba(239,68,68,0.2); color:#f87171; padding:2px 8px; border-radius:4px; border:1px solid #ef4444;">⚠️ Punycode Homoglyph (xn--)</span>');
    }

    if (matchedTld) {
      chips.push(`<span style="background:rgba(239,68,68,0.2); color:#f87171; padding:2px 8px; border-radius:4px; border:1px solid #ef4444;">🚨 High-Risk TLD (${matchedTld})</span>`);
    }

    if (liveChips) liveChips.innerHTML = chips.join('');
    if (liveInspector) liveInspector.style.display = 'block';
  }

  // Real-time input listener with debounced auto-scan
  if (input) {
    input.addEventListener('input', () => {
      const val = input.value.trim();
      inspectUrlRealtime(val);

      if (autoScanCheckbox && autoScanCheckbox.checked && val.includes('.') && val.length >= 5) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          executeScan(val);
        }, 400);
      }
    });

    // Instant trigger on paste
    input.addEventListener('paste', () => {
      setTimeout(() => {
        const val = input.value.trim();
        inspectUrlRealtime(val);
        if (autoScanCheckbox && autoScanCheckbox.checked && val.includes('.')) {
          executeScan(val);
        }
      }, 50);
    });
  }

  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      executeScan(input.value.trim());
    });
  }

  // Sample URL quick buttons
  document.querySelectorAll('.sample-url-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      input.value = btn.getAttribute('data-url');
      form.dispatchEvent(new Event('submit'));
    });
  });
});

function applyClientUrlDefenses(analysis, rawUrl) {
  const result = { ...(analysis || {}) };
  let val = (rawUrl || '').trim();
  const malformedMatch = val.match(/^(https?p?|htps?|hppt|htpp|htttp)[:/]+/i);
  const isMalformed = malformedMatch && !/^https?:\/\//i.test(val);
  const syntheticKeywords = ['demo', 'fake', 'dummy', 'sample', 'test', 'temp', 'staging', 'mock', 'sandbox', 'phish', 'spoof'];
  const hasSynthetic = syntheticKeywords.some(k => val.toLowerCase().includes(k));

  if (isMalformed || hasSynthetic || result.riskLevel === 'INVALID' || result.riskScore === 0) {
    if (isMalformed || hasSynthetic) {
      result.riskScore = Math.max(result.riskScore || 0, isMalformed && hasSynthetic ? 90 : (isMalformed ? 80 : 70));
      result.riskLevel = result.riskScore >= 75 ? 'MALICIOUS' : 'HIGH RISK';
      result.verified = false;
      result.indicators = Array.isArray(result.indicators) ? [...result.indicators] : [];
      if (isMalformed && !result.indicators.some(i => i.text && i.text.includes('Malformed Protocol'))) {
        result.indicators.unshift({
          type: 'alert',
          text: `🚨 Malformed Protocol Header (${malformedMatch ? malformedMatch[0] : 'corrupted'}): Intentionally or accidentally corrupt protocol structure commonly deployed in spam evasion.`
        });
      }
      if (hasSynthetic && !result.indicators.some(i => i.text && i.text.includes('Synthetic'))) {
        result.indicators.unshift({
          type: 'alert',
          text: `🚨 Synthetic / Fake Test Domain: URL targets an artificial mock domain (${val}) not registered as a legitimate public production service.`
        });
      }
      result.explanation = isMalformed && hasSynthetic
        ? 'CRITICAL THREAT: Corrupted protocol evasion syntax paired with synthetic/fake mock domain signature.'
        : (isMalformed ? 'HIGH RISK: Malformed protocol syntax header evasion detected.' : 'HIGH RISK: Artificial test domain flagged.');
    } else if (result.riskLevel === 'INVALID') {
      result.riskScore = 40;
      result.riskLevel = 'SUSPICIOUS';
      result.verified = false;
      result.explanation = 'SUSPICIOUS / UNPARSEABLE: Provided URL syntax fails strict RFC standards. Malformed addresses often attempt parser confusion attacks.';
    } else if (result.riskScore === 0 && !result.verified) {
      result.riskScore = 25;
      result.riskLevel = 'SUSPICIOUS';
      result.explanation = 'UNVERIFIED DOMAIN: This domain lacks verified government or accredited enterprise trust credentials. Proceed with vigilance.';
    }
  }
  return result;
}

function renderScanResult(analysis, originalInput) {
  const card = document.getElementById('scanner-result');
  if (!card) return;

  const riskClass = getRiskCssClass(analysis.riskLevel);
  const colorMap = {
    'LOW RISK': '#10b981',
    'SUSPICIOUS': '#f59e0b',
    'HIGH RISK': '#f97316',
    'MALICIOUS': '#ef4444',
    'INVALID': '#64748b',
    'UNKNOWN / UNABLE TO VERIFY': '#818cf8'
  };
  const themeColor = colorMap[analysis.riskLevel] || '#818cf8';

  // Risk Tag & Score
  const riskTagEl = document.getElementById('result-risk-tag');
  const scoreNumEl = document.getElementById('result-score-num');
  const scoreBarEl = document.getElementById('result-score-bar');
  const verifiedBadgeEl = document.getElementById('result-verified-badge');

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

  if (verifiedBadgeEl) {
    if (analysis.verified) {
      verifiedBadgeEl.innerHTML = `<span style="color:#10b981; font-size:0.8rem; font-weight:700;">✓ Verified Reputation</span>`;
    } else {
      verifiedBadgeEl.innerHTML = `<span style="color:#94a3b8; font-size:0.8rem;">○ Unverified / Independent Source</span>`;
    }
  }

  // Explanation
  const explanationEl = document.getElementById('result-explanation');
  if (explanationEl) {
    explanationEl.textContent = analysis.explanation;
  }

  // Indicators
  const indicatorsListEl = document.getElementById('result-indicators-list');
  if (indicatorsListEl) {
    if (!analysis.indicators || analysis.indicators.length === 0) {
      indicatorsListEl.innerHTML = `<div class="indicator-item info"><span>ℹ</span><span>No specific threat indicators flagged.</span></div>`;
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
      recListEl.innerHTML = `<li>Do not enter banking or sensitive details without independent verification.</li>`;
    } else {
      recListEl.innerHTML = analysis.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');
    }
  }

  // Configure Cyber Agent Escalation Button
  const escalateBtn = document.getElementById('btn-escalate-cyber-agent');
  if (escalateBtn) {
    const urgency = ['HIGH RISK', 'MALICIOUS'].includes(analysis.riskLevel) ? 'CRITICAL' : 'HIGH';
    const evidenceSummary = `Threat Score: ${analysis.riskScore}/100. Risk Level: ${analysis.riskLevel}. Reason: ${analysis.explanation || ''}. Flags: ${(analysis.indicators || []).map(i => i.text).join('; ')}`;
    escalateBtn.href = `report.html?category=url&target=${encodeURIComponent(originalInput)}&urgency=${urgency}&evidence=${encodeURIComponent(evidenceSummary)}`;
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
