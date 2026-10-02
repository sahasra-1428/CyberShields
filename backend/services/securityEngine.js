const { analyzeUrl } = require('./urlAnalyzer');
const { analyzeMessage } = require('./messageAnalyzer');
const { analyzeEmail } = require('./emailAnalyzer');
const { analyzePhone } = require('./phoneAnalyzer');

/**
 * Dispatches and analyzes decoded QR code payload based on detected content type.
 */
async function analyzeQrContent(content, options = {}) {
  const timestamp = new Date().toISOString();

  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return {
      riskLevel: 'INVALID',
      riskScore: 50,
      confidence: 100,
      verified: false,
      indicators: [
        { type: 'error', code: 'EMPTY_QR_CONTENT', text: 'No decoded QR code data provided.' }
      ],
      explanation: 'Unable to extract data from the QR code. Please ensure the QR code image is clear and well-lit.',
      recommendations: ['Rescan with proper focus or upload a high-resolution QR image.'],
      source: 'qr_security_engine',
      timestamp
    };
  }

  const raw = content.trim();

  // 1. UPI QR Code Check (upi://pay?pa=...)
  if (raw.toLowerCase().startsWith('upi://pay')) {
    let riskScore = 30; // Baseline caution for all incoming UPI payment QR codes
    const indicators = [];
    const recommendations = [];

    indicators.push({
      type: 'info',
      code: 'UPI_QR_DETECTED',
      text: 'Payload is a Unified Payments Interface (UPI) payment request link.'
    });

    try {
      const upiUrl = new URL(raw);
      const pa = upiUrl.searchParams.get('pa') || ''; // Payee address
      const pn = upiUrl.searchParams.get('pn') || ''; // Payee name
      const am = upiUrl.searchParams.get('am') || ''; // Amount

      indicators.push({
        type: 'info',
        code: 'UPI_PAYEE_DETAILS',
        text: `Payee VPA: ${pa || 'Hidden/Not specified'} | Payee Name: ${pn || 'Not specified'}`
      });

      if (am) {
        riskScore += 25;
        indicators.push({
          type: 'warning',
          code: 'PRE_SET_AMOUNT',
          text: `Pre-set payment amount of ₹${am} will be immediately debited upon entering your UPI PIN!`
        });
      }

      // Check if payee VPA looks deceptive or uses prize/scam keywords
      const scamVpaKeywords = ['winner', 'lottery', 'gift', 'reward', 'refund', 'cashback', 'bonus', 'claim', 'support', 'helpdesk'];
      const matchedScamKeyword = scamVpaKeywords.find(k => pa.toLowerCase().includes(k) || pn.toLowerCase().includes(k));
      if (matchedScamKeyword) {
        riskScore += 50;
        indicators.push({
          type: 'alert',
          code: 'SUSPICIOUS_UPI_VPA',
          text: `Payee address/name contains deceptive incentive keyword ("${matchedScamKeyword}"). Hallmark of advance-fee QR payment fraud.`
        });
      }

      recommendations.push('REMEMBER: SCANNING A QR CODE AND ENTERING YOUR UPI PIN ALWAYS DEBITS MONEY FROM YOUR ACCOUNT. YOU NEVER ENTER A PIN TO RECEIVE MONEY.');
      recommendations.push('Verify the recipient name on your payment app screen before approving any transaction.');

      // Clamp score
      riskScore = Math.min(Math.max(riskScore, 0), 100);

      let riskLevel = riskScore >= 70 ? 'MALICIOUS' : (riskScore >= 45 ? 'HIGH RISK' : 'SUSPICIOUS');
      let explanation = riskScore >= 70
        ? 'High probability of a UPI payment trap. Scammers frequently entice victims into scanning QR codes claiming they will receive funds.'
        : 'UPI payment request payload. Scanning this QR code will initiate a fund deduction from your linked bank account upon PIN entry.';

      return {
        riskLevel,
        riskScore,
        confidence: 90,
        verified: false,
        indicators,
        explanation,
        recommendations,
        source: 'qr_security_engine',
        timestamp,
        details: {
          type: 'upi',
          rawContent: raw,
          vpa: pa,
          payeeName: pn,
          amount: am
        }
      };
    } catch {
      // Fall through to generic handler
    }
  }

  // 2. URL embedded in QR Code
  if (/^https?:\/\//i.test(raw) || /^www\./i.test(raw) || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/i.test(raw)) {
    const urlAnalysis = await analyzeUrl(raw, options);
    
    // Qshing / Physical tampering elevation: Unverified QR links are inherently suspicious
    let qrRiskScore = urlAnalysis.verified ? urlAnalysis.riskScore : Math.max(urlAnalysis.riskScore, 35);
    let qrRiskLevel = urlAnalysis.verified ? urlAnalysis.riskLevel : (qrRiskScore >= 50 ? urlAnalysis.riskLevel : 'SUSPICIOUS');

    const indicators = [
      {
        type: 'info',
        code: 'QR_CONTAINS_URL',
        text: `QR code decodes to an external web URL: ${raw}`
      },
      {
        type: 'warning',
        code: 'QR_TAMPERING_RISK',
        text: 'Physical QR Tampering Risk (Qshing): Cybercriminals frequently paste counterfeit QR code stickers over genuine merchant signboards or parking meters.'
      },
      ...urlAnalysis.indicators
    ];

    const recommendations = [
      'Inspect physical QR code stickers for peeling or signs of being pasted over original merchant codes.',
      'Do NOT enter login credentials or bank details on pages reached via unfamiliar QR codes.',
      ...urlAnalysis.recommendations
    ];

    return {
      riskLevel: qrRiskLevel,
      riskScore: qrRiskScore,
      confidence: urlAnalysis.confidence,
      verified: urlAnalysis.verified,
      indicators,
      explanation: `[QR Code Destination] ${urlAnalysis.explanation} Note: QR destination carries physical sticker-tampering risk.`,
      recommendations,
      source: 'qr_security_engine',
      timestamp,
      details: {
        type: 'url',
        rawContent: raw,
        ...urlAnalysis.details
      }
    };
  }

  // 3. Email embedded in QR Code (mailto: or pure email)
  const cleanEmail = raw.replace(/^mailto:/i, '');
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    const emailAnalysis = await analyzeEmail(cleanEmail, options);
    return {
      ...emailAnalysis,
      source: 'qr_security_engine',
      explanation: `[QR Code Email Target] ${emailAnalysis.explanation}`,
      details: {
        type: 'email',
        rawContent: raw,
        ...emailAnalysis.details
      }
    };
  }

  // 4. Phone embedded in QR Code (tel: or digits)
  const cleanPhone = raw.replace(/^tel:/i, '');
  if (/^[\d+()\-\s]{7,20}$/.test(cleanPhone)) {
    const phoneAnalysis = await analyzePhone(cleanPhone, options);
    return {
      ...phoneAnalysis,
      source: 'qr_security_engine',
      explanation: `[QR Code Phone Target] ${phoneAnalysis.explanation}`,
      details: {
        type: 'phone',
        rawContent: raw,
        ...phoneAnalysis.details
      }
    };
  }

  // 5. Default: Treat as text payload
  const msgAnalysis = await analyzeMessage(raw, options);
  
  // Check for fake incentive / reward keywords in plain text QR payload
  const qrIncentiveWords = ['receive', 'refund', 'cash', 'prize', 'win', '₹', 'inr', 'bonus', 'claim', 'money', 'free'];
  const hasIncentive = qrIncentiveWords.some(w => raw.toLowerCase().includes(w));
  let finalScore = msgAnalysis.riskScore;

  const extraIndicators = [];
  if (hasIncentive) {
    finalScore = Math.max(finalScore, 70);
    extraIndicators.push({
      type: 'alert',
      code: 'QR_FINANCIAL_INCENTIVE_TRAP',
      text: 'QR Financial Lure: Decoded payload offers funds, rewards, or refunds. In standard payment workflows, QR codes are NEVER used to receive money.'
    });
  } else {
    // Unverified arbitrary plain text payload baseline
    finalScore = Math.max(finalScore, 30);
    extraIndicators.push({
      type: 'warning',
      code: 'UNVERIFIED_QR_PAYLOAD',
      text: 'Unverified QR Payload: Static analysis cannot establish authentic origin or cryptographic trust for this arbitrary QR content.'
    });
  }

  let finalLevel = finalScore >= 70 ? 'MALICIOUS' : (finalScore >= 45 ? 'HIGH RISK' : 'SUSPICIOUS');

  return {
    ...msgAnalysis,
    riskLevel: finalLevel,
    riskScore: finalScore,
    indicators: [...extraIndicators, ...msgAnalysis.indicators],
    source: 'qr_security_engine',
    explanation: `[QR Code Payload] ${msgAnalysis.explanation} Unverified QR payloads must be treated with caution.`,
    details: {
      type: 'text',
      rawContent: raw,
      ...msgAnalysis.details
    }
  };
}

module.exports = {
  analyzeUrl,
  analyzeMessage,
  analyzeEmail,
  analyzePhone,
  analyzeQrContent
};
