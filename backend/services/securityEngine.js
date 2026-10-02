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
      riskScore: 0,
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
    let riskScore = 0;
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
        indicators.push({
          type: 'warning',
          code: 'PRE_SET_AMOUNT',
          text: `Pre-set payment amount of ₹${am} will be debited upon authorization!`
        });
      }

      // Check if payee VPA looks deceptive or uses personal numbers
      if (pa.includes('winner') || pa.includes('lottery') || pa.includes('gift') || pa.includes('reward') || pa.includes('refund')) {
        riskScore += 50;
        indicators.push({
          type: 'alert',
          code: 'SUSPICIOUS_UPI_VPA',
          text: `Payee address '${pa}' contains keywords indicative of a scam or prize fraud.`
        });
      }

      recommendations.push('REMEMBER: SCANNING A QR CODE AND ENTERING YOUR UPI PIN ALWAYS DEBITS MONEY FROM YOUR ACCOUNT. YOU NEVER ENTER A PIN TO RECEIVE MONEY.');
      recommendations.push('Verify the recipient name on your payment app screen before approving any transaction.');

      let riskLevel = riskScore >= 50 ? 'HIGH RISK' : (riskScore > 0 ? 'SUSPICIOUS' : 'UNKNOWN / UNABLE TO VERIFY');
      let explanation = riskScore >= 50
        ? 'High probability of a UPI payment trap. Scammers frequently entice victims into scanning QR codes claiming they will receive funds.'
        : 'Valid UPI payment request string. CyberShield cannot verify the intent of individual private VPA addresses.';

      return {
        riskLevel,
        riskScore,
        confidence: 85,
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
    const indicators = [
      {
        type: 'info',
        code: 'QR_CONTAINS_URL',
        text: `QR code decodes to an external web URL: ${raw}`
      },
      ...urlAnalysis.indicators
    ];

    const recommendations = [
      'QR destination analyzed. Do NOT automatically follow links from unverified physical QR stickers or unsolicited emails.',
      ...urlAnalysis.recommendations
    ];

    return {
      riskLevel: urlAnalysis.riskLevel,
      riskScore: urlAnalysis.riskScore,
      confidence: urlAnalysis.confidence,
      verified: urlAnalysis.verified,
      indicators,
      explanation: `[QR Code Destination] ${urlAnalysis.explanation}`,
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

  // 5. Default: Treat as text message / plain payload
  const msgAnalysis = await analyzeMessage(raw, options);
  return {
    ...msgAnalysis,
    source: 'qr_security_engine',
    explanation: `[QR Code Text Content] ${msgAnalysis.explanation}`,
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
