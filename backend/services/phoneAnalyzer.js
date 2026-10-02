const pool = require('../config/database');

// Country code mappings
const COUNTRY_CODES = [
  { code: '+91', country: 'India', flag: '🇮🇳' },
  { code: '+1', country: 'USA / Canada', flag: '🇺🇸' },
  { code: '+44', country: 'United Kingdom', flag: '🇬🇧' },
  { code: '+61', country: 'Australia', flag: '🇦🇺' },
  { code: '+971', country: 'United Arab Emirates', flag: '🇦🇪' },
  { code: '+65', country: 'Singapore', flag: '🇸🇬' },
  { code: '+234', country: 'Nigeria (High-Risk Scam Origin)', flag: '🇳🇬', elevatedRisk: true },
  { code: '+92', country: 'Pakistan', flag: '🇵🇰' },
  { code: '+880', country: 'Bangladesh', flag: '🇧🇩' },
  { code: '+232', country: 'Sierra Leone (Wangiri Fraud Prefix)', flag: '🇸🇱', elevatedRisk: true },
  { code: '+247', country: 'Ascension Island (Wangiri Fraud Prefix)', flag: '🇦🇨', elevatedRisk: true }
];

/**
 * Normalizes a phone string into standard E.164-like digits with optional leading plus.
 */
function normalizePhone(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  const digitsOnly = trimmed.replace(/[^\d+]/g, '');
  if (!digitsOnly || digitsOnly.length < 7 || digitsOnly.length > 17) {
    return null;
  }
  return digitsOnly;
}

/**
 * Analyzes phone number security, international origin, and cross-references reports in MySQL.
 */
async function analyzePhone(rawInput, options = {}) {
  const timestamp = new Date().toISOString();
  const normalized = normalizePhone(rawInput);

  if (!normalized) {
    return {
      riskLevel: 'INVALID',
      riskScore: 0,
      confidence: 100,
      verified: false,
      indicators: [
        { type: 'error', code: 'INVALID_PHONE_FORMAT', text: 'Phone number format is invalid. Please include standard digits (min 7, max 16).' }
      ],
      explanation: 'Please provide a valid phone number, optionally prefixed with your country dialing code (e.g. +91 9876543210).',
      recommendations: ['Check for missing country code or invalid characters.'],
      source: 'phone_security_engine',
      timestamp
    };
  }

  let riskScore = 0;
  const indicators = [];
  const recommendations = [];

  // 1. Identify Country Code
  let detectedCountry = 'Unknown Region';
  let countryFlag = '🌐';
  let hasHighRiskOrigin = false;

  for (const c of COUNTRY_CODES) {
    if (normalized.startsWith(c.code) || normalized.startsWith(c.code.replace('+', ''))) {
      detectedCountry = c.country;
      countryFlag = c.flag;
      if (c.elevatedRisk) {
        hasHighRiskOrigin = true;
      }
      break;
    }
  }

  indicators.push({
    type: 'info',
    code: 'REGION_IDENTIFIED',
    text: `Origin Country/Region: ${countryFlag} ${detectedCountry} (Normalized: ${normalized})`
  });

  if (hasHighRiskOrigin) {
    riskScore += 35;
    indicators.push({
      type: 'warning',
      code: 'ELEVATED_RISK_ORIGIN',
      text: 'Number originates from an international dialing code frequently exploited in one-ring callback (Wangiri) or cross-border telecom scams.'
    });
    recommendations.push('Do NOT call back missed calls from unfamiliar international numbers.');
  }

  // 2. Query CyberShield database for previous community reports
  let reportCount = 0;
  try {
    const [reports] = await pool.query(
      `SELECT COUNT(*) as cnt, status FROM reports 
       WHERE (target LIKE ? OR target LIKE ?) 
       GROUP BY status`,
      [`%${normalized}%`, `%${rawInput.trim()}%`]
    );

    for (const r of reports) {
      reportCount += r.cnt;
      if (r.status === 'Verified') {
        riskScore += 45;
        indicators.push({
          type: 'alert',
          code: 'VERIFIED_SCAM_DATABASE',
          text: `This phone number has been officially verified as fraudulent in CyberShield scam database (${r.cnt} verified report(s)).`
        });
      }
    }

    if (reportCount > 0) {
      riskScore += Math.min(reportCount * 15, 45);
      indicators.push({
        type: 'warning',
        code: 'COMMUNITY_REPORTS_EXIST',
        text: `Found ${reportCount} active scam report(s) associated with this phone number in the CyberShield platform.`
      });
      recommendations.push('Multiple citizens have reported deceptive or fraudulent contact from this line.');
    } else {
      indicators.push({
        type: 'info',
        code: 'NO_COMMUNITY_REPORTS',
        text: 'No matching fraud reports currently recorded in CyberShield community registry.'
      });
    }
  } catch (dbErr) {
    indicators.push({
      type: 'info',
      code: 'DATABASE_LOOKUP_OFFLINE',
      text: 'Scam registry lookup could not be completed at this time.'
    });
  }

  // 3. Pattern / Repeated digits / Spoofing indicators
  const digits = normalized.replace(/\D/g, '');
  if (/^(\d)\1{6,}$/.test(digits) || digits === '1234567890' || digits === '0000000000') {
    riskScore += 40;
    indicators.push({
      type: 'warning',
      code: 'REPEATED_OR_SEQUENTIAL_DIGITS',
      text: 'Pattern indicates a test number or synthetically generated caller ID (CLI spoofing candidate).'
    });
  }

  // Clamp score
  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // Risk Classification
  let riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
  let explanation = '';
  let verified = false;

  if (riskScore >= 80) {
    riskLevel = 'MALICIOUS';
    explanation = 'Verified malicious history in the CyberShield fraud repository. Confirmed involvement in telemarketing scams or social engineering attempts.';
    recommendations.push('Block this number immediately and report any threatening communications to your local cyber police.');
  } else if (riskScore >= 45) {
    riskLevel = 'HIGH RISK';
    explanation = 'Multiple community reports or high-risk international spoofing vectors detected for this phone identity.';
    recommendations.push('Do not share bank OTPs or engage in financial transactions with this caller.');
  } else if (riskScore >= 25) {
    riskLevel = 'SUSPICIOUS';
    explanation = 'Suspicious traits detected (such as international Wangiri origin or pending citizen reports). Proceed with elevated caution.';
  } else {
    // CRITICAL: "Do NOT call a number malicious without evidence. If insufficient evidence: 'Not enough verified information.'"
    riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
    explanation = 'Not enough verified information. No malicious reports exist in our database, but caller identity cannot be verified through automated static analysis.';
    recommendations.push('If this caller asks for OTPs, money, or claims to be an authority, report them to CyberShield immediately.');
  }

  recommendations.push('You can submit an official community report to alert fellow citizens if this number attempts fraud.');

  return {
    riskLevel,
    riskScore,
    confidence: reportCount > 0 ? 90 : 70,
    verified,
    indicators,
    explanation,
    recommendations,
    source: 'phone_security_engine',
    timestamp,
    details: {
      normalizedPhone: normalized,
      country: detectedCountry,
      reportCount
    }
  };
}

module.exports = { analyzePhone };
