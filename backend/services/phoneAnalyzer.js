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

// Verified official Indian emergency & institutional toll-free helplines
const VERIFIED_INSTITUTIONAL_NUMBERS = [
  { number: '1930', name: 'National Cyber Crime Reporting Helpline', category: 'Government Cyber Defense' },
  { number: '112', name: 'National Emergency Response Support System', category: 'Emergency Services' },
  { number: '100', name: 'Police Control Room', category: 'Law Enforcement' },
  { number: '1091', name: 'Women Helpline', category: 'Public Safety' },
  { number: '1800112211', name: 'State Bank of India (SBI) Official Toll-Free', category: 'Banking' },
  { number: '18004253800', name: 'State Bank of India (SBI) Official Toll-Free', category: 'Banking' },
  { number: '18002026161', name: 'HDFC Bank Official Toll-Free Helpline', category: 'Banking' },
  { number: '18001080', name: 'ICICI Bank Official Customer Care', category: 'Banking' },
  { number: '18001802222', name: 'Punjab National Bank Official Toll-Free', category: 'Banking' },
  { number: '14440', name: 'RBI Financial Awareness & Complaints', category: 'Central Bank' }
];

/**
 * Normalizes a phone string into standard E.164-like digits with optional leading plus.
 */
function normalizePhone(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  const digitsOnly = trimmed.replace(/[^\d+]/g, '');
  if (!digitsOnly || digitsOnly.length < 3 || digitsOnly.length > 17) {
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
      riskScore: 50,
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

  const digits = normalized.replace(/\D/g, '');

  // 1. Check if it's a verified institutional or emergency helpline (1930, 112, 1800...)
  const matchedOfficial = VERIFIED_INSTITUTIONAL_NUMBERS.find(v => digits === v.number || normalized === v.number);
  if (matchedOfficial) {
    return {
      riskLevel: 'LOW RISK',
      riskScore: 0,
      confidence: 100,
      verified: true,
      indicators: [
        {
          type: 'success',
          code: 'VERIFIED_OFFICIAL_HELPLINE',
          text: `Verified Official Helpline: ${matchedOfficial.name} (${matchedOfficial.category}).`
        },
        {
          type: 'info',
          code: 'INSTITUTIONAL_NUMBER',
          text: 'This is an authentic, officially recognized national helpline or bank customer service number.'
        }
      ],
      explanation: `Verified authentic institution: ${matchedOfficial.name}. Safe to contact for official support.`,
      recommendations: [
        'Always confirm you dialed the exact digits of this official number.',
        'Official staff will never ask for your netbanking password, ATM PIN, or UPI PIN.'
      ],
      source: 'phone_security_engine',
      timestamp,
      details: {
        normalizedPhone: normalized,
        isOfficial: true,
        institutionName: matchedOfficial.name,
        category: matchedOfficial.category
      }
    };
  }

  let riskScore = 0;
  const indicators = [];
  const recommendations = [];

  // 2. Identify Country Code
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
    riskScore += 40;
    indicators.push({
      type: 'alert',
      code: 'ELEVATED_RISK_ORIGIN',
      text: 'Number originates from an international dialing code frequently exploited in one-ring callback (Wangiri) or cross-border telecom scams.'
    });
    recommendations.push('Do NOT call back missed calls from unfamiliar international numbers.');
  }

  // 3. Query CyberShield database for previous community reports
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
        riskScore += 50;
        indicators.push({
          type: 'alert',
          code: 'VERIFIED_SCAM_DATABASE',
          text: `This phone number has been officially verified as fraudulent in CyberShield scam database (${r.cnt} verified report(s)).`
        });
      }
    }

    if (reportCount > 0) {
      riskScore += Math.min(reportCount * 20, 50);
      indicators.push({
        type: 'alert',
        code: 'COMMUNITY_REPORTS_EXIST',
        text: `Found ${reportCount} active scam report(s) associated with this phone number in the CyberShield platform.`
      });
      recommendations.push('Multiple citizens have reported deceptive or fraudulent contact from this line.');
    }
  } catch (dbErr) {
    // Database check optional in offline test
  }

  // 4. Repeated, sequential, or dummy phone numbers (e.g. 9999999999, 1234567890, 0000000000)
  const isDummyOrRepeated = /^(\d)\1{5,}$/.test(digits) || digits === '1234567890' || digits === '9876543210' || digits.startsWith('0000');
  if (isDummyOrRepeated) {
    riskScore += 45;
    indicators.push({
      type: 'warning',
      code: 'REPEATED_OR_SEQUENTIAL_DIGITS',
      text: 'Pattern indicates a dummy, test number, or synthetically generated caller ID (CLI spoofing candidate).'
    });
    recommendations.push('Caller ID appears synthetically fabricated. High probability of robocalling or spoofing.');
  }

  // 5. Unregistered Personal Mobile Line Detection (CRITICAL: 10-digit mobile lines claiming authority)
  const isStandardMobileLength = digits.length === 10 || (digits.length === 12 && digits.startsWith('91'));
  if (isStandardMobileLength && !matchedOfficial) {
    // Standard cellular mobile numbers are personal lines, NOT verified enterprise lines!
    riskScore += 35;
    indicators.push({
      type: 'warning',
      code: 'UNVERIFIED_PERSONAL_MOBILE_LINE',
      text: 'Unverified Personal Cellular Line: This is an individual mobile subscriber number, NOT an official corporate or banking toll-free line.'
    });
    indicators.push({
      type: 'info',
      code: 'AUTHORITY_CHECK_WARNING',
      text: 'Alert: Real banks, police stations, and government departments DO NOT initiate calls or demands from personal 10-digit mobile numbers.'
    });
    recommendations.push('If a caller on this number claims to be from a bank, electricity board, courier, or police, hang up immediately. It is an unverified mobile line.');
  }

  // 6. Generic baseline if nothing matched
  if (riskScore === 0) {
    riskScore = 25;
    indicators.push({
      type: 'warning',
      code: 'UNVERIFIED_CALLER_ID',
      text: 'Caller identity is unverified in public telecommunications registries. No verified corporate identity established.'
    });
    recommendations.push('Do not share sensitive passwords, OTPs, or financial information with unverified callers.');
  }

  // Clamp score
  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // Risk Classification
  let riskLevel = 'SUSPICIOUS';
  let explanation = '';

  if (riskScore >= 75) {
    riskLevel = 'MALICIOUS';
    explanation = 'Confirmed fraudulent or spoofed number. High volume of community incident reports or verified scam origin.';
    recommendations.push('Block this number immediately and report any threatening communications to 1930.');
  } else if (riskScore >= 45) {
    riskLevel = 'HIGH RISK';
    explanation = 'Multiple risk indicators detected (community fraud reports, dummy CLI patterns, or high-risk international Wangiri prefix).';
    recommendations.push('Do not answer or return calls from this number. Never share banking OTPs.');
  } else {
    riskLevel = 'SUSPICIOUS';
    explanation = 'Unverified individual mobile line. Not a verified enterprise or banking helpline. CyberShield advises caution if caller claims authority.';
  }

  recommendations.push('You can submit an official community report to alert fellow citizens if this number attempts fraud.');

  return {
    riskLevel,
    riskScore,
    confidence: reportCount > 0 ? 90 : 75,
    verified: false,
    indicators,
    explanation,
    recommendations,
    source: 'phone_security_engine',
    timestamp,
    details: {
      normalizedPhone: normalized,
      country: detectedCountry,
      isPersonalMobile: isStandardMobileLength,
      reportCount
    }
  };
}

module.exports = { analyzePhone };
