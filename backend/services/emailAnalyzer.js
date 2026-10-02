// Disposable and temporary mail domain indicators
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.com',
  'trashmail.com', 'throwawaymail.com', 'sharklasers.com', 'getairmail.com',
  'dispostable.com', 'yopmail.com', 'fakemailgenerator.com', 'burnermail.io'
]);

// Well-known trusted consumer mail providers
const TRUSTED_CONSUMER_PROVIDERS = new Set([
  'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com',
  'proton.me', 'protonmail.com', 'zoho.com', 'aol.com', 'live.com'
]);

// Targeted institutional brands for email spoofing
const TARGETED_ORGANIZATIONS = [
  { brand: 'paypal', official: ['paypal.com'] },
  { brand: 'sbi', official: ['sbi.co.in'] },
  { brand: 'hdfc', official: ['hdfcbank.com'] },
  { brand: 'icici', official: ['icicibank.com'] },
  { brand: 'amazon', official: ['amazon.com', 'amazon.in'] },
  { brand: 'apple', official: ['apple.com', 'id.apple.com'] },
  { brand: 'google', official: ['google.com'] },
  { brand: 'microsoft', official: ['microsoft.com'] },
  { brand: 'netflix', official: ['netflix.com'] },
  { brand: 'rbi', official: ['rbi.org.in'] },
  { brand: 'incometax', official: ['incometax.gov.in'] },
  { brand: 'indiapost', official: ['indiapost.gov.in'] }
];

/**
 * Validates email syntax strictly.
 */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return re.test(email.trim());
}

/**
 * Analyzes an email address for fraud and spoofing vectors.
 */
async function analyzeEmail(emailInput, options = {}) {
  const timestamp = new Date().toISOString();

  if (!emailInput || typeof emailInput !== 'string' || !isValidEmail(emailInput)) {
    return {
      riskLevel: 'INVALID',
      riskScore: 0,
      confidence: 100,
      verified: false,
      indicators: [
        { type: 'error', code: 'INVALID_SYNTAX', text: 'Provided email address does not follow standard RFC 5322 syntax.' }
      ],
      explanation: 'Please enter a valid email address formatted as username@domain.extension.',
      recommendations: ['Check the address for missing @ symbol, illegal characters, or broken domain.'],
      source: 'email_security_engine',
      timestamp
    };
  }

  const cleanEmail = emailInput.trim().toLowerCase();
  const [localPart, domain] = cleanEmail.split('@');

  let riskScore = 0;
  const indicators = [];
  const recommendations = [];
  let isReputableConsumer = false;
  let isSpoofedBrand = false;

  // 1. Syntax & structure check
  indicators.push({
    type: 'info',
    code: 'VALID_SYNTAX',
    text: `Syntax is valid. Domain: ${domain}`
  });

  // 2. Disposable / temporary email check
  if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
    riskScore += 45;
    indicators.push({
      type: 'alert',
      code: 'DISPOSABLE_EMAIL',
      text: `Domain '${domain}' is an ephemeral or disposable email service frequently used for throwaway registrations and abuse.`
    });
    recommendations.push('Accounts registered with throwaway disposable inboxes are untrusted.');
  }

  // 3. Trusted consumer provider check
  if (TRUSTED_CONSUMER_PROVIDERS.has(domain)) {
    isReputableConsumer = true;
    indicators.push({
      type: 'info',
      code: 'PUBLIC_EMAIL_PROVIDER',
      text: `Domain belongs to a major public email service (${domain}). Anyone can register an account here.`
    });
  }

  // 4. Targeted brand typosquatting / spoofing
  for (const org of TARGETED_ORGANIZATIONS) {
    if (domain.includes(org.brand)) {
      const isOfficial = org.official.includes(domain);
      if (!isOfficial) {
        isSpoofedBrand = true;
        riskScore += 55;
        indicators.push({
          type: 'alert',
          code: 'ORGANIZATION_IMPERSONATION',
          text: `The domain '${domain}' incorporates the brand name '${org.brand}', but is NOT among its official domains (${org.official.join(', ')}). High risk of spoofing!`
        });
        recommendations.push(`Official emails from ${org.brand} will only originate from verified domains such as ${org.official[0]}.`);
        break;
      } else {
        indicators.push({
          type: 'success',
          code: 'OFFICIAL_ORGANIZATION_DOMAIN',
          text: `Verified official domain for ${org.brand} (${domain}).`
        });
      }
    }
  }

  // 5. Look-alike character / Leetspeak detection in domain (e.g. paypa1, g00gle)
  if (/[0-9]/.test(domain)) {
    const leetReplacements = domain.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's');
    for (const org of TARGETED_ORGANIZATIONS) {
      if (leetReplacements.includes(org.brand) && !domain.includes(org.brand)) {
        riskScore += 60;
        indicators.push({
          type: 'alert',
          code: 'TYPOSQUATTING_HOMOGLYPH',
          text: `Domain '${domain}' mimics '${org.brand}' using alphanumeric substitution (homoglyph deception).`
        });
        recommendations.push('Do not reply or click links from this spoofed domain.');
        break;
      }
    }
  }

  // 6. Suspicious words in username or domain
  const suspiciousWords = ['support', 'security', 'alert', 'verify', 'billing', 'official', 'service', 'helpdesk'];
  const matchedWords = suspiciousWords.filter(w => domain.includes(w) || localPart.includes(w));
  if (matchedWords.length > 0 && !isReputableConsumer && !isSpoofedBrand) {
    riskScore += 15;
    indicators.push({
      type: 'warning',
      code: 'HIGH_PRIVILEGE_KEYWORD',
      text: `Contains administrative/security keyword(s): ${matchedWords.join(', ')}.`
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
    explanation = 'Strong homoglyph deception or spoofed institutional domain identified. This sender address is designed to deceive recipients into believing it is an official authority.';
  } else if (riskScore >= 45) {
    riskLevel = 'HIGH RISK';
    explanation = 'Disposable mailbox or brand-mimicking domain detected. Unsolicited emails from this origin represent elevated fraud risk.';
  } else if (riskScore >= 20) {
    riskLevel = 'SUSPICIOUS';
    explanation = 'Address incorporates keywords or domain traits commonly observed in phishing campaigns.';
  } else {
    // Insufficient evidence - CRITICAL REQUIREMENT: Do NOT mark email as "SAFE" just because it's Gmail!
    if (isReputableConsumer) {
      riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
      explanation = `The email address is on a legitimate public provider (${domain}), but since anyone can register free accounts on public services, sender trustworthiness cannot be verified automatically.`;
      recommendations.push('Never trust an unfamiliar individual asking for payments or personal information, even from a common email provider.');
    } else {
      riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
      explanation = 'The email syntax is valid and no known abusive spoofing signatures were triggered. However, CyberShield has no verified organizational reputation for this domain.';
      recommendations.push('Verify the identity of the sender through official communication channels before responding or sharing confidential information.');
    }
  }

  if (recommendations.length === 0) {
    recommendations.push('Never send sensitive identification, passwords, or bank data over email.');
  }

  return {
    riskLevel,
    riskScore,
    confidence: isSpoofedBrand ? 95 : 80,
    verified,
    indicators,
    explanation,
    recommendations,
    source: 'email_security_engine',
    timestamp,
    details: {
      email: cleanEmail,
      domain,
      isDisposable: DISPOSABLE_EMAIL_DOMAINS.has(domain),
      isPublicProvider: isReputableConsumer
    }
  };
}

module.exports = { analyzeEmail };
