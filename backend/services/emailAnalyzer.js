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

// Fictitious / test / dummy domains
const FAKE_SAMPLE_DOMAINS = new Set([
  'demo.com', 'fake.com', 'test.com', 'sample.com', 'example.com',
  'dummy.com', 'invalid.com', 'temp.com', 'testing.com', 'mock.com'
]);

// Targeted institutional brands for email spoofing
const TARGETED_ORGANIZATIONS = [
  { brand: 'paypal', official: ['paypal.com'] },
  { brand: 'sbi', official: ['sbi.co.in'] },
  { brand: 'hdfc', official: ['hdfcbank.com'] },
  { brand: 'icici', official: ['icicibank.com'] },
  { brand: 'axis', official: ['axisbank.com'] },
  { brand: 'pnb', official: ['pnbindia.in'] },
  { brand: 'amazon', official: ['amazon.com', 'amazon.in'] },
  { brand: 'apple', official: ['apple.com', 'id.apple.com'] },
  { brand: 'google', official: ['google.com'] },
  { brand: 'microsoft', official: ['microsoft.com'] },
  { brand: 'netflix', official: ['netflix.com'] },
  { brand: 'rbi', official: ['rbi.org.in'] },
  { brand: 'incometax', official: ['incometax.gov.in'] },
  { brand: 'indiapost', official: ['indiapost.gov.in'] },
  { brand: 'police', official: ['police.gov.in'] },
  { brand: 'cbi', official: ['cbi.gov.in'] }
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
      riskScore: 60,
      confidence: 100,
      verified: false,
      indicators: [
        { type: 'error', code: 'INVALID_SYNTAX', text: 'Provided email address does not follow standard RFC 5322 syntax.' }
      ],
      explanation: 'Invalid email syntax. Malformed or fragmented address provided.',
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
  let isVerifiedOfficial = false;

  // 1. Syntax check
  indicators.push({
    type: 'info',
    code: 'VALID_SYNTAX',
    text: `Syntax is valid. Domain: ${domain}`
  });

  // 2. Synthetic / Dummy / Test Domain detection (e.g. demo.com, fake.com)
  if (FAKE_SAMPLE_DOMAINS.has(domain) || domain.startsWith('demo.') || domain.startsWith('fake.') || domain.startsWith('test.')) {
    riskScore += 65;
    indicators.push({
      type: 'alert',
      code: 'SYNTHETIC_FAKE_DOMAIN',
      text: `Domain '${domain}' is a known dummy, placeholder, or synthetic test domain. Highly unauthentic.`
    });
    recommendations.push('Do NOT accept communications or credentials from synthetic or placeholder domains.');
  }

  // 3. Disposable / Temporary Email Check
  if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
    riskScore += 70;
    indicators.push({
      type: 'alert',
      code: 'DISPOSABLE_EMAIL',
      text: `Domain '${domain}' is an ephemeral or disposable email service frequently used for throwaway registrations and abuse.`
    });
    recommendations.push('Accounts registered with throwaway disposable inboxes are untrusted.');
  }

  // 4. Trusted Consumer Provider Check
  if (TRUSTED_CONSUMER_PROVIDERS.has(domain)) {
    isReputableConsumer = true;
    indicators.push({
      type: 'info',
      code: 'PUBLIC_EMAIL_PROVIDER',
      text: `Domain belongs to a free consumer email provider (${domain}). Anyone can register an account here.`
    });
  }

  // 5. CRITICAL: Free Webmail Authority / Brand Impersonation Check (e.g., sbi.helpdesk@gmail.com)
  const authorityKeywords = ['sbi', 'hdfc', 'icici', 'axis', 'pnb', 'rbi', 'police', 'cbi', 'customs', 'incometax', 'aadhaar', 'uidai', 'support', 'customercare', 'security', 'billing', 'official', 'helpdesk', 'rewards', 'lottery', 'refund'];
  const matchedAuthorityInUser = authorityKeywords.filter(k => localPart.includes(k));

  if (isReputableConsumer && matchedAuthorityInUser.length > 0) {
    riskScore += 75;
    indicators.push({
      type: 'alert',
      code: 'FREE_WEBMAIL_AUTHORITY_IMPERSONATION',
      text: `Impersonation Alert: Username contains official/authority keyword(s) "${matchedAuthorityInUser.join(', ')}" on a free consumer service (@${domain}). Real banks, police, and agencies NEVER use free webmail!`
    });
    recommendations.push('NEVER trust emails from free Gmail, Yahoo, or Outlook accounts claiming to represent banks, law enforcement, or government agencies.');
  }

  // 6. Targeted Brand Typosquatting / Spoofing in Domain
  for (const org of TARGETED_ORGANIZATIONS) {
    if (domain.includes(org.brand)) {
      const isOfficial = org.official.includes(domain);
      if (!isOfficial) {
        isSpoofedBrand = true;
        riskScore += 75;
        indicators.push({
          type: 'alert',
          code: 'ORGANIZATION_IMPERSONATION',
          text: `The domain '${domain}' incorporates the brand name '${org.brand}', but is NOT among its official domains (${org.official.join(', ')}). High risk of spoofing!`
        });
        recommendations.push(`Official emails from ${org.brand} will only originate from verified domains such as ${org.official[0]}.`);
        break;
      } else {
        isVerifiedOfficial = true;
        indicators.push({
          type: 'success',
          code: 'OFFICIAL_ORGANIZATION_DOMAIN',
          text: `Verified official domain for ${org.brand} (${domain}).`
        });
      }
    }
  }

  // 7. Look-alike character / Leetspeak detection in domain (e.g. paypa1, g00gle)
  if (/[0-9]/.test(domain)) {
    const leetReplacements = domain.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's');
    for (const org of TARGETED_ORGANIZATIONS) {
      if (leetReplacements.includes(org.brand) && !domain.includes(org.brand)) {
        riskScore += 70;
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

  // 8. Suspicious administrative keywords in custom domain
  if (!isReputableConsumer && !isSpoofedBrand && !isVerifiedOfficial) {
    const adminKeywords = ['support', 'security', 'alert', 'verify', 'billing', 'official', 'service', 'helpdesk', 'account', 'login'];
    const matchedAdmin = adminKeywords.filter(w => domain.includes(w) || localPart.includes(w));
    if (matchedAdmin.length > 0) {
      riskScore += 35;
      indicators.push({
        type: 'warning',
        code: 'HIGH_PRIVILEGE_KEYWORD',
        text: `Contains administrative/security keyword(s): "${matchedAdmin.join(', ')}" on an unverified domain.`
      });
    }
  }

  // 9. Baseline for unverified third-party domains
  if (!isReputableConsumer && !isVerifiedOfficial && riskScore === 0) {
    riskScore = 30; // Unverified custom domain baseline, NEVER 0!
    indicators.push({
      type: 'warning',
      code: 'UNVERIFIED_SENDER_DOMAIN',
      text: `Domain '${domain}' is an unverified private domain with no established corporate reputation in our trust registry.`
    });
    recommendations.push('Exercise caution. Independently verify the sender identity before replying.');
  }

  // 10. Clamp score
  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // Risk Classification
  let riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
  let explanation = '';
  let verified = isVerifiedOfficial;

  if (riskScore >= 70) {
    riskLevel = 'MALICIOUS';
    explanation = 'High-confidence fraudulent or deceptive sender identity. Incorporates fake/disposable domains or attempts brand/authority impersonation.';
  } else if (riskScore >= 45) {
    riskLevel = 'HIGH RISK';
    explanation = 'Elevated risk detected. Disposable mailbox, homoglyph substitute, or suspicious keyword combination identified.';
  } else if (riskScore >= 25) {
    riskLevel = 'SUSPICIOUS';
    explanation = 'Unverified private domain or generic sender profile. Cannot be verified as safe without cryptographic email authentication (SPF/DKIM).';
  } else {
    // Normal consumer address without suspicious claims (e.g. personal regular gmail)
    riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
    riskScore = 15;
    explanation = `Email is on a standard public provider (${domain}). Anyone can create a free account, so identity cannot be established without digital signatures.`;
    recommendations.push('Verify the person\'s real identity through outside communication channels.');
  }

  if (recommendations.length === 0) {
    recommendations.push('Never send sensitive passwords, PINs, or financial details via email.');
  }

  return {
    riskLevel,
    riskScore,
    confidence: isSpoofedBrand || isVerifiedOfficial ? 95 : 80,
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
