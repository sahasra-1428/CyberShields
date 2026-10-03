const dns = require('dns').promises;
const { checkUrlThreatIntel } = require('./threatIntelligence');

// Known high-risk and abused top-level domains
const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw',
  '.buzz', '.rest', '.live', '.work', '.click', '.loan', '.zip',
  '.mov', '.country', '.stream', '.gdn', '.mom', '.monster', '.icu',
  '.cam', '.surf', '.sbs', '.cfd'
]);

// Recognized URL shorteners that obscure the real destination
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'cutt.ly',
  'shorturl.at', 'rb.gy', 'buff.ly', 'goo.gl', 'bl.ink', 'adf.ly',
  'tiny.cc', 'bc.vc', 'qr.ae'
]);

// Brands often targeted by phishing and typosquatting
const TARGETED_BRANDS = [
  'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix',
  'facebook', 'instagram', 'whatsapp', 'telegram', 'sbi', 'hdfc',
  'icici', 'axis', 'pnb', 'rbi', 'paytm', 'phonepe', 'bhim',
  'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'income-tax',
  'uidai', 'epfo', 'speedpost', 'indiapost'
];

// Sensitive phishing keywords in domain, subdomain, or path
const CREDENTIAL_KEYWORDS = [
  'login', 'signin', 'log-in', 'sign-in', 'password', 'credential',
  'verify', 'verification', 'authenticate', 'authentication', 'security',
  'account', 'update-account', 'confirm', 'wallet', 'banking', 'otp',
  'kyc', 'profile-update', 'recover', 'reactivate', 'unlock', 'claim',
  'reward', 'bonus', 'refund', 'lottery', 'prize', 'winner'
];

// Verified high-reputation domains
const REPUTABLE_DOMAINS = [
  'google.com', 'google.co.in', 'youtube.com', 'microsoft.com',
  'apple.com', 'github.com', 'wikipedia.org', 'cloudflare.com',
  'amazon.com', 'amazon.in', 'linkedin.com', 'gov.in', 'nic.in',
  'gov', 'edu', 'europa.eu', 'mozilla.org', 'stackoverflow.com',
  'iana.org', 'icann.org'
];

// Synthetic, mock, and placeholder domain markers
const SYNTHETIC_DOMAIN_KEYWORDS = [
  'demo', 'fake', 'dummy', 'sample', 'temp', 'staging', 'mock',
  'sandbox', 'phish', 'spoof', 'test'
];

/**
 * Validates and normalizes URL string with detection for malformed protocols.
 */
function normalizeUrl(input) {
  if (typeof input !== 'string') return null;

  let trimmed = input.trim();

  if (!trimmed || trimmed.length > 2048) return null;

  let hasProtocolTypo = false;
  let rawProtocol = null;

  // Detect corrupted protocol prefixes
  const malformedProtoMatch =
    trimmed.match(/^(https?p?|htps?|hppt|htpp|htttp)[:/]+/i);

  if (
    malformedProtoMatch &&
    !/^https?:\/\//i.test(trimmed)
  ) {
    hasProtocolTypo = true;
    rawProtocol = malformedProtoMatch[0];

    trimmed =
      'https://' +
      trimmed.slice(malformedProtoMatch[0].length);

  } else if (!/^https?:\/\//i.test(trimmed)) {

    // Only add HTTPS when the input looks like a real domain
    if (
      /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?(\/.*)?$/i.test(trimmed)
    ) {
      trimmed = 'https://' + trimmed;
    } else {
      return null;
    }
  }

  try {
    const parsed = new URL(trimmed);

    if (
      !['http:', 'https:'].includes(parsed.protocol) ||
      !parsed.hostname
    ) {
      return null;
    }

    return {
      parsed,
      hasProtocolTypo,
      rawProtocol
    };

  } catch {
    return null;
  }
}

/**
 * Checks if a hostname is an IP address.
 */
function isIpAddress(hostname) {

  const ipv4Pattern =
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  const ipv6Pattern =
    /^\[?[a-fA-F0-9:]+\]?$/;

  return (
    ipv4Pattern.test(hostname) ||
    (hostname.includes(':') && ipv6Pattern.test(hostname))
  );
}

/**
 * Checks whether the hostname belongs to a known reputable domain.
 *
 * This is stricter than the original suffix-only check.
 */
function isKnownReputableDomain(hostname) {

  const exactDomains = [
    'google.com',
    'google.co.in',
    'youtube.com',
    'microsoft.com',
    'apple.com',
    'github.com',
    'wikipedia.org',
    'cloudflare.com',
    'amazon.com',
    'amazon.in',
    'linkedin.com',
    'europa.eu',
    'mozilla.org',
    'stackoverflow.com',
    'iana.org',
    'icann.org'
  ];

  // Exact official domain
  if (exactDomains.includes(hostname)) {
    return true;
  }

  // Legitimate subdomain of an official domain
  if (
    exactDomains.some(
      domain => hostname.endsWith('.' + domain)
    )
  ) {
    return true;
  }

  // Government / NIC domains
  if (
    hostname === 'gov.in' ||
    hostname.endsWith('.gov.in') ||
    hostname === 'nic.in' ||
    hostname.endsWith('.nic.in')
  ) {
    return true;
  }

  return false;
}

/**
 * Analyzes a URL and produces an explainable cybersecurity risk assessment.
 */
async function analyzeUrl(rawInput, options = {}) {

  const timestamp = new Date().toISOString();

  const normResult = normalizeUrl(rawInput);

  if (!normResult || !normResult.parsed) {

    return {
      riskLevel: 'INVALID',
      riskScore: 65,
      confidence: 100,
      verified: false,

      indicators: [
        {
          type: 'alert',
          code: 'MALFORMED_URL',
          text:
            'Malformed URL: The input contains invalid syntax, corrupted protocol formatting, or missing top-level domain.'
        }
      ],

      explanation:
        'The provided address is not a valid Internet URL. Malformed or broken links are frequently generated by scammers to confuse security filters.',

      recommendations: [
        'Check for typos or illegal characters in the address (e.g. missing colon in http://).',
        'Ensure the address begins with a valid web domain.'
      ],

      source: 'local_security_engine',

      timestamp,

      details: {
        normalizedUrl: rawInput,
        protocol: null,
        hostname: null
      }
    };
  }

  const {
    parsed,
    hasProtocolTypo,
    rawProtocol
  } = normResult;

  const normalizedUrl = parsed.toString();

  const hostname = parsed.hostname.toLowerCase();

  const pathname = parsed.pathname.toLowerCase();

  const search = parsed.search.toLowerCase();

  const fullPath = pathname + search;

  let riskScore = 0;

  const indicators = [];

  const recommendations = [];

  let isBrandImpersonation = false;

  let isReputable = false;

  // ---------------------------------------------------------
  // 0. Malformed / Corrupted Protocol Evasion Check
  // ---------------------------------------------------------

  if (hasProtocolTypo) {

    riskScore += 45;

    indicators.push({
      type: 'alert',
      code: 'MALFORMED_PROTOCOL_EVASION',

      text:
        `Corrupted Protocol Detected: Input used "${rawProtocol}" instead of standard "http://" or "https://". Attackers often use malformed protocol headers to bypass automated regex security filters.`
    });

    recommendations.push(
      'Do NOT follow links with malformed or typoed protocol schemes.'
    );
  }

  // ---------------------------------------------------------
  // 1. Synthetic / Dummy / Test Domain Detection
  // ---------------------------------------------------------

  const matchedSynthetic =
    SYNTHETIC_DOMAIN_KEYWORDS.find(keyword => {

      const parts = hostname.split('.');

      return parts.some(
        p => p === keyword || p.includes(keyword)
      );
    });

  if (matchedSynthetic) {

    riskScore += 45;

    indicators.push({
      type: 'alert',
      code: 'SYNTHETIC_FAKE_DOMAIN',

      text:
        `Synthetic / Testbed Domain: Hostname contains test/dummy keyword "${matchedSynthetic}". Often used in non-production environments, staging sites, or fake demonstration lures.`
    });

    recommendations.push(
      `Domain "${hostname}" contains "${matchedSynthetic}". Do not treat test/demo sites as genuine production services.`
    );
  }

  // ---------------------------------------------------------
  // 2. Protocol Check
  // ---------------------------------------------------------

  if (parsed.protocol === 'https:') {

    indicators.push({
      type: 'info',
      code: 'HTTPS_ENABLED',

      text:
        'HTTPS encryption is present (Note: HTTPS encrypts transit but does NOT guarantee website trustworthiness).'
    });

  } else if (parsed.protocol === 'http:') {

    riskScore += 25;

    indicators.push({
      type: 'warning',
      code: 'UNENCRYPTED_HTTP',

      text:
        'Unencrypted HTTP protocol detected. Data is sent in plain text, making it vulnerable to interception.'
    });
  }

  // ---------------------------------------------------------
  // 3. IP Address as Hostname
  // ---------------------------------------------------------

  if (isIpAddress(hostname)) {

    riskScore += 35;

    indicators.push({
      type: 'alert',
      code: 'IP_BASED_URL',

      text:
        'URL directly uses a raw IP address instead of a registered domain name (common evasion technique in phishing and malware campaigns).'
    });

    recommendations.push(
      'Legitimate services rarely share direct IP URLs with public users. Avoid accessing.'
    );
  }

  // ---------------------------------------------------------
  // 4. Punycode / IDN Homograph Detection
  // ---------------------------------------------------------

  if (hostname.includes('xn--')) {

    riskScore += 30;

    indicators.push({
      type: 'alert',
      code: 'PUNYCODE_HOMOGRAPH',

      text:
        'Punycode internationalized domain (IDN) detected. Attackers frequently use look-alike characters to spoof legitimate brands.'
    });

    recommendations.push(
      'Verify the exact spelling and decoded characters of the domain name.'
    );
  }

  // ---------------------------------------------------------
  // 5. URL Shortener Detection
  // ---------------------------------------------------------

  if (
    URL_SHORTENERS.has(hostname) ||
    [...URL_SHORTENERS].some(
      short => hostname.endsWith('.' + short)
    )
  ) {

    riskScore += 20;

    indicators.push({
      type: 'warning',
      code: 'URL_SHORTENER',

      text:
        'URL shortener detected. The actual final destination is obscured from immediate view.'
    });

    recommendations.push(
      'Expand and preview the shortened link before opening.'
    );
  }

  // ---------------------------------------------------------
  // 6. Suspicious TLD Analysis
  // ---------------------------------------------------------

  const matchedTld =
    [...SUSPICIOUS_TLDS].find(
      tld => hostname.endsWith(tld)
    );

  if (matchedTld) {

    riskScore += 25;

    indicators.push({
      type: 'warning',
      code: 'HIGH_RISK_TLD',

      text:
        `Domain uses top-level domain '${matchedTld}', which can have elevated abuse or low-cost registrations.`
    });
  }

  // ---------------------------------------------------------
  // 7. Excessive Subdomains
  // ---------------------------------------------------------

  const subdomains = hostname.split('.');

  if (
    subdomains.length > 3 &&
    !hostname.endsWith('.gov.in') &&
    !hostname.endsWith('.co.uk')
  ) {

    riskScore += 18;

    indicators.push({
      type: 'warning',
      code: 'EXCESSIVE_SUBDOMAINS',

      text:
        `Excessive subdomains detected (${subdomains.length - 2} levels). Phishers frequently stack subdomains to simulate trusted namespaces.`
    });
  }

  // ---------------------------------------------------------
  // 8. Non-standard Port
  // ---------------------------------------------------------

  if (
    parsed.port &&
    !['80', '443'].includes(parsed.port)
  ) {

    riskScore += 20;

    indicators.push({
      type: 'warning',
      code: 'NON_STANDARD_PORT',

      text:
        `URL targets a non-standard port (:${parsed.port}).`
    });
  }

  // ---------------------------------------------------------
  // 9. Brand Impersonation & Typosquatting
  // ---------------------------------------------------------

  for (const brand of TARGETED_BRANDS) {

    if (hostname.includes(brand)) {

      const isOfficial =
        hostname === `${brand}.com` ||
        hostname === `${brand}.co.in` ||
        hostname === `${brand}.in` ||
        hostname === `${brand}.org` ||
        hostname.endsWith(`.${brand}.com`) ||
        hostname.endsWith(`.${brand}.co.in`);

      if (!isOfficial) {

        isBrandImpersonation = true;

        riskScore += 40;

        indicators.push({
          type: 'alert',
          code: 'BRAND_IMPERSONATION',

          text:
            `Target brand name '${brand}' was detected in a third-party or sub-domain structure (${hostname}). High probability of phishing impersonation.`
        });

        recommendations.push(
          `Do not log in or verify credentials. Navigate to the verified official portal for ${brand} directly.`
        );

        break;
      }
    }
  }

  // ---------------------------------------------------------
  // 10. Credential Harvesting & Suspicious Keywords
  // ---------------------------------------------------------

  const foundKeywords = [];

  for (const kw of CREDENTIAL_KEYWORDS) {

    if (
      fullPath.includes(kw) ||
      hostname.includes(kw)
    ) {
      foundKeywords.push(kw);
    }
  }

  if (foundKeywords.length > 0) {

    const kwPenalty =
      Math.min(foundKeywords.length * 10, 30);

    riskScore += kwPenalty;

    indicators.push({
      type: 'warning',
      code: 'SUSPICIOUS_KEYWORDS',

      text:
        `URL contains sensitive action keywords (${foundKeywords.slice(0, 4).join(', ')}). Frequently associated with credential harvesting pages.`
    });

    recommendations.push(
      'Do not submit passwords, OTPs, or financial details on pages linked to this address.'
    );
  }

  // ---------------------------------------------------------
  // 11. Open Redirect / Suspicious Query Parameters
  // ---------------------------------------------------------

  const redirectParams = [
    'redirect',
    'url',
    'target',
    'dest',
    'next',
    'return',
    'callback',
    'goto'
  ];

  const hasRedirectParam =
    redirectParams.some(
      p => parsed.searchParams.has(p)
    );

  if (hasRedirectParam) {

    riskScore += 15;

    indicators.push({
      type: 'warning',
      code: 'SUSPICIOUS_REDIRECT_PARAMETER',

      text:
        'URL contains redirection parameters that could bounce the browser to an unverified third-party location.'
    });
  }

  // ---------------------------------------------------------
  // 12. Obfuscated / Encoded Path
  // ---------------------------------------------------------

  if (
    /%[0-9a-f]{2}/i.test(parsed.pathname) ||
    /\/{2,}/.test(parsed.pathname)
  ) {

    riskScore += 12;

    indicators.push({
      type: 'warning',
      code: 'OBFUSCATED_PATH',

      text:
        'URL contains encoded or unusual path sequences attempting to bypass superficial URL filters.'
    });
  }

  // ---------------------------------------------------------
  // 13. Reputable Domain Check
  // ---------------------------------------------------------

  isReputable =
    isKnownReputableDomain(hostname);

  if (
    isReputable &&
    !isBrandImpersonation &&
    riskScore < 20
  ) {

    indicators.push({
      type: 'success',
      code: 'KNOWN_REPUTABLE_DOMAIN',

      text:
        `Domain matches a known, high-reputation organization (${hostname}).`
    });
  }

  // ---------------------------------------------------------
  // 14. Real-Time DNS Resolution Probe
  // ---------------------------------------------------------

  let liveDnsHost = null;

  if (!isIpAddress(hostname)) {

    try {

      const dnsLookup =
        await Promise.race([

          dns.lookup(hostname),

          new Promise((_, reject) =>
            setTimeout(
              () => reject(new Error('DNS_TIMEOUT')),
              1500
            )
          )
        ]);

      if (
        dnsLookup &&
        dnsLookup.address
      ) {

        liveDnsHost =
          dnsLookup.address;

        const isPrivate =
          /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|0\.|169\.254\.)/
            .test(dnsLookup.address);

        if (isPrivate) {

          riskScore += 45;

          indicators.push({
            type: 'alert',
            code: 'INTERNAL_IP_DNS_REBINDING',

            text:
              `Domain resolves to an internal/private network IP address (${dnsLookup.address}). Threat pattern indicates DNS Rebinding or Intranet Probe.`
          });

          recommendations.push(
            'Do NOT connect. This domain points to private infrastructure.'
          );

        } else {

          indicators.push({
            type: 'info',
            code: 'LIVE_DNS_RESOLVED',

            text:
              `Real-time DNS Resolution: Host is active in public DNS routing to live server IP [${dnsLookup.address}] (IPv${dnsLookup.family}).`
          });
        }
      }

    } catch (dnsErr) {

      if (
        dnsErr.code === 'ENOTFOUND' ||
        dnsErr.code === 'EAI_AGAIN'
      ) {

        riskScore += 35;

        indicators.push({
          type: 'alert',
          code: 'UNRESOLVABLE_DOMAIN',

          text:
            `Real-time DNS Probe: Host '${hostname}' does not exist or has no active public DNS records.`
        });

        recommendations.push(
          'Do NOT interact with unresolvable domains. This address does not resolve to an active Internet host.'
        );
      }
    }
  }

  // ---------------------------------------------------------
  // 15. Threat Intelligence Query
  // ---------------------------------------------------------

  const threatIntel =
    await checkUrlThreatIntel(normalizedUrl);

  if (threatIntel.available) {

    if (threatIntel.maliciousCount > 0) {

      riskScore =
        Math.max(
          riskScore + 50,
          85
        );

      indicators.push({
        type: 'alert',
        code: 'EXTERNAL_THREAT_MALICIOUS',

        text:
          `External threat intelligence detected ${threatIntel.maliciousCount} security vendor(s) flagging this URL as MALICIOUS.`
      });

    } else if (
      threatIntel.suspiciousCount > 0
    ) {

      riskScore =
        Math.max(
          riskScore + 30,
          55
        );

      indicators.push({
        type: 'warning',
        code: 'EXTERNAL_THREAT_SUSPICIOUS',

        text:
          `External threat intelligence detected ${threatIntel.suspiciousCount} security vendor(s) flagging this URL as SUSPICIOUS.`
      });

    } else {

      indicators.push({
        type: 'info',
        code: 'EXTERNAL_THREAT_CLEAN',

        text:
          `External threat intelligence: 0 / ${threatIntel.totalEngines} security vendors flagged this specific URL.`
      });
    }

  } else {

    indicators.push({
      type: 'info',
      code: 'EXTERNAL_THREAT_UNAVAILABLE',

      text:
        threatIntel.reason
    });
  }

  // ---------------------------------------------------------
  // Clamp risk score to 0 - 100
  // ---------------------------------------------------------

  riskScore =
    Math.min(
      Math.max(riskScore, 0),
      100
    );

  // ---------------------------------------------------------
  // Map Risk Level
  // ---------------------------------------------------------

  let riskLevel =
    'UNKNOWN / UNABLE TO VERIFY';

  let explanation = '';

  let verified = false;

  if (riskScore >= 80) {

    riskLevel = 'MALICIOUS';

    explanation =
      'Multiple high-severity security anomalies and/or external threat intelligence indicate an unsafe URL.';

    if (recommendations.length === 0) {

      recommendations.push(
        'Do NOT visit this link or interact with any prompts.'
      );
    }

  } else if (riskScore >= 51) {

    riskLevel = 'HIGH RISK';

    explanation =
      'Strong deception indicators were detected, such as brand impersonation, high-risk TLDs, or credential-harvesting patterns.';

    if (recommendations.length === 0) {

      recommendations.push(
        'Do not enter passwords, OTPs, or financial information.'
      );
    }

  } else if (riskScore >= 25) {

    riskLevel = 'SUSPICIOUS';

    explanation =
      'Several suspicious characteristics were detected. The safety of this link cannot be confirmed.';

    if (recommendations.length === 0) {

      recommendations.push(
        'Verify the destination directly with the official service before proceeding.'
      );
    }

  } else {

    // Score is low (0 - 24)

    if (
      isReputable &&
      parsed.protocol === 'https:' &&
      !isBrandImpersonation
    ) {

      riskLevel = 'LOW RISK';

      verified = true;

      explanation =
        'The URL belongs to an established, verified domain name and uses HTTPS encryption with no abnormal structural flags detected.';

      recommendations.push(
        'Continue exercising standard browsing safety and never share passwords or OTPs.'
      );

    } else {

      riskLevel =
        'UNKNOWN / UNABLE TO VERIFY';

      riskScore = 25;

      indicators.push({
        type: 'warning',
        code: 'UNVERIFIED_THIRD_PARTY_DOMAIN',

        text:
          'Unverified Domain: The domain has no established institutional trust rating in our verification database. Cannot be declared safe.'
      });

      explanation =
        'The URL has a valid structure, but the domain has no established trust rating in our verification database. CyberShield cannot verify this destination as safe.';

      recommendations.push(
        'Verify the identity of the sender independently before sharing any information or logging in.'
      );
    }
  }

  // ---------------------------------------------------------
  // Standard recommendations fallback
  // ---------------------------------------------------------

  if (recommendations.length === 0) {

    recommendations.push(
      'Never disclose your OTP, UPI PIN, or bank passwords under any circumstances.'
    );
  }

  // ---------------------------------------------------------
  // Final Result
  // ---------------------------------------------------------

  return {

    riskLevel,

    riskScore,

    confidence:
      isReputable
        ? 90
        : (threatIntel.available ? 85 : 75),

    verified,

    indicators,

    explanation,

    recommendations,

    source:
      threatIntel.available
        ? 'hybrid_engine_vt'
        : 'local_security_engine',

    timestamp,

    details: {

      normalizedUrl,

      protocol:
        parsed.protocol.replace(':', ''),

      hostname,

      pathname,

      liveDnsHost,

      hasThreatIntel:
        threatIntel.available
    }
  };
}

module.exports = {
  analyzeUrl,
  normalizeUrl
};
