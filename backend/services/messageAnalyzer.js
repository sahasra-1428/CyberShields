const { analyzeUrl } = require('./urlAnalyzer');

// Regex patterns to detect embedded URLs within unstructured text
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"{}|\\^`\[\]]+/gi;

// Heuristic keyword catalogs
const URGENCY_PATTERNS = [
  /\b(?:immediately|urgent|urgently|within \d+ (?:hours?|mins?|minutes?|days?)|act now|expires? today|final notice|last warning|instant(?:ly)?)\b/i,
  /\b(?:blocked today|suspended within|immediate suspension|legal action will be taken|arrest warrant|cbi fir|digital arrest)\b/i
];

const PRIZE_PATTERNS = [
  /\b(?:congratulations?|you(?: have)? won|selected for a prize|cash prize|won ₹?[\d,]+|claim your reward|lottery winner|lucky draw|free gift|gift voucher)\b/i,
  /\b(?:bonus reward|claim ₹?[\d,]+|free recharge|exclusive jackpot)\b/i
];

const FINANCIAL_PATTERNS = [
  /\b(?:pay|send|transfer|deposit|fee|redelivery fee|processing fee|investment|commission)\b/i,
  /\b(?:earn ₹?[\d,]+ (?:daily|per day)|part-time task|prepaid task|review tasks?)\b/i
];

const CREDENTIAL_PATTERNS = [
  /\b(?:share (?:your )?otp|send (?:the )?(?:6-digit )?code|verify otp|enter your (?:upi )?pin|card cvv|atm pin|netbanking password)\b/i,
  /\b(?:update (?:your )?kyc|link pan|pan verification|aadhaar update|unblock account)\b/i
];

const AUTHORITY_PATTERNS = [
  /\b(?:government approved|approved by government|govt of india|rbi approved|reserve bank of india|police verified|mumbai police|cbi arrest|customs officer|income tax department|sbi branch|hdfc security team)\b/i
];

// 19 Standardized Structured Scam Message Patterns
const STRUCTURED_PATTERNS = [
  {
    prefix: 'G-',
    regex: /(?:^|[\s\n\r\[\(])G-([^\s].*)/i,
    meaning: 'Government-related claim',
    example: 'G-Your Aadhaar verification is pending',
    riskScore: 30,
    type: 'warning',
    code: 'PATTERN_GOVERNMENT_CLAIM',
    recommendation: 'Government agencies (UIDAI, MyGov) never send messages with "G-" prefixes. Verify directly at official .gov.in portals.'
  },
  {
    prefix: 'BANK-',
    regex: /(?:^|[\s\n\r\[\(])BANK-([^\s].*)/i,
    meaning: 'Banking-related claim',
    example: 'BANK-Your account will be blocked',
    riskScore: 35,
    type: 'alert',
    code: 'PATTERN_BANKING_CLAIM',
    recommendation: 'Legitimate banks never threaten immediate account blocking via casual SMS with "BANK-". Contact your bank branch or use the verified app.'
  },
  {
    prefix: 'KYC-',
    regex: /(?:^|[\s\n\r\[\(])KYC-([^\s].*)/i,
    meaning: 'KYC-related claim',
    example: 'KYC-Update your KYC immediately',
    riskScore: 32,
    type: 'alert',
    code: 'PATTERN_KYC_CLAIM',
    recommendation: 'Do not click links in "KYC-" messages. RBI guidelines require KYC verification in person at a branch or via secure official apps.'
  },
  {
    prefix: 'UPI-',
    regex: /(?:^|[\s\n\r\[\(])UPI-([^\s].*)/i,
    meaning: 'UPI/payment claim',
    example: 'UPI-Approve the request to receive refund',
    riskScore: 35,
    type: 'alert',
    code: 'PATTERN_UPI_CLAIM',
    recommendation: 'NEVER approve a UPI collect request or enter your PIN to receive money. Entering a UPI PIN always deducts funds from your account.'
  },
  {
    prefix: 'OTP-',
    regex: /(?:^|[\s\n\r\[\(])OTP-([^\s].*)/i,
    meaning: 'OTP-related claim',
    example: 'OTP-Share the OTP to complete verification',
    riskScore: 42,
    type: 'alert',
    code: 'PATTERN_OTP_SOLICITATION',
    recommendation: 'NEVER disclose OTPs. Bank employees and authentic service providers will NEVER request your OTP over phone, chat, or SMS.'
  },
  {
    prefix: 'CARD-',
    regex: /(?:^|[\s\n\r\[\(])CARD-([^\s].*)/i,
    meaning: 'Debit/credit card claim',
    example: 'CARD-Your card will expire today',
    riskScore: 30,
    type: 'warning',
    code: 'PATTERN_CARD_CLAIM',
    recommendation: 'Card renewals are dispatched automatically by your bank without requiring link verification. Check status in your netbanking portal.'
  },
  {
    prefix: 'TAX-',
    regex: /(?:^|[\s\n\r\[\(])TAX-([^\s].*)/i,
    meaning: 'Tax-related claim',
    example: 'TAX-Your refund is waiting for verification',
    riskScore: 30,
    type: 'warning',
    code: 'PATTERN_TAX_CLAIM',
    recommendation: 'Income tax communications arrive only via e-filing (incometax.gov.in). Never input banking credentials on SMS links.'
  },
  {
    prefix: 'CBI-',
    regex: /(?:^|[\s\n\r\[\(])CBI-([^\s].*)/i,
    meaning: 'Police/CBI impersonation claim',
    example: 'CBI-Your number is linked to a criminal case',
    riskScore: 45,
    type: 'alert',
    code: 'PATTERN_CBI_IMPERSONATION',
    recommendation: 'CBI does not issue notices or register FIRs through SMS or WhatsApp. Immediately report this impersonation to 1930.'
  },
  {
    prefix: 'POLICE-',
    regex: /(?:^|[\s\n\r\[\(])POLICE-([^\s].*)/i,
    meaning: 'Police impersonation claim',
    example: 'POLICE-Your account is under investigation',
    riskScore: 45,
    type: 'alert',
    code: 'PATTERN_POLICE_IMPERSONATION',
    recommendation: 'Real police investigations follow formal summons under CrPC/BNS in person. Never transfer funds to "clear" your name.'
  },
  {
    prefix: 'COURT-',
    regex: /(?:^|[\s\n\r\[\(])COURT-([^\s].*)/i,
    meaning: 'Court/legal-threat claim',
    example: 'COURT-A warrant has been issued against you',
    riskScore: 42,
    type: 'alert',
    code: 'PATTERN_COURT_LEGAL_THREAT',
    recommendation: 'Judicial warrants are physically served by court bailiffs or local police stations, never delivered as SMS threat text.'
  },
  {
    prefix: 'JOB-',
    regex: /(?:^|[\s\n\r\[\(])JOB-([^\s].*)/i,
    meaning: 'Job scam pattern',
    example: 'JOB-Earn ₹5000 daily by completing tasks',
    riskScore: 35,
    type: 'alert',
    code: 'PATTERN_JOB_SCAM',
    recommendation: 'Any freelance or work-from-home job requiring you to deposit money or complete Telegram tasks is a Ponzi scam.'
  },
  {
    prefix: 'REWARD-',
    regex: /(?:^|[\s\n\r\[\(])REWARD-([^\s].*)/i,
    meaning: 'Prize/reward bait',
    example: 'REWARD-You have won a ₹50,000 reward',
    riskScore: 30,
    type: 'warning',
    code: 'PATTERN_REWARD_BAIT',
    recommendation: 'Never pay processing fees or GST to claim rewards. Unsolicited rewards are classic fee-fraud lures.'
  },
  {
    prefix: 'LOTTERY-',
    regex: /(?:^|[\s\n\r\[\(])LOTTERY-([^\s].*)/i,
    meaning: 'Lottery scam pattern',
    example: 'LOTTERY-You have won ₹10 lakh',
    riskScore: 35,
    type: 'alert',
    code: 'PATTERN_LOTTERY_SCAM',
    recommendation: 'Lottery scams request advance clearance fees. Delete the message and block the sender.'
  },
  {
    prefix: 'REFUND-',
    regex: /(?:^|[\s\n\r\[\(])REFUND-([^\s].*)/i,
    meaning: 'Refund bait',
    example: 'REFUND-Click to receive your refund',
    riskScore: 30,
    type: 'warning',
    code: 'PATTERN_REFUND_BAIT',
    recommendation: 'Merchant refunds credit back automatically to your original account without requiring link interaction.'
  },
  {
    prefix: 'ACCOUNT-',
    regex: /(?:^|[\s\n\r\[\(])ACCOUNT-([^\s].*)/i,
    meaning: 'Account-threat pattern',
    example: 'ACCOUNT-Your account will be suspended today',
    riskScore: 28,
    type: 'warning',
    code: 'PATTERN_ACCOUNT_THREAT',
    recommendation: 'Verify account status by opening the official app directly. Do not follow recovery links sent via SMS.'
  },
  {
    prefix: 'URGENT-',
    regex: /(?:^|[\s\n\r\[\(])URGENT-([^\s].*)/i,
    meaning: 'Urgency pattern',
    example: 'URGENT-Verify immediately',
    riskScore: 25,
    type: 'warning',
    code: 'PATTERN_URGENCY_PATTERN',
    recommendation: 'Scammers use artificial urgency to prevent you from cross-checking facts. Always take time to verify.'
  },
  {
    prefix: 'VERIFY-',
    regex: /(?:^|[\s\n\r\[\(])VERIFY-([^\s].*)/i,
    meaning: 'Verification request',
    example: 'VERIFY-Confirm your details now',
    riskScore: 25,
    type: 'warning',
    code: 'PATTERN_VERIFICATION_REQUEST',
    recommendation: 'Do not submit identity numbers or credentials on web pages reached through unverified SMS.'
  },
  {
    prefix: 'APK-',
    regex: /(?:^|[\s\n\r\[\(])APK-([^\s].*)/i,
    meaning: 'Suspicious APK/download pattern',
    example: 'APK-Install this app to receive your refund',
    riskScore: 45,
    type: 'alert',
    code: 'PATTERN_APK_DOWNLOAD',
    recommendation: 'NEVER install .apk files received via messages. They infect phones with spyware, SMS forwarders, and screen recorders.'
  },
  {
    prefix: 'ARREST-',
    regex: /(?:^|[\s\n\r\[\(])ARREST-([^\s].*)/i,
    meaning: 'Arrest/digital-arrest pattern',
    example: 'ARREST-You will be arrested unless you cooperate',
    riskScore: 50,
    type: 'alert',
    code: 'PATTERN_DIGITAL_ARREST',
    recommendation: 'There is NO legal "Digital Arrest" in India. Law enforcement never arrests via video call or SMS. Dial 1930 immediately.'
  }
];

/**
 * Analyzes an incoming message or communication for social engineering and scam tactics.
 */
async function analyzeMessage(text, options = {}) {
  const timestamp = new Date().toISOString();

  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return {
      riskLevel: 'INVALID',
      riskScore: 0,
      confidence: 100,
      verified: false,
      indicators: [
        { type: 'error', code: 'EMPTY_MESSAGE', text: 'No message content provided for analysis.' }
      ],
      explanation: 'Please provide the text of an SMS, WhatsApp message, email, or social media communication to analyze.',
      recommendations: ['Paste the full suspicious text message into the analyzer.'],
      source: 'message_security_engine',
      timestamp
    };
  }

  const cleanText = text.trim();
  let riskScore = 0;
  const indicators = [];
  const recommendations = [];

  // 0. Detect Standardized Structured Scam Message Patterns (G-, BANK-, KYC-, etc.)
  const detectedPatterns = [];
  for (const p of STRUCTURED_PATTERNS) {
    if (p.regex.test(cleanText)) {
      detectedPatterns.push({
        prefix: p.prefix,
        meaning: p.meaning,
        example: p.example,
        category: p.code,
        riskScore: p.riskScore
      });

      riskScore += p.riskScore;
      indicators.push({
        type: p.type,
        code: p.code,
        text: `Structured Scam Signature [${p.prefix}]: ${p.meaning}. Matches pattern: "${p.example}".`
      });
      recommendations.push(p.recommendation);
    }
  }

  // 1. Detect Urgency / Fear tactics
  let urgencyHit = false;
  for (const regex of URGENCY_PATTERNS) {
    if (regex.test(cleanText)) {
      urgencyHit = true;
      break;
    }
  }
  if (urgencyHit) {
    riskScore += 25;
    indicators.push({
      type: 'warning',
      code: 'URGENCY_PRESSURE',
      text: 'Artificial urgency or fear-inducing language detected. Scammers create false urgency to prevent logical verification.'
    });
    recommendations.push('Do not panic or rush into action. Always verify independently through trusted official contacts.');
  }

  // 2. Detect Prize / Lottery claims
  let prizeHit = false;
  for (const regex of PRIZE_PATTERNS) {
    if (regex.test(cleanText)) {
      prizeHit = true;
      break;
    }
  }
  if (prizeHit) {
    riskScore += 30;
    indicators.push({
      type: 'alert',
      code: 'PRIZE_LOTTERY_CLAIM',
      text: 'Unsolicited prize, lottery, or financial incentive claim detected. Legitimate lotteries do not contact winners via casual messages.'
    });
    recommendations.push('Never pay any "processing fees" or "taxes" to receive an unearned prize or gift.');
  }

  // 3. Detect Credential & OTP requests
  let credentialHit = false;
  for (const regex of CREDENTIAL_PATTERNS) {
    if (regex.test(cleanText)) {
      credentialHit = true;
      break;
    }
  }
  if (credentialHit) {
    riskScore += 35;
    indicators.push({
      type: 'alert',
      code: 'CREDENTIAL_OTP_HARVESTING',
      text: 'Direct or indirect solicitation of OTP, PIN, password, or urgent KYC update detected.'
    });
    recommendations.push('NEVER share One-Time Passwords (OTPs), UPI PINs, or banking passwords with anyone, including callers claiming to be bank employees.');
  }

  // 4. Detect Financial / Investment requests
  let financialHit = false;
  for (const regex of FINANCIAL_PATTERNS) {
    if (regex.test(cleanText)) {
      financialHit = true;
      break;
    }
  }
  if (financialHit && !prizeHit) {
    riskScore += 18;
    indicators.push({
      type: 'warning',
      code: 'FINANCIAL_REQUEST',
      text: 'Payment, advance fee, or high-yield task investment request detected.'
    });
    recommendations.push('Avoid sending funds or purchasing cryptocurrency for "prepaid tasks" or freelance job activations.');
  }

  // 5. Authority Affiliation Claims (CRITICAL HANDLING REQUIREMENT)
  let authorityHit = false;
  for (const regex of AUTHORITY_PATTERNS) {
    if (regex.test(cleanText)) {
      authorityHit = true;
      break;
    }
  }
  if (authorityHit) {
    riskScore += 25;
    indicators.push({
      type: 'warning',
      code: 'AUTHORITY_AFFILIATION_CLAIM',
      text: 'Authority affiliation claim detected (Government / RBI / Police / Bank). Do not treat authority claims as proof of authenticity.'
    });
    recommendations.push('Verify this claim through the organization\'s official website or verified communication channel. Real agencies never demand immediate payments or digital arrests over chat.');
  }

  // 6. Extract and Analyze Embedded URLs using central urlAnalyzer
  const matchedUrls = cleanText.match(URL_REGEX) || [];
  const extractedUrlAnalyses = [];

  for (const rawUrl of matchedUrls.slice(0, 3)) {
    const urlAnalysis = await analyzeUrl(rawUrl, options);
    extractedUrlAnalyses.push({
      url: rawUrl,
      riskLevel: urlAnalysis.riskLevel,
      riskScore: urlAnalysis.riskScore,
      indicators: urlAnalysis.indicators
    });

    if (urlAnalysis.riskLevel === 'MALICIOUS' || urlAnalysis.riskScore >= 80) {
      riskScore = Math.max(riskScore + 40, 85);
      indicators.push({
        type: 'alert',
        code: 'EMBEDDED_MALICIOUS_URL',
        text: `Message contains a HIGH-RISK/MALICIOUS link: ${rawUrl}`
      });
      recommendations.push(`DO NOT click the link: ${rawUrl}`);
    } else if (urlAnalysis.riskLevel === 'HIGH RISK' || urlAnalysis.riskScore >= 50) {
      riskScore = Math.max(riskScore + 25, 60);
      indicators.push({
        type: 'warning',
        code: 'EMBEDDED_SUSPICIOUS_URL',
        text: `Message contains a suspicious link: ${rawUrl} (${urlAnalysis.riskLevel})`
      });
      recommendations.push(`Avoid opening the link: ${rawUrl}`);
    } else if (urlAnalysis.riskLevel === 'INVALID') {
      indicators.push({
        type: 'warning',
        code: 'EMBEDDED_INVALID_LINK',
        text: `Message contains a malformed or broken link structure: ${rawUrl}`
      });
    } else {
      indicators.push({
        type: 'info',
        code: 'EMBEDDED_URL_DETECTED',
        text: `Link analyzed: ${rawUrl} (${urlAnalysis.riskLevel})`
      });
    }
  }

  // Score clamping
  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // Classify Risk Level
  let riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
  let explanation = '';
  let verified = false;

  if (riskScore >= 80) {
    riskLevel = 'MALICIOUS';
    explanation = 'This communication exhibits high-confidence patterns of an active scam or phishing attack (such as credential theft, fraudulent prize claims, or malicious links).';
  } else if (riskScore >= 51) {
    riskLevel = 'HIGH RISK';
    explanation = 'Multiple social engineering triggers were identified (urgency, authority claims, or financial demands). High probability of fraudulent intent.';
  } else if (riskScore >= 20) {
    riskLevel = 'SUSPICIOUS';
    explanation = 'The message contains linguistic traits frequently associated with spam or unsolicited promotions. Exercise caution.';
  } else {
    // Low indicators, but we CANNOT call a random text message "SAFE" because attackers can send innocuous opening messages
    riskLevel = 'UNKNOWN / UNABLE TO VERIFY';
    explanation = 'No obvious automated phishing or scam keywords were flagged in this excerpt, but message safety cannot be guaranteed without verified sender origin.';
    recommendations.push('Always confirm the sender\'s identity using trusted contact details outside of this chat.');
  }

  if (recommendations.length === 0) {
    recommendations.push('Do not share sensitive passwords, PINs, or banking info in reply to unsolicited messages.');
  }

  return {
    riskLevel,
    riskScore,
    confidence: 85,
    verified,
    indicators,
    explanation,
    recommendations,
    source: 'message_security_engine',
    timestamp,
    details: {
      extractedUrls: extractedUrlAnalyses,
      detectedPatterns,
      flagsDetected: {
        urgency: urgencyHit,
        prize: prizeHit,
        credentials: credentialHit,
        financial: financialHit,
        authority: authorityHit
      }
    }
  };
}

module.exports = { analyzeMessage };
