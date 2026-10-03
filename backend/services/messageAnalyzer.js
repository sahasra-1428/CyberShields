/**
 * CYBERSHIELD - ADVANCED MESSAGE SCAM ANALYZER
 *
 * Rule-based analysis.
 * No external API key required.
 *
 * Output format is compatible with scanController,
 * securityEngine and the MySQL scans table.
 */

const URL_REGEX = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi;

const EMAIL_REGEX =
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

const PHONE_REGEX =
  /(?:\+91[\s-]?)?[6-9]\d{9}\b/g;

const AMOUNT_REGEX =
  /(?:₹|rs\.?|inr)\s*[\d,]+(?:\.\d{1,2})?/gi;


/* =========================================================
   HELPERS
========================================================= */

function cleanText(value) {
  return String(value || "")
    .replace(/\r/g, " ")
    .replace(/\n+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function unique(values) {
  return [...new Set(values)];
}

function containsAny(text, words) {
  const lower = text.toLowerCase();

  return words.filter(word =>
    lower.includes(word.toLowerCase())
  );
}

function hasAnyRegex(text, patterns) {
  return patterns.some(pattern => pattern.test(text));
}

function extractUrls(text) {
  return unique(
    (text.match(URL_REGEX) || []).map(url =>
      url.replace(/[),.!?;:]+$/g, "")
    )
  );
}

function extractEmails(text) {
  return unique(text.match(EMAIL_REGEX) || []);
}

function extractPhones(text) {
  return unique(text.match(PHONE_REGEX) || []);
}

function extractAmounts(text) {
  return unique(text.match(AMOUNT_REGEX) || []);
}


/* =========================================================
   URL ANALYSIS INSIDE MESSAGE
========================================================= */

function analyzeMessageUrl(url) {

  const result = {
    url,
    riskScore: 0,
    indicators: []
  };

  let parsed;

  try {

    let normalized = url;

    if (/^www\./i.test(normalized)) {
      normalized = "https://" + normalized;
    }

    parsed = new URL(normalized);

  } catch (error) {

    result.riskScore += 30;

    result.indicators.push({
      type: "warning",
      code: "INVALID_URL",
      text: `The detected URL could not be parsed safely: ${url}`
    });

    return result;
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = parsed.href.toLowerCase();

  /* HTTPS */

  if (parsed.protocol !== "https:") {

    result.riskScore += 15;

    result.indicators.push({
      type: "warning",
      code: "NO_HTTPS",
      text: "The detected link does not use HTTPS."
    });

  } else {

    result.indicators.push({
      type: "positive",
      code: "HTTPS",
      text: "The detected link uses HTTPS."
    });
  }


  /* IP ADDRESS */

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {

    result.riskScore += 35;

    result.indicators.push({
      type: "alert",
      code: "IP_ADDRESS_URL",
      text: "The link uses an IP address instead of a normal domain name."
    });
  }


  /* URL SHORTENERS */

  const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "buff.ly"
  ];

  if (
    shorteners.some(domain =>
      hostname === domain || hostname.endsWith("." + domain)
    )
  ) {

    result.riskScore += 30;

    result.indicators.push({
      type: "alert",
      code: "SHORTENED_URL",
      text: "The link uses a URL-shortening service, hiding its final destination."
    });
  }


  /* @ SYMBOL */

  if (url.includes("@")) {

    result.riskScore += 25;

    result.indicators.push({
      type: "alert",
      code: "URL_AT_SYMBOL",
      text: "The URL contains '@', which can be used to disguise the actual destination."
    });
  }


  /* PUNYCODE */

  if (hostname.includes("xn--")) {

    result.riskScore += 35;

    result.indicators.push({
      type: "alert",
      code: "PUNYCODE_DOMAIN",
      text: "The domain uses punycode and may represent a look-alike domain."
    });
  }


  /* TOO MANY SUBDOMAINS */

  const domainParts = hostname.split(".");

  if (domainParts.length >= 5) {

    result.riskScore += 15;

    result.indicators.push({
      type: "warning",
      code: "MANY_SUBDOMAINS",
      text: "The domain contains an unusually large number of subdomains."
    });
  }


  /* SUSPICIOUS URL WORDS */

  const suspiciousUrlWords = [
    "verify",
    "verification",
    "secure",
    "security",
    "login",
    "signin",
    "account",
    "password",
    "wallet",
    "refund",
    "reward",
    "prize",
    "claim",
    "kyc",
    "update",
    "confirm"
  ];

  const matchedUrlWords = suspiciousUrlWords.filter(word =>
    fullUrl.includes(word)
  );

  if (matchedUrlWords.length > 0) {

    result.riskScore += Math.min(
      matchedUrlWords.length * 5,
      20
    );

    result.indicators.push({
      type: "warning",
      code: "SENSITIVE_URL_KEYWORDS",
      text:
        `The URL contains sensitive keywords: ${matchedUrlWords.join(", ")}.`
    });
  }


  /* EXECUTABLE FILE */

  if (
    /\.(exe|apk|scr|bat|cmd|msi|js)(\?|$)/i.test(parsed.pathname)
  ) {

    result.riskScore += 50;

    result.indicators.push({
      type: "alert",
      code: "DANGEROUS_FILE",
      text: "The link appears to point to a potentially executable file."
    });
  }


  /* SUSPICIOUS QUERY PARAMETERS */

  const sensitiveParameters = [
    "password",
    "passwd",
    "pwd",
    "otp",
    "pin",
    "cvv",
    "card",
    "token"
  ];

  const parameterNames = [
    ...parsed.searchParams.keys()
  ].map(key => key.toLowerCase());

  const sensitiveParams = parameterNames.filter(param =>
    sensitiveParameters.includes(param)
  );

  if (sensitiveParams.length > 0) {

    result.riskScore += 25;

    result.indicators.push({
      type: "alert",
      code: "SENSITIVE_URL_PARAMETERS",
      text:
        `The URL contains sensitive parameters: ${sensitiveParams.join(", ")}.`
    });
  }

  return result;
}


/* =========================================================
   MAIN MESSAGE ANALYZER
========================================================= */

async function analyzeMessage(rawMessage, options = {}) {

  const timestamp = new Date().toISOString();

  const message = cleanText(rawMessage);

  if (!message) {

    return {
      riskLevel: "INVALID",
      riskScore: 50,
      confidence: 100,
      verified: false,

      indicators: [
        {
          type: "error",
          code: "EMPTY_MESSAGE",
          text: "No message content was provided."
        }
      ],

      explanation:
        "Unable to analyze an empty message.",

      recommendations: [
        "Enter an SMS, email message or suspicious text for analysis."
      ],

      source: "message_security_engine",
      timestamp,

      details: {
        type: "message",
        messageLength: 0,
        urls: [],
        emails: [],
        phones: [],
        amounts: []
      }
    };
  }


  /* =======================================================
     EXTRACT DATA
  ======================================================= */

  const urls = extractUrls(message);
  const emails = extractEmails(message);
  const phones = extractPhones(message);
  const amounts = extractAmounts(message);


  let riskScore = 0;

  const indicators = [];
  const recommendations = [];
  const positiveSignals = [];

  const detectedCategories = [];


  /* =======================================================
     1. URGENCY / THREATS
  ======================================================= */

  const urgencyPatterns = [
    /\burgent\b/i,
    /\bimmediately\b/i,
    /\bact now\b/i,
    /\bdo not delay\b/i,
    /\blast warning\b/i,
    /\bfinal warning\b/i,
    /\bwithin\s+\d+\s*(minutes?|hours?|days?)\b/i,
    /\bexpires?\s+(today|soon)\b/i,
    /\baccount.{0,40}(blocked|suspended|closed)\b/i,
    /\bwill be blocked\b/i,
    /\bwill be suspended\b/i,
    /\blegal action\b/i,
    /\bpolice action\b/i
  ];

  const urgencyMatches = urgencyPatterns.filter(pattern =>
    pattern.test(message)
  );

  if (urgencyMatches.length > 0) {

    riskScore += Math.min(
      urgencyMatches.length * 10,
      30
    );

    detectedCategories.push("URGENCY");

    indicators.push({
      type: "warning",
      code: "URGENCY_LANGUAGE",
      text:
        "The message uses urgency, threat or time-pressure language."
    });

  } else {

    positiveSignals.push(
      "No strong urgency or threat language detected."
    );
  }


  /* =======================================================
     2. OTP / PASSWORD / CREDENTIALS
  ======================================================= */

  const credentialWords = [
    "otp",
    "one time password",
    "one-time password",
    "password",
    "passcode",
    "pin",
    "cvv",
    "card number",
    "account number",
    "net banking",
    "login",
    "sign in"
  ];

  const credentialMatches =
    containsAny(message, credentialWords);

  const requestWords = [
    "share",
    "send",
    "provide",
    "enter",
    "submit",
    "confirm",
    "verify",
    "tell",
    "give"
  ];

  const requestMatches =
    containsAny(message, requestWords);


  if (
    credentialMatches.length > 0 &&
    requestMatches.length > 0
  ) {

    riskScore += 35;

    detectedCategories.push("CREDENTIAL_REQUEST");

    indicators.push({
      type: "alert",
      code: "SENSITIVE_CREDENTIAL_REQUEST",
      text:
        `The message appears to request sensitive information: ${credentialMatches.join(", ")}.`
    });

    recommendations.push(
      "Never share OTPs, passwords, PINs or CVV numbers with another person."
    );

  } else if (credentialMatches.length > 0) {

    indicators.push({
      type: "info",
      code: "CREDENTIAL_REFERENCE",
      text:
        "The message mentions authentication or account credentials."
    });
  }


  /* =======================================================
     3. BANKING / PAYMENT / UPI
  ======================================================= */

  const financialWords = [
    "upi",
    "payment",
    "pay now",
    "pay immediately",
    "bank",
    "bank account",
    "credit card",
    "debit card",
    "transaction",
    "transfer",
    "wallet",
    "refund",
    "cashback",
    "fee",
    "fine",
    "penalty",
    "kyc"
  ];

  const financialMatches =
    containsAny(message, financialWords);


  const financialActionPatterns = [
    /\bpay\b/i,
    /\bsend\b/i,
    /\btransfer\b/i,
    /\bdeposit\b/i,
    /\bclick\b/i,
    /\bverify\b/i,
    /\bconfirm\b/i,
    /\bscan\b/i
  ];

  const financialAction =
    hasAnyRegex(message, financialActionPatterns);


  if (
    financialMatches.length > 0 &&
    financialAction
  ) {

    riskScore += 20;

    detectedCategories.push("FINANCIAL_REQUEST");

    indicators.push({
      type: "warning",
      code: "FINANCIAL_ACTION",
      text:
        `Financial/payment terms combined with an action request: ${financialMatches.join(", ")}.`
    });

    recommendations.push(
      "Verify payment requests through the organization's official app or website."
    );

  } else if (financialMatches.length > 0) {

    positiveSignals.push(
      "Financial or billing terminology detected without a strong payment-action request."
    );
  }


  /* =======================================================
     4. PRIZE / LOTTERY / REWARD
  ======================================================= */

  const prizePatterns = [
    /\byou have won\b/i,
    /\byou won\b/i,
    /\bcongratulations\b/i,
    /\blottery\b/i,
    /\bjackpot\b/i,
    /\bprize\b/i,
    /\breward\b/i,
    /\bfree gift\b/i,
    /\blucky winner\b/i,
    /\bcash prize\b/i,
    /\bbonus\b/i
  ];

  const prizeMatches = prizePatterns.filter(pattern =>
    pattern.test(message)
  );

  if (prizeMatches.length > 0) {

    riskScore += 30;

    detectedCategories.push("PRIZE_SCAM");

    indicators.push({
      type: "alert",
      code: "PRIZE_REWARD_PATTERN",
      text:
        "The message contains prize, lottery, reward or unexpected-gift language."
    });

    recommendations.push(
      "Do not pay fees or provide banking information to claim an unexpected prize."
    );
  }


  /* =======================================================
     5. PERSONAL INFORMATION
  ======================================================= */

  const personalInfoWords = [
    "aadhaar",
    "aadhar",
    "pan card",
    "date of birth",
    "dob",
    "address",
    "identity proof",
    "bank details",
    "account details",
    "personal details"
  ];

  const personalInfoMatches =
    containsAny(message, personalInfoWords);


  if (
    personalInfoMatches.length > 0 &&
    requestMatches.length > 0
  ) {

    riskScore += 25;

    detectedCategories.push("PERSONAL_DATA_REQUEST");

    indicators.push({
      type: "alert",
      code: "PERSONAL_INFORMATION_REQUEST",
      text:
        `The message appears to request personal information: ${personalInfoMatches.join(", ")}.`
    });

    recommendations.push(
      "Do not submit Aadhaar, PAN, banking or identity information through an unverified message."
    );
  }


  /* =======================================================
     6. SOCIAL ENGINEERING
  ======================================================= */

  const socialEngineeringPatterns = [
    /\bclick here\b/i,
    /\bclick the link\b/i,
    /\bclaim now\b/i,
    /\bverify now\b/i,
    /\bconfirm now\b/i,
    /\blogin immediately\b/i,
    /\bupdate immediately\b/i,
    /\bdownload now\b/i,
    /\binstall this app\b/i,
    /\bcontact immediately\b/i,
    /\bcall immediately\b/i,
    /\bdo not tell anyone\b/i,
    /\bkeep this confidential\b/i
  ];

  const socialMatches =
    socialEngineeringPatterns.filter(pattern =>
      pattern.test(message)
    );

  if (socialMatches.length > 0) {

    riskScore += Math.min(
      socialMatches.length * 8,
      25
    );

    detectedCategories.push("SOCIAL_ENGINEERING");

    indicators.push({
      type: "warning",
      code: "SOCIAL_ENGINEERING",
      text:
        "The message contains language commonly used to persuade recipients into immediate action."
    });
  }


  /* =======================================================
     7. DOWNLOAD / APP INSTALLATION
  ======================================================= */

  const downloadPatterns = [
    /\bdownload\b/i,
    /\binstall\b/i,
    /\bapk\b/i,
    /\bapplication\b/i,
    /\bapp\b/i
  ];

  const downloadMatches =
    downloadPatterns.filter(pattern =>
      pattern.test(message)
    );


  if (
    downloadMatches.length > 0 &&
    urls.length > 0
  ) {

    riskScore += 25;

    detectedCategories.push("DOWNLOAD_REQUEST");

    indicators.push({
      type: "alert",
      code: "EXTERNAL_DOWNLOAD",
      text:
        "The message contains a link together with download or app-installation language."
    });

    recommendations.push(
      "Do not install APKs or applications received through unknown messages."
    );
  }


  /* =======================================================
     8. URL ANALYSIS
  ======================================================= */

  const analyzedUrls = [];

  for (const url of urls) {

    const analysis = analyzeMessageUrl(url);

    analyzedUrls.push(analysis);

    riskScore += Math.min(
      analysis.riskScore,
      35
    );

    indicators.push(
      ...analysis.indicators
    );
  }


  if (urls.length > 0) {

    indicators.push({
      type: "info",
      code: "URL_DETECTED",
      text:
        `${urls.length} web link(s) detected in the message.`
    });

  } else {

    positiveSignals.push(
      "No web links were detected in the message."
    );
  }


  /* =======================================================
     9. EMAIL ANALYSIS
  ======================================================= */

  if (emails.length > 0) {

    indicators.push({
      type: "info",
      code: "EMAIL_DETECTED",
      text:
        `${emails.length} email address(es) detected.`
    });

    positiveSignals.push(
      `Email address(es) detected: ${emails.join(", ")}`
    );
  }


  /* =======================================================
     10. PHONE ANALYSIS
  ======================================================= */

  if (phones.length > 0) {

    indicators.push({
      type: "info",
      code: "PHONE_DETECTED",
      text:
        `${phones.length} Indian phone number(s) detected.`
    });

    if (
      /\b(call|contact|whatsapp|message)\b/i.test(message)
    ) {

      riskScore += 10;

      indicators.push({
        type: "warning",
        code: "CONTACT_REQUEST",
        text:
          "The message asks the recipient to contact a phone number."
      });
    }
  }


  /* =======================================================
     11. MONEY / BILL AMOUNTS
  ======================================================= */

  if (amounts.length > 0) {

    indicators.push({
      type: "info",
      code: "MONEY_AMOUNT_DETECTED",
      text:
        `Money amount(s) detected: ${amounts.join(", ")}`
    });
  }


  /* =======================================================
     12. BILLING MESSAGE DETECTION
  ======================================================= */

  const billingWords = [
    "bill",
    "bill period",
    "amount payable",
    "payment due date",
    "due date",
    "invoice",
    "statement",
    "billing",
    "monthly bill"
  ];

  const billingMatches =
    containsAny(message, billingWords);


  const billingStructurePatterns = [
    /\bbill period\b/i,
    /\btotal amount payable\b/i,
    /\bpayment due date\b/i,
    /\bdue date\b/i
  ];

  const structuredBilling =
    billingStructurePatterns.filter(pattern =>
      pattern.test(message)
    );


  if (
    billingMatches.length >= 2 &&
    structuredBilling.length >= 1
  ) {

    positiveSignals.push(
      "The message contains structured billing information such as bill period, amount payable or payment due date."
    );

    indicators.push({
      type: "positive",
      code: "STRUCTURED_BILLING",
      text:
        "Structured billing/statement pattern detected."
    });

    // Billing information alone is NOT a scam indicator.
    riskScore -= 10;
  }


  /* =======================================================
     13. COMPANY / BRAND REFERENCES
  ======================================================= */

  const organizations = [
    "jio",
    "jiohome",
    "airtel",
    "vi",
    "vodafone",
    "sbi",
    "hdfc",
    "icici",
    "axis bank",
    "paytm",
    "phonepe",
    "amazon",
    "flipkart",
    "google",
    "microsoft",
    "apple",
    "whatsapp",
    "instagram",
    "facebook"
  ];

  const detectedOrganizations =
    containsAny(message, organizations);


  if (detectedOrganizations.length > 0) {

    indicators.push({
      type: "info",
      code: "ORGANIZATION_REFERENCE",
      text:
        `Organization/company references detected: ${detectedOrganizations.join(", ")}`
    });
  }


  /* =======================================================
     14. OFFICIAL DOMAIN MATCH
  ======================================================= */

  const officialDomains = {
    jio: [
      "jio.com"
    ],

    airtel: [
      "airtel.in"
    ],

    amazon: [
      "amazon.in",
      "amazon.com"
    ],

    flipkart: [
      "flipkart.com"
    ],

    paytm: [
      "paytm.com"
    ],

    phonepe: [
      "phonepe.com"
    ],

    google: [
      "google.com"
    ],

    microsoft: [
      "microsoft.com"
    ],

    apple: [
      "apple.com"
    ]
  };


  let officialDomainFound = false;


  for (const urlAnalysis of analyzedUrls) {

    try {

      let normalized = urlAnalysis.url;

      if (/^www\./i.test(normalized)) {
        normalized = "https://" + normalized;
      }

      const parsed = new URL(normalized);

      const hostname =
        parsed.hostname.toLowerCase();

      for (const organization of detectedOrganizations) {

        const domains =
          officialDomains[organization];

        if (!domains) continue;

        const matches =
          domains.some(domain =>
            hostname === domain ||
            hostname.endsWith("." + domain)
          );

        if (matches) {

          officialDomainFound = true;

          positiveSignals.push(
            `The detected link uses a domain associated with ${organization}: ${hostname}`
          );

          indicators.push({
            type: "positive",
            code: "KNOWN_OFFICIAL_DOMAIN",
            text:
              `The link domain matches a known official domain associated with ${organization}.`
          });

        } else if (
          detectedOrganizations.length > 0 &&
          /https?:\/\//i.test(urlAnalysis.url)
        ) {

          indicators.push({
            type: "warning",
            code: "DOMAIN_REQUIRES_VERIFICATION",
            text:
              `The message references ${organization}, but the detected link should be independently verified.`
          });
        }
      }

    } catch (error) {
      // Already handled by URL analysis.
    }
  }


  /* =======================================================
     15. GENERIC FREE EMAIL + COMPANY IMPERSONATION
  ======================================================= */

  const genericEmailDomains = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "rediffmail.com"
  ];


  for (const email of emails) {

    const domain =
      email.split("@")[1]?.toLowerCase();

    if (
      domain &&
      genericEmailDomains.includes(domain) &&
      detectedOrganizations.length > 0
    ) {

      if (
        requestMatches.length > 0 ||
        credentialMatches.length > 0 ||
        financialMatches.length > 0
      ) {

        riskScore += 15;

        indicators.push({
          type: "warning",
          code: "GENERIC_EMAIL_IMPERSONATION",
          text:
            `The message references an organization but uses a generic email provider: ${email}`
        });
      }
    }
  }


  /* =======================================================
     16. REPEATED EXCLAMATION / ALL CAPS
  ======================================================= */

  const exclamationCount =
    (message.match(/!/g) || []).length;

  if (exclamationCount >= 4) {

    riskScore += 5;

    indicators.push({
      type: "warning",
      code: "EXCESSIVE_EXCLAMATION",
      text:
        "The message uses unusually strong punctuation."
    });
  }


  const uppercaseLetters =
    (message.match(/[A-Z]/g) || []).length;

  const lowercaseLetters =
    (message.match(/[a-z]/g) || []).length;


  if (
    uppercaseLetters > 20 &&
    uppercaseLetters > lowercaseLetters * 1.5
  ) {

    riskScore += 5;

    indicators.push({
      type: "warning",
      code: "EXCESSIVE_CAPITALIZATION",
      text:
        "The message contains unusually high capitalization."
    });
  }


  /* =======================================================
     17. FINAL SCORE
  ======================================================= */

  riskScore = Math.round(
    Math.max(
      0,
      Math.min(
        100,
        riskScore
      )
    )
  );


  /* =======================================================
     18. RISK LEVEL
  ======================================================= */

  let riskLevel;

  if (riskScore >= 70) {

    riskLevel = "MALICIOUS";

  } else if (riskScore >= 45) {

    riskLevel = "HIGH RISK";

  } else if (riskScore >= 20) {

    riskLevel = "SUSPICIOUS";

  } else {

    riskLevel = "LOW RISK";
  }


  /* =======================================================
     19. CONFIDENCE
  ======================================================= */

  let confidence = 55;

  if (message.length > 50) {
    confidence += 5;
  }

  if (urls.length > 0) {
    confidence += 10;
  }

  if (emails.length > 0) {
    confidence += 5;
  }

  if (detectedCategories.length > 0) {
    confidence += 10;
  }

  if (indicators.length >= 5) {
    confidence += 5;
  }

  confidence =
    Math.min(95, confidence);


  /* =======================================================
     20. EXPLANATION
  ======================================================= */

  let explanation;

  if (riskLevel === "MALICIOUS") {

    explanation =
      "The message contains multiple strong indicators associated with scam, phishing or social-engineering activity.";

  } else if (riskLevel === "HIGH RISK") {

    explanation =
      "The message contains several characteristics that require caution before clicking links, sharing information or making payments.";

  } else if (riskLevel === "SUSPICIOUS") {

    explanation =
      "The message contains some characteristics that require verification before taking action.";

  } else {

    explanation =
      "The message did not trigger significant scam indicators under the current rule-based analysis.";
  }


  /* =======================================================
     21. RECOMMENDATIONS
  ======================================================= */

  if (riskLevel === "MALICIOUS") {

    recommendations.push(
      "Do not click links in this message."
    );

    recommendations.push(
      "Do not share OTP, PIN, password, CVV or banking information."
    );

    recommendations.push(
      "Do not transfer money based only on this message."
    );

    recommendations.push(
      "Verify the organization using its official website or application."
    );

  } else if (riskLevel === "HIGH RISK") {

    recommendations.push(
      "Verify the sender independently before taking action."
    );

    recommendations.push(
      "Avoid clicking unfamiliar links."
    );

    recommendations.push(
      "Never share OTPs, passwords, PINs or CVV numbers."
    );

  } else if (riskLevel === "SUSPICIOUS") {

    recommendations.push(
      "Verify the sender and destination before taking action."
    );

    recommendations.push(
      "Use the organization's official application or website where possible."
    );

  } else {

    recommendations.push(
      "No major scam indicators were detected."
    );

    recommendations.push(
      "For financial or account-related messages, independently verify important information through the official app or website."
    );
  }


  /* =======================================================
     22. REMOVE DUPLICATES
  ======================================================= */

  const uniqueIndicators = [];

  const indicatorKeys = new Set();

  for (const indicator of indicators) {

    const key =
      `${indicator.code}|${indicator.text}`;

    if (!indicatorKeys.has(key)) {

      indicatorKeys.add(key);
      uniqueIndicators.push(indicator);
    }
  }


  /* =======================================================
     23. RETURN RESULT
  ======================================================= */

  return {

    riskLevel,

    riskScore,

    confidence,

    verified: false,

    indicators: uniqueIndicators,

    explanation,

    recommendations: unique(recommendations),

    source: "message_security_engine",

    timestamp,

    details: {

      type: "message",

      messageLength: message.length,

      urls,

      analyzedUrls,

      emails,

      phones,

      amounts,

      organizations: detectedOrganizations,

      billingIndicators: billingMatches,

      structuredBillingIndicators: structuredBilling,

      urgencyIndicators: urgencyMatches.length,

      credentialIndicators: credentialMatches,

      financialIndicators: financialMatches,

      prizeIndicators: prizeMatches.length,

      personalInformationIndicators: personalInfoMatches,

      socialEngineeringIndicators: socialMatches.length,

      downloadIndicators: downloadMatches,

      detectedCategories,

      officialDomainFound,

      positiveSignals: unique(positiveSignals)
    }
  };
}


/* =========================================================
   EXPORT
========================================================= */

module.exports = {
  analyzeMessage
};
