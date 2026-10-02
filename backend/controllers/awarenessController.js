const pool = require('../config/database');

exports.getModules = async (req, res, next) => {
  try {
    const userId = req.user ? req.user.id : null;

    let query = `
      SELECT m.id, m.title, m.category, m.content, m.created_at,
             COALESCE(p.completed, 0) as is_completed,
             p.completed_at
      FROM awareness_modules m
      LEFT JOIN user_progress p ON m.id = p.module_id AND p.user_id = ?
      ORDER BY m.id ASC
    `;

    const [rows] = await pool.query(query, [userId]);

    const formatted = rows.map(r => ({
      id: r.id,
      title: r.title,
      category: r.category,
      content: typeof r.content === 'string' ? JSON.parse(r.content) : r.content,
      isCompleted: Boolean(r.is_completed),
      completedAt: r.completed_at
    }));

    return res.json({
      success: true,
      modules: formatted
    });
  } catch (error) {
    next(error);
  }
};

exports.getModuleById = async (req, res, next) => {
  try {
    const moduleId = req.params.id;
    const userId = req.user ? req.user.id : null;

    const [rows] = await pool.query(
      `SELECT m.*, COALESCE(p.completed, 0) as is_completed, p.completed_at
       FROM awareness_modules m
       LEFT JOIN user_progress p ON m.id = p.module_id AND p.user_id = ?
       WHERE m.id = ?`,
      [userId, moduleId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Awareness lesson not found.' }
      });
    }

    const row = rows[0];
    return res.json({
      success: true,
      module: {
        id: row.id,
        title: row.title,
        category: row.category,
        content: typeof row.content === 'string' ? JSON.parse(row.content) : row.content,
        isCompleted: Boolean(row.is_completed),
        completedAt: row.completed_at
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.completeModule = async (req, res, next) => {
  try {
    const moduleId = req.params.id;
    const userId = req.user.id;

    // Verify module exists
    const [mod] = await pool.query('SELECT id, title FROM awareness_modules WHERE id = ?', [moduleId]);
    if (mod.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Awareness module does not exist.' }
      });
    }

    // Upsert into user_progress
    await pool.query(
      `INSERT INTO user_progress (user_id, module_id, completed, score, completed_at)
       VALUES (?, ?, 1, 100, NOW())
       ON DUPLICATE KEY UPDATE completed = 1, completed_at = NOW()`,
      [userId, moduleId]
    );

    // Record security event
    await pool.query(
      `INSERT INTO security_events (user_id, event_type, description)
       VALUES (?, 'LESSON_COMPLETED', ?)`,
      [userId, `Completed security awareness lesson: ${mod[0].title}`]
    );

    return res.json({
      success: true,
      message: `Lesson "${mod[0].title}" marked as completed!`
    });
  } catch (error) {
    next(error);
  }
};

/**
 * 10 Real-World Scenario Questions Assessing Cyber Crime Awareness
 */
const CYBER_CRIME_QUIZ_QUESTIONS = [
  {
    id: 1,
    category: 'Phishing URLs',
    scenario: "You receive an SMS: 'Your Netflix account is on hold. Update billing: https://netflix.com.account-update-portal.xyz/pay'. What is the true destination website?",
    options: [
      "netflix.com because it appears first in the address.",
      "account-update-portal.xyz because it is the actual registered domain before the slash.",
      "A secure Netflix billing subdomain.",
      "It is impossible to tell without opening the website."
    ],
    correctIndex: 1,
    explanation: "Attackers use 'Subdomain Stacking' to fool your eyes. Reading backward from the first single forward slash (/) reveals the actual host: account-update-portal.xyz, NOT Netflix."
  },
  {
    id: 2,
    category: 'Digital Arrest Scam',
    scenario: "A caller in police uniform on a Skype video call shows an official-looking CBI warrant and states you are under 'Digital Arrest' for a seized contraband parcel. What should you do?",
    options: [
      "Stay on the video call and transfer money to the 'Supreme Court RBI safety account' to prove innocence.",
      "Disconnect immediately and report to local police or cybercrime.gov.in (Dial 1930) — Digital Arrest does not exist in law.",
      "Lock yourself in a room as ordered until the video interrogation concludes.",
      "Show your Aadhaar card and bank passbook to clear your name."
    ],
    correctIndex: 1,
    explanation: "'Digital Arrest' is a complete cyber fraud fabrication. Under Indian and international law, police and courts NEVER conduct trials, interrogations, or arrests via video calls, nor do they demand money to verify funds."
  },
  {
    id: 3,
    category: 'UPI & OTP Security',
    scenario: "You listed furniture for sale online. A buyer messages: 'I will pay you ₹5,000 via Google Pay. Please enter your UPI PIN and recite the SMS OTP to accept the payment.' What happens if you do this?",
    options: [
      "You will immediately receive ₹5,000 into your bank account.",
      "Money will be DEDUCTED from your account because UPI PIN and OTP are strictly used to debit/send money, never to receive it.",
      "The payment will enter escrow until verified.",
      "Google Pay customer care will verify the buyer's identity."
    ],
    correctIndex: 1,
    explanation: "The Golden Rule of UPI: You NEVER need to enter your UPI PIN or disclose an OTP to receive money. A PIN or OTP is exclusively used to authorize debits from your bank."
  },
  {
    id: 4,
    category: 'SMS Urgency Traps',
    scenario: "An SMS arrives at 7:00 PM: 'Dear consumer, power will be disconnected at 9:30 PM tonight due to unpaid bill. Call officer immediately at 9812345678.' What is the safest action?",
    options: [
      "Call the mobile number in the SMS to quickly clear the bill before electricity is cut.",
      "Download the AnyDesk / QuickSupport APK link provided by the officer to test the connection.",
      "Check your official electricity board portal or physical bill, and ignore the personal mobile number.",
      "Reply to the SMS with your electricity meter number and PAN card."
    ],
    correctIndex: 2,
    explanation: "Utility providers issue written statutory notices and official bills. They never issue sudden same-day disconnection threats via personal 10-digit mobile numbers."
  },
  {
    id: 5,
    category: 'Typosquatting',
    scenario: "You receive an email from 'PayPal Customer Care <service@paypa1.com>' stating your account was restricted. What indicates this is fake?",
    options: [
      "PayPal never restricts accounts.",
      "The domain uses the number '1' instead of lowercase 'l' (paypa1.com).",
      "Emails with the word 'service' are always blocked by spam filters.",
      "It arrived in your Primary Inbox instead of the spam folder."
    ],
    correctIndex: 1,
    explanation: "This is Typosquatting. Scammers register visually similar domains (replacing lowercase 'l' with number '1' or 'o' with '0') to deceive inattentive recipients."
  },
  {
    id: 6,
    category: 'Quishing / QR Fraud',
    scenario: "You are at a public parking meter. A new sticker QR code has been placed over the official payment barcode stating 'Quick Pay Parking Here'. What risk does this present?",
    options: [
      "No risk — QR codes are inherently encrypted and tamper-proof.",
      "The physical sticker could redirect your phone to a fake payment gateway or malicious UPI handle (Quishing).",
      "It will only work if your device has NFC enabled.",
      "QR codes can only contain plain text, never executable or redirection links."
    ],
    correctIndex: 1,
    explanation: "Quishing (QR Phishing) involves pasting malicious QR stickers over legitimate payment points, tricking victims into sending money directly to fraudster accounts."
  },
  {
    id: 7,
    category: 'Prepaid Task Scams',
    scenario: "A recruiter on Telegram offers ₹3,000/day for 'liking YouTube videos'. After paying you ₹150 for your first task, they ask you to deposit ₹2,000 into a 'crypto pool' to unlock ₹10,000. What is this?",
    options: [
      "A legitimate freelance performance incentive program.",
      "A classic 'Prepaid Task Scam' designed to lure victims with small initial payouts before stealing larger deposits.",
      "An affiliate marketing program authorized by YouTube.",
      "A bank-approved escrow trading channel."
    ],
    correctIndex: 1,
    explanation: "Prepaid task scams pay tiny amounts initially to build false trust, then demand increasingly large 'recharge' deposits that can never be withdrawn."
  },
  {
    id: 8,
    category: 'The HTTPS / Padlock Myth',
    scenario: "A website displays a secure green padlock icon (https://) in the browser address bar. Does this guarantee the website is genuine and safe?",
    options: [
      "Yes, HTTPS certificates are only issued to verified legitimate corporations.",
      "No, HTTPS only encrypts communication; scammers obtain free SSL certificates for fake websites in minutes.",
      "Yes, modern web browsers automatically block all malicious HTTPS sites.",
      "No, unless the website also displays an ISO certification seal."
    ],
    correctIndex: 1,
    explanation: "HTTPS encrypts the data in transit between browser and server, but over 82% of active phishing websites use free HTTPS certificates. Padlock = Encryption, NOT Authenticity."
  },
  {
    id: 9,
    category: 'Malware Attachments',
    scenario: "An unexpected email with subject 'Pending Tax Invoice #8921' includes an attachment named 'Tax_Invoice_8921.pdf.exe'. What should you do?",
    options: [
      "Double-click to open it because it contains the word 'Invoice'.",
      "Forward it to your colleagues to see if they recognize the invoice.",
      "Do NOT open it — double file extensions (.pdf.exe) are a classic technique to camouflage executable trojans or ransomware.",
      "Rename the file to .pdf and open it safely."
    ],
    correctIndex: 2,
    explanation: "Attackers append fake extensions (e.g. .pdf.exe or .jpg.vbs) so Windows hides the dangerous executable suffix. Opening this executes malicious code."
  },
  {
    id: 10,
    category: 'Cybercrime Reporting (India)',
    scenario: "If you realize you have been defrauded in an online financial scam in India, what is the single most urgent national helpline to dial immediately within the Golden Hour?",
    options: [
      "Dial 100 or 108",
      "Dial 1930 (National Cyber Crime Reporting Portal helpline) or visit cybercrime.gov.in.",
      "Dial your mobile telecom customer care line.",
      "Wait 48 hours for the bank transaction to settle before taking action."
    ],
    correctIndex: 1,
    explanation: "Dialing 1930 immediately alerts the Citizen Financial Cyber Fraud Reporting System to freeze fraudulent recipient accounts before the cybercriminals withdraw the stolen funds."
  }
];

exports.getQuizQuestions = async (req, res, next) => {
  try {
    // Return questions with options and metadata, withholding the correctIndex until client submits
    const clientQuestions = CYBER_CRIME_QUIZ_QUESTIONS.map(q => ({
      id: q.id,
      category: q.category,
      scenario: q.scenario,
      options: q.options
    }));

    return res.json({
      success: true,
      totalQuestions: clientQuestions.length,
      questions: clientQuestions
    });
  } catch (error) {
    next(error);
  }
};

exports.submitQuizScore = async (req, res, next) => {
  try {
    const { answers } = req.body; // e.g. { "1": 1, "2": 1, ... }
    const userId = req.user ? req.user.id : null;

    if (!answers || typeof answers !== 'object') {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_ANSWERS', message: 'Answers payload must be an object with question IDs.' }
      });
    }

    const submittedIds = Object.keys(answers).map(Number);
    const isSingleCheck = submittedIds.length === 1;

    let correctCount = 0;
    const review = [];

    // If single question check, only evaluate the submitted question
    const questionsToEvaluate = isSingleCheck
      ? CYBER_CRIME_QUIZ_QUESTIONS.filter(q => submittedIds.includes(q.id))
      : CYBER_CRIME_QUIZ_QUESTIONS;

    questionsToEvaluate.forEach(q => {
      const selectedIndex = answers[q.id] !== undefined ? Number(answers[q.id]) : -1;
      const isCorrect = selectedIndex === q.correctIndex;
      if (isCorrect) correctCount++;

      review.push({
        id: q.id,
        category: q.category,
        scenario: q.scenario,
        selectedIndex,
        correctIndex: q.correctIndex,
        selectedOption: selectedIndex >= 0 ? (q.options[selectedIndex] || 'Invalid Choice') : 'Skipped',
        correctOption: q.options[q.correctIndex],
        isCorrect,
        explanation: q.explanation
      });
    });

    const totalCount = isSingleCheck ? 1 : CYBER_CRIME_QUIZ_QUESTIONS.length;
    const scorePercentage = Math.round((correctCount / totalCount) * 100);

    let resilienceLevel = 'VULNERABLE';
    let badge = '🚨 High Risk of Victimization';
    if (scorePercentage >= 90) {
      resilienceLevel = 'ELITE_DEFENDER';
      badge = '🛡️ Elite Cyber Defender';
    } else if (scorePercentage >= 70) {
      resilienceLevel = 'VIGILANT_CITIZEN';
      badge = '✓ Vigilant Cyber Citizen';
    } else if (scorePercentage >= 50) {
      resilienceLevel = 'DEVELOPING_AWARENESS';
      badge = '⚠️ Developing Cyber Awareness';
    }

    // Only log security event on full quiz completion (not single intermediate checks)
    if (userId && !isSingleCheck) {
      await pool.query(
        `INSERT INTO security_events (user_id, event_type, description)
         VALUES (?, 'QUIZ_COMPLETED', ?)`,
        [userId, `Completed Cyber Crime Readiness Quiz: ${correctCount}/10 (${scorePercentage}%) - ${resilienceLevel}`]
      );
    }

    return res.json({
      success: true,
      results: {
        score: correctCount,
        total: totalCount,
        percentage: scorePercentage,
        resilienceLevel,
        badge,
        review
      }
    });
  } catch (error) {
    next(error);
  }
};


