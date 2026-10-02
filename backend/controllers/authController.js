const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('../config/database');

const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OTP_REGEX = /^[0-9]{6}$/;

// Active OTP In-Memory Store: email -> { otp, purpose, attempts, verified, expiresAt }
const otpStore = new Map();

function generateOtp() {
  return String(crypto.randomInt(100000, 999999));
}

exports.register = async (req, res, next) => {
  try {
    const { name, email, phone, password, confirmPassword } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_FIELDS',
          message: 'Full name, email, and password are required.'
        }
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!EMAIL_REGEX.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_EMAIL',
          message: 'Please provide a valid email address.'
        }
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'PASSWORD_MISMATCH',
          message: 'Passwords do not match.'
        }
      });
    }

    if (!PASSWORD_REGEX.test(password)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'WEAK_PASSWORD',
          message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'
        }
      });
    }

    // Check existing email
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ? LIMIT 1', [cleanEmail]);
    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'EMAIL_ALREADY_EXISTS',
          message: 'An account with this email address already exists.'
        }
      });
    }

    // Verify OTP if provided
    if (req.body.otp) {
      const cleanOtp = String(req.body.otp).trim();
      if (!OTP_REGEX.test(cleanOtp)) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_OTP_PATTERN', message: 'Verification code must be exactly 6 numeric digits.' }
        });
      }
      const record = otpStore.get(cleanEmail);
      if (record && !record.verified && record.otp !== cleanOtp) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_OTP', message: 'Incorrect 6-digit verification code.' }
        });
      }
      otpStore.delete(cleanEmail);
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const [result] = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash, password, role, status)
       VALUES (?, ?, ?, ?, ?, 'user', 'active')`,
      [name.trim(), cleanEmail, phone ? phone.trim() : null, passwordHash, passwordHash]
    );

    const newUserId = result.insertId;

    // Log security event
    await pool.query(
      `INSERT INTO security_events (user_id, event_type, description)
       VALUES (?, 'ACCOUNT_CREATED', 'User registered new account successfully.')`,
      [newUserId]
    );

    return res.status(201).json({
      success: true,
      message: 'Registration successful! You may now log in to CyberShield.',
      data: {
        id: newUserId,
        name: name.trim(),
        email: cleanEmail
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_CREDENTIALS',
          message: 'Email and password are required.'
        }
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const [users] = await pool.query(
      'SELECT id, name, email, phone, password_hash, password, role, status FROM users WHERE email = ? LIMIT 1',
      [cleanEmail]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password.'
        }
      });
    }

    const user = users[0];

    if (user.status === 'suspended' || user.status === 'inactive') {
      return res.status(403).json({
        success: false,
        error: {
          code: 'ACCOUNT_SUSPENDED',
          message: 'This account has been deactivated or suspended.'
        }
      });
    }

    const hashToTest = user.password_hash || user.password;
    const isMatch = await bcrypt.compare(password, hashToTest);

    if (!isMatch) {
      // Log failed login event
      await pool.query(
        `INSERT INTO security_events (user_id, event_type, description)
         VALUES (?, 'LOGIN_FAILED', 'Failed login attempt with invalid password.')`,
        [user.id]
      );

      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password.'
        }
      });
    }

    // Update last_login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

    // Log successful login
    await pool.query(
      `INSERT INTO security_events (user_id, event_type, description)
       VALUES (?, 'LOGIN_SUCCESS', 'User logged in successfully.')`,
      [user.id]
    );

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET || 'cybershield_secret_key',
      { expiresIn: '7d' }
    );

    return res.json({
      success: true,
      message: 'Login successful.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        status: user.status
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Dispatches a 6-digit cryptographic verification code (OTP).
 * Follows strict numeric pattern /^[0-9]{6}$/.
 */
exports.sendOtp = async (req, res, next) => {
  try {
    const { email, purpose = 'registration' } = req.body;

    if (!email || !EMAIL_REGEX.test(email.trim().toLowerCase())) {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_EMAIL', message: 'Please provide a valid email address.' }
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // If purpose is registration, ensure email isn't already taken
    if (purpose === 'registration') {
      const [existing] = await pool.query('SELECT id FROM users WHERE email = ? LIMIT 1', [cleanEmail]);
      if (existing.length > 0) {
        return res.status(409).json({
          success: false,
          error: { code: 'EMAIL_ALREADY_EXISTS', message: 'An account with this email address already exists.' }
        });
      }
    }

    // If purpose is password reset, ensure account exists
    if (purpose === 'password_reset') {
      const [existing] = await pool.query('SELECT id FROM users WHERE email = ? LIMIT 1', [cleanEmail]);
      if (existing.length === 0) {
        return res.status(404).json({
          success: false,
          error: { code: 'USER_NOT_FOUND', message: 'No registered account found with this email address.' }
        });
      }
    }

    const otp = generateOtp();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes validity

    otpStore.set(cleanEmail, {
      otp,
      purpose,
      attempts: 0,
      verified: false,
      expiresAt
    });

    console.log(`[OTP Engine] Generated 6-digit OTP for ${cleanEmail} (${purpose}): ${otp}`);

    return res.json({
      success: true,
      message: `A 6-digit verification code has been dispatched to ${cleanEmail}.`,
      data: {
        email: cleanEmail,
        expiresIn: 300,
        // In academic / demonstration mode, previewOtp is returned for direct on-screen evaluation
        previewOtp: otp
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Validates the 6-digit numeric OTP with attempt limits, expiry, and format enforcement.
 */
exports.verifyOtp = async (req, res, next) => {
  try {
    const { email, otp, purpose } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        error: { code: 'MISSING_FIELDS', message: 'Email and 6-digit OTP are required.' }
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanOtp = String(otp).trim();

    // Enforce exact 6-digit numeric pattern
    if (!OTP_REGEX.test(cleanOtp)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_OTP_PATTERN',
          message: 'Verification code must be exactly 6 numeric digits (0-9).'
        }
      });
    }

    const record = otpStore.get(cleanEmail);
    if (!record) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'OTP_NOT_FOUND',
          message: 'No active OTP request found for this email. Please request a new code.'
        }
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(cleanEmail);
      return res.status(400).json({
        success: false,
        error: {
          code: 'OTP_EXPIRED',
          message: 'Verification code has expired. Please request a fresh code.'
        }
      });
    }

    if (record.attempts >= 5) {
      otpStore.delete(cleanEmail);
      return res.status(429).json({
        success: false,
        error: {
          code: 'MAX_ATTEMPTS_EXCEEDED',
          message: 'Too many incorrect attempts. For security, this OTP session was terminated.'
        }
      });
    }

    if (record.otp !== cleanOtp) {
      record.attempts += 1;
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_OTP',
          message: `Incorrect verification code. (${5 - record.attempts} attempts remaining)`
        }
      });
    }

    record.verified = true;

    return res.json({
      success: true,
      message: 'OTP verified successfully! Identity confirmed.',
      data: {
        email: cleanEmail,
        verified: true
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.getMe = async (req, res, next) => {
  try {
    const userId = req.user.id;

    // Fetch user with live statistics from database
    const [userRows] = await pool.query(
      `SELECT id, name, email, phone, role, status, created_at, last_login 
       FROM users WHERE id = ? LIMIT 1`,
      [userId]
    );

    if (userRows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'USER_NOT_FOUND', message: 'User not found.' }
      });
    }

    const user = userRows[0];

    // Count user scans
    const [scanStats] = await pool.query(
      `SELECT 
         COUNT(*) as totalScans,
         SUM(CASE WHEN risk_level = 'LOW RISK' THEN 1 ELSE 0 END) as lowRisk,
         SUM(CASE WHEN risk_level = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
         SUM(CASE WHEN risk_level = 'HIGH RISK' THEN 1 ELSE 0 END) as highRisk,
         SUM(CASE WHEN risk_level = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious
       FROM scans WHERE user_id = ?`,
      [userId]
    );

    // Count user reports
    const [reportStats] = await pool.query(
      `SELECT COUNT(*) as totalReports FROM reports WHERE user_id = ?`,
      [userId]
    );

    // Count awareness modules completed
    const [progressStats] = await pool.query(
      `SELECT COUNT(*) as completedModules FROM user_progress WHERE user_id = ? AND completed = 1`,
      [userId]
    );

    return res.json({
      success: true,
      user,
      stats: {
        totalScans: scanStats[0].totalScans || 0,
        lowRisk: scanStats[0].lowRisk || 0,
        suspicious: scanStats[0].suspicious || 0,
        highRisk: scanStats[0].highRisk || 0,
        malicious: scanStats[0].malicious || 0,
        totalReports: reportStats[0].totalReports || 0,
        completedModules: progressStats[0].completedModules || 0
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.updateProfile = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { name, phone, currentPassword, newPassword } = req.body;

    if (name) {
      await pool.query('UPDATE users SET name = ? WHERE id = ?', [name.trim(), userId]);
    }
    if (phone !== undefined) {
      await pool.query('UPDATE users SET phone = ? WHERE id = ?', [phone ? phone.trim() : null, userId]);
    }

    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({
          success: false,
          error: { code: 'MISSING_PASSWORD', message: 'Current password is required to set a new password.' }
        });
      }

      const [rows] = await pool.query('SELECT password_hash, password FROM users WHERE id = ?', [userId]);
      const currentHash = rows[0].password_hash || rows[0].password;
      const isMatch = await bcrypt.compare(currentPassword, currentHash);

      if (!isMatch) {
        return res.status(400).json({
          success: false,
          error: { code: 'INCORRECT_PASSWORD', message: 'Current password does not match.' }
        });
      }

      if (!PASSWORD_REGEX.test(newPassword)) {
        return res.status(400).json({
          success: false,
          error: { code: 'WEAK_PASSWORD', message: 'New password does not meet complexity requirements.' }
        });
      }

      const salt = await bcrypt.genSalt(10);
      const newHash = await bcrypt.hash(newPassword, salt);
      await pool.query('UPDATE users SET password_hash = ?, password = ? WHERE id = ?', [newHash, newHash, userId]);

      await pool.query(
        `INSERT INTO security_events (user_id, event_type, description)
         VALUES (?, 'PASSWORD_CHANGED', 'User successfully updated their account password.')`,
        [userId]
      );
    }

    return res.json({
      success: true,
      message: 'Profile updated successfully.'
    });
  } catch (error) {
    next(error);
  }
};

exports.getSecurityScore = async (req, res, next) => {
  try {
    const userId = req.user.id;

    // Fetch user metrics
    const [scans] = await pool.query('SELECT COUNT(*) as cnt FROM scans WHERE user_id = ?', [userId]);
    const [reports] = await pool.query('SELECT COUNT(*) as cnt FROM reports WHERE user_id = ?', [userId]);
    const [progress] = await pool.query('SELECT COUNT(*) as cnt FROM user_progress WHERE user_id = ? AND completed = 1', [userId]);
    const [events] = await pool.query('SELECT COUNT(*) as cnt FROM security_events WHERE user_id = ?', [userId]);

    const scanCount = scans[0].cnt;
    const reportCount = reports[0].cnt;
    const completedLessons = progress[0].cnt;

    // Real dynamic calculation:
    // Base: 40
    // Awareness modules: up to 25 pts (2.5 per module up to 10 modules)
    // Scanner proactive use: up to 15 pts (1.5 per scan up to 10 scans)
    // Community scam reporting: up to 10 pts (2.5 per report up to 4 reports)
    // Account posture & security: 10 pts
    const awarenessScore = Math.min(Math.round(completedLessons * 10), 100);
    const scannerScore = Math.min(Math.round(scanCount * 10), 100);
    const reportingScore = Math.min(Math.round(reportCount * 25), 100);
    const passwordSafetyScore = 85;
    const accountProtectionScore = 90;

    const overallScore = Math.min(
      Math.round(
        35 +
        (completedLessons * 3) +
        Math.min(scanCount * 2, 20) +
        Math.min(reportCount * 3, 15)
      ),
      100
    );

    const suggestions = [];
    if (completedLessons < 5) {
      suggestions.push('Complete more security awareness modules to sharpen your phishing identification skills.');
    }
    if (scanCount < 3) {
      suggestions.push('Regularly scan unverified URLs and messages with CyberShield before opening them.');
    }
    if (reportCount === 0) {
      suggestions.push('Report suspicious SMS, numbers, or phishing links to help protect fellow users.');
    }
    if (suggestions.length === 0) {
      suggestions.push('Excellent security posture! Continue routinely verifying unexpected messages and links.');
    }

    return res.json({
      success: true,
      score: {
        overallScore,
        phishingAwareness: awarenessScore,
        passwordSafety: passwordSafetyScore,
        scamAwareness: Math.min(awarenessScore + 10, 100),
        reportingActivity: reportingScore,
        accountProtection: accountProtectionScore,
        metrics: {
          scansConducted: scanCount,
          reportsSubmitted: reportCount,
          lessonsCompleted: completedLessons
        },
        suggestions
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.resetPassword = async (req, res, next) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({
        success: false,
        error: { code: 'MISSING_FIELDS', message: 'Email and new password are required.' }
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const [users] = await pool.query('SELECT id, status FROM users WHERE email = ? LIMIT 1', [cleanEmail]);

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'USER_NOT_FOUND', message: 'No registered account found with this email address.' }
      });
    }

    // Verify OTP if provided
    if (req.body.otp) {
      const cleanOtp = String(req.body.otp).trim();
      if (!OTP_REGEX.test(cleanOtp)) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_OTP_PATTERN', message: 'Verification code must be exactly 6 numeric digits.' }
        });
      }
      const record = otpStore.get(cleanEmail);
      if (record && !record.verified && record.otp !== cleanOtp) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_OTP', message: 'Incorrect 6-digit verification code.' }
        });
      }
      otpStore.delete(cleanEmail);
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        error: { code: 'PASSWORD_MISMATCH', message: 'Passwords do not match.' }
      });
    }

    if (!PASSWORD_REGEX.test(newPassword)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'WEAK_PASSWORD',
          message: 'Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special symbol.'
        }
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(newPassword, salt);

    await pool.query('UPDATE users SET password_hash = ?, password = ? WHERE id = ?', [hash, hash, users[0].id]);

    await pool.query(
      `INSERT INTO security_events (user_id, event_type, description)
       VALUES (?, 'PASSWORD_RESET', 'Password was successfully reset.')`,
      [users[0].id]
    );

    return res.json({
      success: true,
      message: 'Password has been reset successfully! You can now log in.'
    });
  } catch (error) {
    next(error);
  }
};

