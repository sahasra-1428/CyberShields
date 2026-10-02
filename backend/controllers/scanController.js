const pool = require('../config/database');
const securityEngine = require('../services/securityEngine');

/**
 * Saves analysis result into MySQL scans table.
 */
async function recordScan(userId, scanType, inputValue, analysis) {
  try {
    const normalized = analysis.details?.normalizedUrl ||
                       analysis.details?.normalizedPhone ||
                       analysis.details?.email ||
                       inputValue;

    const [result] = await pool.query(
      `INSERT INTO scans 
       (user_id, scan_type, input_value, normalized_value, risk_level, risk_score, confidence, verified, indicators, recommendations, source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId || null,
        scanType,
        inputValue.slice(0, 5000),
        String(normalized).slice(0, 1000),
        analysis.riskLevel,
        analysis.riskScore,
        analysis.confidence || 85,
        analysis.verified ? 1 : 0,
        JSON.stringify(analysis.indicators || []),
        JSON.stringify(analysis.recommendations || []),
        analysis.source || 'security_engine'
      ]
    );
    return result.insertId;
  } catch (err) {
    console.error('[DB] Failed to record scan:', err.message);
    return null;
  }
}

exports.scanUrl = async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Please provide a URL to analyze.' }
      });
    }

    const analysis = await securityEngine.analyzeUrl(url);
    const scanId = await recordScan(req.user?.id, 'url', url, analysis);

    return res.json({
      success: true,
      scanId,
      analysis
    });
  } catch (error) {
    next(error);
  }
};

exports.scanMessage = async (req, res, next) => {
  try {
    const { message } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Please provide message content to analyze.' }
      });
    }

    const analysis = await securityEngine.analyzeMessage(message);
    const scanId = await recordScan(req.user?.id, 'message', message, analysis);

    return res.json({
      success: true,
      scanId,
      analysis
    });
  } catch (error) {
    next(error);
  }
};

exports.scanEmail = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Please provide an email address to analyze.' }
      });
    }

    const analysis = await securityEngine.analyzeEmail(email);
    const scanId = await recordScan(req.user?.id, 'email', email, analysis);

    return res.json({
      success: true,
      scanId,
      analysis
    });
  } catch (error) {
    next(error);
  }
};

exports.scanPhone = async (req, res, next) => {
  try {
    const { phone } = req.body;
    if (!phone || typeof phone !== 'string') {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Please provide a phone number to analyze.' }
      });
    }

    const analysis = await securityEngine.analyzePhone(phone);
    const scanId = await recordScan(req.user?.id, 'phone', phone, analysis);

    return res.json({
      success: true,
      scanId,
      analysis
    });
  } catch (error) {
    next(error);
  }
};

exports.scanQr = async (req, res, next) => {
  try {
    const { content } = req.body;
    if (!content || typeof content !== 'string') {
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'Please provide decoded QR code content.' }
      });
    }

    const analysis = await securityEngine.analyzeQrContent(content);
    const scanId = await recordScan(req.user?.id, 'qr', content, analysis);

    return res.json({
      success: true,
      scanId,
      analysis
    });
  } catch (error) {
    next(error);
  }
};

exports.getScans = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { type, risk, search, page = 1, limit = 20 } = req.query;

    let query = 'SELECT * FROM scans WHERE user_id = ?';
    const params = [userId];

    if (type && type !== 'all') {
      query += ' AND scan_type = ?';
      params.push(type.toLowerCase());
    }

    if (risk && risk !== 'all') {
      query += ' AND risk_level = ?';
      params.push(risk.toUpperCase());
    }

    if (search && search.trim()) {
      query += ' AND (input_value LIKE ? OR normalized_value LIKE ?)';
      params.push(`%${search.trim()}%`, `%${search.trim()}%`);
    }

    // Count total for pagination
    const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
    const [countRows] = await pool.query(countQuery, params);
    const totalCount = countRows[0].total;

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit, 10), (parseInt(page, 10) - 1) * parseInt(limit, 10));

    const [rows] = await pool.query(query, params);

    // Parse JSON fields
    const formatted = rows.map(r => ({
      ...r,
      indicators: typeof r.indicators === 'string' ? JSON.parse(r.indicators) : r.indicators,
      recommendations: typeof r.recommendations === 'string' ? JSON.parse(r.recommendations) : r.recommendations
    }));

    return res.json({
      success: true,
      scans: formatted,
      pagination: {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        total: totalCount,
        totalPages: Math.ceil(totalCount / parseInt(limit, 10))
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.getScanById = async (req, res, next) => {
  try {
    const scanId = req.params.id;
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin';

    let query = 'SELECT * FROM scans WHERE id = ?';
    const params = [scanId];

    if (!isAdmin) {
      query += ' AND user_id = ?';
      params.push(userId);
    }

    const [rows] = await pool.query(query, params);

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'SCAN_NOT_FOUND', message: 'Scan record not found or access unauthorized.' }
      });
    }

    const scan = rows[0];
    scan.indicators = typeof scan.indicators === 'string' ? JSON.parse(scan.indicators) : scan.indicators;
    scan.recommendations = typeof scan.recommendations === 'string' ? JSON.parse(scan.recommendations) : scan.recommendations;

    return res.json({
      success: true,
      scan
    });
  } catch (error) {
    next(error);
  }
};

exports.deleteScan = async (req, res, next) => {
  try {
    const scanId = req.params.id;
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin';

    let query = 'DELETE FROM scans WHERE id = ?';
    const params = [scanId];

    if (!isAdmin) {
      query += ' AND user_id = ?';
      params.push(userId);
    }

    const [result] = await pool.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Scan record not found or already deleted.' }
      });
    }

    return res.json({
      success: true,
      message: 'Scan record deleted successfully.'
    });
  } catch (error) {
    next(error);
  }
};

exports.getUserDashboardStats = async (req, res, next) => {
  try {
    const userId = req.user.id;

    // 1. Live count of scans by risk category
    const [counts] = await pool.query(
      `SELECT 
         COUNT(*) as totalScans,
         SUM(CASE WHEN risk_level = 'LOW RISK' THEN 1 ELSE 0 END) as lowRisk,
         SUM(CASE WHEN risk_level = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
         SUM(CASE WHEN risk_level = 'HIGH RISK' THEN 1 ELSE 0 END) as highRisk,
         SUM(CASE WHEN risk_level = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious,
         SUM(CASE WHEN risk_level = 'INVALID' THEN 1 ELSE 0 END) as invalid,
         SUM(CASE WHEN risk_level = 'UNKNOWN / UNABLE TO VERIFY' THEN 1 ELSE 0 END) as unknownRisk
       FROM scans WHERE user_id = ?`,
      [userId]
    );

    // 2. Scan distribution by type
    const [types] = await pool.query(
      `SELECT scan_type, COUNT(*) as count 
       FROM scans WHERE user_id = ? 
       GROUP BY scan_type`,
      [userId]
    );

    // 3. Scan activity by last 7 days
    const [activity] = await pool.query(
      `SELECT DATE(created_at) as scanDate, COUNT(*) as count 
       FROM scans 
       WHERE user_id = ? AND created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
       GROUP BY DATE(created_at)
       ORDER BY scanDate ASC`,
      [userId]
    );

    // 4. Recent scans (last 8)
    const [recentScans] = await pool.query(
      `SELECT id, scan_type, input_value, risk_level, risk_score, verified, created_at 
       FROM scans 
       WHERE user_id = ? 
       ORDER BY created_at DESC LIMIT 8`,
      [userId]
    );

    return res.json({
      success: true,
      stats: {
        totalScans: counts[0].totalScans || 0,
        lowRisk: counts[0].lowRisk || 0,
        suspicious: counts[0].suspicious || 0,
        highRisk: counts[0].highRisk || 0,
        malicious: counts[0].malicious || 0,
        invalid: counts[0].invalid || 0,
        unknownRisk: counts[0].unknownRisk || 0,
        types: types.reduce((acc, cur) => { acc[cur.scan_type] = cur.count; return acc; }, {}),
        activity,
        recentScans
      }
    });
  } catch (error) {
    next(error);
  }
};
