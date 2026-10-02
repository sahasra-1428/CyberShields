const pool = require('../config/database');

exports.getAdminDashboard = async (req, res, next) => {
  try {
    // 1. Overall counts
    const [userCount] = await pool.query('SELECT COUNT(*) as total FROM users');
    const [scanStats] = await pool.query(
      `SELECT 
         COUNT(*) as totalScans,
         SUM(CASE WHEN risk_level = 'LOW RISK' THEN 1 ELSE 0 END) as lowRisk,
         SUM(CASE WHEN risk_level = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
         SUM(CASE WHEN risk_level = 'HIGH RISK' THEN 1 ELSE 0 END) as highRisk,
         SUM(CASE WHEN risk_level = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious,
         SUM(CASE WHEN risk_level = 'INVALID' THEN 1 ELSE 0 END) as invalid,
         SUM(CASE WHEN risk_level = 'UNKNOWN / UNABLE TO VERIFY' THEN 1 ELSE 0 END) as unknownRisk,
         SUM(CASE WHEN created_at >= CURDATE() THEN 1 ELSE 0 END) as scansToday,
         SUM(CASE WHEN created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) as scansThisWeek
       FROM scans`
    );

    const [reportStats] = await pool.query(
      `SELECT 
         COUNT(*) as totalReports,
         SUM(CASE WHEN status = 'Submitted' THEN 1 ELSE 0 END) as submittedReports,
         SUM(CASE WHEN status = 'Under Review' THEN 1 ELSE 0 END) as underReviewReports,
         SUM(CASE WHEN status = 'Verified' THEN 1 ELSE 0 END) as verifiedReports,
         SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as resolvedReports
       FROM reports`
    );

    // 2. Scan types distribution
    const [types] = await pool.query(
      `SELECT scan_type, COUNT(*) as count 
       FROM scans 
       GROUP BY scan_type`
    );

    // 3. Reports by category
    const [reportsByCategory] = await pool.query(
      `SELECT category, COUNT(*) as count 
       FROM reports 
       GROUP BY category`
    );

    // 4. Daily scan counts for the last 7 days
    const [dailyScans] = await pool.query(
      `SELECT DATE(created_at) as scanDate, COUNT(*) as count 
       FROM scans 
       WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
       GROUP BY DATE(created_at)
       ORDER BY scanDate ASC`
    );

    // 5. Recent scans across all users
    const [recentScans] = await pool.query(
      `SELECT s.id, s.scan_type, s.input_value, s.risk_level, s.risk_score, s.source, s.created_at,
              u.name as user_name, u.email as user_email
       FROM scans s
       LEFT JOIN users u ON s.user_id = u.id
       ORDER BY s.created_at DESC LIMIT 10`
    );

    // 6. Recent audit logs
    const [auditLogs] = await pool.query(
      `SELECT a.*, u.name as admin_name 
       FROM audit_logs a
       LEFT JOIN users u ON a.admin_id = u.id
       ORDER BY a.created_at DESC LIMIT 8`
    );

    return res.json({
      success: true,
      stats: {
        totalUsers: userCount[0].total,
        totalScans: scanStats[0].totalScans || 0,
        scansToday: scanStats[0].scansToday || 0,
        scansThisWeek: scanStats[0].scansThisWeek || 0,
        lowRisk: scanStats[0].lowRisk || 0,
        suspicious: scanStats[0].suspicious || 0,
        highRisk: scanStats[0].highRisk || 0,
        malicious: scanStats[0].malicious || 0,
        invalid: scanStats[0].invalid || 0,
        unknownRisk: scanStats[0].unknownRisk || 0,
        totalReports: reportStats[0].totalReports || 0,
        submittedReports: reportStats[0].submittedReports || 0,
        verifiedReports: reportStats[0].verifiedReports || 0,
        resolvedReports: reportStats[0].resolvedReports || 0,
        scanTypes: types.reduce((acc, cur) => { acc[cur.scan_type] = cur.count; return acc; }, {}),
        reportsByCategory: reportsByCategory.reduce((acc, cur) => { acc[cur.category] = cur.count; return acc; }, {}),
        dailyScans,
        recentScans,
        auditLogs
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.getAdminUsers = async (req, res, next) => {
  try {
    const { search, role, status, page = 1, limit = 20 } = req.query;

    let query = `
      SELECT u.id, u.name, u.email, u.phone, u.role, u.status, u.created_at, u.last_login,
             COUNT(s.id) as scan_count
      FROM users u
      LEFT JOIN scans s ON u.id = s.user_id
      WHERE 1=1
    `;
    const params = [];

    if (search && search.trim()) {
      query += ' AND (u.name LIKE ? OR u.email LIKE ? OR u.phone LIKE ?)';
      params.push(`%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`);
    }

    if (role && role !== 'all') {
      query += ' AND u.role = ?';
      params.push(role);
    }

    if (status && status !== 'all') {
      query += ' AND u.status = ?';
      params.push(status);
    }

    query += ' GROUP BY u.id';

    // Count
    const [allRows] = await pool.query(query, params);
    const total = allRows.length;

    query += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit, 10), (parseInt(page, 10) - 1) * parseInt(limit, 10));

    const [users] = await pool.query(query, params);

    return res.json({
      success: true,
      users,
      pagination: {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        total,
        totalPages: Math.ceil(total / parseInt(limit, 10))
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.updateUserStatus = async (req, res, next) => {
  try {
    const adminId = req.user.id;
    const targetUserId = req.params.id;
    const { status, role } = req.body;

    if (!status && !role) {
      return res.status(400).json({
        success: false,
        error: { code: 'NO_CHANGES', message: 'No status or role change provided.' }
      });
    }

    const [userRows] = await pool.query('SELECT id, name, email, role, status FROM users WHERE id = ?', [targetUserId]);
    if (userRows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'USER_NOT_FOUND', message: 'User does not exist.' }
      });
    }

    const updates = [];
    const params = [];

    if (status) {
      if (!['active', 'inactive', 'suspended'].includes(status)) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_STATUS', message: 'Status must be active, inactive, or suspended.' }
        });
      }
      updates.push('status = ?');
      params.push(status);
    }

    if (role) {
      if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_ROLE', message: 'Role must be user or admin.' }
        });
      }
      updates.push('role = ?');
      params.push(role);
    }

    params.push(targetUserId);
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);

    // Audit log
    await pool.query(
      `INSERT INTO audit_logs (admin_id, action, target_type, target_id, details)
       VALUES (?, 'UPDATE_USER', 'user', ?, ?)`,
      [adminId, targetUserId, `Updated user ${userRows[0].email}: status=${status || 'unchanged'}, role=${role || 'unchanged'}`]
    );

    return res.json({
      success: true,
      message: 'User status successfully updated.'
    });
  } catch (error) {
    next(error);
  }
};

exports.getAdminScans = async (req, res, next) => {
  try {
    const { type, risk, search, page = 1, limit = 25 } = req.query;

    let query = `
      SELECT s.*, u.name as user_name, u.email as user_email
      FROM scans s
      LEFT JOIN users u ON s.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (type && type !== 'all') {
      query += ' AND s.scan_type = ?';
      params.push(type.toLowerCase());
    }

    if (risk && risk !== 'all') {
      query += ' AND s.risk_level = ?';
      params.push(risk.toUpperCase());
    }

    if (search && search.trim()) {
      query += ' AND (s.input_value LIKE ? OR s.normalized_value LIKE ? OR u.name LIKE ? OR u.email LIKE ?)';
      params.push(`%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`);
    }

    const countQuery = query.replace('SELECT s.*, u.name as user_name, u.email as user_email', 'SELECT COUNT(*) as total');
    const [countRows] = await pool.query(countQuery, params);
    const total = countRows[0].total;

    query += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit, 10), (parseInt(page, 10) - 1) * parseInt(limit, 10));

    const [rows] = await pool.query(query, params);

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
        total,
        totalPages: Math.ceil(total / parseInt(limit, 10))
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.getAdminReports = async (req, res, next) => {
  try {
    const { category, status, search, page = 1, limit = 25 } = req.query;

    let query = `
      SELECT r.*, u.name as reporter_name, u.email as reporter_email
      FROM reports r
      LEFT JOIN users u ON r.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (category && category !== 'all') {
      query += ' AND r.category = ?';
      params.push(category.toLowerCase());
    }

    if (status && status !== 'all') {
      query += ' AND r.status = ?';
      params.push(status);
    }

    if (search && search.trim()) {
      query += ' AND (r.target LIKE ? OR r.description LIKE ? OR u.name LIKE ? OR u.email LIKE ?)';
      params.push(`%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`, `%${search.trim()}%`);
    }

    const countQuery = query.replace('SELECT r.*, u.name as reporter_name, u.email as reporter_email', 'SELECT COUNT(*) as total');
    const [countRows] = await pool.query(countQuery, params);
    const total = countRows[0].total;

    query += ' ORDER BY r.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit, 10), (parseInt(page, 10) - 1) * parseInt(limit, 10));

    const [reports] = await pool.query(query, params);

    return res.json({
      success: true,
      reports,
      pagination: {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        total,
        totalPages: Math.ceil(total / parseInt(limit, 10))
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.updateReport = async (req, res, next) => {
  try {
    const adminId = req.user.id;
    const reportId = req.params.id;
    const { status, admin_notes, assigned_agent, urgency } = req.body;

    const [existing] = await pool.query('SELECT id, status, target FROM reports WHERE id = ?', [reportId]);
    if (existing.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'REPORT_NOT_FOUND', message: 'Report does not exist.' }
      });
    }

    const updates = [];
    const params = [];

    if (status) {
      const validStatuses = ['Submitted', 'Under Review', 'Verified', 'Resolved', 'Rejected'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_STATUS', message: `Status must be one of: ${validStatuses.join(', ')}` }
        });
      }
      updates.push('status = ?');
      params.push(status);
    }

    if (admin_notes !== undefined) {
      updates.push('admin_notes = ?');
      params.push(admin_notes ? admin_notes.trim() : null);
    }

    if (assigned_agent !== undefined) {
      updates.push('assigned_agent = ?');
      params.push(assigned_agent ? assigned_agent.trim() : null);
    }

    if (urgency && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(urgency.toUpperCase())) {
      updates.push('urgency = ?');
      params.push(urgency.toUpperCase());
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        error: { code: 'NO_UPDATES', message: 'No updates provided.' }
      });
    }

    params.push(reportId);
    await pool.query(`UPDATE reports SET ${updates.join(', ')} WHERE id = ?`, params);

    // Write audit log
    await pool.query(
      `INSERT INTO audit_logs (admin_id, action, target_type, target_id, details)
       VALUES (?, 'UPDATE_REPORT', 'report', ?, ?)`,
      [adminId, reportId, `Status: ${status || 'unchanged'}, Agent: ${assigned_agent || 'unchanged'}, Notes: ${admin_notes || 'none'}`]
    );

    return res.json({
      success: true,
      message: 'Report status updated successfully.'
    });
  } catch (error) {
    next(error);
  }
};
