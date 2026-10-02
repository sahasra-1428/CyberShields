const pool = require('../config/database');

const VALID_CATEGORIES = ['url', 'phone', 'email', 'message', 'social_media', 'other'];
const VALID_STATUSES = ['Submitted', 'Under Review', 'Verified', 'Resolved', 'Rejected'];

const AGENT_UNITS = {
  url: 'Central Phishing Takedown & Domain Suspension Cell',
  phone: 'Telecom Cyber Crime & Anti-Smishing Wing (Sanchar Saathi)',
  email: 'CERT-In Incident Response & Malware Analysis Unit',
  message: 'National Cyber Crime Bureau (I4C / 1930) - SMS Taskforce',
  social_media: 'Social Engineering & Identity Theft Investigation Wing',
  other: 'Citizen Financial Cyber Fraud & Bank Freezing Cell (1930)'
};

const AGENT_ROSTER = {
  url: 'Officer Priya Nair (Badge #CA-7821, Phishing & Domain Takedown Taskforce)',
  phone: 'Officer Sneha Kulkarni (Badge #CA-5514, Telecom Anti-Smishing & SIM Fraud Wing)',
  email: 'Officer Arun Verma (Badge #CA-3390, CERT-In Emergency Response Unit)',
  message: 'Officer Rajesh Menon (Badge #CA-6219, Social Engineering & Identity Fraud Wing)',
  social_media: 'Officer Ananya Sen (Badge #CA-8903, Identity Theft & Impersonation Desk)',
  other: 'Inspector Vikram Sharma (Badge #CA-4102, Financial Crime & Mule Account Freezing Wing)'
};

exports.createReport = async (req, res, next) => {
  try {
    const userId = req.user ? req.user.id : null;
    const {
      category,
      target,
      description,
      evidence,
      agent_unit,
      urgency = 'HIGH',
      loss_amount = 0,
      suspect_phone,
      suspect_upi,
      action_requested
    } = req.body;

    if (!category || !target || !description) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_FIELDS',
          message: 'Category, target, and description are required.'
        }
      });
    }

    const catKey = category.toLowerCase();
    if (!VALID_CATEGORIES.includes(catKey)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_CATEGORY',
          message: `Category must be one of: ${VALID_CATEGORIES.join(', ')}`
        }
      });
    }

    // Generate unique official Cyber Agent Docket Number
    const docketRandom = Math.floor(100000 + Math.random() * 900000);
    const docketNo = `CAD-2026-${docketRandom}`;

    // Resolve assigned agent and agent unit
    const assignedAgent = AGENT_ROSTER[catKey] || AGENT_ROSTER.other;
    const selectedAgentUnit = agent_unit || AGENT_UNITS[catKey] || 'National Cyber Crime Reporting Cell (1930 / I4C)';
    const selectedAction = action_requested || 'Domain / SIM Takedown & Evidence Forensics';
    const parsedLoss = parseFloat(loss_amount) || 0.00;

    const [result] = await pool.query(
      `INSERT INTO reports (
        user_id, category, target, description, evidence, status,
        agent_unit, urgency, docket_no, assigned_agent, loss_amount,
        suspect_phone, suspect_upi, action_requested
      ) VALUES (?, ?, ?, ?, ?, 'Submitted', ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        catKey,
        target.trim().slice(0, 500),
        description.trim(),
        evidence ? evidence.trim() : null,
        selectedAgentUnit,
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(urgency?.toUpperCase()) ? urgency.toUpperCase() : 'HIGH',
        docketNo,
        assignedAgent,
        parsedLoss,
        suspect_phone ? suspect_phone.trim().slice(0, 50) : null,
        suspect_upi ? suspect_upi.trim().slice(0, 120) : null,
        selectedAction
      ]
    );

    const reportId = result.insertId;

    if (userId) {
      await pool.query(
        `INSERT INTO security_events (user_id, event_type, description)
         VALUES (?, 'SCAM_REPORTED', ?)`,
        [userId, `Dispatched incident #${reportId} [Docket: ${docketNo}] to ${assignedAgent} at ${selectedAgentUnit}.`]
      );
    }

    return res.status(201).json({
      success: true,
      message: `Incident dispatched to Cyber Crime Agents successfully. Docket reference: ${docketNo}.`,
      report: {
        id: reportId,
        docketNo,
        category: catKey,
        target,
        status: 'Submitted',
        urgency: urgency.toUpperCase(),
        agentUnit: selectedAgentUnit,
        assignedAgent,
        lossAmount: parsedLoss,
        actionRequested: selectedAction,
        createdAt: new Date().toISOString(),
        emergencyAdvisory: {
          nationalHelpline: '1930 (Golden Hour Financial Fraud Freezing)',
          nationalPortal: 'https://cybercrime.gov.in',
          certInEmergency: 'incident@cert-in.org.in | 1800-11-4949',
          advice: parsedLoss > 0 
            ? 'CRITICAL FINANCIAL LOSS: Immediately call 1930 within the first 2 hours to freeze recipient mule accounts.' 
            : 'Evidence logged and dispatched to the on-duty Cyber Investigation Agent.'
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

exports.getReports = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin';
    const { category, status, page = 1, limit = 20 } = req.query;

    let query = 'SELECT r.*, u.name as reporter_name, u.email as reporter_email FROM reports r LEFT JOIN users u ON r.user_id = u.id WHERE 1=1';
    const params = [];

    if (!isAdmin) {
      query += ' AND r.user_id = ?';
      params.push(userId);
    }

    if (category && category !== 'all') {
      query += ' AND r.category = ?';
      params.push(category.toLowerCase());
    }

    if (status && status !== 'all') {
      query += ' AND r.status = ?';
      params.push(status);
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

exports.getReportById = async (req, res, next) => {
  try {
    const reportId = req.params.id;
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin';

    let query = 'SELECT r.*, u.name as reporter_name, u.email as reporter_email FROM reports r LEFT JOIN users u ON r.user_id = u.id WHERE r.id = ?';
    const params = [reportId];

    if (!isAdmin) {
      query += ' AND r.user_id = ?';
      params.push(userId);
    }

    const [rows] = await pool.query(query, params);

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Report not found or unauthorized.' }
      });
    }

    return res.json({
      success: true,
      report: rows[0]
    });
  } catch (error) {
    next(error);
  }
};

exports.getReportByDocket = async (req, res, next) => {
  try {
    const { docketNo } = req.params;
    if (!docketNo) {
      return res.status(400).json({
        success: false,
        error: { code: 'MISSING_DOCKET', message: 'Docket number is required.' }
      });
    }

    const [rows] = await pool.query(
      `SELECT id, category, target, status, agent_unit, urgency, docket_no, assigned_agent, action_requested, created_at, updated_at
       FROM reports WHERE docket_no = ?`,
      [docketNo.trim().toUpperCase()]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: 'No Cyber Agent docket found with this identifier.' }
      });
    }

    return res.json({
      success: true,
      report: rows[0]
    });
  } catch (error) {
    next(error);
  }
};

