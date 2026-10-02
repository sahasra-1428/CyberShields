const jwt = require('jsonwebtoken');
const pool = require('../config/database');

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Access denied. Authentication token missing or invalid.'
        }
      });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication token missing.'
        }
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cybershield_secret_key');

    // Verify user exists and is active in database
    const [rows] = await pool.query(
      'SELECT id, name, email, phone, role, status FROM users WHERE id = ? LIMIT 1',
      [decoded.id]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User account does not exist or was deleted.'
        }
      });
    }

    const user = rows[0];
    if (user.status === 'suspended' || user.status === 'inactive') {
      return res.status(403).json({
        success: false,
        error: {
          code: 'ACCOUNT_LOCKED',
          message: 'Your account is currently inactive or suspended. Contact support.'
        }
      });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: {
          code: 'TOKEN_EXPIRED',
          message: 'Your session has expired. Please log in again.'
        }
      });
    }
    return res.status(401).json({
      success: false,
      error: {
        code: 'INVALID_TOKEN',
        message: 'Invalid authentication token.'
      }
    });
  }
};

// Optional auth for public scanner calls where logged-in user can get history saved to account
const optionalAuthMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      if (token) {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cybershield_secret_key');
        const [rows] = await pool.query(
          'SELECT id, name, email, phone, role, status FROM users WHERE id = ? LIMIT 1',
          [decoded.id]
        );
        if (rows.length > 0 && rows[0].status === 'active') {
          req.user = rows[0];
        }
      }
    }
  } catch {
    // Ignore invalid token on optional routes
  }
  next();
};

module.exports = { authMiddleware, optionalAuthMiddleware };
