const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');
const { authMiddleware, optionalAuthMiddleware } = require('../middleware/authMiddleware');

// Scanners can be used with optional authentication (attaches scan to user account if logged in)
router.post('/url', optionalAuthMiddleware, scanController.scanUrl);
router.post('/message', optionalAuthMiddleware, scanController.scanMessage);
router.post('/email', optionalAuthMiddleware, scanController.scanEmail);
router.post('/phone', optionalAuthMiddleware, scanController.scanPhone);
router.post('/qr', optionalAuthMiddleware, scanController.scanQr);

// User scan management (requires authentication)
router.get('/dashboard-stats', authMiddleware, scanController.getUserDashboardStats);
router.get('/', authMiddleware, scanController.getScans);
router.get('/:id', authMiddleware, scanController.getScanById);
router.delete('/:id', authMiddleware, scanController.deleteScan);

module.exports = router;
