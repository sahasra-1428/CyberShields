const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { authMiddleware } = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');

// All admin routes strictly require valid JWT AND admin role
router.use(authMiddleware, adminMiddleware);

router.get('/dashboard', adminController.getAdminDashboard);
router.get('/users', adminController.getAdminUsers);
router.patch('/users/:id', adminController.updateUserStatus);
router.get('/scans', adminController.getAdminScans);
router.get('/reports', adminController.getAdminReports);
router.patch('/reports/:id', adminController.updateReport);

module.exports = router;
