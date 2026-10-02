const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { authMiddleware, optionalAuthMiddleware } = require('../middleware/authMiddleware');

router.post('/', optionalAuthMiddleware, reportController.createReport);
router.get('/docket/:docketNo', reportController.getReportByDocket);
router.get('/', authMiddleware, reportController.getReports);
router.get('/:id', authMiddleware, reportController.getReportById);

module.exports = router;
