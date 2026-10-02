const express = require('express');
const router = express.Router();
const awarenessController = require('../controllers/awarenessController');
const { authMiddleware, optionalAuthMiddleware } = require('../middleware/authMiddleware');

router.get('/quiz/questions', awarenessController.getQuizQuestions);
router.post('/quiz/submit', optionalAuthMiddleware, awarenessController.submitQuizScore);
router.get('/', optionalAuthMiddleware, awarenessController.getModules);
router.get('/:id', optionalAuthMiddleware, awarenessController.getModuleById);
router.post('/:id/complete', authMiddleware, awarenessController.completeModule);

module.exports = router;
