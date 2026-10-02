const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');
const reportRoutes = require('./routes/reportRoutes');
const awarenessRoutes = require('./routes/awarenessRoutes');
const adminRoutes = require('./routes/adminRoutes');
const { errorHandler, notFoundHandler } = require('./middleware/errorMiddleware');

const app = express();
const PORT = process.env.PORT || 5000;

// Security HTTP headers with content security policy configured for development & CDN scripts
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

// Cross-Origin Resource Sharing
app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
);

// Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Global rate limiting: max 200 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests from this IP address. Please try again after 15 minutes.'
    }
  }
});
app.use('/api/', globalLimiter);

// Specific stricter limiter for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'AUTH_RATE_LIMIT_EXCEEDED',
      message: 'Too many authentication attempts. Please try again later.'
    }
  }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Serve frontend static files directly from the same server for convenient zero-config preview
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use(express.static(frontendPath));

// Avoid 404 on browser favicon request
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(frontendPath, 'favicon.svg'));
});

// API Health Check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'ONLINE',
    platform: 'CYBERSHIELD - Cyber Scam Protection & Detection Platform',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/scans', scanRoutes); // Alias for scan listing
app.use('/api/reports', reportRoutes);
app.use('/api/awareness', awarenessRoutes);
app.use('/api/admin', adminRoutes);

// Catch 404 for API routes
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) {
    return notFoundHandler(req, res);
  }
  next();
});

// Central Error Handler
app.use(errorHandler);

const server = app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` 🛡️  CYBERSHIELD SERVER ONLINE`);
  console.log(` 🚀 Listening on http://localhost:${PORT}`);
  console.log(` 🌐 Serving Frontend from: ${frontendPath}`);
  console.log(`=======================================================`);
});

module.exports = app;
