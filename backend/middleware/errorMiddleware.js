const errorHandler = (err, req, res, next) => {
  console.error('[SERVER ERROR]', err);

  const statusCode = err.status || err.statusCode || 500;
  const errorCode = err.code || 'INTERNAL_SERVER_ERROR';
  const errorMessage = statusCode === 500
    ? 'An unexpected security engine error occurred. Please try again later.'
    : err.message || 'Request could not be processed.';

  res.status(statusCode).json({
    success: false,
    error: {
      code: errorCode,
      message: errorMessage
    }
  });
};

const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `The requested endpoint ${req.method} ${req.originalUrl} was not found on CyberShield API.`
    }
  });
};

module.exports = { errorHandler, notFoundHandler };
