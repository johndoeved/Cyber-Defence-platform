// Vercel serverless entry point
// Wraps the Express app from backend/server.js so Vercel can invoke it as a
// serverless function. All existing route logic and JS fallbacks are preserved.
// Python features are automatically skipped (JS fallbacks are used instead).

const { app } = require('../backend/server');

module.exports = app;
