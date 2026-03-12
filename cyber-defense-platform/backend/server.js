const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const http = require('http');

const app = express();
const server = http.createServer(app);

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Import tool routes
const phishingDetection = require('./tools/phishing-detection');
const passwordAnalyzer = require('./tools/password-analyzer');
const smsScamDetector = require('./tools/sms-scam-detector');
const digitalFootprint = require('./tools/digital-footprint');
const privacyChecker = require('./tools/privacy-checker');
const hackbotAgent = require('./tools/hackbot-agent');

// Mount tool routes
app.use('/api/phishing', phishingDetection);
app.use('/api/password', passwordAnalyzer);
app.use('/api/sms', smsScamDetector);
app.use('/api/footprint', digitalFootprint);
app.use('/api/privacy', privacyChecker);
app.use('/api/hackbot', hackbotAgent);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'operational',
        platform: 'Cyber Guard IQ',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        tools: [
            { name: 'Phishing Detection', endpoint: '/api/phishing/analyze', status: 'active' },
            { name: 'Password Analyzer', endpoint: '/api/password/analyze', status: 'active' },
            { name: 'SMS Scam Detector', endpoint: '/api/sms/analyze', status: 'active' },
            { name: 'Digital Footprint', endpoint: '/api/footprint/scan', status: 'active' },
            { name: 'Privacy Checker', endpoint: '/api/privacy/check', status: 'active' },
            { name: 'HackBot Agent', endpoint: '/api/hackbot/scan', status: 'active' }
        ]
    });
});

// Catch-all route for SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════════╗
    ║       🛡️  Cyber Guard IQ v1.0.0  🛡️      ║
    ║──────────────────────────────────────────║
    ║  Server running on port ${PORT}             ║
    ║  http://localhost:${PORT}                   ║
    ║                                          ║
    ║  Tools:                                  ║
    ║  • Phishing Detection    ✅              ║
    ║  • Password Analyzer     ✅              ║
    ║  • SMS Scam Detector     ✅              ║
    ║  • Digital Footprint     ✅              ║
    ║  • Privacy Checker       ✅              ║
    ║  • HackBot Agent         ✅              ║
    ╚══════════════════════════════════════════╝
    `);
});

module.exports = { app, server };
