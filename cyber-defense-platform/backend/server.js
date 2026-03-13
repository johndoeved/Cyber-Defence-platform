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

// Request logging middleware
app.use((req, res, next) => {
    const start = Date.now();
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - Started`);
    if (req.method === 'POST') console.log('Payload:', JSON.stringify(req.body).substring(0, 100));
    
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - ${res.statusCode} (${duration}ms)`);
    });
    next();
});



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
app.use('/api/phishing', (req, res, next) => { console.log('Tool: Phishing'); next(); }, phishingDetection);
app.use('/api/password', (req, res, next) => { console.log('Tool: Password'); next(); }, passwordAnalyzer);
app.use('/api/sms', (req, res, next) => { console.log('Tool: SMS'); next(); }, smsScamDetector);
app.use('/api/footprint', (req, res, next) => { console.log('Tool: Footprint'); next(); }, digitalFootprint);
app.use('/api/privacy', (req, res, next) => { console.log('Tool: Privacy'); next(); }, privacyChecker);
app.use('/api/hackbot', (req, res, next) => { console.log('Tool: HackBot'); next(); }, hackbotAgent);


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

// On Vercel, we don't need to call listen() as it's handled by the serverless function environment
if (!process.env.VERCEL) {
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
}

module.exports = { app, server };
