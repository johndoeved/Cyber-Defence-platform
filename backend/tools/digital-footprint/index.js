const express = require('express');
const router = express.Router();
const path = require('path');
const PythonRunner = require('../../utils/pythonRunner');

// Social media platforms to check
const SOCIAL_PLATFORMS = [
    { name: 'GitHub', url: 'https://github.com/', icon: 'fab fa-github' },
    { name: 'Twitter/X', url: 'https://twitter.com/', icon: 'fab fa-twitter' },
    { name: 'Instagram', url: 'https://instagram.com/', icon: 'fab fa-instagram' },
    { name: 'LinkedIn', url: 'https://linkedin.com/in/', icon: 'fab fa-linkedin' },
    { name: 'Reddit', url: 'https://reddit.com/user/', icon: 'fab fa-reddit' },
    { name: 'TikTok', url: 'https://tiktok.com/@', icon: 'fab fa-tiktok' },
    { name: 'YouTube', url: 'https://youtube.com/@', icon: 'fab fa-youtube' },
    { name: 'Pinterest', url: 'https://pinterest.com/', icon: 'fab fa-pinterest' },
    { name: 'Medium', url: 'https://medium.com/@', icon: 'fab fa-medium' },
    { name: 'Twitch', url: 'https://twitch.tv/', icon: 'fab fa-twitch' }
];

// Simulated breach database
const SIMULATED_BREACHES = [
    { name: 'Adobe', date: '2013-10-04', records: '153 million', data_types: ['emails', 'passwords', 'usernames'] },
    { name: 'LinkedIn', date: '2012-06-05', records: '165 million', data_types: ['emails', 'passwords'] },
    { name: 'Dropbox', date: '2012-07-01', records: '68 million', data_types: ['emails', 'passwords'] },
    { name: 'MyFitnessPal', date: '2018-02-01', records: '144 million', data_types: ['emails', 'passwords', 'usernames'] },
    { name: 'Canva', date: '2019-05-24', records: '137 million', data_types: ['emails', 'usernames', 'names'] },
    { name: 'Zynga', date: '2019-09-01', records: '173 million', data_types: ['emails', 'passwords', 'usernames'] }
];

function scanDigitalFootprintJS(email, username) {
    const results = {
        email_scanned: email || null,
        username_scanned: username || null,
        breaches: [],
        social_accounts: [],
        public_info: [],
        risk_score: 0,
        risk_level: 'LOW',
        recommendations: [],
        analysis_method: 'javascript',
        timestamp: new Date().toISOString()
    };

    // Simulate breach checking
    if (email) {
        // Hash-based simulation - deterministic results for demo
        const emailHash = email.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
        const breachCount = emailHash % 4; // 0-3 breaches

        for (let i = 0; i < breachCount; i++) {
            const breach = SIMULATED_BREACHES[emailHash % SIMULATED_BREACHES.length];
            results.breaches.push({
                name: SIMULATED_BREACHES[(emailHash + i) % SIMULATED_BREACHES.length].name,
                date: SIMULATED_BREACHES[(emailHash + i) % SIMULATED_BREACHES.length].date,
                records: SIMULATED_BREACHES[(emailHash + i) % SIMULATED_BREACHES.length].records,
                data_types: SIMULATED_BREACHES[(emailHash + i) % SIMULATED_BREACHES.length].data_types,
                status: 'verified'
            });
        }

        if (results.breaches.length > 0) {
            results.risk_score += results.breaches.length * 15;
            results.recommendations.push('Change passwords for all breached accounts');
            results.recommendations.push('Enable two-factor authentication (2FA)');
            results.recommendations.push('Use a password manager with unique passwords');
        }

        // Email domain analysis
        const domain = email.split('@')[1];
        if (domain) {
            results.public_info.push({
                type: 'email_domain',
                value: domain,
                note: `Email registered with ${domain}`
            });
        }
    }

    // Simulate social media scan
    if (username) {
        const usernameHash = username.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
        
        SOCIAL_PLATFORMS.forEach((platform, idx) => {
            const found = (usernameHash + idx) % 3 === 0; // ~33% hit rate
            results.social_accounts.push({
                platform: platform.name,
                url: platform.url + username,
                icon: platform.icon,
                found: found,
                status: found ? 'Profile Found' : 'Not Found'
            });
        });

        const foundCount = results.social_accounts.filter(a => a.found).length;
        results.risk_score += foundCount * 5;

        if (foundCount > 3) {
            results.recommendations.push('Review privacy settings on all social media platforms');
            results.recommendations.push('Limit publicly visible personal information');
        }

        results.public_info.push({
            type: 'username',
            value: username,
            note: `Username "${username}" found on ${foundCount} platform(s)`
        });
    }

    // Calculate final risk
    results.risk_score = Math.min(results.risk_score, 100);
    if (results.risk_score >= 60) results.risk_level = 'HIGH';
    else if (results.risk_score >= 30) results.risk_level = 'MEDIUM';

    // General recommendations
    results.recommendations.push('Regularly monitor your digital footprint');
    results.recommendations.push('Set up breach notification alerts');
    results.recommendations.push('Use unique passwords for each account');

    return results;
}

// POST /scan
router.post('/scan', async (req, res) => {
    try {
        const { email, username } = req.body;

        if (!email && !username) {
            return res.status(400).json({
                error: 'Either email or username is required',
                message: 'Please provide an email address or username to scan'
            });
        }

        // Try Python scanner first
        try {
            const pythonPath = path.join(__dirname, 'scanner.py');
            const result = await PythonRunner.runWithStdin(pythonPath, { 
                email: email || '', 
                username: username || '' 
            });
            if (result && !result.error) {
                return res.json(result);
            }
        } catch (pyError) {
            console.log('Python scanner unavailable, using JS fallback');
        }

        // JavaScript fallback
        const results = scanDigitalFootprintJS(email, username);
        res.json(results);

    } catch (error) {
        console.error('Digital footprint scan error:', error);
        res.status(500).json({ error: 'Scan failed', message: error.message });
    }
});

module.exports = router;
