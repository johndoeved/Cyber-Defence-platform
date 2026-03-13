const express = require('express');
const router = express.Router();
const path = require('path');
const PythonRunner = require('../../utils/pythonRunner');

// Privacy settings database
const PLATFORM_SETTINGS = {
    facebook: {
        name: 'Facebook',
        icon: 'fab fa-facebook',
        settings: [
            { id: 'profile_public', name: 'Public Profile', risk: 'high', recommendation: 'Set profile to Friends Only' },
            { id: 'search_engines', name: 'Search Engine Indexing', risk: 'high', recommendation: 'Disable search engine indexing' },
            { id: 'face_recognition', name: 'Face Recognition', risk: 'medium', recommendation: 'Disable face recognition feature' },
            { id: 'location_sharing', name: 'Location Sharing', risk: 'high', recommendation: 'Disable location sharing' },
            { id: 'third_party_apps', name: 'Third-Party App Access', risk: 'medium', recommendation: 'Review and revoke unnecessary app permissions' },
            { id: 'ad_tracking', name: 'Ad Tracking', risk: 'medium', recommendation: 'Opt out of ad personalization' }
        ]
    },
    google: {
        name: 'Google',
        icon: 'fab fa-google',
        settings: [
            { id: 'web_activity', name: 'Web & App Activity', risk: 'high', recommendation: 'Pause web & app activity tracking' },
            { id: 'location_history', name: 'Location History', risk: 'high', recommendation: 'Pause location history' },
            { id: 'youtube_history', name: 'YouTube History', risk: 'medium', recommendation: 'Pause YouTube watch/search history' },
            { id: 'ad_personalization', name: 'Ad Personalization', risk: 'medium', recommendation: 'Turn off ad personalization' },
            { id: 'shared_endorsements', name: 'Shared Endorsements', risk: 'low', recommendation: 'Opt out of shared endorsements' }
        ]
    },
    instagram: {
        name: 'Instagram',
        icon: 'fab fa-instagram',
        settings: [
            { id: 'private_account', name: 'Private Account', risk: 'high', recommendation: 'Switch to private account' },
            { id: 'activity_status', name: 'Activity Status', risk: 'medium', recommendation: 'Disable activity status' },
            { id: 'story_sharing', name: 'Story Sharing', risk: 'low', recommendation: 'Restrict story sharing' },
            { id: 'data_download', name: 'Third-Party Data Sharing', risk: 'medium', recommendation: 'Limit data sharing with third parties' }
        ]
    },
    twitter: {
        name: 'Twitter/X',
        icon: 'fab fa-twitter',
        settings: [
            { id: 'protect_tweets', name: 'Protect Tweets', risk: 'high', recommendation: 'Enable protected tweets' },
            { id: 'location_tweets', name: 'Location in Tweets', risk: 'medium', recommendation: 'Disable location tagging' },
            { id: 'discoverability', name: 'Email/Phone Discoverability', risk: 'high', recommendation: 'Disable discoverability by email/phone' },
            { id: 'personalization', name: 'Personalization & Data', risk: 'medium', recommendation: 'Disable personalization tracking' }
        ]
    },
    general: {
        name: 'General Browser',
        icon: 'fas fa-globe',
        settings: [
            { id: 'cookies', name: 'Third-Party Cookies', risk: 'high', recommendation: 'Block third-party cookies' },
            { id: 'do_not_track', name: 'Do Not Track', risk: 'medium', recommendation: 'Enable Do Not Track header' },
            { id: 'javascript', name: 'JavaScript (Untrusted Sites)', risk: 'medium', recommendation: 'Use NoScript for untrusted sites' },
            { id: 'webrtc', name: 'WebRTC Leak Prevention', risk: 'high', recommendation: 'Disable WebRTC or use a VPN' },
            { id: 'fingerprinting', name: 'Browser Fingerprinting', risk: 'high', recommendation: 'Use anti-fingerprinting extensions' },
            { id: 'password_manager', name: 'Password Manager', risk: 'medium', recommendation: 'Use a dedicated password manager' }
        ]
    }
};

function checkPrivacyJS(platform, settings = {}) {
    const platformKey = (platform || 'general').toLowerCase();
    const platformConfig = PLATFORM_SETTINGS[platformKey] || PLATFORM_SETTINGS.general;

    let totalScore = 0;
    let maxScore = 0;
    const checks = [];
    const recommendations = [];

    platformConfig.settings.forEach(setting => {
        const weight = setting.risk === 'high' ? 20 : setting.risk === 'medium' ? 12 : 6;
        maxScore += weight;

        const userSetting = settings[setting.id];
        const isSecure = userSetting === true || userSetting === 'enabled' || userSetting === 'on';

        if (isSecure) {
            totalScore += weight;
        } else {
            recommendations.push({
                setting: setting.name,
                risk_level: setting.risk,
                action: setting.recommendation
            });
        }

        checks.push({
            id: setting.id,
            name: setting.name,
            risk_level: setting.risk,
            status: isSecure ? 'secure' : 'at_risk',
            recommendation: isSecure ? 'Good! This setting is properly configured.' : setting.recommendation
        });
    });

    const privacyScore = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;

    let risk_level = 'LOW';
    if (privacyScore < 40) risk_level = 'HIGH';
    else if (privacyScore < 70) risk_level = 'MEDIUM';

    return {
        platform: platformConfig.name,
        platform_icon: platformConfig.icon,
        privacy_score: privacyScore,
        risk_level,
        total_checks: checks.length,
        secure_count: checks.filter(c => c.status === 'secure').length,
        at_risk_count: checks.filter(c => c.status === 'at_risk').length,
        checks,
        recommendations,
        general_tips: [
            'Use a VPN for enhanced privacy',
            'Regularly review app permissions',
            'Enable two-factor authentication',
            'Use encrypted messaging apps',
            'Regularly clear browser data',
            'Review connected third-party apps'
        ],
        analysis_method: 'javascript',
        timestamp: new Date().toISOString()
    };
}

// POST /check
router.post('/check', async (req, res) => {
    try {
        const { platform, settings } = req.body;

        if (!platform) {
            return res.status(400).json({ error: 'Platform is required' });
        }

        // Try Python checker first
        try {
            const pythonPath = path.join(__dirname, 'checker.py');
            const result = await PythonRunner.runWithStdin(pythonPath, { platform, settings: settings || {} });
            if (result && !result.error) {
                return res.json(result);
            }
        } catch (pyError) {
            console.log('Python privacy checker unavailable, using JS fallback');
        }

        // JavaScript fallback
        const analysis = checkPrivacyJS(platform, settings || {});
        res.json(analysis);

    } catch (error) {
        console.error('Privacy check error:', error);
        res.status(500).json({ error: 'Check failed', message: error.message });
    }
});

// GET /platforms
router.get('/platforms', (req, res) => {
    const platforms = Object.entries(PLATFORM_SETTINGS).map(([key, val]) => ({
        id: key,
        name: val.name,
        icon: val.icon,
        settings_count: val.settings.length
    }));
    res.json({ platforms });
});

module.exports = router;
