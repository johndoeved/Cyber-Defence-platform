const express = require('express');
const router = express.Router();
const path = require('path');
const PythonRunner = require('../../utils/pythonRunner');

// Scam pattern categories
const SCAM_PATTERNS = {
    prize_lottery: {
        keywords: ['congratulations', 'you won', 'winner', 'prize', 'lottery', 'sweepstakes',
                   'lucky', 'selected', 'claim your', 'reward', 'giveaway', 'jackpot', 'million'],
        weight: 25
    },
    financial: {
        keywords: ['bank', 'account suspended', 'verify your account', 'unauthorized',
                   'transaction', 'credit card', 'payment', 'billing', 'overdue', 'debt',
                   'irs', 'tax refund', 'wire transfer', 'bitcoin', 'crypto'],
        weight: 25
    },
    urgency: {
        keywords: ['urgent', 'immediately', 'act now', 'limited time', 'expires',
                   'last chance', 'don\'t miss', 'hurry', 'asap', 'deadline',
                   'within 24 hours', 'right away', 'final notice', 'warning'],
        weight: 20
    },
    suspicious_links: {
        patterns: [
            /https?:\/\/[^\s]+/i,
            /bit\.ly|tinyurl|goo\.gl|t\.co/i,
            /click here|tap here|visit here/i
        ],
        weight: 20
    },
    grammar: {
        patterns: [
            /\b(u|ur|plz|pls|msg|txt|da|dis)\b/i,
            /[A-Z]{5,}/,  // EXCESSIVE CAPS
            /!{2,}/,       // Multiple exclamation marks
            /\${1,}/,      // Dollar signs
            /free\s+(?:gift|money|cash|iphone)/i,
            /dear\s+(?:customer|user|member|sir|madam)/i
        ],
        weight: 10
    }
};

function analyzeSmsJS(message) {
    const indicators = [];
    let totalScore = 0;
    const messageLower = message.toLowerCase();
    const categories_matched = [];

    // Check prize/lottery patterns
    const prizeMatches = SCAM_PATTERNS.prize_lottery.keywords.filter(kw => messageLower.includes(kw));
    if (prizeMatches.length > 0) {
        indicators.push(`Prize/lottery keywords detected: ${prizeMatches.join(', ')}`);
        totalScore += Math.min(SCAM_PATTERNS.prize_lottery.weight, prizeMatches.length * 10);
        categories_matched.push('Prize/Lottery Scam');
    }

    // Check financial patterns
    const financialMatches = SCAM_PATTERNS.financial.keywords.filter(kw => messageLower.includes(kw));
    if (financialMatches.length > 0) {
        indicators.push(`Financial/banking keywords detected: ${financialMatches.join(', ')}`);
        totalScore += Math.min(SCAM_PATTERNS.financial.weight, financialMatches.length * 10);
        categories_matched.push('Financial Scam');
    }

    // Check urgency patterns
    const urgencyMatches = SCAM_PATTERNS.urgency.keywords.filter(kw => messageLower.includes(kw));
    if (urgencyMatches.length > 0) {
        indicators.push(`Urgency phrases detected: ${urgencyMatches.join(', ')}`);
        totalScore += Math.min(SCAM_PATTERNS.urgency.weight, urgencyMatches.length * 8);
        categories_matched.push('Urgency Manipulation');
    }

    // Check for suspicious links
    const linkMatches = SCAM_PATTERNS.suspicious_links.patterns.filter(p => p.test(message));
    if (linkMatches.length > 0) {
        indicators.push('Message contains suspicious links');
        totalScore += SCAM_PATTERNS.suspicious_links.weight;
        
        // Extract actual URLs
        const urlRegex = /https?:\/\/[^\s]+/gi;
        const urls = message.match(urlRegex) || [];
        if (urls.length > 0) {
            indicators.push(`URLs found: ${urls.join(', ')}`);
        }
    }

    // Check grammar patterns
    const grammarMatches = SCAM_PATTERNS.grammar.patterns.filter(p => p.test(message));
    if (grammarMatches.length > 0) {
        indicators.push('Poor grammar or spammy formatting detected');
        totalScore += Math.min(SCAM_PATTERNS.grammar.weight, grammarMatches.length * 5);
        categories_matched.push('Poor Grammar/Formatting');
    }

    // Check for phone number requests
    if (/call\s+\d|text\s+\d|dial\s+\d|reply\s+to/i.test(message)) {
        indicators.push('Requests to call or text a number');
        totalScore += 15;
    }

    // Check for personal info requests
    if (/ssn|social security|password|pin|cvv|routing number|account number/i.test(message)) {
        indicators.push('Requests for sensitive personal information');
        totalScore += 25;
        categories_matched.push('Personal Info Phishing');
    }

    totalScore = Math.min(totalScore, 100);

    let risk_level = 'LOW';
    if (totalScore >= 60) risk_level = 'HIGH';
    else if (totalScore >= 30) risk_level = 'MEDIUM';

    let verdict = 'Likely Legitimate';
    if (totalScore >= 60) verdict = 'Likely Scam';
    else if (totalScore >= 30) verdict = 'Suspicious';

    return {
        message: message.substring(0, 200),
        message_length: message.length,
        is_scam: totalScore >= 30,
        confidence_score: totalScore,
        risk_level,
        verdict,
        categories: categories_matched.length > 0 ? categories_matched : ['No scam patterns detected'],
        indicators,
        analysis_method: 'javascript',
        timestamp: new Date().toISOString()
    };
}

// POST /analyze
router.post('/analyze', async (req, res) => {
    try {
        const { message } = req.body;

        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'Message text is required' });
        }

        if (message.trim().length === 0) {
            return res.status(400).json({ error: 'Message cannot be empty' });
        }

        // Try Python analyzer first
        try {
            const pythonPath = path.join(__dirname, 'detector.py');
            const result = await PythonRunner.runWithStdin(pythonPath, { message: message.trim() });
            if (result && !result.error) {
                return res.json(result);
            }
        } catch (pyError) {
            console.log('Python SMS detector unavailable, using JS fallback');
        }

        // JavaScript fallback
        const analysis = analyzeSmsJS(message.trim());
        res.json(analysis);

    } catch (error) {
        console.error('SMS analysis error:', error);
        res.status(500).json({ error: 'Analysis failed', message: error.message });
    }
});

module.exports = router;
