const express = require('express');
const router = express.Router();
const zxcvbn = require('zxcvbn');
const crypto = require('crypto');
const path = require('path');
const PythonRunner = require('../../utils/pythonRunner');

// Common passwords blacklist
const COMMON_PASSWORDS = new Set([
    'password', '123456', '123456789', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine', 'princess',
    'football', 'charlie', 'shadow', 'michael', 'password1', 'letmein', 'admin',
    '1234567', '1234567890', '12345', '123123', 'welcome', '666666', 'lovely',
    '654321', '! @ # $ % ^ & *', 'ashley', 'qwerty123', 'passw0rd', 'hello'
]);

function analyzePasswordJS(password) {
    const result = zxcvbn(password);
    const indicators = [];
    let score = 0;

    // Length analysis
    if (password.length >= 16) score += 25;
    else if (password.length >= 12) score += 20;
    else if (password.length >= 8) score += 10;
    else {
        indicators.push('Password is too short (minimum 8 characters recommended)');
        score += 5;
    }

    // Character variety
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    const variety = [hasUpper, hasLower, hasNumber, hasSymbol].filter(Boolean).length;

    if (variety === 4) score += 25;
    else if (variety === 3) score += 15;
    else if (variety === 2) score += 10;
    else {
        indicators.push('Password lacks character variety');
        score += 5;
    }

    if (!hasUpper) indicators.push('Add uppercase letters for better security');
    if (!hasLower) indicators.push('Add lowercase letters');
    if (!hasNumber) indicators.push('Add numbers for better security');
    if (!hasSymbol) indicators.push('Add special characters (!@#$%) for better security');

    // Common password check
    if (COMMON_PASSWORDS.has(password.toLowerCase())) {
        indicators.push('This is a commonly used password — extremely vulnerable');
        score = Math.max(score - 40, 5);
    }

    // Repeated characters
    if (/(.)\1{2,}/.test(password)) {
        indicators.push('Avoid repeated characters (e.g., "aaa")');
        score = Math.max(score - 10, 5);
    }

    // Sequential characters
    if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)) {
        indicators.push('Avoid sequential characters (e.g., "abc", "123")');
        score = Math.max(score - 10, 5);
    }

    // Keyboard patterns
    if (/(qwert|asdf|zxcv|qazwsx|!@#\$%)/i.test(password)) {
        indicators.push('Avoid keyboard patterns (e.g., "qwerty")');
        score = Math.max(score - 10, 5);
    }

    // zxcvbn score mapping
    score += result.score * 10;
    score = Math.min(score, 100);

    // Entropy calculation
    const charsetSize = (hasUpper ? 26 : 0) + (hasLower ? 26 : 0) + (hasNumber ? 10 : 0) + (hasSymbol ? 33 : 0);
    const entropy = password.length * Math.log2(charsetSize || 1);

    // Crack time
    const crackTimes = result.crack_times_display;

    // Strength label
    let strength = 'Very Weak';
    if (score >= 80) strength = 'Very Strong';
    else if (score >= 60) strength = 'Strong';
    else if (score >= 40) strength = 'Moderate';
    else if (score >= 20) strength = 'Weak';

    return {
        password_length: password.length,
        score,
        strength,
        entropy: Math.round(entropy * 100) / 100,
        crack_times: {
            online_throttled: crackTimes.online_throttling_100_per_hour,
            online_unthrottled: crackTimes.online_no_throttling_10_per_second,
            offline_slow: crackTimes.offline_slow_hashing_1e4_per_second,
            offline_fast: crackTimes.offline_fast_hashing_1e10_per_second
        },
        character_analysis: { hasUpper, hasLower, hasNumber, hasSymbol, variety },
        indicators,
        suggestions: result.feedback.suggestions || [],
        warning: result.feedback.warning || null,
        analysis_method: 'javascript'
    };
}

function generatePassword(length = 16, options = {}) {
    const {
        includeUppercase = true,
        includeNumbers = true,
        includeSymbols = true
    } = options;

    let charset = 'abcdefghijklmnopqrstuvwxyz';
    if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeNumbers) charset += '0123456789';
    if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const bytes = crypto.randomBytes(length);
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset[bytes[i] % charset.length];
    }

    // Ensure at least one of each required type
    const requirements = [
        { test: /[a-z]/, chars: 'abcdefghijklmnopqrstuvwxyz' }
    ];
    if (includeUppercase) requirements.push({ test: /[A-Z]/, chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' });
    if (includeNumbers) requirements.push({ test: /[0-9]/, chars: '0123456789' });
    if (includeSymbols) requirements.push({ test: /[^A-Za-z0-9]/, chars: '!@#$%^&*()_+-=[]{}|;:,.<>?' });

    let pwd = password.split('');
    requirements.forEach((req, idx) => {
        if (!req.test.test(password)) {
            const pos = idx % pwd.length;
            pwd[pos] = req.chars[crypto.randomBytes(1)[0] % req.chars.length];
        }
    });

    return pwd.join('');
}

// POST /analyze
router.post('/analyze', async (req, res) => {
    try {
        const { password } = req.body;

        if (!password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Password is required' });
        }

        // Try Python analyzer first
        try {
            const pythonPath = path.join(__dirname, 'checker.py');
            const result = await PythonRunner.runWithStdin(pythonPath, { password, action: 'analyze' });
            if (result && !result.error) {
                return res.json(result);
            }
        } catch (pyError) {
            console.log('Python password analyzer unavailable, using JS fallback');
        }

        // JavaScript fallback
        const analysis = analyzePasswordJS(password);
        res.json(analysis);

    } catch (error) {
        console.error('Password analysis error:', error);
        res.status(500).json({ error: 'Analysis failed', message: error.message });
    }
});

// POST /generate
router.post('/generate', (req, res) => {
    try {
        const {
            length = 16,
            includeUppercase = true,
            includeNumbers = true,
            includeSymbols = true
        } = req.body;

        const pwdLength = Math.max(8, Math.min(128, parseInt(length) || 16));
        const password = generatePassword(pwdLength, { includeUppercase, includeNumbers, includeSymbols });
        const analysis = analyzePasswordJS(password);

        res.json({
            generated_password: password,
            analysis
        });

    } catch (error) {
        console.error('Password generation error:', error);
        res.status(500).json({ error: 'Generation failed', message: error.message });
    }
});

module.exports = router;
