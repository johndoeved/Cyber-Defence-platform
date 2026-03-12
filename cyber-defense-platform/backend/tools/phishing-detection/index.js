const express = require('express');
const router = express.Router();
const validator = require('validator');
const dns = require('dns');
const path = require('path');
const PythonRunner = require('../../utils/pythonRunner');

// Suspicious URL patterns
const SUSPICIOUS_PATTERNS = {
    ipAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    atSymbol: /@/,
    encodedChars: /%[0-9a-fA-F]{2}/,
    longUrl: /^.{75,}$/,
    shorteners: /(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|tiny\.cc|lnkd\.in)/i,
    suspiciousKeywords: /(login|signin|verify|account|update|secure|banking|confirm|password|credential|wallet|paypal|amazon|apple|microsoft|support)/i,
    multipleSubdomains: /([a-z0-9]+\.){4,}/i,
    suspiciousTLD: /\.(xyz|top|club|work|date|racing|win|bid|stream|download|gdn|loan|men|click|link|zip|mov)$/i,
    homograph: /[а-яА-ЯёЁ]/,
    dataUri: /^data:/i
};

// JS Fallback Analyzer
function analyzeUrlJS(url) {
    const indicators = [];
    let score = 0;

    // Validate URL format
    if (!validator.isURL(url, { require_protocol: false })) {
        return {
            url,
            suspicious: true,
            score: 95,
            indicators: ['Invalid URL format'],
            risk_level: 'HIGH',
            details: { valid_format: false }
        };
    }

    // Check for IP address instead of domain
    if (SUSPICIOUS_PATTERNS.ipAddress.test(url)) {
        indicators.push('URL uses IP address instead of domain name');
        score += 25;
    }

    // Check for @ symbol
    if (SUSPICIOUS_PATTERNS.atSymbol.test(url)) {
        indicators.push('URL contains @ symbol (potential redirect)');
        score += 20;
    }

    // Check for encoded characters
    const encodedMatches = url.match(SUSPICIOUS_PATTERNS.encodedChars);
    if (encodedMatches && encodedMatches.length > 2) {
        indicators.push('URL contains excessive encoded characters');
        score += 15;
    }

    // Check URL length
    if (SUSPICIOUS_PATTERNS.longUrl.test(url)) {
        indicators.push('URL is suspiciously long (>75 characters)');
        score += 10;
    }

    // Check for URL shorteners
    if (SUSPICIOUS_PATTERNS.shorteners.test(url)) {
        indicators.push('URL uses a link shortener service');
        score += 15;
    }

    // Check for suspicious keywords
    const keywordMatch = url.match(SUSPICIOUS_PATTERNS.suspiciousKeywords);
    if (keywordMatch) {
        indicators.push(`URL contains suspicious keyword: "${keywordMatch[1]}"`);
        score += 20;
    }

    // Check for multiple subdomains
    if (SUSPICIOUS_PATTERNS.multipleSubdomains.test(url)) {
        indicators.push('URL has an excessive number of subdomains');
        score += 15;
    }

    // Check for suspicious TLDs
    if (SUSPICIOUS_PATTERNS.suspiciousTLD.test(url)) {
        indicators.push('URL uses a suspicious top-level domain');
        score += 15;
    }

    // Check for data URIs
    if (SUSPICIOUS_PATTERNS.dataUri.test(url)) {
        indicators.push('URL is a data URI (potential phishing vector)');
        score += 30;
    }

    // Check HTTPS
    const hasHttps = url.startsWith('https://');
    if (!hasHttps && !url.startsWith('http://')) {
        // No protocol specified
    } else if (!hasHttps) {
        indicators.push('URL does not use HTTPS encryption');
        score += 10;
    }

    // Cap score at 100
    score = Math.min(score, 100);

    // Determine risk level
    let risk_level = 'LOW';
    if (score >= 60) risk_level = 'HIGH';
    else if (score >= 30) risk_level = 'MEDIUM';

    return {
        url,
        suspicious: score >= 30,
        score,
        indicators,
        risk_level,
        details: {
            valid_format: true,
            has_https: hasHttps,
            url_length: url.length,
            analysis_method: 'javascript',
            checked_patterns: Object.keys(SUSPICIOUS_PATTERNS).length,
            timestamp: new Date().toISOString()
        }
    };
}

// DNS resolution check
function checkDNS(hostname) {
    return new Promise((resolve) => {
        try {
            const cleanHost = hostname.replace(/^(https?:\/\/)/, '').split('/')[0].split(':')[0];
            dns.resolve(cleanHost, (err) => {
                resolve(!err);
            });
        } catch {
            resolve(false);
        }
    });
}

// POST /analyze
router.post('/analyze', async (req, res) => {
    try {
        const { url } = req.body;

        if (!url || typeof url !== 'string') {
            return res.status(400).json({
                error: 'URL is required',
                message: 'Please provide a valid URL to analyze'
            });
        }

        const trimmedUrl = url.trim();

        // Try Python analyzer first
        try {
            const pythonPath = path.join(__dirname, 'analyzer.py');
            const result = await PythonRunner.runScript(pythonPath, [trimmedUrl]);
            if (result && !result.error) {
                return res.json(result);
            }
        } catch (pyError) {
            console.log('Python analyzer unavailable, using JS fallback');
        }

        // JavaScript fallback
        const analysis = analyzeUrlJS(trimmedUrl);

        // Additional DNS check
        try {
            const dnsResolved = await checkDNS(trimmedUrl);
            if (!dnsResolved) {
                analysis.indicators.push('Domain does not resolve (may not exist)');
                analysis.score = Math.min(analysis.score + 20, 100);
                if (analysis.score >= 60) analysis.risk_level = 'HIGH';
                else if (analysis.score >= 30) analysis.risk_level = 'MEDIUM';
                analysis.suspicious = analysis.score >= 30;
            }
            analysis.details.dns_resolves = dnsResolved;
        } catch {
            analysis.details.dns_resolves = 'unknown';
        }

        res.json(analysis);

    } catch (error) {
        console.error('Phishing analysis error:', error);
        res.status(500).json({
            error: 'Analysis failed',
            message: error.message
        });
    }
});

module.exports = router;
