const axios = require('axios');

const API_BASE = 'http://localhost:3000/api';

async function verifyTools() {
    console.log('🚀 Starting tool verification...\n');

    const tests = [
        {
            name: 'Phishing Detection',
            endpoint: '/phishing/analyze',
            payload: { url: 'http://suspicious-login-verify-account.xyz/update' },
            validate: (data) => data.analysis_method === 'python'
        },
        {
            name: 'Digital Footprint',
            endpoint: '/footprint/scan',
            payload: { email: 'test@example.com', username: 'testuser' },
            validate: (data) => data.analysis_method === 'python'
        },
        {
            name: 'Password Analyzer',
            endpoint: '/password/analyze',
            payload: { password: 'P@ssword123!' },
            validate: (data) => !!data.score
        },
         {
            name: 'SMS Scam Detector',
            endpoint: '/sms/analyze',
            payload: { message: 'URGENT: Your account has been suspended. Click here to verify: http://scam.link' },
            validate: (data) => !!data.verdict
        }
    ];

    for (const test of tests) {
        try {
            console.log(`Testing ${test.name}...`);
            const response = await axios.post(`${API_BASE}${test.endpoint}`, test.payload);
            const data = response.data;

            if (test.validate(data)) {
                console.log(`✅ ${test.name}: PASSED (Method: ${data.analysis_method || 'N/A'})\n`);
            } else {
                console.warn(`⚠️ ${test.name}: WARNING - Expected Python engine but got ${data.analysis_method || 'unknown'}\n`);
            }
        } catch (error) {
            console.error(`❌ ${test.name}: FAILED`);
            if (error.response) {
                console.error(`   Error ${error.response.status}: ${JSON.stringify(error.response.data)}\n`);
            } else {
                console.error(`   Error: ${error.message}\n`);
            }
        }
    }

    console.log('Verification finished.');
}

verifyTools();
