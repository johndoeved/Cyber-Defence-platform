/* ============================================
   CYBER GUARD IQ - Frontend Application Logic
   ============================================ */

const API_BASE = window.location.origin + '/api';

// ── Utility Functions ──
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', info: 'fa-info-circle' };
    toast.innerHTML = `
        <i class="fas ${icons[type]} toast-icon"></i>
        <span class="toast-message">${message}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function showLoading(containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = '<div class="loading-skeleton"></div>';
}

function setButtonLoading(button, loading) {
    if (loading) {
        button.dataset.originalText = button.innerHTML;
        button.innerHTML = '<span class="loading-spinner"></span> Analyzing...';
        button.disabled = true;
    } else {
        button.innerHTML = button.dataset.originalText || button.innerHTML;
        button.disabled = false;
    }
}

async function apiCall(endpoint, data) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({ message: 'Request failed' }));
        throw new Error(error.message || error.error || 'Request failed');
    }
    return response.json();
}

function getRiskClass(level) {
    const l = (level || '').toLowerCase();
    if (l === 'critical') return 'risk-critical';
    if (l === 'high') return 'risk-high';
    if (l === 'medium') return 'risk-medium';
    return 'risk-low';
}

function getScoreColor(score) {
    if (score >= 70) return 'var(--accent-red)';
    if (score >= 40) return 'var(--accent-orange)';
    return 'var(--accent-green)';
}

function getStrengthColor(score) {
    if (score >= 80) return 'var(--accent-green)';
    if (score >= 60) return 'var(--accent-teal)';
    if (score >= 40) return 'var(--accent-orange)';
    return 'var(--accent-red)';
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(() => {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copied to clipboard!', 'success');
    });
}

// ── Background Particles ──
function createParticles() {
    const container = document.getElementById('particles');
    for (let i = 0; i < 30; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 8 + 's';
        particle.style.animationDuration = (6 + Math.random() * 6) + 's';
        container.appendChild(particle);
    }
}

// ══════════════════════════════════
// TOOL 1: Phishing Detection
// ══════════════════════════════════
document.getElementById('phishing-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('phishing-url').value.trim();
    if (!url) return;

    const btn = e.target.querySelector('button[type="submit"]');
    setButtonLoading(btn, true);
    showLoading('phishing-results');

    try {
        const result = await apiCall('/phishing/analyze', { url });
        renderPhishingResults(result);
    } catch (err) {
        showToast(err.message, 'error');
        document.getElementById('phishing-results').innerHTML = '';
    } finally {
        setButtonLoading(btn, false);
    }
});

function renderPhishingResults(data) {
    const container = document.getElementById('phishing-results');
    const scoreColor = getScoreColor(data.score);

    container.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-title">
                    <i class="fas fa-fish" style="color: var(--accent-blue); margin-right: 0.5rem;"></i>
                    Phishing Analysis Results
                </span>
                <span class="risk-badge ${getRiskClass(data.risk_level)}">${data.risk_level} Risk</span>
            </div>
            <div class="score-display">
                <div class="score-circle" style="background: conic-gradient(${scoreColor} ${data.score * 3.6}deg, rgba(35,59,85,0.3) 0deg);">
                    <span class="score-value" style="color: ${scoreColor}">${data.score}</span>
                </div>
                <div class="score-info">
                    <div class="score-label">Suspicion Score</div>
                    <div class="score-strength" style="color: ${scoreColor}">
                        ${data.suspicious ? '⚠️ Suspicious URL Detected' : '✅ URL Appears Safe'}
                    </div>
                </div>
            </div>
            ${data.indicators && data.indicators.length > 0 ? `
                <h3 class="section-title"><i class="fas fa-exclamation-triangle" style="color: var(--accent-orange); margin-right: 0.4rem;"></i>Indicators Found</h3>
                <ul class="indicators-list">
                    ${data.indicators.map(ind => `
                        <li class="indicator-item">
                            <i class="fas fa-circle-exclamation indicator-icon"></i>
                            <span>${ind}</span>
                        </li>`).join('')}
                </ul>
            ` : '<p class="section-title" style="color: var(--accent-green);">✅ No suspicious indicators found</p>'}
            <div class="details-grid">
                <div class="detail-item">
                    <div class="detail-label">URL Length</div>
                    <div class="detail-value">${data.details?.url_length || data.url?.length || '-'} chars</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">HTTPS</div>
                    <div class="detail-value">${data.details?.has_https ? '✅ Yes' : '❌ No'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">DNS Resolves</div>
                    <div class="detail-value">${data.details?.dns_resolves === true ? '✅ Yes' : data.details?.dns_resolves === false ? '❌ No' : '—'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Analysis Engine</div>
                    <div class="detail-value">${(data.analysis_method || data.details?.analysis_method || 'JS').toUpperCase()}</div>
                </div>
            </div>
        </div>
    `;
}

// ══════════════════════════════════
// TOOL 2: Password Analyzer
// ══════════════════════════════════
const passwordInput = document.getElementById('password-input');
const strengthBar = document.getElementById('strength-bar');

passwordInput.addEventListener('input', () => {
    const pwd = passwordInput.value;
    if (!pwd) {
        strengthBar.style.width = '0%';
        strengthBar.style.background = 'var(--accent-red)';
        return;
    }
    // Quick local strength estimate
    let strength = 0;
    if (pwd.length >= 8) strength += 20;
    if (pwd.length >= 12) strength += 15;
    if (pwd.length >= 16) strength += 10;
    if (/[A-Z]/.test(pwd)) strength += 15;
    if (/[a-z]/.test(pwd)) strength += 10;
    if (/[0-9]/.test(pwd)) strength += 15;
    if (/[^A-Za-z0-9]/.test(pwd)) strength += 15;
    strength = Math.min(strength, 100);

    strengthBar.style.width = strength + '%';
    strengthBar.style.background = getStrengthColor(strength);
});

document.getElementById('password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = passwordInput.value;
    if (!password) return;

    const btn = e.target.querySelector('button[type="submit"]');
    setButtonLoading(btn, true);
    showLoading('password-results');

    try {
        const result = await apiCall('/password/analyze', { password });
        renderPasswordResults(result);
    } catch (err) {
        showToast(err.message, 'error');
        document.getElementById('password-results').innerHTML = '';
    } finally {
        setButtonLoading(btn, false);
    }
});

function renderPasswordResults(data) {
    const container = document.getElementById('password-results');
    const color = getStrengthColor(data.score);

    container.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-title">
                    <i class="fas fa-key" style="color: var(--accent-green); margin-right: 0.5rem;"></i>
                    Password Strength Analysis
                </span>
                <span class="risk-badge" style="background: ${color}20; color: ${color}; border: 1px solid ${color}40;">${data.strength}</span>
            </div>
            <div class="score-display">
                <div class="score-circle" style="background: conic-gradient(${color} ${data.score * 3.6}deg, rgba(35,59,85,0.3) 0deg);">
                    <span class="score-value" style="color: ${color}">${data.score}</span>
                </div>
                <div class="score-info">
                    <div class="score-label">Strength Score</div>
                    <div class="score-strength" style="color: ${color}">${data.strength}</div>
                    <div class="score-label" style="margin-top: 0.3rem;">Entropy: ${data.entropy} bits</div>
                </div>
            </div>
            <div class="details-grid">
                <div class="detail-item">
                    <div class="detail-label">Length</div>
                    <div class="detail-value">${data.password_length} chars</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Uppercase</div>
                    <div class="detail-value">${data.character_analysis?.hasUpper ? '✅' : '❌'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Lowercase</div>
                    <div class="detail-value">${data.character_analysis?.hasLower ? '✅' : '❌'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Numbers</div>
                    <div class="detail-value">${data.character_analysis?.hasNumber ? '✅' : '❌'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Symbols</div>
                    <div class="detail-value">${data.character_analysis?.hasSymbol ? '✅' : '❌'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Crack Time (Online)</div>
                    <div class="detail-value">${data.crack_times?.online_throttled || '—'}</div>
                </div>
            </div>
            ${data.indicators && data.indicators.length > 0 ? `
                <h3 class="section-title"><i class="fas fa-lightbulb" style="color: var(--accent-orange); margin-right: 0.4rem;"></i>Suggestions</h3>
                <ul class="indicators-list">
                    ${data.indicators.map(ind => `
                        <li class="indicator-item">
                            <i class="fas fa-arrow-right indicator-icon"></i>
                            <span>${ind}</span>
                        </li>`).join('')}
                </ul>
            ` : ''}
            ${data.hibp_check ? `
                <h3 class="section-title"><i class="fas fa-database" style="color: ${data.hibp_check.found ? 'var(--accent-red)' : 'var(--accent-green)'}; margin-right: 0.4rem;"></i>Breach Check</h3>
                <div class="indicator-item">
                    <i class="fas ${data.hibp_check.found ? 'fa-exclamation-triangle' : 'fa-shield-halved'} indicator-icon ${data.hibp_check.found ? '' : 'safe'}"></i>
                    <span>${data.hibp_check.message}</span>
                </div>
            ` : ''}
        </div>
    `;
}

// Password Generator
document.getElementById('generate-pwd-btn').addEventListener('click', async () => {
    const length = document.getElementById('gen-length').value;
    const includeUppercase = document.getElementById('gen-upper').checked;
    const includeNumbers = document.getElementById('gen-numbers').checked;
    const includeSymbols = document.getElementById('gen-symbols').checked;

    try {
        const result = await apiCall('/password/generate', {
            length: parseInt(length),
            includeUppercase, includeNumbers, includeSymbols
        });

        const display = document.getElementById('generated-password-display');
        display.innerHTML = `
            <div class="generated-password-box">
                <code>${result.generated_password}</code>
                <button class="copy-btn" onclick="copyToClipboard('${result.generated_password.replace(/'/g, "\\'")}')">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
        `;

        if (result.analysis) {
            renderPasswordResults(result.analysis);
        }

        showToast('Secure password generated!', 'success');
    } catch (err) {
        showToast(err.message, 'error');
    }
});

// ══════════════════════════════════
// TOOL 3: SMS Scam Detector
// ══════════════════════════════════
const smsInput = document.getElementById('sms-input');
const smsCharCount = document.getElementById('sms-char-count');

smsInput.addEventListener('input', () => {
    const count = smsInput.value.length;
    smsCharCount.textContent = `${count} / 500`;
    smsCharCount.style.color = count > 500 ? 'var(--accent-red)' : 'var(--text-muted)';
});

document.getElementById('sms-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const message = smsInput.value.trim();
    if (!message) return;

    const btn = e.target.querySelector('button[type="submit"]');
    setButtonLoading(btn, true);
    showLoading('sms-results');

    try {
        const result = await apiCall('/sms/analyze', { message });
        renderSmsResults(result);
    } catch (err) {
        showToast(err.message, 'error');
        document.getElementById('sms-results').innerHTML = '';
    } finally {
        setButtonLoading(btn, false);
    }
});

function renderSmsResults(data) {
    const container = document.getElementById('sms-results');
    const scoreColor = getScoreColor(data.confidence_score);

    container.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-title">
                    <i class="fas fa-comment-sms" style="color: var(--accent-orange); margin-right: 0.5rem;"></i>
                    SMS Analysis Results
                </span>
                <span class="risk-badge ${getRiskClass(data.risk_level)}">${data.verdict}</span>
            </div>
            <div class="score-display">
                <div class="score-circle" style="background: conic-gradient(${scoreColor} ${data.confidence_score * 3.6}deg, rgba(35,59,85,0.3) 0deg);">
                    <span class="score-value" style="color: ${scoreColor}">${data.confidence_score}</span>
                </div>
                <div class="score-info">
                    <div class="score-label">Scam Confidence Score</div>
                    <div class="score-strength" style="color: ${scoreColor}">
                        ${data.is_scam ? '⚠️ Scam Indicators Detected' : '✅ No Scam Patterns Found'}
                    </div>
                </div>
            </div>
            ${data.categories && data.categories.length > 0 ? `
                <h3 class="section-title"><i class="fas fa-tags" style="color: var(--accent-purple); margin-right: 0.4rem;"></i>Categories</h3>
                <div class="details-grid">
                    ${data.categories.map(cat => `
                        <div class="detail-item">
                            <div class="detail-value">${cat}</div>
                        </div>
                    `).join('')}
                </div>
            ` : ''}
            ${data.indicators && data.indicators.length > 0 ? `
                <h3 class="section-title"><i class="fas fa-exclamation-triangle" style="color: var(--accent-orange); margin-right: 0.4rem;"></i>Indicators</h3>
                <ul class="indicators-list">
                    ${data.indicators.map(ind => `
                        <li class="indicator-item">
                            <i class="fas fa-circle-exclamation indicator-icon"></i>
                            <span>${ind}</span>
                        </li>`).join('')}
                </ul>
            ` : ''}
            <div class="details-grid" style="margin-top: 1rem;">
                <div class="detail-item">
                    <div class="detail-label">Message Length</div>
                    <div class="detail-value">${data.message_length} chars</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Analysis Engine</div>
                    <div class="detail-value">${(data.analysis_method || 'JS').toUpperCase()}</div>
                </div>
            </div>
        </div>
    `;
}

// ══════════════════════════════════
// TOOL 4: Digital Footprint
// ══════════════════════════════════
document.getElementById('footprint-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('footprint-email').value.trim();
    const username = document.getElementById('footprint-username').value.trim();

    if (!email && !username) {
        showToast('Please enter an email or username', 'error');
        return;
    }

    const btn = e.target.querySelector('button[type="submit"]');
    setButtonLoading(btn, true);
    showLoading('footprint-results');

    try {
        const result = await apiCall('/footprint/scan', { email, username });
        renderFootprintResults(result);
    } catch (err) {
        showToast(err.message, 'error');
        document.getElementById('footprint-results').innerHTML = '';
    } finally {
        setButtonLoading(btn, false);
    }
});

function renderFootprintResults(data) {
    const container = document.getElementById('footprint-results');
    const scoreColor = getScoreColor(data.risk_score);

    const breachesHtml = data.breaches && data.breaches.length > 0 ? `
        <h3 class="section-title"><i class="fas fa-database" style="color: var(--accent-red); margin-right: 0.4rem;"></i>Data Breaches (${data.breaches.length})</h3>
        <table class="breach-table">
            <thead><tr><th>Source</th><th>Date</th><th>Records</th><th>Data Exposed</th></tr></thead>
            <tbody>
                ${data.breaches.map(b => `
                    <tr>
                        <td style="font-weight: 600; color: var(--accent-orange);">${b.name}</td>
                        <td>${b.date}</td>
                        <td>${b.records}</td>
                        <td>${Array.isArray(b.data_types) ? b.data_types.join(', ') : b.data_types}</td>
                    </tr>`).join('')}
            </tbody>
        </table>
    ` : '<p style="color: var(--accent-green); margin-top: 0.5rem;"><i class="fas fa-shield-halved"></i> No known breaches found</p>';

    const socialHtml = data.social_accounts && data.social_accounts.length > 0 ? `
        <h3 class="section-title"><i class="fas fa-share-nodes" style="color: var(--accent-blue); margin-right: 0.4rem;"></i>Social Media Accounts</h3>
        <div class="social-grid">
            ${data.social_accounts.map(acc => `
                <div class="social-item ${acc.found ? 'found' : 'not-found'}">
                    <i class="${acc.icon || 'fas fa-globe'}"></i>
                    <span>${acc.platform}</span>
                    <span style="margin-left: auto; font-size: 0.75rem; color: ${acc.found ? 'var(--accent-orange)' : 'var(--text-muted)'};">
                        ${acc.found ? 'Found' : '—'}
                    </span>
                </div>`).join('')}
        </div>
    ` : '';

    container.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-title">
                    <i class="fas fa-fingerprint" style="color: var(--accent-purple); margin-right: 0.5rem;"></i>
                    Digital Footprint Report
                </span>
                <span class="risk-badge ${getRiskClass(data.risk_level)}">${data.risk_level} Exposure</span>
            </div>
            <div class="score-display">
                <div class="score-circle" style="background: conic-gradient(${scoreColor} ${data.risk_score * 3.6}deg, rgba(35,59,85,0.3) 0deg);">
                    <span class="score-value" style="color: ${scoreColor}">${data.risk_score}</span>
                </div>
                <div class="score-info">
                    <div class="score-label">Exposure Risk Score</div>
                    <div class="score-strength" style="color: ${scoreColor}">${data.risk_level} Risk</div>
                </div>
            </div>
            ${breachesHtml}
            ${socialHtml}
            ${data.recommendations && data.recommendations.length > 0 ? `
                <h3 class="section-title"><i class="fas fa-shield-halved" style="color: var(--accent-teal); margin-right: 0.4rem;"></i>Recommendations</h3>
                <div class="recommendations-list">
                    ${data.recommendations.map(rec => `
                        <div class="rec-item">
                            <i class="fas fa-check-circle"></i>
                            <span>${rec}</span>
                        </div>`).join('')}
                </div>
            ` : ''}
        </div>
    `;
}

// ══════════════════════════════════
// TOOL 5: Privacy Checker
// ══════════════════════════════════
const privacyPlatformSettings = {
    general: [
        { id: 'cookies', name: 'Block Third-Party Cookies', risk: 'high' },
        { id: 'do_not_track', name: 'Do Not Track', risk: 'medium' },
        { id: 'webrtc', name: 'WebRTC Leak Prevention', risk: 'high' },
        { id: 'fingerprinting', name: 'Anti-Fingerprinting', risk: 'high' },
        { id: 'password_manager', name: 'Password Manager', risk: 'medium' },
        { id: 'javascript', name: 'NoScript for Untrusted Sites', risk: 'medium' }
    ],
    facebook: [
        { id: 'profile_public', name: 'Friends-Only Profile', risk: 'high' },
        { id: 'search_engines', name: 'Block Search Indexing', risk: 'high' },
        { id: 'face_recognition', name: 'Disable Face Recognition', risk: 'medium' },
        { id: 'location_sharing', name: 'Disable Location', risk: 'high' },
        { id: 'third_party_apps', name: 'Restrict Third-Party Apps', risk: 'medium' },
        { id: 'ad_tracking', name: 'Opt Out of Ads', risk: 'medium' }
    ],
    google: [
        { id: 'web_activity', name: 'Pause Web Activity', risk: 'high' },
        { id: 'location_history', name: 'Pause Location History', risk: 'high' },
        { id: 'youtube_history', name: 'Pause YouTube History', risk: 'medium' },
        { id: 'ad_personalization', name: 'Turn Off Ad Personalization', risk: 'medium' },
        { id: 'shared_endorsements', name: 'Opt Out of Endorsements', risk: 'low' }
    ],
    instagram: [
        { id: 'private_account', name: 'Private Account', risk: 'high' },
        { id: 'activity_status', name: 'Disable Activity Status', risk: 'medium' },
        { id: 'story_sharing', name: 'Restrict Story Sharing', risk: 'low' },
        { id: 'data_download', name: 'Limit Data Sharing', risk: 'medium' }
    ],
    twitter: [
        { id: 'protect_tweets', name: 'Protect Tweets', risk: 'high' },
        { id: 'location_tweets', name: 'Disable Location Tagging', risk: 'medium' },
        { id: 'discoverability', name: 'Disable Discoverability', risk: 'high' },
        { id: 'personalization', name: 'Disable Personalization', risk: 'medium' }
    ]
};

const platformSelect = document.getElementById('privacy-platform');
const settingsGrid = document.getElementById('privacy-settings-grid');

function renderPrivacySettings(platform) {
    const settings = privacyPlatformSettings[platform] || privacyPlatformSettings.general;
    settingsGrid.innerHTML = settings.map(s => `
        <div class="privacy-setting-item">
            <span class="risk-indicator ${s.risk}"></span>
            <label for="ps-${s.id}">${s.name}</label>
            <input type="checkbox" id="ps-${s.id}" data-id="${s.id}">
        </div>
    `).join('');
}

platformSelect.addEventListener('change', () => {
    renderPrivacySettings(platformSelect.value);
});

// Initial render
renderPrivacySettings('general');

document.getElementById('privacy-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const platform = platformSelect.value;
    const settings = {};
    settingsGrid.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        settings[cb.dataset.id] = cb.checked;
    });

    const btn = e.target.querySelector('button[type="submit"]');
    setButtonLoading(btn, true);
    showLoading('privacy-results');

    try {
        const result = await apiCall('/privacy/check', { platform, settings });
        renderPrivacyResults(result);
    } catch (err) {
        showToast(err.message, 'error');
        document.getElementById('privacy-results').innerHTML = '';
    } finally {
        setButtonLoading(btn, false);
    }
});

function renderPrivacyResults(data) {
    const container = document.getElementById('privacy-results');
    const color = getStrengthColor(data.privacy_score);

    container.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <span class="result-title">
                    <i class="fas fa-user-shield" style="color: var(--accent-teal); margin-right: 0.5rem;"></i>
                    Privacy Analysis — ${data.platform}
                </span>
                <span class="risk-badge ${getRiskClass(data.risk_level)}">${data.risk_level} Risk</span>
            </div>
            <div class="score-display">
                <div class="score-circle" style="background: conic-gradient(${color} ${data.privacy_score * 3.6}deg, rgba(35,59,85,0.3) 0deg);">
                    <span class="score-value" style="color: ${color}">${data.privacy_score}</span>
                </div>
                <div class="score-info">
                    <div class="score-label">Privacy Score</div>
                    <div class="score-strength" style="color: ${color}">
                        ${data.privacy_score >= 70 ? '✅ Good Privacy' : data.privacy_score >= 40 ? '⚠️ Moderate Risk' : '🔴 Poor Privacy'}
                    </div>
                    <div class="score-label" style="margin-top: 0.3rem;">
                        ${data.secure_count}/${data.total_checks} settings secure
                    </div>
                </div>
            </div>
            ${data.checks && data.checks.length > 0 ? `
                <h3 class="section-title"><i class="fas fa-list-check" style="margin-right: 0.4rem;"></i>Settings Analysis</h3>
                <ul class="indicators-list">
                    ${data.checks.map(check => `
                        <li class="indicator-item">
                            <i class="fas ${check.status === 'secure' ? 'fa-check-circle' : 'fa-exclamation-circle'} indicator-icon ${check.status === 'secure' ? 'safe' : ''}"></i>
                            <span><strong>${check.name}:</strong> ${check.recommendation}</span>
                        </li>`).join('')}
                </ul>
            ` : ''}
            ${data.general_tips ? `
                <h3 class="section-title"><i class="fas fa-lightbulb" style="color: var(--accent-teal); margin-right: 0.4rem;"></i>Tips</h3>
                <div class="recommendations-list">
                    ${data.general_tips.map(tip => `
                        <div class="rec-item">
                            <i class="fas fa-check-circle"></i>
                            <span>${tip}</span>
                        </div>`).join('')}
                </div>
            ` : ''}
        </div>
    `;
}

// ══════════════════════════════════
// TOOL 6: HackBot Agent
// ══════════════════════════════════
let scanPollInterval = null;

document.getElementById('hackbot-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = document.getElementById('hackbot-target').value.trim();
    if (!target) return;

    const btn = e.target.querySelector('button[type="submit"]');
    setButtonLoading(btn, true);

    // Clear terminal
    const terminalBody = document.getElementById('terminal-body');
    terminalBody.innerHTML = '';
    document.getElementById('hackbot-results').innerHTML = '';

    // Show progress bar
    const progressContainer = document.getElementById('terminal-progress');
    const progressBar = document.getElementById('scan-progress-bar');
    progressContainer.classList.add('active');
    progressBar.style.width = '0%';

    addTerminalLine('phase', `Initiating scan on target: ${target}`);
    addTerminalLine('command', 'Connecting to HackBot Agent v2.0...');

    try {
        const scanResult = await apiCall('/hackbot/scan', { target });
        const scanId = scanResult.scanId;

        addTerminalLine('success', `Scan initiated (ID: ${scanId.substring(0, 8)}...)`);

        // Poll for status
        scanPollInterval = setInterval(async () => {
            try {
                const statusRes = await fetch(`${API_BASE}/hackbot/status/${scanId}`);
                const status = await statusRes.json();

                progressBar.style.width = status.progress + '%';

                // Add new output lines
                if (status.output) {
                    terminalBody.innerHTML = '';
                    status.output.forEach(line => {
                        addTerminalLine(line.type, line.text);
                    });
                    terminalBody.scrollTop = terminalBody.scrollHeight;
                }

                if (status.status === 'complete') {
                    clearInterval(scanPollInterval);
                    scanPollInterval = null;
                    progressContainer.classList.remove('active');
                    setButtonLoading(btn, false);

                    addTerminalLine('success', '═══ Scan Complete ═══');
                    addTerminalLine('result', `Elapsed: ${status.elapsed}`);

                    if (status.results) {
                        renderHackbotResults(status.results);
                    }

                    showToast('Security scan completed!', 'success');
                }
            } catch {
                // Ignore polling errors
            }
        }, 800);

        // Timeout fallback
        setTimeout(() => {
            if (scanPollInterval) {
                clearInterval(scanPollInterval);
                scanPollInterval = null;
                progressContainer.classList.remove('active');
                setButtonLoading(btn, false);
                addTerminalLine('error', 'Scan timed out. Fetching available results...');

                // Quick scan fallback
                apiCall('/hackbot/quick-scan', { target }).then(results => {
                    renderHackbotResults(results);
                }).catch(() => {});
            }
        }, 30000);

    } catch (err) {
        showToast(err.message, 'error');
        addTerminalLine('error', `Error: ${err.message}`);
        progressContainer.classList.remove('active');
        setButtonLoading(btn, false);
    }
});

function addTerminalLine(type, text) {
    const terminalBody = document.getElementById('terminal-body');
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const prompt = document.createElement('span');
    prompt.className = 'terminal-prompt';
    prompt.textContent = type === 'phase' ? '»' : type === 'error' ? '!' : '$';

    const content = document.createElement('span');
    content.className = `terminal-text ${type}`;
    content.textContent = text;

    line.appendChild(prompt);
    line.appendChild(content);
    terminalBody.appendChild(line);
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

function renderHackbotResults(data) {
    const container = document.getElementById('hackbot-results');

    const vulnsHtml = data.vulnerabilities ? data.vulnerabilities.map(v => `
        <div class="vuln-item ${v.severity.toLowerCase()}">
            <div class="vuln-header">
                <span class="vuln-name">${v.name}</span>
                <span class="risk-badge ${getRiskClass(v.severity)}">${v.severity} (CVSS: ${v.cvss})</span>
            </div>
            <div class="vuln-id">${v.id}</div>
            <div class="vuln-desc">${v.description}</div>
            <div class="vuln-fix"><i class="fas fa-wrench" style="margin-right: 0.3rem;"></i>${v.remediation}</div>
        </div>
    `).join('') : '';

    const headersHtml = data.headers_analysis ? Object.entries(data.headers_analysis).map(([key, val]) => `
        <div class="detail-item">
            <div class="detail-label">${key}</div>
            <div class="detail-value" style="color: ${val === 'PRESENT' ? 'var(--accent-green)' : 'var(--accent-red)'}">
                ${val === 'PRESENT' ? '✅ Present' : '❌ Missing'}
            </div>
        </div>
    `).join('') : '';

    container.innerHTML = `
        <div class="result-card" style="margin-top: 1rem;">
            <div class="result-header">
                <span class="result-title">
                    <i class="fas fa-robot" style="color: var(--accent-red); margin-right: 0.5rem;"></i>
                    Security Scan Report — ${data.target}
                </span>
                <span class="risk-badge ${getRiskClass(data.overall_risk)}">${data.overall_risk}</span>
            </div>
            <div class="details-grid">
                <div class="detail-item">
                    <div class="detail-label">Scan Time</div>
                    <div class="detail-value">${data.scan_time}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Ports Scanned</div>
                    <div class="detail-value">${data.summary?.total_ports_scanned || '—'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Open Ports</div>
                    <div class="detail-value">${data.summary?.open_ports || '—'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Vulnerabilities</div>
                    <div class="detail-value" style="color: var(--accent-orange);">${data.summary?.vulnerabilities_found || '—'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">SSL Grade</div>
                    <div class="detail-value">${data.ssl_analysis?.grade || '—'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">TLS Protocol</div>
                    <div class="detail-value">${data.ssl_analysis?.protocol || '—'}</div>
                </div>
            </div>
            ${data.open_ports && data.open_ports.length > 0 ? `
                <h3 class="section-title"><i class="fas fa-network-wired" style="margin-right: 0.4rem;"></i>Open Ports</h3>
                <table class="breach-table">
                    <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th></tr></thead>
                    <tbody>
                        ${data.open_ports.map(p => `
                            <tr>
                                <td style="font-weight: 600;">${p.port}</td>
                                <td>${p.service}</td>
                                <td>${p.version}</td>
                                <td><span class="risk-badge ${getRiskClass(p.risk)}" style="padding: 0.2rem 0.6rem; font-size: 0.7rem;">${p.risk.toUpperCase()}</span></td>
                            </tr>`).join('')}
                    </tbody>
                </table>
            ` : ''}
            ${vulnsHtml ? `
                <h3 class="section-title"><i class="fas fa-bug" style="color: var(--accent-red); margin-right: 0.4rem;"></i>Vulnerabilities</h3>
                ${vulnsHtml}
            ` : ''}
            ${headersHtml ? `
                <h3 class="section-title"><i class="fas fa-heading" style="margin-right: 0.4rem;"></i>Security Headers</h3>
                <div class="details-grid">${headersHtml}</div>
            ` : ''}
            ${data.recommendations ? `
                <h3 class="section-title"><i class="fas fa-shield-halved" style="color: var(--accent-teal); margin-right: 0.4rem;"></i>Recommendations</h3>
                <div class="recommendations-list">
                    ${data.recommendations.map(rec => `
                        <div class="rec-item">
                            <i class="fas fa-check-circle"></i>
                            <span>${rec}</span>
                        </div>`).join('')}
                </div>
            ` : ''}
        </div>
    `;
}

// ── Health Check ──
document.getElementById('health-check-btn').addEventListener('click', async (e) => {
    e.preventDefault();
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        const activeTools = data.tools.filter(t => t.status === 'active').length;
        showToast(`System: ${data.status} | ${activeTools}/${data.tools.length} tools active | Uptime: ${Math.round(data.uptime)}s`, 'success');
    } catch {
        showToast('Unable to reach server. Please ensure the backend is running.', 'error');
    }
});

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
    createParticles();
});
