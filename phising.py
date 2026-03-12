from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import hashlib
import requests
from urllib.parse import urlparse
import json
import whois
import datetime
import random
import string

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Add this root route
@app.route('/')
def home():
    return jsonify({
        'message': 'CyberGuardIQ API is running',
        'endpoints': {
            'phishing': '/api/phishing-detect',
            'password': '/api/analyze-password',
            'sms': '/api/analyze-sms',
            'footprint': '/api/check-footprint',
            'privacy': '/api/check-privacy',
            'tips': '/api/awareness-tips',
            'dashboard': '/api/dashboard-data'
        }
    })

# Your existing routes here...

# ========== PHISHING DETECTION TOOL ==========
@app.route('http://127.0.0.1:5000/api/awareness-tips', methods=['GET'])
def get_awareness_tips():
    # Placeholder for awareness tips data
    tips = [
        "Always verify the sender's email address before clicking on any links.",
        "Be cautious of emails that create a sense of urgency or fear.",
        "Never share your login credentials or personal information via email or unknown websites."
    ]
    return jsonify(tips)
    return jsonify({'error': 'No URL provided'}), 400
    
    # Phishing detection logic
    result = analyze_url_for_phishing(url)
    return jsonify(result)

def analyze_url_for_phishing(url):
    score = 100
    warnings = []
    suggestions = []
    
    # Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Check for IP address in URL
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, domain):
            score -= 30
            warnings.append("URL uses IP address instead of domain name")
            suggestions.append("Legitimate sites typically use domain names, not IP addresses")
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        if any(shortener in domain for shortener in shorteners):
            score -= 20
            warnings.append("URL uses a link shortening service")
            suggestions.append("Shortened URLs can hide the actual destination")
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            score -= 15
            warnings.append("Unusual number of subdomains detected")
            suggestions.append("Legitimate sites rarely use more than 2-3 subdomains")
        
        # Check for @ symbol in URL
        if '@' in url:
            score -= 25
            warnings.append("URL contains @ symbol which can be used for deception")
            suggestions.append("The @ symbol can make the URL appear different than it really is")
        
        # Check for HTTPS
        if parsed.scheme != 'https':
            score -= 20
            warnings.append("Website does not use HTTPS encryption")
            suggestions.append("Secure sites should use HTTPS to encrypt your data")
        
        # Check for common phishing keywords
        phishing_keywords = ['secure', 'login', 'verify', 'account', 'update', 'banking', 
                           'paypal', 'apple', 'microsoft', 'amazon', 'confirm']
        url_lower = url.lower()
        for keyword in phishing_keywords:
            if keyword in url_lower and keyword not in domain.lower():
                score -= 10
                warnings.append(f"Contains '{keyword}' which is common in phishing URLs")
                break
        
        # Check for misspellings of popular domains
        popular_domains = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix']
        for popular in popular_domains:
            if popular in domain.lower():
                # Check if it's exactly the domain or a misspelling
                if popular not in domain.lower().split('.')[0]:
                    score -= 25
                    warnings.append(f"Possible misspelling of '{popular}.com'")
                    suggestions.append(f"Verify you're visiting the real {popular}.com")
        
        # Domain age check (if we can get WHOIS info)
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age_days = (datetime.datetime.now() - creation_date).days
                if age_days < 30:
                    score -= 40
                    warnings.append("Domain was created very recently (< 30 days)")
                    suggestions.append("New domains are often used for phishing campaigns")
                elif age_days < 90:
                    score -= 20
                    warnings.append("Domain is relatively new (< 90 days)")
        except:
            # WHOIS lookup failed, add a warning
            score -= 10
            warnings.append("Could not verify domain age")
    
    except Exception as e:
        return {'error': str(e), 'score': 0, 'risk_level': 'Unknown'}
    
    # Determine risk level
    if score >= 80:
        risk_level = 'Low'
    elif score >= 60:
        risk_level = 'Medium'
    elif score >= 40:
        risk_level = 'High'
    else:
        risk_level = 'Critical'
    
    return {
        'url': url,
        'score': max(0, score),
        'risk_level': risk_level,
        'warnings': warnings[:3],  # Limit to top 3 warnings
        'suggestions': suggestions[:3]
    }

# ========== PASSWORD ANALYZER TOOL ==========
@app.route('/api/analyze-password', methods=['POST'])
def analyze_password():
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    result = analyze_password_strength(password)
    return jsonify(result)

def analyze_password_strength(password):
    score = 0
    feedback = []
    suggestions = []
    
    # Length check
    length = len(password)
    if length < 8:
        score += 0
        feedback.append("Too short")
        suggestions.append("Use at least 12 characters for better security")
    elif length < 12:
        score += 20
        feedback.append("Good length")
        suggestions.append("Consider making it longer for better security")
    else:
        score += 25
        feedback.append("Excellent length")
    
    # Uppercase letters
    if re.search(r'[A-Z]', password):
        score += 15
        feedback.append("Contains uppercase letters")
    else:
        suggestions.append("Add uppercase letters")
    
    # Lowercase letters
    if re.search(r'[a-z]', password):
        score += 15
        feedback.append("Contains lowercase letters")
    else:
        suggestions.append("Add lowercase letters")
    
    # Numbers
    if re.search(r'\d', password):
        score += 15
        feedback.append("Contains numbers")
    else:
        suggestions.append("Add numbers")
    
    # Special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 20
        feedback.append("Contains special characters")
    else:
        suggestions.append("Add special characters (!@#$% etc.)")
    
    # Common patterns check
    common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin', 'letmein', 'welcome']
    for pattern in common_patterns:
        if pattern in password.lower():
            score -= 20
            feedback.append("Contains common pattern")
            suggestions.append("Avoid common words and patterns")
            break
    
    # Sequential characters
    if re.search(r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        score -= 15
        feedback.append("Contains sequential letters")
        suggestions.append("Avoid sequential characters")
    
    if re.search(r'(?:123|234|345|456|567|678|789|890)', password):
        score -= 15
        feedback.append("Contains sequential numbers")
        suggestions.append("Avoid sequential numbers")
    
    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        score -= 15
        feedback.append("Contains repeated characters")
        suggestions.append("Avoid repeating the same character")
    
    # Check against common passwords (simplified)
    common_passwords = ['password123', '123456', 'qwerty123', 'admin123']
    if password.lower() in common_passwords:
        score = 0
        feedback = ["This is a commonly used password"]
        suggestions = ["Choose a unique password not found in common lists"]
    
    # Ensure score is within 0-100
    score = max(0, min(100, score))
    
    # Determine strength level
    if score >= 80:
        strength = "Strong"
        color = "#00ff9d"
    elif score >= 60:
        strength = "Good"
        color = "#ffaa00"
    elif score >= 40:
        strength = "Fair"
        color = "#ff6600"
    else:
        strength = "Weak"
        color = "#ff4d4d"
    
    # Generate a strong password suggestion
    suggested_password = generate_strong_password()
    
    return {
        'password_length': length,
        'score': score,
        'strength': strength,
        'color': color,
        'feedback': feedback[:5],
        'suggestions': suggestions[:3],
        'suggested_password': suggested_password
    }

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(random.choice(chars) for _ in range(length))
    return password

# ========== SMS SCAM DETECTOR ==========
@app.route('/api/analyze-sms', methods=['POST'])
def analyze_sms():
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'No message provided'}), 400
    
    result = analyze_sms_scam(message)
    return jsonify(result)

def analyze_sms_scam(message):
    scam_score = 0
    flags = []
    reasons = []
    suggestions = []
    
    message_lower = message.lower()
    
    # Check for urgency/pressure tactics
    urgency_words = ['urgent', 'immediately', 'asap', 'quickly', 'now', 'limited time', 'expires', 'today only']
    for word in urgency_words:
        if word in message_lower:
            scam_score += 15
            flags.append("Urgency/Pressure tactics")
            reasons.append(f"Uses '{word}' to create false urgency")
            break
    
    # Check for threats
    threat_words = ['suspend', 'block', 'close', 'terminate', 'legal action', 'lawsuit', 'arrest']
    for word in threat_words:
        if word in message_lower:
            scam_score += 20
            flags.append("Threatening language")
            reasons.append(f"Contains '{word}' to intimidate")
            break
    
    # Check for prize/gift claims
    prize_words = ['won', 'winner', 'prize', 'gift', 'free', 'cash', 'money', 'lottery', 'inheritance']
    for word in prize_words:
        if word in message_lower:
            scam_score += 20
            flags.append("Prize/Money claim")
            reasons.append(f"Claims you've '{word}' something")
            break
    
    # Check for payment requests
    payment_words = ['pay', 'payment', 'transfer', 'send money', 'bitcoin', 'gift card', 'western union']
    for word in payment_words:
        if word in message_lower:
            scam_score += 25
            flags.append("Payment request")
            reasons.append(f"Asks you to '{word}'")
            break
    
    # Check for personal information requests
    info_words = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'pin', 'verify account']
    for word in info_words:
        if word in message_lower:
            scam_score += 25
            flags.append("Personal info request")
            reasons.append(f"Asks for '{word}'")
            break
    
    # Check for links
    if re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', message):
        scam_score += 15
        flags.append("Contains link")
        reasons.append("Messages with links can lead to phishing sites")
        suggestions.append("Never click links in unsolicited messages")
    
    # Check for phone numbers
    if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', message):
        scam_score += 10
        if "call" in message_lower:
            flags.append("Phone number provided")
            reasons.append("Asks you to call a number")
    
    # Check for poor grammar/spelling
    grammar_issues = ['verfication', 'recieved', 'acount', 'maintanance', 'immeditely']
    for issue in grammar_issues:
        if issue in message_lower:
            scam_score += 10
            flags.append("Poor grammar/spelling")
            reasons.append(f"Contains misspelled word: '{issue}'")
            break
    
    # Check for generic greetings
    generic_greetings = ['dear customer', 'dear user', 'valued customer', 'account holder']
    for greeting in generic_greetings:
        if greeting in message_lower:
            scam_score += 10
            flags.append("Generic greeting")
            reasons.append("Scammers often use generic greetings instead of your name")
            break
    
    # Determine scam likelihood
    if scam_score >= 60:
        likelihood = "Very High"
        color = "#ff4d4d"
    elif scam_score >= 40:
        likelihood = "High"
        color = "#ff6600"
    elif scam_score >= 20:
        likelihood = "Medium"
        color = "#ffaa00"
    else:
        likelihood = "Low"
        color = "#00ff9d"
    
    # General suggestions
    if not suggestions:
        suggestions = [
            "Don't click any links in the message",
            "Never share personal information via SMS",
            "Verify the sender through official channels"
        ]
    
    return {
        'message': message[:100] + ('...' if len(message) > 100 else ''),
        'scam_score': min(100, scam_score),
        'likelihood': likelihood,
        'color': color,
        'flags': flags[:5],
        'reasons': reasons[:5],
        'suggestions': suggestions[:3]
    }

# ========== DIGITAL FOOTPRINT CHECKER ==========
@app.route('/api/check-footprint', methods=['POST'])
def check_footprint():
    data = request.json
    email = data.get('email', '')
    
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    
    result = analyze_digital_footprint(email)
    return jsonify(result)

def analyze_digital_footprint(email):
    # Simulate digital footprint analysis
    # In production, you would integrate with breach databases APIs
    
    username = email.split('@')[0]
    domain = email.split('@')[1]
    
    # Simulated breach data
    breach_databases = [
        {'name': 'HaveIBeenPwned', 'breaches': random.randint(0, 5)},
        {'name': 'DataBreachDB', 'breaches': random.randint(0, 3)},
    ]
    
    total_breaches = sum(db['breaches'] for db in breach_databases)
    
    # Social media presence simulation
    social_platforms = ['Facebook', 'Twitter', 'LinkedIn', 'Instagram', 'GitHub']
    accounts_found = []
    
    for platform in social_platforms:
        # Simulate 60% chance of having account
        if random.random() < 0.6:
            accounts_found.append(platform)
    
    # Data exposure simulation
    exposed_data = []
    if total_breaches > 0:
        possible_data = ['Email', 'Password', 'Name', 'Phone', 'Address', 'Date of Birth']
        exposed_data = random.sample(possible_data, min(total_breaches, len(possible_data)))
    
    # Risk score calculation
    risk_score = 100
    risk_score -= total_breaches * 10
    risk_score -= len(accounts_found) * 5
    risk_score -= len(exposed_data) * 8
    
    risk_score = max(0, min(100, risk_score))
    
    if risk_score >= 70:
        risk_level = "Low"
        color = "#00ff9d"
    elif risk_score >= 40:
        risk_level = "Medium"
        color = "#ffaa00"
    else:
        risk_level = "High"
        color = "#ff4d4d"
    
    # Recommendations
    recommendations = []
    if total_breaches > 0:
        recommendations.append("Change passwords for affected accounts")
        recommendations.append("Use unique passwords for each account")
    
    if 'Facebook' in accounts_found:
        recommendations.append("Review Facebook privacy settings")
    
    if 'Twitter' in accounts_found:
        recommendations.append("Check Twitter account visibility settings")
    
    if len(accounts_found) > 3:
        recommendations.append("Consider consolidating or deleting unused accounts")
    
    if not recommendations:
        recommendations = [
            "Enable two-factor authentication on all accounts",
            "Regularly review app permissions",
            "Use a password manager"
        ]
    
    return {
        'email': email,
        'username': username,
        'domain': domain,
        'breaches_found': total_breaches,
        'breach_details': breach_databases,
        'accounts_found': accounts_found,
        'exposed_data': exposed_data,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'color': color,
        'recommendations': recommendations[:5]
    }

# ========== PRIVACY CHECKER ==========
@app.route('/api/check-privacy', methods=['POST'])
def check_privacy():
    data = request.json
    platform = data.get('platform', 'general')
    
    result = analyze_privacy_settings(platform)
    return jsonify(result)

def analyze_privacy_settings(platform):
    privacy_score = random.randint(40, 95)
    
    platforms = {
        'facebook': {
            'name': 'Facebook',
            'settings': [
                {'name': 'Profile Visibility', 'status': random.choice(['Public', 'Friends', 'Only Me']), 'secure': 'Only Me'},
                {'name': 'Email Visibility', 'status': random.choice(['Public', 'Friends', 'Hidden']), 'secure': 'Hidden'},
                {'name': 'Phone Visibility', 'status': random.choice(['Public', 'Friends', 'Hidden']), 'secure': 'Hidden'},
                {'name': 'Tag Review', 'status': random.choice(['Enabled', 'Disabled']), 'secure': 'Enabled'},
                {'name': 'Location Sharing', 'status': random.choice(['Enabled', 'Disabled']), 'secure': 'Disabled'}
            ]
        },
        'twitter': {
            'name': 'Twitter',
            'settings': [
                {'name': 'Tweet Privacy', 'status': random.choice(['Public', 'Protected']), 'secure': 'Protected'},
                {'name': 'Photo Tagging', 'status': random.choice(['Anyone', 'People you follow', 'Only you']), 'secure': 'Only you'},
                {'name': 'Discoverability', 'status': random.choice(['Everyone', 'Nobody']), 'secure': 'Nobody'},
                {'name': 'Location in Tweets', 'status': random.choice(['Enabled', 'Disabled']), 'secure': 'Disabled'}
            ]
        },
        'instagram': {
            'name': 'Instagram',
            'settings': [
                {'name': 'Account Privacy', 'status': random.choice(['Public', 'Private']), 'secure': 'Private'},
                {'name': 'Story Sharing', 'status': random.choice(['Everyone', 'Close Friends', 'Off']), 'secure': 'Close Friends'},
                {'name': 'Activity Status', 'status': random.choice(['On', 'Off']), 'secure': 'Off'},
                {'name': 'Message Controls', 'status': random.choice(['Everyone', 'People you follow']), 'secure': 'People you follow'}
            ]
        },
        'general': {
            'name': 'General Privacy Check',
            'settings': [
                {'name': 'Browser Cookies', 'status': random.choice(['All enabled', 'Blocked third-party', 'All blocked']), 'secure': 'Blocked third-party'},
                {'name': 'Location Tracking', 'status': random.choice(['Always', 'While using', 'Never']), 'secure': 'Never'},
                {'name': 'Camera Access', 'status': random.choice(['Always', 'Ask', 'Denied']), 'secure': 'Ask'},
                {'name': 'Microphone Access', 'status': random.choice(['Always', 'Ask', 'Denied']), 'secure': 'Ask'},
                {'name': 'Ad Tracking', 'status': random.choice(['Enabled', 'Disabled']), 'secure': 'Disabled'}
            ]
        }
    }
    
    platform_data = platforms.get(platform.lower(), platforms['general'])
    
    # Calculate privacy score based on settings
    secure_count = 0
    for setting in platform_data['settings']:
        if setting['status'] == setting['secure']:
            secure_count += 1
    
    privacy_score = int((secure_count / len(platform_data['settings'])) * 100)
    
    # Recommendations
    recommendations = []
    for setting in platform_data['settings']:
        if setting['status'] != setting['secure']:
            recommendations.append(f"Change '{setting['name']}' from '{setting['status']}' to '{setting['secure']}'")
    
    if privacy_score >= 80:
        level = "Excellent"
        color = "#00ff9d"
    elif privacy_score >= 60:
        level = "Good"
        color = "#ffaa00"
    elif privacy_score >= 40:
        level = "Fair"
        color = "#ff6600"
    else:
        level = "Poor"
        color = "#ff4d4d"
    
    return {
        'platform': platform_data['name'],
        'privacy_score': privacy_score,
        'level': level,
        'color': color,
        'settings': platform_data['settings'],
        'recommendations': recommendations[:5]
    }

# ========== CYBER AWARENESS TIPS ==========
@app.route('/api/awareness-tips', methods=['GET'])
def get_awareness_tips():
    tips = [
        {
            'category': 'Passwords',
            'title': 'Use a Password Manager',
            'content': 'Password managers generate and store strong, unique passwords for all your accounts.',
            'tip': 'Never reuse passwords across multiple sites'
        },
        {
            'category': 'Phishing',
            'title': 'Spotting Phishing Emails',
            'content': 'Check sender email addresses carefully - one wrong character can indicate a scam.',
            'tip': 'Hover over links before clicking to see the real destination'
        },
        {
            'category': 'Social Media',
            'title': 'Oversharing Risks',
            'content': 'Sharing your location, birthday, or vacation plans can make you a target.',
            'tip': 'Post vacation photos after you return home'
        },
        {
            'category': 'WiFi Security',
            'title': 'Public WiFi Dangers',
            'content': 'Public networks are often unencrypted, allowing hackers to intercept your data.',
            'tip': 'Always use a VPN on public WiFi networks'
        },
        {
            'category': 'Two-Factor Authentication',
            'title': 'Enable 2FA',
            'content': 'Two-factor authentication adds an extra layer of security beyond just passwords.',
            'tip': 'Use authenticator apps instead of SMS for 2FA when possible'
        },
        {
            'category': 'Software Updates',
            'title': 'Keep Everything Updated',
            'content': 'Updates often contain security patches for newly discovered vulnerabilities.',
            'tip': 'Enable automatic updates where possible'
        }
    ]
    
    return jsonify({'tips': tips})

# ========== DASHBOARD DATA ==========
@app.route('/api/dashboard-data', methods=['GET'])
def get_dashboard_data():
    # Simulate real-time dashboard data
    data = {
        'threat_level': random.choice(['Low', 'Medium', 'High']),
        'active_scans': random.randint(0, 5),
        'last_scan': '2 minutes ago',
        'security_score': random.randint(65, 95),
        'recent_threats': [
            {'type': 'Phishing Attempt', 'status': 'Blocked', 'time': '5m ago'},
            {'type': 'Weak Password', 'status': 'Detected', 'time': '15m ago'},
            {'type': 'Suspicious Login', 'status': 'Reviewed', 'time': '1h ago'}
        ],
        'quick_actions': [
            {'name': 'Scan Email', 'url': '/tools/phishing.html'},
            {'name': 'Check Password', 'url': '/tools/password.html'},
            {'name': 'Privacy Check', 'url': '/tools/privacy.html'}
        ]
    }
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True, port=5000)