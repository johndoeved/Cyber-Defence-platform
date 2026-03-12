#!/usr/bin/env python3
"""
Phishing URL Analyzer - Advanced URL analysis for phishing detection
"""
import sys
import json
import re
import hashlib
from urllib.parse import urlparse
from datetime import datetime

class PhishingAnalyzer:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url if '://' in url else f'http://{url}')
        self.indicators = []
        self.score = 0

    def analyze_url_length(self):
        """Flag URLs longer than 75 characters"""
        length = len(self.url)
        if length > 75:
            self.indicators.append(f'URL is suspiciously long ({length} characters)')
            self.score += 15
        elif length > 50:
            self.score += 5
        return {'url_length': length, 'flagged': length > 75}

    def analyze_special_chars(self):
        """Flag excessive special characters"""
        special_chars = re.findall(r'[@#$%^&*(){}|\\<>]', self.url)
        count = len(special_chars)
        if count > 5:
            self.indicators.append(f'URL contains {count} special characters')
            self.score += 20
        elif count > 2:
            self.indicators.append(f'URL contains {count} special characters')
            self.score += 10
        return {'special_char_count': count, 'characters': special_chars}

    def analyze_domain_age(self):
        """Check domain characteristics (simulated when whois unavailable)"""
        domain = self.parsed.hostname or ''
        result = {'domain': domain, 'check_performed': False}
        
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                age_days = (datetime.now() - creation).days
                result['age_days'] = age_days
                result['check_performed'] = True
                if age_days < 30:
                    self.indicators.append(f'Domain is very new ({age_days} days old)')
                    self.score += 25
                elif age_days < 90:
                    self.indicators.append(f'Domain is relatively new ({age_days} days old)')
                    self.score += 15
        except Exception:
            # Use heuristic analysis when whois is unavailable
            suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.date', '.racing',
                             '.win', '.bid', '.stream', '.download', '.gdn', '.loan',
                             '.men', '.click', '.link', '.zip', '.mov']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    self.indicators.append(f'Domain uses suspicious TLD: {tld}')
                    self.score += 15
                    result['suspicious_tld'] = True
                    break

        return result

    def analyze_ssl_certificate(self):
        """Check SSL certificate (simulated analysis)"""
        has_https = self.url.startswith('https://')
        result = {'has_https': has_https}

        if not has_https and self.url.startswith('http://'):
            self.indicators.append('URL does not use HTTPS encryption')
            self.score += 10
            result['ssl_warning'] = 'No HTTPS detected'

        try:
            import ssl
            import socket
            hostname = self.parsed.hostname
            if hostname and has_https:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(5)
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                    result['cert_issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    result['cert_expiry'] = cert.get('notAfter', '')
                    result['cert_valid'] = True
        except Exception:
            if has_https:
                result['cert_valid'] = 'unable_to_verify'

        return result

    def check_google_safe_browsing(self):
        """Check for suspicious keywords and patterns"""
        suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'update', 'secure',
            'banking', 'confirm', 'password', 'credential', 'wallet',
            'paypal', 'amazon', 'apple', 'microsoft', 'support',
            'suspended', 'unusual', 'unauthorized', '限', 'urgent'
        ]
        
        url_lower = self.url.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]

        if len(found_keywords) > 2:
            self.indicators.append(f'Multiple suspicious keywords found: {", ".join(found_keywords)}')
            self.score += 25
        elif found_keywords:
            self.indicators.append(f'Suspicious keyword found: {", ".join(found_keywords)}')
            self.score += 15

        return {'suspicious_keywords': found_keywords, 'count': len(found_keywords)}

    def analyze(self):
        """Run complete analysis"""
        details = {
            'url_length': self.analyze_url_length(),
            'special_chars': self.analyze_special_chars(),
            'domain_age': self.analyze_domain_age(),
            'ssl_certificate': self.analyze_ssl_certificate(),
            'safe_browsing': self.check_google_safe_browsing()
        }

        # Check for IP address usage
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(self.url):
            self.indicators.append('URL uses IP address instead of domain name')
            self.score += 25

        # Check for @ symbol
        if '@' in self.url:
            self.indicators.append('URL contains @ symbol (potential redirect trick)')
            self.score += 20

        # Check for multiple subdomains
        hostname = self.parsed.hostname or ''
        if hostname.count('.') > 3:
            self.indicators.append('URL has excessive subdomains')
            self.score += 15

        # Cap score
        self.score = min(self.score, 100)

        # Risk level
        risk_level = 'LOW'
        if self.score >= 60:
            risk_level = 'HIGH'
        elif self.score >= 30:
            risk_level = 'MEDIUM'

        return {
            'url': self.url,
            'suspicious': self.score >= 30,
            'score': self.score,
            'indicators': self.indicators,
            'risk_level': risk_level,
            'details': details,
            'analysis_method': 'python',
            'timestamp': datetime.now().isoformat()
        }


if __name__ == '__main__':
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input().strip()

    analyzer = PhishingAnalyzer(url)
    result = analyzer.analyze()
    print(json.dumps(result))
