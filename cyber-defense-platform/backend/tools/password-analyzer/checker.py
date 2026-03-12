#!/usr/bin/env python3
"""
Password Strength Analyzer - Advanced password analysis with HIBP integration
"""
import sys
import json
import re
import math
import hashlib
import string

class PasswordAnalyzer:
    def __init__(self, password):
        self.password = password
    
    def check_hibp(self):
        """Check against Have I Been Pwned API using k-anonymity"""
        try:
            import requests
            sha1 = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]
            
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=5,
                headers={'User-Agent': 'CyberGuardIQ-PasswordChecker'}
            )
            
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return {
                            'found': True,
                            'count': int(count),
                            'message': f'This password has been seen {count} times in data breaches!'
                        }
            return {'found': False, 'count': 0, 'message': 'Password not found in known data breaches'}
        except Exception as e:
            return {'found': None, 'count': 0, 'message': f'Unable to check: {str(e)}'}
    
    def calculate_entropy(self):
        """Calculate password entropy in bits"""
        charset_size = 0
        if re.search(r'[a-z]', self.password):
            charset_size += 26
        if re.search(r'[A-Z]', self.password):
            charset_size += 26
        if re.search(r'[0-9]', self.password):
            charset_size += 10
        if re.search(r'[^A-Za-z0-9]', self.password):
            charset_size += 33
        
        if charset_size == 0:
            return {'entropy': 0, 'charset_size': 0}
        
        entropy = len(self.password) * math.log2(charset_size)
        
        # Estimate crack times
        guesses_per_second = {
            'online_throttled': 100,
            'online_unthrottled': 10,
            'offline_slow': 1e4,
            'offline_fast': 1e10
        }
        
        total_combinations = charset_size ** len(self.password)
        crack_times = {}
        for scenario, rate in guesses_per_second.items():
            seconds = total_combinations / (rate * 2)  # Average case
            crack_times[scenario] = self._format_time(seconds)
        
        return {
            'entropy': round(entropy, 2),
            'charset_size': charset_size,
            'total_combinations': f'{total_combinations:.2e}',
            'crack_times': crack_times
        }
    
    def _format_time(self, seconds):
        """Format seconds into human readable time"""
        if seconds < 1:
            return 'instant'
        elif seconds < 60:
            return f'{seconds:.0f} seconds'
        elif seconds < 3600:
            return f'{seconds/60:.0f} minutes'
        elif seconds < 86400:
            return f'{seconds/3600:.0f} hours'
        elif seconds < 86400 * 365:
            return f'{seconds/86400:.0f} days'
        elif seconds < 86400 * 365 * 100:
            return f'{seconds/(86400*365):.0f} years'
        elif seconds < 86400 * 365 * 1e6:
            return f'{seconds/(86400*365*1000):.0f} thousand years'
        elif seconds < 86400 * 365 * 1e9:
            return f'{seconds/(86400*365*1e6):.0f} million years'
        else:
            return 'centuries'
    
    def analyze_patterns(self):
        """Detect repeated chars, sequences, keyboard patterns"""
        patterns = []
        
        # Repeated characters
        repeats = re.findall(r'(.)\1{2,}', self.password)
        if repeats:
            patterns.append({
                'type': 'repeated_characters',
                'detail': f'Found repeated characters: {"".join(repeats)}',
                'severity': 'medium'
            })
        
        # Sequential characters
        sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '0123456789',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
        ]
        
        pwd_lower = self.password.lower()
        for seq in sequences:
            seq_lower = seq.lower()
            for i in range(len(seq_lower) - 2):
                if seq_lower[i:i+3] in pwd_lower:
                    patterns.append({
                        'type': 'sequential',
                        'detail': f'Sequential pattern: "{seq_lower[i:i+3]}"',
                        'severity': 'medium'
                    })
                    break
        
        # Keyboard patterns
        keyboard_patterns = ['qwert', 'asdf', 'zxcv', 'qazwsx', '!@#$%']
        for kp in keyboard_patterns:
            if kp in pwd_lower:
                patterns.append({
                    'type': 'keyboard_pattern',
                    'detail': f'Keyboard pattern detected: "{kp}"',
                    'severity': 'high'
                })
        
        # Dictionary words (simple check)
        common_words = ['password', 'admin', 'login', 'welcome', 'hello', 'monkey',
                       'dragon', 'master', 'shadow', 'sunshine', 'princess', 'football']
        for word in common_words:
            if word in pwd_lower:
                patterns.append({
                    'type': 'dictionary_word',
                    'detail': f'Contains common word: "{word}"',
                    'severity': 'high'
                })
        
        return patterns
    
    def analyze_strength(self):
        """Combine all factors for a comprehensive 0-100 score"""
        score = 0
        indicators = []
        
        # Length scoring
        length = len(self.password)
        if length >= 16:
            score += 25
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 10
        else:
            score += 5
            indicators.append('Password is too short (minimum 8 characters recommended)')
        
        # Character variety
        has_upper = bool(re.search(r'[A-Z]', self.password))
        has_lower = bool(re.search(r'[a-z]', self.password))
        has_number = bool(re.search(r'[0-9]', self.password))
        has_symbol = bool(re.search(r'[^A-Za-z0-9]', self.password))
        variety = sum([has_upper, has_lower, has_number, has_symbol])
        
        score += variety * 7
        
        if not has_upper: indicators.append('Add uppercase letters')
        if not has_lower: indicators.append('Add lowercase letters')
        if not has_number: indicators.append('Add numbers')
        if not has_symbol: indicators.append('Add special characters')
        
        # Entropy bonus
        entropy_data = self.calculate_entropy()
        entropy = entropy_data['entropy']
        if entropy >= 60:
            score += 25
        elif entropy >= 40:
            score += 15
        elif entropy >= 28:
            score += 10
        
        # Pattern penalties
        patterns = self.analyze_patterns()
        for p in patterns:
            if p['severity'] == 'high':
                score -= 15
                indicators.append(p['detail'])
            elif p['severity'] == 'medium':
                score -= 8
                indicators.append(p['detail'])
        
        # HIBP check
        hibp = self.check_hibp()
        if hibp['found']:
            score -= 30
            indicators.append(hibp['message'])
        
        score = max(0, min(100, score))
        
        # Strength label
        if score >= 80: strength = 'Very Strong'
        elif score >= 60: strength = 'Strong'
        elif score >= 40: strength = 'Moderate'
        elif score >= 20: strength = 'Weak'
        else: strength = 'Very Weak'
        
        return {
            'password_length': length,
            'score': score,
            'strength': strength,
            'entropy': entropy_data['entropy'],
            'crack_times': entropy_data.get('crack_times', {}),
            'character_analysis': {
                'hasUpper': has_upper,
                'hasLower': has_lower,
                'hasNumber': has_number,
                'hasSymbol': has_symbol,
                'variety': variety
            },
            'patterns_found': patterns,
            'hibp_check': hibp,
            'indicators': indicators,
            'analysis_method': 'python'
        }

if __name__ == '__main__':
    input_data = json.loads(sys.stdin.read())
    password = input_data.get('password', '')
    
    analyzer = PasswordAnalyzer(password)
    result = analyzer.analyze_strength()
    print(json.dumps(result))
