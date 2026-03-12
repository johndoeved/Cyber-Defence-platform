#!/usr/bin/env python3
"""
SMS Scam Detector - Advanced message analysis with NLP capabilities
"""
import sys
import json
import re
from datetime import datetime

class SMSScamDetector:
    def __init__(self, message):
        self.message = message
        self.message_lower = message.lower()
        self.indicators = []
        self.score = 0
        self.categories = []

    def analyze_sentiment(self):
        """Analyze sentiment using keyword-based approach (NLTK fallback)"""
        result = {'method': 'keyword_analysis'}
        
        try:
            import nltk
            from nltk.sentiment.vader import SentimentIntensityAnalyzer
            try:
                nltk.data.find('sentiment/vader_lexicon.zip')
            except LookupError:
                nltk.download('vader_lexicon', quiet=True)
            
            sia = SentimentIntensityAnalyzer()
            scores = sia.polarity_scores(self.message)
            result = {
                'method': 'vader',
                'positive': scores['pos'],
                'negative': scores['neg'],
                'neutral': scores['neu'],
                'compound': scores['compound']
            }
            
            if scores['neg'] > 0.5:
                self.indicators.append('Message has highly negative/threatening sentiment')
                self.score += 10
            elif scores['pos'] > 0.7:
                self.indicators.append('Message has excessively positive sentiment (common in scams)')
                self.score += 10
        except ImportError:
            # Keyword-based fallback
            negative_words = ['urgent', 'suspended', 'blocked', 'unauthorized', 'warning',
                            'threatened', 'expire', 'cancel', 'fraud', 'illegal']
            positive_words = ['congratulations', 'won', 'winner', 'reward', 'bonus',
                            'free', 'gift', 'lucky', 'selected', 'exclusive']
            
            neg_count = sum(1 for w in negative_words if w in self.message_lower)
            pos_count = sum(1 for w in positive_words if w in self.message_lower)
            
            result['negative_keywords'] = neg_count
            result['positive_keywords'] = pos_count
            
            if neg_count >= 2:
                self.indicators.append('Multiple threatening/negative keywords detected')
                self.score += 10
            if pos_count >= 2:
                self.indicators.append('Multiple enticement keywords detected')
                self.score += 10
        
        return result

    def extract_entities(self):
        """Detect URLs, phone numbers, and email addresses"""
        entities = {'urls': [], 'phone_numbers': [], 'emails': []}
        
        # URLs
        urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', self.message)
        entities['urls'] = urls
        if urls:
            self.indicators.append(f'Contains {len(urls)} URL(s): {", ".join(urls[:3])}')
            self.score += 15
            
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'tiny.cc']
            for url in urls:
                for s in shorteners:
                    if s in url.lower():
                        self.indicators.append(f'Contains shortened URL ({s}) - hiding destination')
                        self.score += 10
                        break
        
        # Phone numbers
        phones = re.findall(r'(?:\+?1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', self.message)
        entities['phone_numbers'] = phones
        if phones:
            self.indicators.append(f'Contains phone number(s): {", ".join(phones)}')
            self.score += 5
        
        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', self.message)
        entities['emails'] = emails
        if emails:
            self.indicators.append(f'Contains email address(es): {", ".join(emails)}')
        
        return entities

    def categorize_scam(self):
        """Classify into scam categories"""
        categories_config = {
            'Prize/Lottery': {
                'keywords': ['congratulations', 'you won', 'winner', 'prize', 'lottery',
                           'sweepstakes', 'claim', 'reward', 'giveaway', 'jackpot', 'million'],
                'weight': 25
            },
            'Financial/Banking': {
                'keywords': ['bank', 'account suspended', 'verify your account', 'unauthorized',
                           'transaction', 'credit card', 'payment', 'billing', 'wire transfer',
                           'bitcoin', 'crypto', 'investment'],
                'weight': 25
            },
            'Personal Info Phishing': {
                'keywords': ['ssn', 'social security', 'password', 'pin', 'cvv',
                           'routing number', 'account number', 'verify identity'],
                'weight': 30
            },
            'Package/Delivery': {
                'keywords': ['package', 'delivery', 'tracking', 'shipment', 'usps',
                           'fedex', 'ups', 'customs', 'parcel'],
                'weight': 15
            },
            'Tech Support': {
                'keywords': ['virus', 'infected', 'compromised', 'hacked', 'security alert',
                           'apple', 'microsoft', 'google', 'tech support'],
                'weight': 20
            },
            'Romance/Social': {
                'keywords': ['dating', 'meet singles', 'lonely', 'match', 'profile',
                           'interested in you', 'beautiful', 'handsome'],
                'weight': 15
            }
        }
        
        matched = []
        for category, config in categories_config.items():
            matches = [kw for kw in config['keywords'] if kw in self.message_lower]
            if matches:
                matched.append(category)
                self.score += min(config['weight'], len(matches) * 8)
                self.indicators.append(f'{category} patterns: {", ".join(matches)}')
        
        self.categories = matched if matched else ['Uncategorized']
        return matched

    def check_grammar_quality(self):
        """Detect poor grammar patterns common in scams"""
        grammar_issues = []
        
        patterns = {
            'txtspeak': (r'\b(u|ur|plz|pls|msg|txt|da|dis|dat|gud|luv)\b', 'Text speak abbreviations'),
            'excessive_caps': (r'[A-Z]{5,}', 'EXCESSIVE CAPITALIZATION'),
            'multiple_exclamation': (r'!{2,}', 'Multiple exclamation marks'),
            'dollar_signs': (r'\${2,}', 'Multiple dollar signs'),
            'dear_customer': (r'dear\s+(?:customer|user|member|sir|madam|valued)', 'Generic salutation'),
            'broken_english': (r'\b(kindly|hereby|henceforth|herewith)\b', 'Overly formal phrasing'),
            'spacing_issues': (r'  {2,}', 'Irregular spacing')
        }
        
        for name, (pattern, description) in patterns.items():
            if re.search(pattern, self.message, re.IGNORECASE):
                grammar_issues.append({'type': name, 'description': description})
        
        if len(grammar_issues) >= 2:
            self.indicators.append(f'Multiple grammar/formatting issues ({len(grammar_issues)} found)')
            self.score += 10
        elif grammar_issues:
            self.score += 5
        
        return grammar_issues

    def analyze_urgency_patterns(self):
        """Detect urgency manipulation tactics"""
        urgency_patterns = [
            ('immediate_action', r'(act now|immediately|right away|asap|right now)', 'Demands immediate action'),
            ('time_limit', r'(within \d+ hours?|expires? (today|soon)|limited time|last chance)', 'Imposes time pressure'),
            ('threat', r'(will be (suspended|closed|terminated|locked)|legal action|arrest|warrant)', 'Contains threats'),
            ('final_notice', r'(final notice|final warning|last attempt|account closure)', 'Claims to be a final notice'),
            ('consequences', r'(or else|otherwise|failure to|if you don\'t|if you fail)', 'Warns of consequences')
        ]
        
        urgency_found = []
        for name, pattern, description in urgency_patterns:
            if re.search(pattern, self.message_lower):
                urgency_found.append({'type': name, 'description': description})
                self.score += 8
        
        if urgency_found:
            self.indicators.append(f'Urgency manipulation detected ({len(urgency_found)} tactics)')
            self.categories.append('Urgency Manipulation') if 'Urgency Manipulation' not in self.categories else None
        
        return urgency_found

    def analyze(self):
        """Run complete SMS analysis"""
        sentiment = self.analyze_sentiment()
        entities = self.extract_entities()
        scam_categories = self.categorize_scam()
        grammar = self.check_grammar_quality()
        urgency = self.analyze_urgency_patterns()
        
        # Cap score
        self.score = min(self.score, 100)
        
        # Risk level
        risk_level = 'LOW'
        if self.score >= 60:
            risk_level = 'HIGH'
        elif self.score >= 30:
            risk_level = 'MEDIUM'
        
        # Verdict
        verdict = 'Likely Legitimate'
        if self.score >= 60:
            verdict = 'Likely Scam'
        elif self.score >= 30:
            verdict = 'Suspicious'
        
        return {
            'message': self.message[:200],
            'message_length': len(self.message),
            'is_scam': self.score >= 30,
            'confidence_score': self.score,
            'risk_level': risk_level,
            'verdict': verdict,
            'categories': self.categories,
            'indicators': self.indicators,
            'details': {
                'sentiment': sentiment,
                'entities': entities,
                'grammar_issues': grammar,
                'urgency_tactics': urgency
            },
            'analysis_method': 'python',
            'timestamp': datetime.now().isoformat()
        }


if __name__ == '__main__':
    input_data = json.loads(sys.stdin.read())
    message = input_data.get('message', '')
    
    detector = SMSScamDetector(message)
    result = detector.analyze()
    print(json.dumps(result))
