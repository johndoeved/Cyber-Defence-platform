#!/usr/bin/env python3
"""
Privacy Checker - Analyze privacy settings and browser fingerprinting risks
"""
import sys
import json
from datetime import datetime

class PrivacyChecker:
    def __init__(self, platform='general', settings=None):
        self.platform = platform.lower()
        self.settings = settings or {}
        self.score = 0
        self.max_score = 0
        self.checks = []
        self.recommendations = []

    def check_browser_fingerprint(self):
        """Analyze browser fingerprinting risks"""
        fingerprint_risks = [
            {
                'id': 'canvas_fingerprint',
                'name': 'Canvas Fingerprinting',
                'risk': 'high',
                'description': 'Websites can use HTML5 Canvas to create unique fingerprints',
                'mitigation': 'Use anti-fingerprinting browser extensions (e.g., Canvas Defender)'
            },
            {
                'id': 'webgl_fingerprint',
                'name': 'WebGL Fingerprinting',
                'risk': 'high',
                'description': 'WebGL rendering can reveal GPU and driver information',
                'mitigation': 'Disable WebGL or use WebGL fingerprint spoofing'
            },
            {
                'id': 'audio_fingerprint',
                'name': 'AudioContext Fingerprinting',
                'risk': 'medium',
                'description': 'Audio processing can create unique device signatures',
                'mitigation': 'Use browsers with audio fingerprint protection'
            },
            {
                'id': 'font_fingerprint',
                'name': 'Font Enumeration',
                'risk': 'medium',
                'description': 'Installed fonts create a unique system signature',
                'mitigation': 'Use browser extensions that block font enumeration'
            },
            {
                'id': 'screen_fingerprint',
                'name': 'Screen Resolution Tracking',
                'risk': 'low',
                'description': 'Screen resolution and color depth aid fingerprinting',
                'mitigation': 'Use standard/common resolution settings'
            }
        ]
        
        return fingerprint_risks

    def check_tracking_cookies(self):
        """Detect tracking cookie risks"""
        cookie_risks = [
            {
                'type': 'third_party',
                'risk': 'high',
                'description': 'Third-party cookies track across multiple websites',
                'action': 'Block all third-party cookies in browser settings'
            },
            {
                'type': 'supercookies',
                'risk': 'high',
                'description': 'ETags and HSTS supercookies persist after clearing',
                'action': 'Use private browsing mode or Tor browser'
            },
            {
                'type': 'flash_cookies',
                'risk': 'medium',
                'description': 'Flash LSOs persist independently of browser cookies',
                'action': 'Remove Flash and use HTML5-only browsers'
            },
            {
                'type': 'zombie_cookies',
                'risk': 'high',
                'description': 'Cookies that recreate themselves after deletion',
                'action': 'Use cookie management extensions like Cookie AutoDelete'
            }
        ]
        
        return cookie_risks

    def analyze_permissions(self):
        """Analyze app permission risks"""
        permission_categories = {
            'camera': {'risk': 'high', 'reason': 'Can record video without knowledge'},
            'microphone': {'risk': 'high', 'reason': 'Can record audio conversations'},
            'location': {'risk': 'high', 'reason': 'Tracks physical movements'},
            'contacts': {'risk': 'medium', 'reason': 'Access to personal contact list'},
            'storage': {'risk': 'medium', 'reason': 'Access to files and photos'},
            'notifications': {'risk': 'low', 'reason': 'Can send persistent notifications'},
            'clipboard': {'risk': 'medium', 'reason': 'Can read copied text including passwords'},
            'bluetooth': {'risk': 'medium', 'reason': 'Can detect nearby devices'}
        }
        
        return permission_categories

    def check_social_media_privacy(self):
        """Check social media privacy settings for given platform"""
        platform_configs = {
            'facebook': {
                'name': 'Facebook',
                'settings': [
                    {'id': 'profile_public', 'name': 'Public Profile', 'risk': 'high',
                     'recommendation': 'Set profile to Friends Only'},
                    {'id': 'search_engines', 'name': 'Search Engine Indexing', 'risk': 'high',
                     'recommendation': 'Disable search engine indexing'},
                    {'id': 'face_recognition', 'name': 'Face Recognition', 'risk': 'medium',
                     'recommendation': 'Disable face recognition feature'},
                    {'id': 'location_sharing', 'name': 'Location Sharing', 'risk': 'high',
                     'recommendation': 'Disable location sharing'},
                    {'id': 'third_party_apps', 'name': 'Third-Party App Access', 'risk': 'medium',
                     'recommendation': 'Review and revoke unnecessary app permissions'},
                    {'id': 'ad_tracking', 'name': 'Ad Tracking', 'risk': 'medium',
                     'recommendation': 'Opt out of ad personalization'}
                ]
            },
            'google': {
                'name': 'Google',
                'settings': [
                    {'id': 'web_activity', 'name': 'Web & App Activity', 'risk': 'high',
                     'recommendation': 'Pause web & app activity tracking'},
                    {'id': 'location_history', 'name': 'Location History', 'risk': 'high',
                     'recommendation': 'Pause location history'},
                    {'id': 'youtube_history', 'name': 'YouTube History', 'risk': 'medium',
                     'recommendation': 'Pause YouTube watch/search history'},
                    {'id': 'ad_personalization', 'name': 'Ad Personalization', 'risk': 'medium',
                     'recommendation': 'Turn off ad personalization'},
                    {'id': 'shared_endorsements', 'name': 'Shared Endorsements', 'risk': 'low',
                     'recommendation': 'Opt out of shared endorsements'}
                ]
            },
            'instagram': {
                'name': 'Instagram',
                'settings': [
                    {'id': 'private_account', 'name': 'Private Account', 'risk': 'high',
                     'recommendation': 'Switch to private account'},
                    {'id': 'activity_status', 'name': 'Activity Status', 'risk': 'medium',
                     'recommendation': 'Disable activity status'},
                    {'id': 'story_sharing', 'name': 'Story Sharing', 'risk': 'low',
                     'recommendation': 'Restrict story sharing'},
                    {'id': 'data_download', 'name': 'Third-Party Data Sharing', 'risk': 'medium',
                     'recommendation': 'Limit data sharing with third parties'}
                ]
            },
            'twitter': {
                'name': 'Twitter/X',
                'settings': [
                    {'id': 'protect_tweets', 'name': 'Protect Tweets', 'risk': 'high',
                     'recommendation': 'Enable protected tweets'},
                    {'id': 'location_tweets', 'name': 'Location in Tweets', 'risk': 'medium',
                     'recommendation': 'Disable location tagging'},
                    {'id': 'discoverability', 'name': 'Email/Phone Discoverability', 'risk': 'high',
                     'recommendation': 'Disable discoverability by email/phone'},
                    {'id': 'personalization', 'name': 'Personalization & Data', 'risk': 'medium',
                     'recommendation': 'Disable personalization tracking'}
                ]
            }
        }
        
        config = platform_configs.get(self.platform, platform_configs.get('google'))
        return config

    def generate_privacy_score(self):
        """Calculate overall privacy score"""
        platform_config = self.check_social_media_privacy()
        
        if not platform_config:
            return {'score': 50, 'risk_level': 'MEDIUM'}
        
        checks = []
        total_weight = 0
        secure_weight = 0
        
        for setting in platform_config['settings']:
            weight = 20 if setting['risk'] == 'high' else 12 if setting['risk'] == 'medium' else 6
            total_weight += weight
            
            user_val = self.settings.get(setting['id'])
            is_secure = user_val in [True, 'enabled', 'on', 'true']
            
            if is_secure:
                secure_weight += weight
            else:
                self.recommendations.append({
                    'setting': setting['name'],
                    'risk_level': setting['risk'],
                    'action': setting['recommendation']
                })
            
            checks.append({
                'id': setting['id'],
                'name': setting['name'],
                'risk_level': setting['risk'],
                'status': 'secure' if is_secure else 'at_risk',
                'recommendation': 'Good! Properly configured.' if is_secure else setting['recommendation']
            })
        
        score = round((secure_weight / total_weight) * 100) if total_weight > 0 else 0
        
        risk_level = 'LOW'
        if score < 40:
            risk_level = 'HIGH'
        elif score < 70:
            risk_level = 'MEDIUM'
        
        # Add browser fingerprinting info
        fingerprint_risks = self.check_browser_fingerprint()
        cookie_risks = self.check_tracking_cookies()
        permissions = self.analyze_permissions()
        
        return {
            'platform': platform_config['name'],
            'privacy_score': score,
            'risk_level': risk_level,
            'total_checks': len(checks),
            'secure_count': len([c for c in checks if c['status'] == 'secure']),
            'at_risk_count': len([c for c in checks if c['status'] == 'at_risk']),
            'checks': checks,
            'recommendations': self.recommendations,
            'browser_fingerprint_risks': fingerprint_risks,
            'cookie_risks': cookie_risks,
            'permission_risks': permissions,
            'general_tips': [
                'Use a VPN for enhanced privacy',
                'Regularly review app permissions',
                'Enable two-factor authentication',
                'Use encrypted messaging apps',
                'Regularly clear browser data',
                'Review connected third-party apps'
            ],
            'analysis_method': 'python',
            'timestamp': datetime.now().isoformat()
        }


if __name__ == '__main__':
    input_data = json.loads(sys.stdin.read())
    platform = input_data.get('platform', 'general')
    settings = input_data.get('settings', {})
    
    checker = PrivacyChecker(platform, settings)
    result = checker.generate_privacy_score()
    print(json.dumps(result))
