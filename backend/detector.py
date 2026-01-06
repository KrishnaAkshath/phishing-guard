"""
Phishing Detection Module
Analyzes URLs and page content to detect potential phishing attempts
"""

import re
import socket
from urllib.parse import urlparse
import tldextract
import requests

# Known phishing indicators and suspicious patterns
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
    'update', 'confirm', 'account', 'secure', 'security', 'banking',
    'password', 'credential', 'authenticate', 'wallet', 'paypal',
    'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'icloud'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw',
    '.cc', '.su', '.ru', '.cn', '.work', '.click', '.link'
]

# Known legitimate domains (whitelist) - expanded list
TRUSTED_DOMAINS = [
    # Google services
    'google.com', 'gmail.com', 'youtube.com', 'googleapis.com', 
    'googleusercontent.com', 'gstatic.com', 'google.co.in', 'google.co.uk',
    'googlesource.com', 'withgoogle.com', 'googleadservices.com',
    'aistudio.google.com', 'cloud.google.com', 'accounts.google.com',
    'makersuite.google.com', 'gemini.google.com', 'bard.google.com',
    
    # Social media
    'facebook.com', 'fb.com', 'messenger.com', 'instagram.com', 
    'twitter.com', 'x.com', 'linkedin.com', 'pinterest.com',
    'tiktok.com', 'snapchat.com', 'reddit.com', 'tumblr.com',
    'discord.com', 'discordapp.com', 'whatsapp.com', 'telegram.org',
    
    # Tech companies
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 
    'office365.com', 'azure.com', 'bing.com', 'msn.com',
    'apple.com', 'icloud.com', 'amazon.com', 'aws.amazon.com',
    'netflix.com', 'spotify.com', 'zoom.us', 'slack.com',
    
    # Development & productivity
    'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
    'stackoverflow.com', 'stackexchange.com', 'npmjs.com', 'pypi.org',
    'notion.so', 'notion.com', 'trello.com', 'asana.com', 'atlassian.com',
    'jira.com', 'confluence.com', 'figma.com', 'canva.com',
    
    # E-commerce & finance
    'paypal.com', 'stripe.com', 'shopify.com', 'ebay.com',
    'walmart.com', 'target.com', 'bestbuy.com', 'etsy.com',
    
    # Cloud & hosting
    'dropbox.com', 'box.com', 'onedrive.com', 'cloudflare.com',
    'vercel.app', 'netlify.app', 'herokuapp.com', 'digitalocean.com',
    
    # News & information
    'wikipedia.org', 'wikimedia.org', 'bbc.com', 'cnn.com',
    'nytimes.com', 'medium.com', 'substack.com',
    
    # Education
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    
    # Other trusted
    'twitch.tv', 'steampowered.com', 'epicgames.com',
    'adobe.com', 'autodesk.com', 'grammarly.com'
]


class PhishingDetector:
    """Main class for detecting phishing URLs and content"""
    
    def __init__(self):
        self.suspicious_patterns = self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for suspicious URL detection"""
        patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address in URL
            r'@',  # @ symbol in URL (credential attack)
            r'-{2,}',  # Multiple dashes
            r'\.{2,}',  # Multiple dots
            r'[0-9]+[a-z]+[0-9]+',  # Mixed numbers and letters
            r'(secure|login|account|verify|update).+(secure|login|account|verify|update)',  # Repeated keywords
            r'xn--',  # Punycode (IDN homograph attacks)
        ]
        return [re.compile(p, re.IGNORECASE) for p in patterns]
    
    def analyze_url(self, url: str) -> dict:
        """
        Analyze a URL for phishing indicators
        Returns a detailed analysis with risk score
        """
        result = {
            'url': url,
            'is_phishing': False,
            'risk_score': 0,
            'risk_level': 'safe',
            'warnings': [],
            'details': {}
        }
        
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Check if URL is valid
            if not parsed.scheme or not parsed.netloc:
                result['warnings'].append('Invalid URL format')
                result['risk_score'] += 30
            
            # === URL Structure Analysis ===
            result['details']['domain'] = extracted.registered_domain
            result['details']['subdomain'] = extracted.subdomain
            result['details']['suffix'] = extracted.suffix
            result['details']['has_https'] = parsed.scheme == 'https'
            
            # Check for HTTPS
            if parsed.scheme != 'https':
                result['warnings'].append('No HTTPS encryption')
                result['risk_score'] += 15
            
            # Check domain against trusted list (improved matching)
            hostname = parsed.netloc.lower()
            is_trusted = False
            
            # Check exact match with registered domain
            if extracted.registered_domain in TRUSTED_DOMAINS:
                is_trusted = True
            
            # Check if hostname ends with a trusted domain (for subdomains)
            if not is_trusted:
                for trusted in TRUSTED_DOMAINS:
                    if hostname == trusted or hostname.endswith('.' + trusted):
                        is_trusted = True
                        break
            
            if is_trusted:
                result['risk_score'] = max(0, result['risk_score'] - 50)  # Stronger trust bonus
                result['details']['trusted_domain'] = True
            else:
                result['details']['trusted_domain'] = False
            
            # === Suspicious Pattern Detection ===
            
            # Check for IP address in URL
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
                result['warnings'].append('IP address used instead of domain')
                result['risk_score'] += 40
            
            # Check for suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if url.endswith(tld) or tld in extracted.suffix:
                    result['warnings'].append(f'Suspicious TLD: {tld}')
                    result['risk_score'] += 25
                    break
            
            # Check for suspicious keywords in domain
            domain_full = parsed.netloc.lower()
            matched_keywords = []
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in domain_full:
                    matched_keywords.append(keyword)
            
            if matched_keywords and not result['details'].get('trusted_domain'):
                result['warnings'].append(f'Suspicious keywords in domain: {", ".join(matched_keywords)}')
                result['risk_score'] += len(matched_keywords) * 8
            
            # Check URL length (phishing URLs tend to be long)
            if len(url) > 100:
                result['warnings'].append('Unusually long URL')
                result['risk_score'] += 10
            
            # Check for excessive subdomains
            subdomain_count = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            if subdomain_count > 3:
                result['warnings'].append(f'Excessive subdomains ({subdomain_count})')
                result['risk_score'] += 15
            
            # Check for @ symbol (credential harvesting attempt)
            if '@' in url:
                result['warnings'].append('URL contains @ symbol (potential credential attack)')
                result['risk_score'] += 35
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if pattern.search(url):
                    result['risk_score'] += 5
            
            # Check for mixed content (numbers replacing letters)
            if re.search(r'[0oO][0oO]gle|amaz[0oO]n|paypa[l1]|faceb[0oO]{2}k', domain_full, re.IGNORECASE):
                result['warnings'].append('Possible typosquatting detected')
                result['risk_score'] += 45
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
            if any(s in domain_full for s in shorteners):
                result['warnings'].append('URL shortener detected (destination unknown)')
                result['risk_score'] += 20
            
            # === Determine Risk Level ===
            result['risk_score'] = min(100, max(0, result['risk_score']))
            
            if result['risk_score'] >= 70:
                result['risk_level'] = 'dangerous'
                result['is_phishing'] = True
            elif result['risk_score'] >= 50:
                result['risk_level'] = 'suspicious'
                result['is_phishing'] = True
            elif result['risk_score'] >= 30:
                result['risk_level'] = 'warning'
            else:
                result['risk_level'] = 'safe'
            
        except Exception as e:
            result['warnings'].append(f'Analysis error: {str(e)}')
            result['risk_score'] = 50
            result['risk_level'] = 'unknown'
        
        return result
    
    def analyze_page_content(self, content: dict) -> dict:
        """
        Analyze page content for phishing indicators
        content should include: forms, links, title, etc.
        """
        result = {
            'content_risks': [],
            'risk_score': 0
        }
        
        # Check for password fields on non-HTTPS pages
        if content.get('has_password_field') and not content.get('is_https'):
            result['content_risks'].append('Password field on non-HTTPS page')
            result['risk_score'] += 40
        
        # Check for login forms
        if content.get('has_login_form'):
            result['content_risks'].append('Login form detected')
            result['risk_score'] += 10
        
        # Check for suspicious form actions
        if content.get('form_actions'):
            for action in content['form_actions']:
                if action and not action.startswith('https://'):
                    result['content_risks'].append('Form submits to non-HTTPS destination')
                    result['risk_score'] += 25
                    break
        
        # Check for external form submissions
        if content.get('external_form_action'):
            result['content_risks'].append('Form submits to external domain')
            result['risk_score'] += 30
        
        # Check title/branding mismatch
        if content.get('claimed_brand') and content.get('actual_domain'):
            if content['claimed_brand'].lower() not in content['actual_domain'].lower():
                result['content_risks'].append('Brand mismatch detected')
                result['risk_score'] += 35
        
        return result


# Create singleton instance
detector = PhishingDetector()


def scan_url(url: str) -> dict:
    """Public function to scan a URL"""
    return detector.analyze_url(url)


def scan_content(content: dict) -> dict:
    """Public function to scan page content"""
    return detector.analyze_page_content(content)
