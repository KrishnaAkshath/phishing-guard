# Phishing Guard - Complete Project Documentation

## Intent-Aware Browser Extension for Phishing Detection

---

# Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Tech Stack](#tech-stack)
4. [Architecture](#architecture)
5. [Setup Guide](#setup-guide)
6. [Code Reference](#code-reference)
7. [API Endpoints](#api-endpoints)
8. [How It Works](#how-it-works)

---

# Overview

Phishing Guard is a Chrome browser extension that protects users from phishing attacks using **intent-aware detection**. Unlike traditional security tools that constantly scan, this extension:

- **Stays silent during normal browsing**
- **Activates only when sensitive actions are detected** (login, payment, OTP)
- **Processes data locally** for privacy
- **Shows beautiful, dismissable alerts** with clear explanations

---

# Features

| Feature | Description |
|---------|-------------|
| Auto-Scan | Automatically scans every page on load |
| Intent Detection | Monitors password, payment, and OTP field access |
| Local Analysis | Privacy-first - most checks run in browser |
| Dismissable Alerts | Beautiful full-screen warnings with animations |
| Scan History | Track all scanned sites in popup |
| Backend Analysis | Python API for deep URL analysis |
| Trusted Domains | Whitelist of 70+ legitimate sites |

---

# Tech Stack

## Frontend (Chrome Extension)

| Technology | Purpose |
|------------|---------|
| JavaScript (ES6+) | Core logic and DOM manipulation |
| Chrome APIs | webNavigation, tabs, storage, notifications |
| Manifest V3 | Modern Chrome extension format |
| CSS3 | Dark theme with animations |

## Backend (Python API)

| Technology | Purpose |
|------------|---------|
| Python 3.x | Server-side language |
| Flask | Web framework |
| flask-cors | Cross-origin support |
| tldextract | Domain parsing |
| python-whois | Domain age checking |
| validators | URL validation |

---

# Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Chrome Browser                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   content.js    │  │  background.js  │  │   popup.js   │ │
│  │  (Page Scanner) │  │ (Service Worker)│  │  (Popup UI)  │ │
│  │                 │  │                 │  │              │ │
│  │ - Auto scan     │  │ - URL scanning  │  │ - Status     │ │
│  │ - Input monitor │  │ - Badge update  │  │ - History    │ │
│  │ - Show alerts   │  │ - Notifications │  │ - Stats      │ │
│  └────────┬────────┘  └────────┬────────┘  └──────────────┘ │
│           │                    │                             │
└───────────│────────────────────│─────────────────────────────┘
            │                    │
            │    HTTP POST       │
            └──────────┬─────────┘
                       ▼
         ┌─────────────────────────┐
         │   Python Flask Backend  │
         │   localhost:5000        │
         │                         │
         │  - URL analysis         │
         │  - Pattern matching     │
         │  - Risk scoring         │
         └─────────────────────────┘
```

---

# Setup Guide

## Prerequisites

- Python 3.8+
- Google Chrome browser
- Node.js (optional, for development)

## Backend Setup

```bash
# Navigate to backend
cd phishing-guard/backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Mac/Linux
# OR
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run server
python app.py
```

Server runs at `http://localhost:5000`

## Extension Setup

1. Open Chrome
2. Go to `chrome://extensions`
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked**
5. Select the `extension` folder
6. Extension icon appears in toolbar

---

# Code Reference

## Backend Files

### requirements.txt

```
flask==3.0.0
flask-cors==4.0.0
requests==2.31.0
tldextract==5.1.1
python-whois==0.8.0
validators==0.22.0
```

### app.py

```python
"""
Phishing Guard - Flask API Server
Provides URL scanning and risk analysis endpoints
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from detector import PhishingDetector
import time

app = Flask(__name__)
CORS(app, origins=['chrome-extension://*', 'http://localhost:*'])

detector = PhishingDetector()

# Statistics tracking
stats = {
    'total_scans': 0,
    'threats_detected': 0,
    'start_time': time.time()
}

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'uptime': int(time.time() - stats['start_time']),
        'stats': stats
    })

@app.route('/api/scan', methods=['POST'])
def scan_url():
    """Scan a URL for phishing indicators"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url']
    content = data.get('content', {})
    
    # Analyze the URL
    analysis = detector.analyze(url, content)
    
    # Update statistics
    stats['total_scans'] += 1
    if analysis['is_phishing']:
        stats['threats_detected'] += 1
    
    return jsonify({
        'url': url,
        'analysis': analysis,
        'timestamp': time.time()
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get scanning statistics"""
    return jsonify(stats)

if __name__ == '__main__':
    print("Starting Phishing Guard Backend...")
    print("API available at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### detector.py

```python
"""
Phishing Detection Module
Analyzes URLs and page content for phishing indicators
"""

import re
from urllib.parse import urlparse
import tldextract

class PhishingDetector:
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'secure', 'account', 'update',
        'confirm', 'password', 'credential', 'banking', 'paypal',
        'apple', 'microsoft', 'google', 'amazon', 'netflix'
    ]
    
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', 
        '.pw', '.click', '.link', '.work', '.date'
    ]
    
    TRUSTED_DOMAINS = [
        'google.com', 'gmail.com', 'youtube.com', 'facebook.com',
        'instagram.com', 'twitter.com', 'x.com', 'amazon.com',
        'microsoft.com', 'apple.com', 'paypal.com', 'github.com',
        'linkedin.com', 'netflix.com', 'dropbox.com', 'reddit.com',
        'discord.com', 'slack.com', 'zoom.us', 'notion.so',
        # ... 70+ total trusted domains
    ]
    
    def analyze(self, url, content=None):
        """Main analysis function"""
        result = {
            'url': url,
            'is_phishing': False,
            'risk_score': 0,
            'risk_level': 'safe',
            'warnings': [],
            'details': {}
        }
        
        # Parse URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        hostname = parsed.netloc.lower()
        domain = extracted.registered_domain
        
        # Check if trusted domain
        if self._is_trusted(hostname, domain):
            result['details']['trusted_domain'] = True
            result['risk_score'] = max(0, result['risk_score'] - 30)
            return result
        
        # Run all checks
        result['risk_score'] += self._check_url_patterns(url, hostname)
        result['risk_score'] += self._check_tld(hostname)
        result['risk_score'] += self._check_https(parsed.scheme)
        result['risk_score'] += self._check_brand_impersonation(hostname)
        
        if content:
            result['risk_score'] += self._check_content(content)
        
        # Determine risk level
        if result['risk_score'] >= 70:
            result['risk_level'] = 'dangerous'
            result['is_phishing'] = True
        elif result['risk_score'] >= 40:
            result['risk_level'] = 'suspicious'
            result['is_phishing'] = True
        elif result['risk_score'] >= 20:
            result['risk_level'] = 'warning'
        
        return result
    
    def _is_trusted(self, hostname, domain):
        """Check if domain is in trusted list"""
        for trusted in self.TRUSTED_DOMAINS:
            if hostname == trusted or hostname.endswith('.' + trusted):
                return True
            if domain == trusted:
                return True
        return False
    
    def _check_url_patterns(self, url, hostname):
        """Check for suspicious URL patterns"""
        score = 0
        
        # IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            score += 40
        
        # Excessive subdomains
        if hostname.count('.') > 4:
            score += 15
        
        # Suspicious keywords in hostname
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in hostname:
                score += 10
                break
        
        return score
    
    def _check_tld(self, hostname):
        """Check for suspicious TLDs"""
        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return 25
        return 0
    
    def _check_https(self, scheme):
        """Check for HTTPS"""
        return 20 if scheme != 'https' else 0
    
    def _check_brand_impersonation(self, hostname):
        """Check for brand impersonation"""
        brands = ['google', 'facebook', 'paypal', 'amazon', 
                  'microsoft', 'apple', 'netflix', 'bank']
        
        for brand in brands:
            if brand in hostname and not self._is_trusted(hostname, ''):
                return 30
        return 0
    
    def _check_content(self, content):
        """Analyze page content"""
        score = 0
        
        if content.get('has_password_field') and content.get('external_form_action'):
            score += 25
        
        if not content.get('is_https'):
            score += 10
        
        return score
```

---

## Extension Files

### manifest.json

```json
{
  "manifest_version": 3,
  "name": "Phishing Guard",
  "version": "2.0.0",
  "description": "Intent-aware phishing protection",
  
  "permissions": [
    "activeTab",
    "tabs",
    "webNavigation",
    "storage",
    "notifications"
  ],
  
  "host_permissions": [
    "http://localhost:5000/*",
    "<all_urls>"
  ],
  
  "background": {
    "service_worker": "background.js"
  },
  
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"],
    "css": ["content.css"],
    "run_at": "document_start"
  }],
  
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon-16.png",
      "32": "icons/icon-32.png",
      "48": "icons/icon-48.png",
      "128": "icons/icon-128.png"
    }
  },
  
  "icons": {
    "16": "icons/icon-16.png",
    "32": "icons/icon-32.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  }
}
```

### background.js (Key Sections)

```javascript
/**
 * Phishing Guard - Background Service Worker
 * Monitors tab navigation and coordinates scanning
 */

const API_BASE = 'http://localhost:5000/api';

const state = {
    isEnabled: true,
    scanHistory: [],
    currentTabStatus: {},
    stats: { totalScans: 0, threatsBlocked: 0 }
};

// Auto-scan on page load
chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    
    const tab = await chrome.tabs.get(details.tabId);
    if (!tab.url || !state.isEnabled) return;
    
    if (tab.url.startsWith('chrome://')) return;
    
    await scanUrl(tab.url, details.tabId);
});

async function scanUrl(url, tabId) {
    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        const result = await response.json();
        
        // Update state and badge
        state.stats.totalScans++;
        if (result.analysis.is_phishing) {
            state.stats.threatsBlocked++;
            showWarning(tabId, result.analysis);
        }
        
        updateBadge(tabId, result.analysis.risk_level);
        
        return result.analysis;
    } catch (error) {
        console.error('Scan error:', error);
    }
}
```

### content.js (Key Sections)

```javascript
/**
 * Phishing Guard - Content Script
 * Auto-scans pages and detects credential access
 */

(function() {
    'use strict';
    
    if (window.__phishingGuardInjected) return;
    window.__phishingGuardInjected = true;
    
    // Auto-scan on page load
    function init() {
        if (document.readyState === 'complete') {
            autoScanPage();
        } else {
            window.addEventListener('load', autoScanPage);
        }
        setupInputMonitoring();
    }
    
    // Monitor sensitive field access
    function setupInputMonitoring() {
        document.addEventListener('focusin', (e) => {
            const input = e.target;
            if (input.type === 'password') {
                onCredentialAccess('password', 'Login Credentials');
            }
            // Also monitors: card numbers, CVV, OTP fields
        }, true);
    }
    
    // Show beautiful dismissable alert
    function showCredentialAlert(type, label, risks) {
        const alertOverlay = document.createElement('div');
        alertOverlay.innerHTML = `
            <div class="pg-alert-backdrop">
                <div class="pg-alert-card">
                    <button class="pg-alert-close">×</button>
                    <h2>Credential Access Detected</h2>
                    <p>You're about to enter: ${label}</p>
                    <div class="risks">...</div>
                    <button class="pg-btn-leave">Leave Site</button>
                    <button class="pg-btn-proceed">I'll Be Careful</button>
                </div>
            </div>
        `;
        document.body.appendChild(alertOverlay);
    }
    
    init();
})();
```

### popup.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Phishing Guard</title>
  <link rel="stylesheet" href="popup.css">
</head>
<body>
  <div class="app">
    <header class="header">
      <div class="logo">
        <svg><!-- Shield icon --></svg>
        <span class="logo-name">Phishing Guard</span>
      </div>
      <button class="toggle-btn" id="protection-toggle"></button>
    </header>
    
    <section class="status-card">
      <div class="status-indicator">
        <span class="status-dot"></span>
        <span class="status-text">Silent Mode</span>
      </div>
      <div class="current-site">
        <span>Current Site:</span>
        <span id="site-url">-</span>
      </div>
      <button class="scan-btn">Scan Now</button>
    </section>
    
    <section class="stats-row">
      <div class="stat"><span id="stat-scans">0</span> Scans</div>
      <div class="stat"><span id="stat-threats">0</span> Blocked</div>
      <div class="stat backend-stat">Backend</div>
    </section>
    
    <section class="history-card">
      <h3>Recent Scans</h3>
      <div id="history-list"></div>
    </section>
    
    <section class="tips-card">
      <h3>Stay Safe</h3>
      <div class="tips-grid">
        <div>Verify URLs before login</div>
        <div>Look for HTTPS lock</div>
        <div>Don't click email links</div>
        <div>Use bookmarks for banks</div>
      </div>
    </section>
  </div>
  <script src="popup.js"></script>
</body>
</html>
```

---

# API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check and uptime |
| `/api/scan` | POST | Scan URL for phishing |
| `/api/stats` | GET | Get scanning statistics |

### Scan Request Example

```json
POST /api/scan
{
  "url": "https://example.com/login",
  "content": {
    "has_password_field": true,
    "is_https": true
  }
}
```

### Scan Response Example

```json
{
  "url": "https://suspicious-site.tk/login",
  "analysis": {
    "is_phishing": true,
    "risk_score": 65,
    "risk_level": "suspicious",
    "warnings": [
      "Suspicious TLD detected",
      "Brand impersonation suspected"
    ]
  }
}
```

---

# How It Works

## 1. Page Load Scan

When you visit any website:
1. `background.js` detects the navigation
2. Sends URL to Python backend
3. Backend analyzes URL patterns
4. Returns risk assessment
5. Badge updates with status

## 2. Intent Detection

When you interact with sensitive fields:
1. `content.js` monitors focus events
2. Detects password/card/OTP fields
3. Checks if site is trusted
4. Shows alert if risks detected

## 3. Risk Scoring

| Factor | Points |
|--------|--------|
| IP address URL | +40 |
| No HTTPS | +20 |
| Suspicious TLD | +25 |
| Brand impersonation | +30 |
| Excessive subdomains | +15 |
| Trusted domain | -30 |

**Risk Levels:**
- 0-19: Safe
- 20-39: Warning
- 40-69: Suspicious
- 70+: Dangerous

---

# Project Files Summary

```
phishing-guard/
├── README.md
├── .gitignore
├── backend/
│   ├── app.py           (Flask server)
│   ├── detector.py      (Detection logic)
│   └── requirements.txt (Dependencies)
└── extension/
    ├── manifest.json    (Extension config)
    ├── background.js    (Service worker)
    ├── content.js       (Page scanner)
    ├── popup.html       (Popup UI)
    ├── popup.js         (Popup logic)
    ├── popup.css        (Styles)
    ├── content.css      (Page styles)
    └── icons/           (Extension icons)
```

---

# GitHub Repository

**URL:** https://github.com/KrishnaAkshath/phishing-guard

---

*Document generated for Phishing Guard v2.0*
*Intent-Aware Browser Extension for Phishing Detection*
