# Phishing Guard - Intent-Aware Browser Extension

A Chrome extension that detects phishing websites and protects users when entering sensitive information.

## Features

- **Intent-Aware Detection**: Only activates when you're about to enter sensitive data
- **Auto-Scan**: Automatically scans every page on load
- **Credential Protection**: Alerts when accessing password, payment, or OTP fields
- **Beautiful Alerts**: Dismissable warnings with security explanations
- **Privacy-First**: Most analysis runs locally in your browser
- **Scan History**: Track all scanned sites in the popup

## Project Structure

```
phishing-guard/
├── backend/           # Python Flask backend
│   ├── app.py         # API server
│   ├── detector.py    # Phishing detection logic
│   └── requirements.txt
├── extension/         # Chrome extension
│   ├── manifest.json  # Extension config
│   ├── background.js  # Service worker
│   ├── content.js     # Page scanner & alerts
│   ├── popup.html     # Extension popup UI
│   ├── popup.js       # Popup logic
│   └── popup.css      # Popup styles
└── README.md
```

## Setup

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Backend runs at `http://localhost:5000`

### Extension

1. Open Chrome and go to `chrome://extensions`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select the `extension` folder

## Usage

1. Start the backend server
2. Load the extension in Chrome
3. Browse normally - the extension scans pages automatically
4. When entering passwords/payments on risky sites, you'll see a warning

## Tech Stack

- **Backend**: Python, Flask, tldextract
- **Extension**: JavaScript, Chrome APIs (Manifest V3)
- **Styling**: CSS with dark theme

## License

MIT
