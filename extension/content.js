/**
 * Phishing Guard - Content Script v2.0
 * Auto-scans on page load, detects credential access, shows beautiful alerts
 */

(function () {
    'use strict';

    if (window.__phishingGuardInjected) return;
    window.__phishingGuardInjected = true;

    // State
    let alertOverlay = null;
    let scanBadge = null;
    let hasShownAlert = false;

    // ==========================================
    // INITIALIZATION - Auto scan on load
    // ==========================================

    function init() {
        console.log('Phishing Guard: Active on', location.hostname);

        // Auto-scan page content on load
        if (document.readyState === 'complete') {
            autoScanPage();
        } else {
            window.addEventListener('load', autoScanPage);
        }

        // Monitor for credential/sensitive input access
        setupInputMonitoring();

        // Listen for messages from background
        chrome.runtime.onMessage.addListener(handleMessage);
    }

    // ==========================================
    // AUTO SCAN
    // ==========================================

    async function autoScanPage() {
        const pageInfo = analyzeCurrentPage();

        // Send to background for full analysis
        try {
            const response = await chrome.runtime.sendMessage({
                action: 'contentScan',
                content: pageInfo
            });

            if (response?.is_phishing || response?.risk_level === 'dangerous') {
                showSecurityAlert('danger', response);
            } else if (response?.risk_level === 'suspicious') {
                showSecurityAlert('warning', response);
            }
        } catch (e) {
            // Background not ready
        }
    }

    function analyzeCurrentPage() {
        return {
            has_password_field: document.querySelector('input[type="password"]') !== null,
            has_login_form: detectLoginForm(),
            has_payment_form: detectPaymentForm(),
            is_https: location.protocol === 'https:',
            external_form_action: checkExternalForms(),
            page_title: document.title,
            hostname: location.hostname
        };
    }

    function detectLoginForm() {
        const forms = document.querySelectorAll('form');
        return Array.from(forms).some(form =>
            form.querySelector('input[type="password"]') ||
            form.querySelector('input[type="email"]') ||
            form.querySelector('input[name*="user"]') ||
            form.querySelector('input[name*="login"]')
        );
    }

    function detectPaymentForm() {
        const inputs = document.querySelectorAll('input');
        return Array.from(inputs).some(input => {
            const name = (input.name + input.id + input.placeholder).toLowerCase();
            return name.includes('card') || name.includes('cvv') ||
                name.includes('credit') || name.includes('payment');
        });
    }

    function checkExternalForms() {
        const forms = document.querySelectorAll('form[action]');
        return Array.from(forms).some(form => {
            const action = form.getAttribute('action');
            if (action && action.startsWith('http')) {
                try {
                    return new URL(action).hostname !== location.hostname;
                } catch { return false; }
            }
            return false;
        });
    }

    // ==========================================
    // INPUT MONITORING - Credential Detection
    // ==========================================

    function setupInputMonitoring() {
        // Monitor password field focus
        document.addEventListener('focusin', (e) => {
            const input = e.target;
            if (!input?.tagName || input.tagName !== 'INPUT') return;

            const type = input.type?.toLowerCase();
            const name = (input.name + input.id + input.placeholder).toLowerCase();

            // Password field accessed
            if (type === 'password') {
                onCredentialAccess('password', 'Login Credentials');
            }
            // Card number field accessed
            else if (name.includes('card') || name.includes('credit') || input.maxLength === 16) {
                onCredentialAccess('payment', 'Payment Information');
            }
            // CVV/Security code
            else if (name.includes('cvv') || name.includes('cvc') || name.includes('security')) {
                onCredentialAccess('payment', 'Card Security Code');
            }
            // OTP/Verification code
            else if (name.includes('otp') || name.includes('code') || name.includes('verify')) {
                onCredentialAccess('otp', 'Verification Code');
            }
        }, true);

        // Monitor form submissions
        document.addEventListener('submit', (e) => {
            const form = e.target;
            if (form.querySelector('input[type="password"]')) {
                onFormSubmit('login', form);
            }
        }, true);
    }

    async function onCredentialAccess(type, label) {
        if (hasShownAlert) return;

        // Check if this is a trusted domain
        if (isTrustedDomain()) {
            showQuickBadge('safe', 'Verified Site');
            return;
        }

        // Get risk analysis
        const risks = getLocalRisks();

        if (risks.length > 0) {
            hasShownAlert = true;
            showCredentialAlert(type, label, risks);
        } else if (!location.protocol.startsWith('https')) {
            showQuickBadge('warning', 'Connection Not Secure');
        }
    }

    function onFormSubmit(type, form) {
        if (!isTrustedDomain()) {
            const risks = getLocalRisks();
            if (risks.length > 0) {
                // Don't block, but warn
                showQuickBadge('warning', 'Submitting to unverified site');
            }
        }
    }

    // ==========================================
    // LOCAL RISK ANALYSIS
    // ==========================================

    function isTrustedDomain() {
        const trusted = [
            'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com',
            'twitter.com', 'x.com', 'amazon.com', 'microsoft.com', 'apple.com',
            'paypal.com', 'github.com', 'linkedin.com', 'netflix.com', 'dropbox.com',
            'discord.com', 'slack.com', 'zoom.us', 'notion.so', 'figma.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'stripe.com'
        ];
        const host = location.hostname.toLowerCase();
        return trusted.some(d => host === d || host.endsWith('.' + d));
    }

    function getLocalRisks() {
        const risks = [];
        const host = location.hostname.toLowerCase();

        // No HTTPS
        if (!location.protocol.startsWith('https')) {
            risks.push({ severity: 'high', message: 'Connection is not encrypted (no HTTPS)' });
        }

        // IP address URL
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
            risks.push({ severity: 'high', message: 'Site uses IP address instead of domain' });
        }

        // Suspicious TLD
        const badTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.click'];
        if (badTlds.some(tld => host.endsWith(tld))) {
            risks.push({ severity: 'medium', message: 'Suspicious domain extension detected' });
        }

        // Brand impersonation
        const brands = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple', 'netflix', 'bank'];
        for (const brand of brands) {
            if (host.includes(brand) && !isTrustedDomain()) {
                risks.push({ severity: 'high', message: `May be impersonating ${brand.charAt(0).toUpperCase() + brand.slice(1)}` });
                break;
            }
        }

        // External form submission
        if (checkExternalForms()) {
            risks.push({ severity: 'medium', message: 'Form submits data to different domain' });
        }

        return risks;
    }

    // ==========================================
    // BEAUTIFUL ALERTS
    // ==========================================

    function showCredentialAlert(type, label, risks) {
        if (alertOverlay) return;

        const typeIcons = {
            password: '<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>',
            payment: '<path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"/>',
            otp: '<path d="M17 1H7c-1.1 0-2 .9-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2V3c0-1.1-.9-2-2-2zm0 18H7V5h10v14z"/>'
        };

        alertOverlay = document.createElement('div');
        alertOverlay.id = 'pg-alert-overlay';
        alertOverlay.innerHTML = `
            <div class="pg-alert-backdrop">
                <div class="pg-alert-card">
                    <button class="pg-alert-close" id="pg-close">
                        <svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
                    </button>
                    
                    <div class="pg-alert-icon">
                        <svg viewBox="0 0 24 24">${typeIcons[type] || typeIcons.password}</svg>
                    </div>
                    
                    <h2 class="pg-alert-title">Credential Access Detected</h2>
                    <p class="pg-alert-subtitle">You're about to enter: <strong>${label}</strong></p>
                    
                    <div class="pg-alert-site">
                        <span class="pg-site-badge ${location.protocol === 'https:' ? 'secure' : 'insecure'}">
                            ${location.protocol === 'https:' ? 'HTTPS' : 'HTTP'}
                        </span>
                        <span class="pg-site-host">${location.hostname}</span>
                    </div>
                    
                    <div class="pg-alert-risks">
                        <h3>Security Concerns:</h3>
                        ${risks.map(r => `
                            <div class="pg-risk-row ${r.severity}">
                                <span class="pg-risk-icon"></span>
                                <span>${r.message}</span>
                            </div>
                        `).join('')}
                    </div>
                    
                    <div class="pg-alert-tips">
                        <h3>Stay Safe:</h3>
                        <ul>
                            <li>Verify URL matches the official site</li>
                            <li>Look for the padlock icon</li>
                            <li>Don't enter credentials from email links</li>
                        </ul>
                    </div>
                    
                    <div class="pg-alert-actions">
                        <button class="pg-btn-leave" id="pg-leave">Leave Site</button>
                        <button class="pg-btn-proceed" id="pg-proceed">I'll Be Careful</button>
                    </div>
                </div>
            </div>
        `;

        injectAlertStyles();
        document.body.appendChild(alertOverlay);

        // Event handlers
        document.getElementById('pg-close')?.addEventListener('click', dismissAlert);
        document.getElementById('pg-leave')?.addEventListener('click', () => {
            window.location.href = 'about:blank';
        });
        document.getElementById('pg-proceed')?.addEventListener('click', dismissAlert);
    }

    function showSecurityAlert(level, analysis) {
        if (alertOverlay || hasShownAlert) return;
        hasShownAlert = true;

        const config = {
            danger: {
                title: 'Phishing Site Detected',
                subtitle: 'This website may steal your information',
                color: '#ef4444'
            },
            warning: {
                title: 'Suspicious Website',
                subtitle: 'This site has concerning characteristics',
                color: '#f59e0b'
            }
        };

        const cfg = config[level] || config.warning;

        alertOverlay = document.createElement('div');
        alertOverlay.id = 'pg-alert-overlay';
        alertOverlay.innerHTML = `
            <div class="pg-alert-backdrop">
                <div class="pg-alert-card ${level}">
                    <button class="pg-alert-close" id="pg-close">
                        <svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
                    </button>
                    
                    <div class="pg-alert-icon ${level}">
                        <svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
                    </div>
                    
                    <h2 class="pg-alert-title">${cfg.title}</h2>
                    <p class="pg-alert-subtitle">${cfg.subtitle}</p>
                    
                    <div class="pg-alert-site">
                        <span class="pg-site-badge insecure">WARNING</span>
                        <span class="pg-site-host">${location.hostname}</span>
                    </div>
                    
                    ${analysis?.warnings?.length ? `
                        <div class="pg-alert-risks">
                            <h3>Issues Found:</h3>
                            ${analysis.warnings.slice(0, 4).map(w => `
                                <div class="pg-risk-row high">
                                    <span class="pg-risk-icon"></span>
                                    <span>${w}</span>
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                    
                    <div class="pg-alert-tips">
                        <h3>Recommended Action:</h3>
                        <ul>
                            <li>Do not enter any personal information</li>
                            <li>Leave this site immediately</li>
                            <li>Go to the official site directly</li>
                        </ul>
                    </div>
                    
                    <div class="pg-alert-actions">
                        <button class="pg-btn-leave" id="pg-leave">Leave Now</button>
                        <button class="pg-btn-proceed" id="pg-proceed">Dismiss Warning</button>
                    </div>
                </div>
            </div>
        `;

        injectAlertStyles();
        document.body.appendChild(alertOverlay);

        document.getElementById('pg-close')?.addEventListener('click', dismissAlert);
        document.getElementById('pg-leave')?.addEventListener('click', () => {
            window.location.href = 'about:blank';
        });
        document.getElementById('pg-proceed')?.addEventListener('click', dismissAlert);
    }

    function showQuickBadge(type, message) {
        if (scanBadge) scanBadge.remove();

        scanBadge = document.createElement('div');
        scanBadge.id = 'pg-quick-badge';
        scanBadge.className = type;
        scanBadge.innerHTML = `
            <svg viewBox="0 0 24 24">
                ${type === 'safe'
                ? '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>'
                : '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>'}
            </svg>
            <span>${message}</span>
        `;

        injectBadgeStyles();
        document.body.appendChild(scanBadge);

        setTimeout(() => {
            scanBadge?.remove();
            scanBadge = null;
        }, 3000);
    }

    function dismissAlert() {
        if (alertOverlay) {
            alertOverlay.style.opacity = '0';
            setTimeout(() => {
                alertOverlay?.remove();
                alertOverlay = null;
            }, 200);
        }
    }

    // ==========================================
    // STYLES
    // ==========================================

    function injectAlertStyles() {
        if (document.getElementById('pg-alert-styles')) return;

        const style = document.createElement('style');
        style.id = 'pg-alert-styles';
        style.textContent = `
            #pg-alert-overlay {
                position: fixed;
                inset: 0;
                z-index: 2147483647;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                transition: opacity 0.2s;
            }
            .pg-alert-backdrop {
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                backdrop-filter: blur(4px);
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                animation: pgFadeIn 0.3s ease;
            }
            .pg-alert-card {
                background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
                border-radius: 20px;
                max-width: 400px;
                width: 100%;
                padding: 32px 24px 24px;
                text-align: center;
                position: relative;
                box-shadow: 0 25px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.1);
                animation: pgSlideUp 0.4s ease;
            }
            .pg-alert-card.danger { border-top: 4px solid #ef4444; }
            .pg-alert-card.warning { border-top: 4px solid #f59e0b; }
            
            .pg-alert-close {
                position: absolute;
                top: 12px;
                right: 12px;
                width: 36px;
                height: 36px;
                border: none;
                background: rgba(255,255,255,0.1);
                border-radius: 50%;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s;
            }
            .pg-alert-close:hover { background: rgba(255,255,255,0.2); transform: scale(1.1); }
            .pg-alert-close svg { width: 18px; height: 18px; fill: #94a3b8; }
            
            .pg-alert-icon {
                width: 64px;
                height: 64px;
                margin: 0 auto 16px;
                background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .pg-alert-icon.danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
            .pg-alert-icon.warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
            .pg-alert-icon svg { width: 32px; height: 32px; fill: white; }
            
            .pg-alert-title {
                font-size: 20px;
                font-weight: 700;
                color: #f1f5f9;
                margin: 0 0 6px;
            }
            .pg-alert-subtitle {
                font-size: 14px;
                color: #94a3b8;
                margin: 0 0 20px;
            }
            .pg-alert-subtitle strong { color: #f1f5f9; }
            
            .pg-alert-site {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(255,255,255,0.05);
                padding: 8px 14px;
                border-radius: 8px;
                margin-bottom: 20px;
            }
            .pg-site-badge {
                font-size: 10px;
                font-weight: 700;
                padding: 3px 6px;
                border-radius: 4px;
            }
            .pg-site-badge.secure { background: #22c55e; color: white; }
            .pg-site-badge.insecure { background: #ef4444; color: white; }
            .pg-site-host {
                font-size: 13px;
                color: #94a3b8;
                font-family: monospace;
            }
            
            .pg-alert-risks, .pg-alert-tips {
                text-align: left;
                background: rgba(0,0,0,0.3);
                border-radius: 12px;
                padding: 14px;
                margin-bottom: 16px;
            }
            .pg-alert-risks h3, .pg-alert-tips h3 {
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: #64748b;
                margin: 0 0 10px;
            }
            .pg-alert-risks h3 { color: #f59e0b; }
            .pg-alert-tips h3 { color: #22c55e; }
            
            .pg-risk-row {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 8px 0;
                font-size: 13px;
                color: #cbd5e1;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
            .pg-risk-row:last-child { border-bottom: none; }
            .pg-risk-icon {
                width: 8px;
                height: 8px;
                border-radius: 50%;
                flex-shrink: 0;
            }
            .pg-risk-row.high .pg-risk-icon { background: #ef4444; }
            .pg-risk-row.medium .pg-risk-icon { background: #f59e0b; }
            .pg-risk-row.low .pg-risk-icon { background: #3b82f6; }
            
            .pg-alert-tips ul {
                margin: 0;
                padding-left: 18px;
                font-size: 12px;
                color: #94a3b8;
                line-height: 1.8;
            }
            
            .pg-alert-actions {
                display: flex;
                gap: 12px;
                margin-top: 8px;
            }
            .pg-btn-leave, .pg-btn-proceed {
                flex: 1;
                padding: 14px 20px;
                border-radius: 10px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                border: none;
                transition: all 0.2s;
            }
            .pg-btn-leave {
                background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
                color: white;
            }
            .pg-btn-leave:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(34,197,94,0.4); }
            .pg-btn-proceed {
                background: transparent;
                border: 1px solid #475569;
                color: #94a3b8;
            }
            .pg-btn-proceed:hover { background: #1e293b; color: #f1f5f9; }
            
            @keyframes pgFadeIn { from { opacity: 0; } to { opacity: 1; } }
            @keyframes pgSlideUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
        `;
        document.head.appendChild(style);
    }

    function injectBadgeStyles() {
        if (document.getElementById('pg-badge-styles')) return;

        const style = document.createElement('style');
        style.id = 'pg-badge-styles';
        style.textContent = `
            #pg-quick-badge {
                position: fixed;
                top: 16px;
                right: 16px;
                z-index: 2147483647;
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 10px 16px;
                border-radius: 10px;
                font-family: -apple-system, sans-serif;
                font-size: 13px;
                font-weight: 500;
                color: white;
                animation: pgBadgeIn 0.3s ease;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            }
            #pg-quick-badge.safe { background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); }
            #pg-quick-badge.warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
            #pg-quick-badge.danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
            #pg-quick-badge svg { width: 16px; height: 16px; fill: white; }
            @keyframes pgBadgeIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
        `;
        document.head.appendChild(style);
    }

    // ==========================================
    // MESSAGE HANDLER
    // ==========================================

    function handleMessage(request, sender, sendResponse) {
        if (request.action === 'showWarning') {
            showSecurityAlert(request.type, request.analysis);
        }
        sendResponse({ received: true });
        return true;
    }

    // Initialize
    init();
})();
