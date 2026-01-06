/**
 * Phishing Guard - Popup Script v2.0
 * Simplified UI with visible history
 */

document.addEventListener('DOMContentLoaded', init);

// UI Elements
const elements = {
    app: document.querySelector('.app'),
    toggle: document.getElementById('protection-toggle'),
    statusIndicator: document.getElementById('status-indicator'),
    statusText: document.getElementById('status-text'),
    siteUrl: document.getElementById('site-url'),
    rescanBtn: document.getElementById('rescan-btn'),
    statScans: document.getElementById('stat-scans'),
    statThreats: document.getElementById('stat-threats'),
    backendStat: document.getElementById('backend-stat'),
    historyList: document.getElementById('history-list')
};

// State
let state = {
    isEnabled: true,
    stats: { totalScans: 0, threatsBlocked: 0 }
};

async function init() {
    const response = await sendMessage({ action: 'getStatus' });

    if (response) {
        state.isEnabled = response.isEnabled;
        state.stats = response.stats || state.stats;
    }

    updateToggle();
    updateStats();
    updateCurrentSite();
    loadHistory();
    checkBackend();

    elements.toggle?.addEventListener('click', toggleProtection);
    elements.rescanBtn?.addEventListener('click', rescanCurrentSite);
}

// Toggle Protection
async function toggleProtection() {
    const response = await sendMessage({ action: 'toggleProtection' });
    if (response) {
        state.isEnabled = response.isEnabled;
        updateToggle();
    }
}

function updateToggle() {
    if (state.isEnabled) {
        elements.toggle?.classList.add('active');
        elements.app?.classList.remove('disabled');
    } else {
        elements.toggle?.classList.remove('active');
        elements.app?.classList.add('disabled');
        if (elements.statusText) elements.statusText.textContent = 'Disabled';
        elements.statusIndicator?.classList.add('disabled');
    }
}

// Current Site
async function updateCurrentSite() {
    if (!state.isEnabled) return;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.url) {
        if (elements.siteUrl) elements.siteUrl.textContent = 'No page';
        return;
    }

    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        if (elements.siteUrl) elements.siteUrl.textContent = 'Browser page';
        if (elements.statusText) elements.statusText.textContent = 'Safe';
        elements.statusIndicator?.classList.add('safe');
        return;
    }

    try {
        const url = new URL(tab.url);
        if (elements.siteUrl) elements.siteUrl.textContent = url.hostname;
    } catch {
        if (elements.siteUrl) elements.siteUrl.textContent = tab.url.substring(0, 30);
    }

    const status = await sendMessage({ action: 'getStatus' });
    if (status?.currentTab) {
        updateScanResult(status.currentTab);
    } else {
        if (elements.statusText) elements.statusText.textContent = 'Monitoring';
        elements.statusIndicator?.classList.remove('safe', 'warning', 'danger');
    }
}

async function rescanCurrentSite() {
    elements.rescanBtn?.classList.add('loading');
    if (elements.statusText) elements.statusText.textContent = 'Scanning...';

    const response = await sendMessage({ action: 'scanCurrentTab' });

    if (response && !response.error) {
        updateScanResult(response);
        loadHistory();
    }

    elements.rescanBtn?.classList.remove('loading');
}

function updateScanResult(result) {
    const { risk_level } = result;

    elements.statusIndicator?.classList.remove('safe', 'warning', 'danger', 'disabled');

    if (risk_level === 'safe') {
        if (elements.statusText) elements.statusText.textContent = 'Safe';
        elements.statusIndicator?.classList.add('safe');
    } else if (risk_level === 'warning' || risk_level === 'suspicious') {
        if (elements.statusText) elements.statusText.textContent = 'Suspicious';
        elements.statusIndicator?.classList.add('warning');
    } else if (risk_level === 'dangerous') {
        if (elements.statusText) elements.statusText.textContent = 'Danger';
        elements.statusIndicator?.classList.add('danger');
    } else {
        if (elements.statusText) elements.statusText.textContent = 'Monitoring';
    }
}

// Stats
function updateStats() {
    if (elements.statScans) elements.statScans.textContent = state.stats.totalScans || 0;
    if (elements.statThreats) elements.statThreats.textContent = state.stats.threatsBlocked || 0;
}

// Backend
async function checkBackend() {
    const response = await sendMessage({ action: 'checkBackend' });

    if (response?.healthy) {
        elements.backendStat?.classList.add('connected');
        elements.backendStat?.classList.remove('offline');
    } else {
        elements.backendStat?.classList.remove('connected');
        elements.backendStat?.classList.add('offline');
    }
}

// History
async function loadHistory() {
    const response = await sendMessage({ action: 'getHistory' });

    if (!elements.historyList) return;

    if (!response?.history || response.history.length === 0) {
        elements.historyList.innerHTML = '<div class="history-empty">No scans yet - browse to start</div>';
        return;
    }

    const html = response.history.slice(0, 8).map(item => {
        const hostname = getHostname(item.url);
        const risk = item.risk_level || 'safe';
        const time = getTimeAgo(item.timestamp);

        return `
            <div class="history-row ${risk}">
                <span class="h-dot"></span>
                <span class="h-site">${hostname}</span>
                <span class="h-status">${risk}</span>
                <span class="h-time">${time}</span>
            </div>
        `;
    }).join('');

    elements.historyList.innerHTML = html;
}

function getHostname(url) {
    try {
        return new URL(url).hostname.replace('www.', '');
    } catch {
        return url?.substring(0, 20) || '?';
    }
}

function getTimeAgo(timestamp) {
    if (!timestamp) return '';
    try {
        const diff = Date.now() - new Date(timestamp).getTime();
        if (diff < 60000) return 'now';
        if (diff < 3600000) return Math.floor(diff / 60000) + 'm';
        if (diff < 86400000) return Math.floor(diff / 3600000) + 'h';
        return Math.floor(diff / 86400000) + 'd';
    } catch {
        return '';
    }
}

// Utility
function sendMessage(message) {
    return new Promise(resolve => {
        chrome.runtime.sendMessage(message, response => {
            resolve(chrome.runtime.lastError ? null : response);
        });
    });
}
