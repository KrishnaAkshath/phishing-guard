/**
 * Phishing Guard - Background Service Worker
 * Monitors tab navigation and coordinates scanning with the Python backend
 */

const API_BASE = 'http://localhost:5000/api';

// Extension state
const state = {
    isEnabled: true,
    scanHistory: [],
    currentTabStatus: {},
    stats: {
        totalScans: 0,
        threatsBlocked: 0
    }
};

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
    console.log('Phishing Guard installed');

    // Load saved state
    const saved = await chrome.storage.local.get(['isEnabled', 'stats', 'scanHistory']);
    if (saved.isEnabled !== undefined) state.isEnabled = saved.isEnabled;
    if (saved.stats) state.stats = saved.stats;
    if (saved.scanHistory) state.scanHistory = saved.scanHistory.slice(-100); // Keep last 100

    // Set initial badge
    updateBadge('active');
});

// Listen for tab updates
chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return; // Only main frame

    const tab = await chrome.tabs.get(details.tabId);
    if (!tab.url || !state.isEnabled) return;

    // Skip chrome:// and extension pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        updateBadgeForTab(details.tabId, 'inactive');
        return;
    }

    await scanUrl(tab.url, details.tabId);
});

// Listen for tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (!tab.url) return;

    const status = state.currentTabStatus[activeInfo.tabId];
    if (status) {
        updateBadgeForTab(activeInfo.tabId, status.riskLevel);
    }
});

// Message handler for popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    handleMessage(request, sender).then(sendResponse);
    return true; // Will respond asynchronously
});

async function handleMessage(request, sender) {
    switch (request.action) {
        case 'getStatus':
            return {
                isEnabled: state.isEnabled,
                stats: state.stats,
                currentTab: await getCurrentTabStatus()
            };

        case 'toggleProtection':
            state.isEnabled = !state.isEnabled;
            await chrome.storage.local.set({ isEnabled: state.isEnabled });
            updateBadge(state.isEnabled ? 'active' : 'disabled');
            return { isEnabled: state.isEnabled };

        case 'scanCurrentTab':
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url) {
                return await scanUrl(tab.url, tab.id, true);
            }
            return { error: 'No active tab' };

        case 'getHistory':
            return { history: state.scanHistory.slice(-20).reverse() };

        case 'contentScan':
            // Content script reports page content for analysis
            if (sender.tab) {
                return await scanWithContent(sender.tab.url, sender.tab.id, request.content);
            }
            return { error: 'No tab context' };

        case 'intentScan':
            // Intent-aware scanning triggered by content script
            if (sender.tab) {
                const result = await scanUrl(sender.tab.url, sender.tab.id);
                return {
                    analysis: result,
                    intent: request.data?.intent,
                    triggered: true
                };
            }
            return { error: 'No tab context' };

        case 'checkBackend':
            return await checkBackendHealth();

        default:
            return { error: 'Unknown action' };
    }
}

async function scanUrl(url, tabId, forceRescan = false) {
    // Check cache if not forcing rescan
    if (!forceRescan && state.currentTabStatus[tabId]?.url === url) {
        return state.currentTabStatus[tabId];
    }

    updateBadgeForTab(tabId, 'scanning');

    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        // Update state
        state.stats.totalScans++;
        if (result.analysis.is_phishing) {
            state.stats.threatsBlocked++;
        }

        // Store result
        const scanResult = {
            url,
            tabId,
            timestamp: new Date().toISOString(),
            ...result.analysis
        };

        state.currentTabStatus[tabId] = scanResult;
        state.scanHistory.push(scanResult);

        // Save to storage
        await chrome.storage.local.set({
            stats: state.stats,
            scanHistory: state.scanHistory.slice(-100)
        });

        // Update badge
        updateBadgeForTab(tabId, result.analysis.risk_level);

        // Show notification for dangerous sites
        if (result.analysis.risk_level === 'dangerous') {
            showPhishingWarning(tabId, result.analysis);
        } else if (result.analysis.risk_level === 'suspicious') {
            showSuspiciousWarning(tabId, result.analysis);
        }

        // Notify content script
        try {
            await chrome.tabs.sendMessage(tabId, {
                action: 'scanResult',
                result: result.analysis
            });
        } catch (e) {
            // Content script may not be ready
        }

        return scanResult;

    } catch (error) {
        console.error('Scan error:', error);
        updateBadgeForTab(tabId, 'error');

        return {
            url,
            error: error.message,
            risk_level: 'unknown',
            is_phishing: false
        };
    }
}

async function scanWithContent(url, tabId, content) {
    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, content })
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        // Update existing result with content analysis
        if (state.currentTabStatus[tabId]) {
            state.currentTabStatus[tabId] = {
                ...state.currentTabStatus[tabId],
                ...result.analysis,
                contentScanned: true
            };
        }

        updateBadgeForTab(tabId, result.analysis.risk_level);

        if (result.analysis.is_phishing) {
            state.stats.threatsBlocked++;
            await chrome.storage.local.set({ stats: state.stats });

            if (result.analysis.risk_level === 'dangerous') {
                showPhishingWarning(tabId, result.analysis);
            }
        }

        return result.analysis;

    } catch (error) {
        console.error('Content scan error:', error);
        return { error: error.message };
    }
}

async function getCurrentTabStatus() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && state.currentTabStatus[tab.id]) {
            return state.currentTabStatus[tab.id];
        }
        return null;
    } catch (e) {
        return null;
    }
}

async function checkBackendHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        return { healthy: true, ...data };
    } catch (error) {
        return { healthy: false, error: error.message };
    }
}

function updateBadge(status) {
    const badges = {
        active: { text: '✓', color: '#22c55e' },
        disabled: { text: 'OFF', color: '#6b7280' },
        scanning: { text: '...', color: '#3b82f6' },
        safe: { text: '✓', color: '#22c55e' },
        warning: { text: '!', color: '#f59e0b' },
        suspicious: { text: '⚠', color: '#f97316' },
        dangerous: { text: '✕', color: '#ef4444' },
        error: { text: '?', color: '#6b7280' },
        inactive: { text: '', color: '#6b7280' }
    };

    const badge = badges[status] || badges.active;
    chrome.action.setBadgeText({ text: badge.text });
    chrome.action.setBadgeBackgroundColor({ color: badge.color });
}

function updateBadgeForTab(tabId, status) {
    const badges = {
        scanning: { text: '...', color: '#3b82f6' },
        safe: { text: '✓', color: '#22c55e' },
        warning: { text: '!', color: '#f59e0b' },
        suspicious: { text: '⚠', color: '#f97316' },
        dangerous: { text: '✕', color: '#ef4444' },
        error: { text: '?', color: '#6b7280' },
        inactive: { text: '', color: '#6b7280' },
        unknown: { text: '?', color: '#6b7280' }
    };

    const badge = badges[status] || { text: '?', color: '#6b7280' };

    chrome.action.setBadgeText({ tabId, text: badge.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

function showPhishingWarning(tabId, analysis) {
    // Show browser notification
    chrome.notifications.create(`phishing-${tabId}`, {
        type: 'basic',
        iconUrl: 'icons/icon-128.png',
        title: 'Phishing Site Detected',
        message: `This website appears to be a phishing attempt. Risk Score: ${analysis.risk_score}%`,
        priority: 2,
        requireInteraction: true
    });

    // Inject warning into page
    chrome.tabs.sendMessage(tabId, {
        action: 'showWarning',
        type: 'dangerous',
        analysis
    }).catch(() => { });
}

function showSuspiciousWarning(tabId, analysis) {
    chrome.notifications.create(`suspicious-${tabId}`, {
        type: 'basic',
        iconUrl: 'icons/icon-128.png',
        title: 'Suspicious Website Detected',
        message: `This website has suspicious characteristics. Proceed with caution.`,
        priority: 1
    });

    chrome.tabs.sendMessage(tabId, {
        action: 'showWarning',
        type: 'suspicious',
        analysis
    }).catch(() => { });
}

// Cleanup old tab status
chrome.tabs.onRemoved.addListener((tabId) => {
    delete state.currentTabStatus[tabId];
});

console.log('Phishing Guard background worker started');
