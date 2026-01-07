/**
 * Phishing Guard - Background Service Worker v2.0
 * Enhanced monitoring with threat intelligence and settings sync
 */

const API_BASE = 'http://localhost:5000/api';

// Extension state
const state = {
    isEnabled: true,
    scanHistory: [],
    currentTabStatus: {},
    settings: {
        protection_level: 'medium',
        modules: {
            phishing_protection: true,
            password_guard: true,
            payment_protection: true,
            link_scanner: true
        },
        preferences: {
            real_time_alerts: true,
            auto_block_dangerous: true,
            notification_sound: false
        }
    },
    whitelist: [],
    blacklist: [],
    stats: {
        totalScans: 0,
        threatsBlocked: 0
    },
    apiKey: null
};

// ============================================
// INITIALIZATION
// ============================================

chrome.runtime.onInstalled.addListener(async () => {
    console.log('Phishing Guard v2.0 installed');
    await loadState();
    updateBadge('active');
});

chrome.runtime.onStartup.addListener(async () => {
    await loadState();
    updateBadge(state.isEnabled ? 'active' : 'disabled');
});

async function loadState() {
    try {
        const saved = await chrome.storage.local.get([
            'isEnabled', 'stats', 'scanHistory', 'settings',
            'whitelist', 'blacklist', 'apiKey'
        ]);

        if (saved.isEnabled !== undefined) state.isEnabled = saved.isEnabled;
        if (saved.stats) state.stats = saved.stats;
        if (saved.scanHistory) state.scanHistory = saved.scanHistory.slice(-100);
        if (saved.settings) state.settings = { ...state.settings, ...saved.settings };
        if (saved.whitelist) state.whitelist = saved.whitelist;
        if (saved.blacklist) state.blacklist = saved.blacklist;
        if (saved.apiKey) state.apiKey = saved.apiKey;
    } catch (e) {
        console.error('Error loading state:', e);
    }
}

async function saveState() {
    try {
        await chrome.storage.local.set({
            isEnabled: state.isEnabled,
            stats: state.stats,
            scanHistory: state.scanHistory.slice(-100),
            settings: state.settings,
            whitelist: state.whitelist,
            blacklist: state.blacklist,
            apiKey: state.apiKey
        });
    } catch (e) {
        console.error('Error saving state:', e);
    }
}

// ============================================
// TAB MONITORING
// ============================================

chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    if (!state.isEnabled) return;

    try {
        const tab = await chrome.tabs.get(details.tabId);
        if (!tab.url) return;

        // Skip chrome:// and extension pages
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            updateBadgeForTab(details.tabId, 'inactive');
            return;
        }

        await scanUrl(tab.url, details.tabId);
    } catch (e) {
        console.error('Navigation handler error:', e);
    }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (!tab.url) return;

        const status = state.currentTabStatus[activeInfo.tabId];
        if (status) {
            updateBadgeForTab(activeInfo.tabId, status.risk_level);
        }
    } catch (e) {
        // Tab might not exist
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    delete state.currentTabStatus[tabId];
});

// ============================================
// MESSAGE HANDLER
// ============================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    handleMessage(request, sender).then(sendResponse);
    return true;
});

async function handleMessage(request, sender) {
    switch (request.action) {
        case 'getStatus':
            return {
                isEnabled: state.isEnabled,
                stats: state.stats,
                settings: state.settings,
                currentTab: await getCurrentTabStatus()
            };

        case 'toggleProtection':
            state.isEnabled = !state.isEnabled;
            await saveState();
            updateBadge(state.isEnabled ? 'active' : 'disabled');
            return { isEnabled: state.isEnabled };

        case 'updateSettings':
            if (request.settings) {
                state.settings = { ...state.settings, ...request.settings };
                await saveState();
            }
            return { success: true, settings: state.settings };

        case 'scanCurrentTab':
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.url) {
                return await scanUrl(tab.url, tab.id, true);
            }
            return { error: 'No active tab' };

        case 'getHistory':
            return { history: state.scanHistory.slice(-20).reverse() };

        case 'contentScan':
            if (sender.tab) {
                return await scanWithContent(sender.tab.url, sender.tab.id, request.content);
            }
            return { error: 'No tab context' };

        case 'addToWhitelist':
            if (request.domain) {
                return await addToWhitelist(request.domain);
            }
            return { error: 'Domain required' };

        case 'addToBlacklist':
            if (request.domain) {
                return await addToBlacklist(request.domain);
            }
            return { error: 'Domain required' };

        case 'getWhitelist':
            return { whitelist: state.whitelist };

        case 'getBlacklist':
            return { blacklist: state.blacklist };

        case 'checkBackend':
            return await checkBackendHealth();

        case 'setApiKey':
            state.apiKey = request.apiKey;
            await saveState();
            return { success: true };

        default:
            return { error: 'Unknown action' };
    }
}

// ============================================
// URL SCANNING
// ============================================

async function scanUrl(url, tabId, forceRescan = false) {
    // Check if module is enabled
    if (!state.settings.modules.phishing_protection) {
        return { skipped: true, reason: 'Module disabled' };
    }

    // Check whitelist
    const domain = getDomain(url);
    if (state.whitelist.includes(domain)) {
        const result = {
            url,
            domain,
            is_phishing: false,
            risk_score: 0,
            risk_level: 'safe',
            warnings: [],
            whitelisted: true
        };
        state.currentTabStatus[tabId] = result;
        updateBadgeForTab(tabId, 'safe');
        return result;
    }

    // Check blacklist
    if (state.blacklist.includes(domain)) {
        const result = {
            url,
            domain,
            is_phishing: true,
            risk_score: 100,
            risk_level: 'dangerous',
            warnings: ['Domain is in your blacklist'],
            blacklisted: true
        };
        state.currentTabStatus[tabId] = result;
        updateBadgeForTab(tabId, 'dangerous');
        showPhishingWarning(tabId, result);
        return result;
    }

    // Check cache if not forcing rescan
    if (!forceRescan && state.currentTabStatus[tabId]?.url === url) {
        return state.currentTabStatus[tabId];
    }

    updateBadgeForTab(tabId, 'scanning');

    try {
        const headers = { 'Content-Type': 'application/json' };
        if (state.apiKey) {
            headers['X-API-Key'] = state.apiKey;
        }

        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        // Update stats
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

        await saveState();

        // Update badge
        updateBadgeForTab(tabId, result.analysis.risk_level);

        // Show warning for dangerous sites
        if (result.analysis.risk_level === 'dangerous') {
            if (state.settings.preferences.auto_block_dangerous) {
                showPhishingWarning(tabId, result.analysis);
            }
        } else if (result.analysis.risk_level === 'suspicious') {
            showSuspiciousWarning(tabId, result.analysis);
        }

        // Notify content script
        notifyContentScript(tabId, result.analysis);

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
    if (!state.settings.modules.phishing_protection) {
        return { skipped: true };
    }

    try {
        const headers = { 'Content-Type': 'application/json' };
        if (state.apiKey) {
            headers['X-API-Key'] = state.apiKey;
        }

        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers,
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
            await saveState();

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

// ============================================
// WHITELIST / BLACKLIST
// ============================================

async function addToWhitelist(domain) {
    domain = domain.toLowerCase();

    // Remove from blacklist if present
    state.blacklist = state.blacklist.filter(d => d !== domain);

    // Add to whitelist if not present
    if (!state.whitelist.includes(domain)) {
        state.whitelist.push(domain);
    }

    await saveState();

    // Notify backend if authenticated
    if (state.apiKey) {
        try {
            await fetch(`${API_BASE}/whitelist`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': state.apiKey
                },
                body: JSON.stringify({ domain })
            });
        } catch (e) {
            console.error('Failed to sync whitelist:', e);
        }
    }

    return { success: true, domain };
}

async function addToBlacklist(domain) {
    domain = domain.toLowerCase();

    // Remove from whitelist if present
    state.whitelist = state.whitelist.filter(d => d !== domain);

    // Add to blacklist if not present
    if (!state.blacklist.includes(domain)) {
        state.blacklist.push(domain);
    }

    await saveState();

    // Notify backend if authenticated
    if (state.apiKey) {
        try {
            await fetch(`${API_BASE}/blacklist`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': state.apiKey
                },
                body: JSON.stringify({ domain })
            });
        } catch (e) {
            console.error('Failed to sync blacklist:', e);
        }
    }

    return { success: true, domain };
}

// ============================================
// HELPERS
// ============================================

function getDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return '';
    }
}

async function getCurrentTabStatus() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && state.currentTabStatus[tab.id]) {
            return state.currentTabStatus[tab.id];
        }
        return null;
    } catch {
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

function notifyContentScript(tabId, result) {
    chrome.tabs.sendMessage(tabId, {
        action: 'scanResult',
        result
    }).catch(() => { });
}

// ============================================
// BADGE UPDATES
// ============================================

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

// ============================================
// NOTIFICATIONS
// ============================================

function showPhishingWarning(tabId, analysis) {
    if (!state.settings.preferences.real_time_alerts) return;

    // Browser notification
    chrome.notifications.create(`phishing-${tabId}`, {
        type: 'basic',
        iconUrl: 'icons/icon-128.png',
        title: '🚨 Phishing Site Detected',
        message: `This website appears to be a phishing attempt. Risk Score: ${analysis.risk_score}%`,
        priority: 2,
        requireInteraction: true
    });

    // Inject warning into page
    chrome.tabs.sendMessage(tabId, {
        action: 'showWarning',
        type: 'danger',
        analysis
    }).catch(() => { });
}

function showSuspiciousWarning(tabId, analysis) {
    if (!state.settings.preferences.real_time_alerts) return;

    chrome.notifications.create(`suspicious-${tabId}`, {
        type: 'basic',
        iconUrl: 'icons/icon-128.png',
        title: '⚠️ Suspicious Website',
        message: `This website has suspicious characteristics. Proceed with caution.`,
        priority: 1
    });

    chrome.tabs.sendMessage(tabId, {
        action: 'showWarning',
        type: 'warning',
        analysis
    }).catch(() => { });
}

// ============================================
// STARTUP
// ============================================

console.log('Phishing Guard v2.0 background worker started');
