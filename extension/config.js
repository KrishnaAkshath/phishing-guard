/**
 * Phishing Guard - Configuration
 * Production URLs
 */

const CONFIG = {
    // Backend API URL - Deployed on Render
    API_URL: 'https://phishing-guard.onrender.com/api',

    // Dashboard URL - Deployed on Vercel
    DASHBOARD_URL: 'https://phishing-guard-seven.vercel.app',

    // Extension version
    VERSION: '2.0.0'
};

// Export for use in other scripts
if (typeof window !== 'undefined') {
    window.PHISHING_GUARD_CONFIG = CONFIG;
}
