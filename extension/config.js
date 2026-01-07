/**
 * Phishing Guard - Configuration
 * Production URLs
 */

const CONFIG = {
    // Backend API URL - Deployed on Render
    API_URL: 'https://phishing-guard.onrender.com/api',

    // Dashboard URL - Update after deploying to Vercel
    DASHBOARD_URL: 'https://phishing-guard-dashboard.vercel.app',

    // Extension version
    VERSION: '2.0.0'
};

// Export for use in other scripts
if (typeof window !== 'undefined') {
    window.PHISHING_GUARD_CONFIG = CONFIG;
}
