/**
 * Phishing Guard - Configuration
 * Update these URLs after deploying to production
 */

const CONFIG = {
    // Backend API URL - Update after deploying backend
    API_URL: 'http://localhost:5000/api',

    // Dashboard URL - Update after deploying dashboard  
    DASHBOARD_URL: 'http://localhost:5173',

    // Extension version
    VERSION: '2.0.0'
};

// Export for use in other scripts
if (typeof window !== 'undefined') {
    window.PHISHING_GUARD_CONFIG = CONFIG;
}
