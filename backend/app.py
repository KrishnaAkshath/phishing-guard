"""
Phishing Guard - Backend API Server
Flask application providing phishing detection API endpoints
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from detector import scan_url, scan_content
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Enable CORS for Chrome extension
CORS(app, resources={
    r"/api/*": {
        "origins": ["chrome-extension://*", "http://localhost:*", "*"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Statistics tracking
stats = {
    'total_scans': 0,
    'threats_detected': 0,
    'start_time': datetime.now().isoformat()
}


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing Guard API',
        'version': '1.0.0',
        'uptime_since': stats['start_time']
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get scanning statistics"""
    return jsonify({
        'total_scans': stats['total_scans'],
        'threats_detected': stats['threats_detected'],
        'uptime_since': stats['start_time']
    })


@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    """
    Main scanning endpoint
    Accepts: { "url": "https://example.com", "content": {...} }
    Returns: Detailed phishing analysis
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        url = data.get('url')
        content = data.get('content', {})
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        logger.info(f"Scanning URL: {url}")
        
        # Perform URL analysis
        url_result = scan_url(url)
        
        # Perform content analysis if provided
        content_result = {}
        if content:
            content_result = scan_content(content)
            # Combine risk scores
            url_result['risk_score'] = min(100, 
                url_result['risk_score'] + content_result.get('risk_score', 0))
            url_result['warnings'].extend(content_result.get('content_risks', []))
            
            # Recalculate risk level
            if url_result['risk_score'] >= 70:
                url_result['risk_level'] = 'dangerous'
                url_result['is_phishing'] = True
            elif url_result['risk_score'] >= 50:
                url_result['risk_level'] = 'suspicious'
                url_result['is_phishing'] = True
            elif url_result['risk_score'] >= 30:
                url_result['risk_level'] = 'warning'
        
        # Update statistics
        stats['total_scans'] += 1
        if url_result['is_phishing']:
            stats['threats_detected'] += 1
        
        # Build response
        response = {
            'success': True,
            'url': url,
            'analysis': {
                'is_phishing': url_result['is_phishing'],
                'risk_score': url_result['risk_score'],
                'risk_level': url_result['risk_level'],
                'warnings': url_result['warnings'],
                'details': url_result['details']
            },
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Scan complete - Risk: {url_result['risk_level']} ({url_result['risk_score']})")
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/batch-scan', methods=['POST'])
def batch_scan_endpoint():
    """
    Batch scanning endpoint for multiple URLs
    Accepts: { "urls": ["url1", "url2", ...] }
    """
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({'error': 'URLs array is required'}), 400
        
        if len(urls) > 50:
            return jsonify({'error': 'Maximum 50 URLs per batch'}), 400
        
        results = []
        for url in urls:
            result = scan_url(url)
            results.append({
                'url': url,
                'is_phishing': result['is_phishing'],
                'risk_score': result['risk_score'],
                'risk_level': result['risk_level']
            })
            stats['total_scans'] += 1
            if result['is_phishing']:
                stats['threats_detected'] += 1
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results)
        })
    
    except Exception as e:
        logger.error(f"Batch scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Starting Phishing Guard API Server...")
    logger.info("API available at http://localhost:5000")
    logger.info("Endpoints:")
    logger.info("  GET  /api/health - Health check")
    logger.info("  GET  /api/stats  - Scanning statistics")
    logger.info("  POST /api/scan   - Scan URL/content")
    logger.info("  POST /api/batch-scan - Batch URL scan")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
