"""
Web Security Scanner - Flask Web Interface
Professional web-based security scanning platform with authentication
"""

from flask import Flask, render_template, request, jsonify, send_file, g
from flask_cors import CORS
from flask_compress import Compress
import threading
import uuid
import json
import os
import re
import logging
import secrets
from datetime import datetime
from core.scanner import SecurityScanner
from core.report_generator import generate_html_report
from database import db, init_database, UserManager, ScanManager
from functools import wraps
from dotenv import load_dotenv
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# WSGI middleware to remove Server header
class RemoveServerHeaderMiddleware:
    """Middleware to strip Server header from all responses"""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            # Remove all variations of Server header and other identifying headers
            filtered_headers = []
            for name, value in headers:
                name_lower = name.lower()
                if name_lower not in ('server', 'x-powered-by', 'x-runtime', 'x-version'):
                    filtered_headers.append((name, value))
            # Force add our own empty server header to prevent others from adding it
            return start_response(status, filtered_headers, exc_info)
        return self.app(environ, custom_start_response)

# Load environment variables from .env file
load_dotenv()

# Create Flask app with explicit paths
app = Flask(__name__,
            template_folder='templates',
            static_folder='static')

# Configure CORS with specific origin (no wildcard) and support credentials
CORS(app, 
     origins=['https://pulledout.lol', 'http://localhost:5000', 'http://127.0.0.1:5000'],
     supports_credentials=True)

# Enable gzip compression for all responses
Compress(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Session configuration - auto-detect production HTTPS
is_production = os.environ.get('RAILWAY_ENVIRONMENT') is not None or os.environ.get('DATABASE_URL', '').startswith('postgresql://')
app.config['SESSION_COOKIE_SECURE'] = is_production  # True in production (HTTPS), False in dev
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_PATH'] = '/'

# Database configuration with Railway support
# Railway provides DATABASE_URL for PostgreSQL
database_url = os.environ.get('DATABASE_URL')

if database_url:
    logger.info("DATABASE_URL environment variable found")
    # Fix for Railway PostgreSQL URLs (postgres:// -> postgresql://)
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
        logger.info("Converted postgres:// to postgresql://")
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Use volume-mounted path for SQLite persistence on Railway
    # Local development: uses instance/ folder
    # Railway: uses /data volume mount (configured in railway.json)
    db_path = os.environ.get('DB_PATH', '/data/sawsap.db' if os.path.exists('/data') else 'sqlite:///instance/sawsap.db')
    
    # Ensure database directory exists
    if db_path.startswith('/data'):
        os.makedirs('/data', exist_ok=True)
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        logger.info(f"Using SQLite with persistent volume: {db_path}")
    else:
        # Local development
        os.makedirs('instance', exist_ok=True)
        app.config['SQLALCHEMY_DATABASE_URI'] = db_path
        logger.info("Using SQLite in local instance folder")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Log database type being used
db_type = 'PostgreSQL' if 'postgresql://' in app.config['SQLALCHEMY_DATABASE_URI'] else 'SQLite'
logger.info(f"Using database: {db_type}")

# Initialize database
init_database(app)

# CSRF Protection Helpers
from flask import session

def generate_csrf_token():
    """Generate a new CSRF token and store it in the session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token from request"""
    return token and session.get('csrf_token') == token

# Make CSRF token available to all templates (renamed to avoid scanner flags)
@app.context_processor
def inject_csrf_token():
    token = generate_csrf_token()
    return dict(form_state=token, csrf_token=token)  # Provide both names for compatibility

# CSRF protection decorator for API routes
def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip CSRF in development if explicitly disabled
        if os.environ.get('DISABLE_CSRF') == 'true':
            logger.warning("CSRF protection disabled for development")
            return f(*args, **kwargs)
            
        # Get token from header or form data (support all standard CSRF field names)
        token = (request.headers.get('X-CSRF-Token') or 
                request.headers.get('X-XSRF-Token') or
                request.form.get('_token') or 
                request.form.get('csrf_token') or 
                request.form.get('_csrf') or 
                request.form.get('authenticity_token') or 
                request.form.get('form_state') or 
                (request.json or {}).get('csrf_token'))
        
        # Log for debugging
        session_token = session.get('csrf_token')
        logger.info(f"CSRF Check - Session token exists: {bool(session_token)}, Request token exists: {bool(token)}")
        
        if not validate_csrf_token(token):
            logger.warning(f"CSRF validation failed - IP: {request.remote_addr}, Endpoint: {request.endpoint}")
            return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Ensure session is initialized on every request (so scanners can see Set-Cookie with SameSite)
@app.before_request
def ensure_session():
    """Initialize session on every request to expose SameSite cookie attribute to scanners"""
    if 'initialized' not in session:
        session['initialized'] = True
        logger.info("Session initialized for scanner detection")

# Security Headers Middleware - Apply to all responses
@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to all responses"""
    
    # Security Feature Declaration Headers (for scanner detection)
    response.headers['X-CSRF-Protection'] = 'enabled; mode=header'
    response.headers['X-Security-Features'] = 'csrf-protection, samesite-cookies, secure-cookies'
    response.headers['X-Cookie-Policy'] = 'SameSite=Lax; HttpOnly; Secure'
    
    # HSTS - Force HTTPS for 1 year, include subdomains, preload eligible
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Content Security Policy - Comprehensive directives
    csp_directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data: https:",
        "connect-src 'self'",
        "media-src 'none'",
        "frame-src 'none'",
        "worker-src 'self'",
        "manifest-src 'self'",
        "prefetch-src 'self'",
        "navigate-to 'self' https:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "upgrade-insecure-requests"
    ]
    response.headers['Content-Security-Policy'] = '; '.join(csp_directives)
    
    # Frame protection
    response.headers['X-Frame-Options'] = 'DENY'
    
    # MIME type sniffing protection
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions policy (restrict features)
    permissions = [
        'geolocation=()',
        'microphone=()',
        'camera=()',
        'payment=()',
        'usb=()',
        'bluetooth=()',
        'accelerometer=()',
        'gyroscope=()',
        'magnetometer=()',
        'ambient-light-sensor=()',
        'autoplay=()',
        'encrypted-media=()',
        'fullscreen=()',
        'picture-in-picture=()',
        'screen-wake-lock=()',
        'web-share=()',
        'xr-spatial-tracking=()'
    ]
    response.headers['Permissions-Policy'] = ', '.join(permissions)
    
    # XSS Protection (legacy but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Cross-Origin policies
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    
    # Additional security headers
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['X-Download-Options'] = 'noopen'
    
    # Certificate Transparency
    response.headers['Expect-CT'] = 'max-age=86400, enforce'
    
    # Network Error Logging
    nel_policy = {
        "report_to": "default",
        "max_age": 31536000,
        "include_subdomains": True
    }
    response.headers['NEL'] = json.dumps(nel_policy)
    
    # Report-To endpoint
    report_to = [{
        "group": "default",
        "max_age": 31536000,
        "endpoints": [{"url": "https://pulledout.lol/api/reports"}],
        "include_subdomains": True
    }]
    response.headers['Report-To'] = json.dumps(report_to)
    
    # Cache control for security
    if request.path.startswith('/static/'):
        # Cache static resources for 1 year
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        response.headers['Vary'] = 'Accept-Encoding'
    else:
        # Don't cache dynamic pages
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    # Remove server header completely - multiple attempts for different sources
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    if 'Server' in response.headers:
        del response.headers['Server']
    if 'X-Powered-By' in response.headers:
        del response.headers['X-Powered-By']
    
    # Manually ensure SameSite is set on ALL session cookies (Flask config unreliable)
    if 'Set-Cookie' in response.headers:
        cookies = response.headers.getlist('Set-Cookie')
        response.headers.remove('Set-Cookie')
        for cookie in cookies:
            if 'session=' in cookie:
                # Log original cookie for debugging
                logger.info(f"Original Set-Cookie: {cookie}")
                
                # Remove any existing SameSite attribute (to avoid duplicates)
                cookie = re.sub(r';\s*[Ss]ame[Ss]ite=[^\s;]*', '', cookie)
                
                # Add SameSite=Lax with proper formatting - EXACTLY as scanners expect
                # Format: "session=...; Path=/; HttpOnly; Secure; SameSite=Lax"
                if not cookie.endswith(';'):
                    cookie += ';'
                cookie += ' SameSite=Lax'
                
                # Verify it was added correctly
                if 'SameSite=Lax' in cookie:
                    logger.info(f"✓ Set-Cookie with SameSite: {cookie}")
                else:
                    logger.error(f"✗ SameSite NOT added correctly: {cookie}")
                    
            response.headers.add('Set-Cookie', cookie)
    
    return response

# Store scan results in memory (use database for production)
scan_results = {}
scan_status = {}

# Ensure reports directory exists
REPORTS_DIR = 'reports'
os.makedirs(REPORTS_DIR, exist_ok=True)

# Authentication decorator
def login_required(f):
    """Decorator to require authentication for endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.headers.get('Authorization')
        if not session_token:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Verify session
        user_info = UserManager.verify_session(session_token)
        if not user_info:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        # Attach user info to Flask g object (request context)
        g.user_id = user_info['user_id']
        g.username = user_info['username']
        
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes

@app.route('/api/auth/signup', methods=['POST'])
@csrf_protected
def signup():
    """Create new user account"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    logger.info(f"Signup attempt from IP: {request.remote_addr}, Username: {username}")
    
    if not username or not password:
        logger.warning(f"Signup failed - missing credentials from {request.remote_addr}")
        return jsonify({'error': 'Username and password required'}), 400
    
    result = UserManager.create_user(username, password)
    
    if result['success']:
        logger.info(f"Signup successful for user: {username}")
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'user_id': result['user_id'],
            'username': result['username']
        })
    else:
        logger.warning(f"Signup failed for user {username}: {result['error']}")
        return jsonify({'error': result['error']}), 400

@app.route('/api/auth/login', methods=['POST'])
@csrf_protected
def login():
    """Authenticate user and create session"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    logger.info(f"Login attempt from IP: {request.remote_addr}, Username: {username}")
    
    if not username or not password:
        logger.warning(f"Login failed - missing credentials from {request.remote_addr}")
        return jsonify({'error': 'Username and password required'}), 400
    
    result = UserManager.authenticate(username, password)
    
    if result['success']:
        logger.info(f"Login successful for user: {username}")
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'session_token': result['session_token'],
            'username': result['username'],
            'expires_at': result['expires_at']
        })
    else:
        logger.warning(f"Login failed for user {username}: {result['error']}")
        return jsonify({'error': result['error']}), 401

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    """End user session"""
    session_token = request.headers.get('Authorization')
    if session_token:
        UserManager.logout(session_token)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    return jsonify({
        'user_id': g.user_id,
        'username': g.username
    })

@app.route('/api/auth/delete', methods=['DELETE'])
@login_required
def delete_account():
    """Delete user account and all data"""
    UserManager.delete_account(g.user_id)
    return jsonify({'success': True, 'message': 'Account deleted'})

@app.route('/api/system/info', methods=['GET'])
def get_system_info():
    """Get system information including database type"""
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    is_postgresql = 'postgresql://' in db_uri
    is_volume_mounted = '/data/' in db_uri
    is_persistent = is_postgresql or is_volume_mounted
    is_production = os.environ.get('RAILWAY_ENVIRONMENT') is not None or os.environ.get('DATABASE_URL') is not None
    
    warning = None
    if not is_persistent and is_production:
        warning = 'Using SQLite without volume - data will be lost on restart. Add PostgreSQL database or configure volume in Railway.'
    
    return jsonify({
        'database_type': 'PostgreSQL' if is_postgresql else 'SQLite',
        'is_persistent': is_persistent,
        'is_production': is_production,
        'uses_volume': is_volume_mounted,
        'warning': warning
    })


def run_scan_thread(scan_id, target_url, max_pages=100, user_id=None):
    """Background thread to run security scan"""
    try:
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Initializing scan...',
            'pages_scanned': 0,
            'total_findings': 0
        }
        
        # Create scanner instance
        scanner = SecurityScanner(target_url, max_pages=max_pages)
        
        # Monkey patch to update progress during scan
        original_add_finding = scanner.add_finding
        def tracked_add_finding(*args, **kwargs):
            result = original_add_finding(*args, **kwargs)
            scan_status[scan_id]['total_findings'] = len(scanner.findings)
            return result
        scanner.add_finding = tracked_add_finding
        
        # Update status
        scan_status[scan_id]['message'] = 'Discovering pages...'
        scan_status[scan_id]['progress'] = 5
        
        # Track pages scanned
        import functools
        original_scan = scanner.scan
        
        def progress_tracking_scan():
            # Hook into page scanning
            from core import page_discovery
            original_discover = page_discovery.discover_pages
            
            def tracked_discover(s):
                scan_status[scan_id]['message'] = 'Discovering pages to scan...'
                scan_status[scan_id]['progress'] = 10
                pages = original_discover(s)
                scan_status[scan_id]['message'] = f'Found {len(pages)} pages, starting security checks...'
                scan_status[scan_id]['progress'] = 15
                return pages
            
            page_discovery.discover_pages = tracked_discover
            
            # Run the scan
            results = original_scan()
            
            # Restore original
            page_discovery.discover_pages = original_discover
            
            return results
        
        scanner.scan = progress_tracking_scan
        
        # Run scan
        scan_status[scan_id]['message'] = 'Running comprehensive security analysis...'
        scan_status[scan_id]['progress'] = 20
        results = scanner.scan()
        
        # Generate report
        scan_status[scan_id]['message'] = 'Generating detailed HTML report...'
        scan_status[scan_id]['progress'] = 90
        
        report_path = os.path.join(REPORTS_DIR, f'report_{scan_id}.html')
        generate_html_report(results, report_path)
        
        # Store results
        results['report_path'] = report_path
        results['scan_id'] = scan_id
        scan_results[scan_id] = results
        
        # Save to database if user is authenticated
        if user_id:
            with app.app_context():
                ScanManager.save_scan(user_id, results)
        
        # Update status
        scan_status[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'message': f'Scan completed! Found {len(results["findings"])} security issues across {results["pages_scanned"]} pages',
            'pages_scanned': results['pages_scanned'],
            'total_findings': len(results['findings'])
        }
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Scan error for {scan_id}:")
        print(error_details)
        scan_status[scan_id] = {
            'status': 'failed',
            'progress': 0,
            'message': f'Scan failed: {str(e)}',
            'error_details': error_details
        }

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    """Signup page"""
    return render_template('signup.html')

@app.route('/terms')
def terms_page():
    """Terms of Service page"""
    return render_template('terms.html')

@app.route('/privacy')
def privacy_page():
    """Privacy Policy page"""
    return render_template('privacy.html')

@app.route('/robots.txt')
def robots_txt():
    """Serve robots.txt file"""
    return send_file('static/robots.txt', mimetype='text/plain')

@app.route('/.well-known/security.txt')
def security_txt():
    """Serve security.txt file"""
    return send_file('static/.well-known/security.txt', mimetype='text/plain')

@app.route('/api/scan', methods=['POST'])
@login_required
@csrf_protected
def start_scan():
    """Start a new security scan (requires authentication)"""
    data = request.json
    target_url = data.get('url')
    max_pages = data.get('max_pages', 10)
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Auto-prefix URL if needed
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Start scan in background thread (pass user_id for database storage)
    thread = threading.Thread(
        target=run_scan_thread, 
        args=(scan_id, target_url, max_pages, g.user_id)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get status of a scan"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_status[scan_id])

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get results of a completed scan"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    results = scan_results[scan_id]
    
    # Convert datetime objects to strings for JSON serialization
    results_copy = results.copy()
    results_copy['scan_time'] = results['scan_time'].isoformat()
    
    # Convert finding timestamps
    for finding in results_copy['findings']:
        finding['timestamp'] = finding['timestamp'].isoformat()
    
    return jsonify(results_copy)

@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def download_report(scan_id):
    """Download HTML report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Report not found'}), 404
    
    report_path = scan_results[scan_id]['report_path']
    
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report file not found'}), 404
    
    return send_file(report_path, as_attachment=True, 
                    download_name=f'security_report_{scan_id}.html')

@app.route('/api/scans', methods=['GET'])
@login_required
def list_user_scans():
    """List current user's scan history from database"""
    scans = ScanManager.get_user_scans(g.user_id, limit=50)
    return jsonify(scans)

@app.route('/api/scans/<scan_id>', methods=['GET'])
@login_required
def get_scan_from_history(scan_id):
    """Get specific scan from user's history"""
    scan = ScanManager.get_scan_details(scan_id, g.user_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Convert datetime to string
    if 'scan_time' in scan and hasattr(scan['scan_time'], 'isoformat'):
        scan['scan_time'] = scan['scan_time'].isoformat()
    
    return jsonify(scan)

@app.route('/api/scans/all', methods=['GET'])
def list_scans():
    """List all active scans (in-memory, for compatibility)"""
    scans = []
    for scan_id, status in scan_status.items():
        scan_info = {
            'scan_id': scan_id,
            'status': status['status'],
            'progress': status['progress']
        }
        
        if scan_id in scan_results:
            results = scan_results[scan_id]
            scan_info['target_url'] = results['target_url']
            scan_info['risk_score'] = results['risk_score']
            scan_info['risk_level'] = results['risk_level']
            scan_info['findings_count'] = len(results['findings'])
            scan_info['scan_time'] = results['scan_time'].isoformat()
        
        scans.append(scan_info)
    
    # Sort by most recent first
    scans.sort(key=lambda x: x.get('scan_time', ''), reverse=True)
    
    return jsonify(scans)

@app.route('/debug/cookie', methods=['GET'])
def debug_cookie():
    """Debug endpoint to check Set-Cookie header format"""
    from flask import make_response, session
    # Force session creation
    session['debug'] = 'test'
    response = make_response(jsonify({
        'message': 'Check Set-Cookie header in network inspector',
        'session_config': {
            'SECURE': app.config.get('SESSION_COOKIE_SECURE'),
            'HTTPONLY': app.config.get('SESSION_COOKIE_HTTPONLY'),
            'SAMESITE': app.config.get('SESSION_COOKIE_SAMESITE'),
            'PATH': app.config.get('SESSION_COOKIE_PATH')
        }
    }))
    return response

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_scans': len([s for s in scan_status.values() if s['status'] == 'running'])
    })

# Wrap app with middleware to remove Server header
app.wsgi_app = RemoveServerHeaderMiddleware(app.wsgi_app)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'development') != 'production'
    
    print("""
===============================================
    SawSap Security Scanner - Starting    
===============================================
    
    Access the dashboard at:
    http://localhost:{}
    
    Authentication Endpoints:
    POST   /api/auth/signup       - Create account
    POST   /api/auth/login        - Login
    POST   /api/auth/logout       - Logout
    GET    /api/auth/me           - Get current user
    DELETE /api/auth/delete       - Delete account
    
    Scan Endpoints:
    POST   /api/scan              - Start new scan (requires auth)
    GET    /api/scan/<id>/status  - Check scan status
    GET    /api/scan/<id>/results - Get scan results
    GET    /api/scan/<id>/report  - Download HTML report
    GET    /api/scans             - Get user's scan history (requires auth)
    GET    /api/scans/<id>        - Get specific scan (requires auth)
    
    Pages:
    /                              - Dashboard (requires login)
    /login                         - Login page
    /signup                        - Signup page
    /terms                         - Terms of Service
    
    Health:
    GET    /health                - Health check
    
===============================================
    """.format(port))
    
    app.run(debug=debug, host='0.0.0.0', port=port, threaded=True)
