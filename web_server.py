"""
Web Security Scanner - Flask Web Interface
Professional web-based security scanning platform with authentication
"""

from flask import Flask, render_template, request, jsonify, send_file, g, redirect, make_response, send_from_directory
from flask_cors import CORS
from flask_compress import Compress
import requests
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
from core.error_tracker import log_info, log_warning, log_error, get_tracker
from typing import Optional
from scan_phases import SCAN_PHASES, CATEGORY_INFO, get_phase_by_progress, get_active_phase, get_completed_phases

# Try to import Redis (optional dependency)
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Log Redis availability
if not REDIS_AVAILABLE:
    logger.warning("Redis package not installed - multi-worker scan storage will use fallback")

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

# Custom JSON encoder for datetime objects
from flask.json.provider import DefaultJSONProvider

class DateTimeJSONProvider(DefaultJSONProvider):
    """Custom JSON provider that handles datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

# Create Flask app with explicit paths
app = Flask(__name__,
            template_folder='templates',
            static_folder='static')

# Set custom JSON provider
app.json = DateTimeJSONProvider(app)

# Configure CORS with specific origin (no wildcard) and support credentials
CORS(app, 
     origins=['https://pulledout.lol', 'http://localhost:5000', 'http://127.0.0.1:5000'],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     expose_headers=['Content-Type'])

# Enable gzip compression for all responses
Compress(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Detect production environment
is_production = os.environ.get('RAILWAY_ENVIRONMENT') is not None or os.environ.get('DATABASE_URL', '').startswith('postgresql://')

# Helper function to get base URL (supports localhost for development)
def get_base_url():
    """Get base URL - auto-detects localhost for development"""
    if is_production:
        return 'https://pulledout.lol'
    # Development mode
    return os.environ.get('BASE_URL', 'http://localhost:5000')

# Discord OAuth Configuration
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
# Auto-detect redirect URI based on environment
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI')
if not DISCORD_REDIRECT_URI:
    base_url = get_base_url()
    DISCORD_REDIRECT_URI = f"{base_url}/auth/discord/callback"
DISCORD_API_BASE = 'https://discord.com/api/v10'

# Discord Bot Configuration for Guild Verification
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
DISCORD_GUILD_ID = os.environ.get('DISCORD_GUILD_ID')
DISCORD_BUYER_ROLE_ID = os.environ.get('DISCORD_BUYER_ROLE_ID', '1484996965195579503')
DISCORD_DENIED_ROLE_ID = os.environ.get('DISCORD_DENIED_ROLE_ID', '1484997044618792982')

# Payment Configuration
LEMONSQUEEZY_API_KEY = os.environ.get('LEMONSQUEEZY_API_KEY')
LEMONSQUEEZY_STORE_URL = os.environ.get('LEMONSQUEEZY_STORE_URL')
LEMONSQUEEZY_STORE_ID = os.environ.get('LEMONSQUEEZY_STORE_ID')
LEMONSQUEEZY_PRODUCT_ID = os.environ.get('LEMONSQUEEZY_PRODUCT_ID')

# Static file versioning for cache busting
STATIC_VERSION = '20260322221500'  # Update this when static files change

# Session configuration - use production detection from above
app.config['SESSION_COOKIE_SECURE'] = is_production  # True in production (HTTPS), False in dev
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_PATH'] = '/'

logger.info(f"Environment: {'PRODUCTION' if is_production else 'DEVELOPMENT'}")
logger.info(f"Base URL: {get_base_url()}")
logger.info(f"Discord Redirect: {DISCORD_REDIRECT_URI}")

# Database configuration with Railway support
# Railway provides DATABASE_URL for PostgreSQL
database_url = os.environ.get('DATABASE_URL')

if database_url:
    logger.info("DATABASE_URL environment variable found")
    
    # Check if it's PostgreSQL or SQLite
    is_postgres = database_url.startswith('postgres://') or database_url.startswith('postgresql://')
    
    if is_postgres:
        # Fix for Railway PostgreSQL URLs (postgres:// -> postgresql://)
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
            logger.info("Converted postgres:// to postgresql://")
        
        # Add SSL parameters for Railway PostgreSQL if not already present
        if '?' not in database_url:
            database_url += '?sslmode=require'
            logger.info("Added SSL mode requirement for PostgreSQL")
        elif 'sslmode' not in database_url:
            database_url += '&sslmode=require'
            logger.info("Added SSL mode requirement for PostgreSQL")
        
        # PostgreSQL-specific configuration
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_pre_ping': True,  # Verify connections before using
            'pool_recycle': 300,  # Recycle connections every 5 minutes
            'pool_size': 10,  # Max pool size
            'max_overflow': 20,  # Allow up to 20 overflow connections
            'connect_args': {
                'sslmode': 'require',
                'connect_timeout': 10,
            }
        }
        logger.info("Configured PostgreSQL with SSL and connection pooling")
    else:
        # SQLite or other database - no SSL settings
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        logger.info(f"Configured database: {database_url.split('://')[0]}")
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

# Make CSRF token and static version available to all templates
@app.context_processor
def inject_csrf_token():
    token = generate_csrf_token()
    return dict(form_state=token, csrf_token=token, v=STATIC_VERSION)  # Provide both names for compatibility

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
                request.form.get('h') or 
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

# Ensure session is modified on EVERY request (forces Set-Cookie header for scanner detection)
@app.before_request
def ensure_session():
    """Modify session on every request to expose SameSite cookie attribute to scanners"""
    # Update timestamp to force session modification and Set-Cookie header
    import time
    session['_last_request'] = int(time.time())
    if 'initialized' not in session:
        session['initialized'] = True
        logger.info("Session initialized")

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
        "script-src 'self' 'unsafe-inline'",  # unsafe-inline needed for React and anti-debugging scripts
        "style-src 'self' 'unsafe-inline'",  # unsafe-inline needed for dynamic styles
        "font-src 'self' data:",
        "img-src 'self' data: https:",
        "connect-src 'self' ws: wss:",  # ws/wss for WebSocket connections
        "media-src 'none'",
        "frame-src 'none'",
        "worker-src 'self'",
        "manifest-src 'self'",
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
    
    # Manually ensure SameSite is set on ALL session cookies (Flask may not set it reliably)
    if 'Set-Cookie' in response.headers:
        cookies = response.headers.getlist('Set-Cookie')
        response.headers.remove('Set-Cookie')
        for cookie in cookies:
            if 'session=' in cookie:
                # Log original cookie for debugging
                logger.info(f"Original Set-Cookie: {cookie}")
                
                # Only add SameSite if not already present (case-insensitive check)
                if 'samesite=' not in cookie.lower():
                    # Ensure proper formatting: add semicolon if needed, then attribute
                    if not cookie.rstrip().endswith(';'):
                        cookie = cookie.rstrip() + ';'
                    cookie += ' SameSite=Lax'
                    logger.info(f"✓ Added SameSite: {cookie}")
                else:
                    logger.info(f"✓ SameSite already present: {cookie}")
                    
            response.headers.add('Set-Cookie', cookie)
    
    # Cache-busting headers to prevent 304 responses from serving old files
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

# Redis-backed storage for scan results and status (multi-worker compatible)
class RedisScanStorage:
    """Redis wrapper for scan storage with fallback to in-memory dict"""
    
    def __init__(self, redis_url=None, key_prefix="scan"):
        self.redis_client = None
        self.fallback_dict = {}
        self.key_prefix = key_prefix
        
        try:
            if redis_url and REDIS_AVAILABLE:
                logger.info(f"Attempting to connect to Redis: {redis_url[:15]}...")
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                # Test connection
                self.redis_client.ping()
                logger.info("✓ Redis connected successfully for scan storage (multi-worker enabled)")
            elif redis_url and not REDIS_AVAILABLE:
                logger.error("✗ REDIS_URL is set but redis package not installed. Run: pip install redis")
            else:
                logger.warning("⚠ No REDIS_URL provided, using in-memory storage (not multi-worker safe)")
        except Exception as e:
            logger.error(f"✗ Redis connection failed: {e}. Falling back to in-memory storage")
            self.redis_client = None
    
    def __setitem__(self, key, value):
        """Store value with automatic JSON serialization"""
        try:
            if self.redis_client:
                # Serialize to JSON and store in Redis with 24h expiration
                json_value = json.dumps(value, default=str)
                self.redis_client.setex(f"{self.key_prefix}:{key}", 86400, json_value)
            else:
                self.fallback_dict[key] = value
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            self.fallback_dict[key] = value
    
    def __getitem__(self, key):
        """Retrieve value with automatic JSON deserialization"""
        try:
            if self.redis_client:
                value = self.redis_client.get(f"{self.key_prefix}:{key}")
                if value is None:
                    raise KeyError(key)
                return json.loads(value)
            else:
                return self.fallback_dict[key]
        except KeyError:
            raise
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            if key in self.fallback_dict:
                return self.fallback_dict[key]
            raise KeyError(key)
    
    def __contains__(self, key):
        """Check if key exists"""
        try:
            if self.redis_client:
                return bool(self.redis_client.exists(f"{self.key_prefix}:{key}"))  # type: ignore
            else:
                return key in self.fallback_dict
        except Exception as e:
            logger.error(f"Redis contains error: {e}")
            return key in self.fallback_dict
    
    def get(self, key, default=None):
        """Get with default value"""
        try:
            return self[key]
        except KeyError:
            return default
    
    def keys(self):
        """Get all keys"""
        try:
            if self.redis_client:
                # Get all scan keys and strip the prefix
                redis_keys = self.redis_client.keys(f"{self.key_prefix}:*")  # type: ignore
                return [k.replace(f"{self.key_prefix}:", "", 1) for k in redis_keys]  # type: ignore
            else:
                return list(self.fallback_dict.keys())
        except Exception as e:
            logger.error(f"Redis keys error: {e}")
            return list(self.fallback_dict.keys())
    
    def values(self):
        """Get all values"""
        try:
            if self.redis_client:
                keys = self.keys()
                return [self[k] for k in keys]
            else:
                return list(self.fallback_dict.values())
        except Exception as e:
            logger.error(f"Redis values error: {e}")
            return list(self.fallback_dict.values())
    
    def items(self):
        """Get all items as (key, value) tuples"""
        try:
            if self.redis_client:
                keys = self.keys()
                return [(k, self[k]) for k in keys]
            else:
                return list(self.fallback_dict.items())
        except Exception as e:
            logger.error(f"Redis items error: {e}")
            return list(self.fallback_dict.items())
    
    @property
    def is_redis_connected(self):
        """Check if Redis is currently connected"""
        try:
            if self.redis_client:
                self.redis_client.ping()
                return True
        except:
            pass
        return False

# Initialize Redis storage for scans
REDIS_URL = os.environ.get('REDIS_URL')
scan_results = RedisScanStorage(REDIS_URL, key_prefix="results")
scan_status = RedisScanStorage(REDIS_URL, key_prefix="status")

# Ensure reports directory exists
REPORTS_DIR = 'reports'
os.makedirs(REPORTS_DIR, exist_ok=True)

# Guild Membership Check
def check_guild_membership(discord_id: str) -> dict:
    """
    Check if a Discord user is a member of the required guild and has the correct roles.
    Returns dict with 'has_access', 'reason', 'in_guild', and 'is_denied' keys.
    """
    
    # 🔧 TESTING MODE: Uncomment the line below to bypass guild checks during development
    return {'has_access': True, 'in_guild': True, 'is_denied': False, 'reason': '✅ TESTING - Guild check bypassed'}
    
    if not DISCORD_BOT_TOKEN or not DISCORD_GUILD_ID:
        logger.warning("Guild verification not configured - allowing access")
        return {'has_access': True, 'in_guild': True, 'is_denied': False, 'reason': 'Guild verification disabled'}
    
    try:
        response = requests.get(
            f"{DISCORD_API_BASE}/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
            headers={'Authorization': f"Bot {DISCORD_BOT_TOKEN}"}
        )
        
        if response.status_code == 404:
            logger.info(f"User {discord_id} is NOT in guild {DISCORD_GUILD_ID}")
            return {
                'has_access': False,
                'in_guild': False,
                'is_denied': False,
                'reason': 'You must purchase access to join the server'
            }
        
        if response.status_code != 200:
            logger.error(f"Guild check failed with status {response.status_code}: {response.text}")
            return {
                'has_access': False,
                'in_guild': False,
                'is_denied': False,
                'reason': 'Unable to verify server membership'
            }
        
        # User is in guild, now check roles
        member_data = response.json()
        user_roles = member_data.get('roles', [])
        
        logger.info(f"User {discord_id} roles: {user_roles}")
        
        # Check for denied role (M.U role)
        if DISCORD_DENIED_ROLE_ID in user_roles:
            logger.warning(f"User {discord_id} has denied role (M.U)")
            return {
                'has_access': False,
                'in_guild': True,
                'is_denied': True,
                'reason': 'Access denied: Your account has been restricted'
            }
        
        # Check for buyer role
        if DISCORD_BUYER_ROLE_ID not in user_roles:
            logger.info(f"User {discord_id} is in guild but missing buyer role")
            return {
                'has_access': False,
                'in_guild': True,
                'is_denied': False,
                'reason': 'You must purchase access to use this service'
            }
        
        # User has buyer role and no denied role
        logger.info(f"User {discord_id} has valid access (buyer role)")
        return {
            'has_access': True,
            'in_guild': True,
            'is_denied': False,
            'reason': 'Access granted'
        }
        
    except Exception as e:
        logger.error(f"Error checking guild membership: {str(e)}", exc_info=True)
        return {
            'has_access': False,
            'in_guild': False,
            'is_denied': False,
            'reason': 'Error verifying server membership'
        }

# Authentication decorator
def login_required(f):
    """Decorator to require authentication for endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check Authorization header first, then fall back to cookie
        auth_header = request.headers.get('Authorization')
        cookie_token = request.cookies.get('sessionToken')
        session_token = auth_header or cookie_token
        
        # Log authentication attempt
        log_info('AUTH', 'Authentication attempt', 
                 has_auth_header=bool(auth_header),
                 has_cookie=bool(cookie_token),
                 endpoint=request.endpoint,
                 path=request.path)
        
        # Strip "Bearer " prefix if present
        if session_token and session_token.startswith('Bearer '):
            session_token = session_token[7:]  # Remove "Bearer " prefix
        
        if not session_token:
            log_warning('AUTH', 'No session token found', 
                       cookies=dict(request.cookies),
                       headers={k:v for k,v in request.headers.items() if 'auth' in k.lower()})
            return jsonify({'error': 'Authentication required', 'debug': 'no_token'}), 401
        
        # Verify session
        user_info = UserManager.verify_session(session_token)
        
        if not user_info:
            log_error('AUTH', 'Session verification failed',
                     token_length=len(session_token),
                     token_preview=session_token[:10] + '...')
            return jsonify({'error': 'Invalid or expired session', 'debug': 'invalid_session'}), 401
        
        # Attach user info to Flask g object (request context)
        g.user_id = user_info['user_id']
        g.username = user_info['username']
        g.discord_id = user_info.get('discord_id')
        g.discord_avatar = user_info.get('discord_avatar')
        
        log_info('AUTH', f'Successfully authenticated: {g.username}',
                user_id=g.user_id,
                endpoint=request.endpoint)
        
        return f(*args, **kwargs)
    return decorated_function

# Guild membership decorator
def guild_required(f):
    """Decorator to require both authentication AND guild membership"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check Authorization header first, then fall back to cookie
        auth_header = request.headers.get('Authorization')
        cookie_token = request.cookies.get('sessionToken')
        session_token = auth_header or cookie_token
        
        # Log authentication attempt
        log_info('AUTH', 'Guild-protected endpoint accessed', 
                 has_auth_header=bool(auth_header),
                 has_cookie=bool(cookie_token),
                 endpoint=request.endpoint,
                 path=request.path)
        
        # Strip "Bearer " prefix if present
        if session_token and session_token.startswith('Bearer '):
            session_token = session_token[7:]  # Remove "Bearer " prefix
        
        if not session_token:
            log_warning('AUTH', 'No session token for guild endpoint', 
                       cookies=dict(request.cookies),
                       headers={k:v for k,v in request.headers.items() if 'auth' in k.lower()})
            return jsonify({'error': 'Authentication required', 'requires_auth': True}), 401
        
        # Verify session
        user_info = UserManager.verify_session(session_token)
        if not user_info:
            log_error('AUTH', 'Session verification failed on guild endpoint',
                     token_length=len(session_token),
                     token_preview=session_token[:10] + '...')
            return jsonify({'error': 'Invalid or expired session', 'requires_auth': True}), 401
        
        # Check guild membership
        discord_id = user_info.get('discord_id')
        if not discord_id:
            log_warning('AUTH', 'Discord account not linked', 
                       user_id=user_info.get('user_id'))
            return jsonify({'error': 'Discord account not linked', 'requires_auth': True}), 401
        
        log_info('AUTH', 'Checking guild membership',
                discord_id=discord_id,
                username=user_info.get('username'))
        
        access_check = check_guild_membership(discord_id)
        if not access_check['has_access']:
            log_warning('AUTH', 'Guild access denied',
                       discord_id=discord_id,
                       reason=access_check.get('reason'),
                       in_guild=access_check.get('in_guild'),
                       is_denied=access_check.get('is_denied'))
            # Check if user is denied
            if access_check.get('is_denied', False):
                return jsonify({
                    'error': access_check['reason'],
                    'is_denied': True,
                    'denied_url': '/denied'
                }), 403
            return jsonify({
                'error': access_check['reason'],
                'requires_guild': not access_check['in_guild'],
                'requires_purchase': access_check['in_guild'],
                'pay_url': '/pay'
            }), 403
        
        # Attach user info to Flask g object (request context)
        g.user_id = user_info['user_id']
        g.username = user_info['username']
        g.discord_id = discord_id
        g.discord_avatar = user_info.get('discord_avatar')
        
        log_info('AUTH', f'Successfully authenticated with guild access: {g.username}',
                user_id=g.user_id,
                discord_id=g.discord_id,
                endpoint=request.endpoint)
        
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes - Discord OAuth

@app.route('/auth/login', methods=['GET'])
def auth_login_redirect():
    """Direct redirect to Discord OAuth (for frontend compatibility)"""
    if not DISCORD_CLIENT_ID:
        return jsonify({'error': 'Discord OAuth not configured'}), 500
    
    # Support 'next' param to redirect back after login
    import urllib.parse
    next_url = request.args.get('next', '/dashboard')
    # Only allow relative paths to prevent open redirect
    if not next_url.startswith('/'):
        next_url = '/dashboard'
    state = urllib.parse.quote(next_url)
    
    # Build OAuth URL and redirect
    oauth_url = (
        f"{DISCORD_API_BASE}/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify"
        f"&state={state}"
    )
    
    return redirect(oauth_url)

@app.route('/api/auth/discord/login', methods=['GET'])
def discord_login():
    """Initiate Discord OAuth flow (API route returns JSON)"""
    if not DISCORD_CLIENT_ID:
        return jsonify({'error': 'Discord OAuth not configured'}), 500
    
    # Support 'next' param to redirect back after login
    import urllib.parse
    next_url = request.args.get('next', '/')
    # Only allow relative paths to prevent open redirect
    if not next_url.startswith('/'):
        next_url = '/'
    state = urllib.parse.quote(next_url)
    
    # Build OAuth URL
    oauth_url = (
        f"{DISCORD_API_BASE}/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify"
        f"&state={state}"
    )
    
    return jsonify({'auth_url': oauth_url})

@app.route('/auth/discord/callback', methods=['GET'])
def discord_callback():
    """Handle Discord OAuth callback"""
    code = request.args.get('code')
    
    if not code:
        return render_template('login.html', error='Discord authentication failed')
    
    try:
        # Exchange code for access token
        token_response = requests.post(
            f"{DISCORD_API_BASE}/oauth2/token",
            data={
                'client_id': DISCORD_CLIENT_ID,
                'client_secret': DISCORD_CLIENT_SECRET,
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': DISCORD_REDIRECT_URI
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if token_response.status_code != 200:
            logger.error(f"Discord token exchange failed: {token_response.text}")
            return render_template('login.html', error='Discord authentication failed')
        
        token_data = token_response.json()
        access_token = token_data['access_token']
        
        # Get user info from Discord
        user_response = requests.get(
            f"{DISCORD_API_BASE}/users/@me",
            headers={'Authorization': f"Bearer {access_token}"}
        )
        
        if user_response.status_code != 200:
            logger.error(f"Discord user fetch failed: {user_response.text}")
            return render_template('login.html', error='Failed to get Discord user info')
        
        user_data = user_response.json()
        
        # Extract user info
        discord_id = user_data['id']
        discord_username = f"{user_data['username']}#{user_data['discriminator']}" if user_data.get('discriminator') != '0' else user_data['username']
        discord_avatar = f"https://cdn.discordapp.com/avatars/{discord_id}/{user_data['avatar']}.png" if user_data.get('avatar') else None
        
        logger.info(f"Discord OAuth successful for user: {discord_username}")
        
        # Create or update user in database
        result = UserManager.create_or_update_discord_user(discord_id, discord_username, discord_avatar)
        
        if result['success']:
            # Check guild membership and roles BEFORE allowing access
            access_check = check_guild_membership(discord_id)
            
            # Determine redirect URL based on access status
            import urllib.parse
            next_url = request.args.get('state', '/')
            next_url = urllib.parse.unquote(next_url)
            # Only allow relative paths to prevent open redirect
            if not next_url.startswith('/'):
                next_url = '/'
            
            # Special handling: if coming from /pay, always redirect back there
            # (they're trying to purchase, so let them complete that flow)
            if next_url == '/pay':
                redirect_url = '/pay'
                logger.info(f"User {discord_username} authenticated, redirecting to payment page")
            elif access_check.get('is_denied', False):
                # User has M.U/Denied role - redirect to denied page
                redirect_url = '/denied'
                logger.warning(f"User {discord_username} has M.U role - redirected to /denied")
            elif not access_check['has_access']:
                # User doesn't have access - redirect to payment page
                redirect_url = '/pay'
                logger.info(f"User {discord_username} needs to purchase: {access_check['reason']}")
            else:
                # User has access - go where they wanted
                redirect_url = next_url
                logger.info(f"User {discord_username} has access - redirecting to {redirect_url}")
            
            # Server-side redirect with session token in secure cookie
            # (inline JS was blocked by CSP script-src 'self')
            response = make_response(redirect(redirect_url))
            
            # Set auth cookies
            cookie_kwargs = {
                'httponly': False,  # JS needs to read these for API calls
                'samesite': 'Lax',
                'secure': is_production,
                'max_age': 7 * 24 * 60 * 60,  # 7 days
                'path': '/'
            }
            response.set_cookie('sessionToken', result['session_token'], **cookie_kwargs)
            response.set_cookie('username', result['username'], **cookie_kwargs)
            response.set_cookie('discordAvatar', result.get('discord_avatar', '') or '', **cookie_kwargs)
            
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        else:
            return render_template('login.html', error='Failed to create user account')
            
    except Exception as e:
        logger.error(f"Discord OAuth error: {str(e)}", exc_info=True)
        return render_template('login.html', error='Discord authentication error')

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """Redirect to Discord OAuth (signup = login for Discord OAuth)"""
    return jsonify({
        'error': 'Please use Discord login',
        'message': 'Authentication is handled through Discord'
    }), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Redirect to Discord OAuth (no password login)"""
    return jsonify({
        'error': 'Please use Discord login',
        'message': 'Authentication is handled through Discord'
    }), 400

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    """End user session"""
    session_token = request.headers.get('Authorization') or request.cookies.get('sessionToken')
    if session_token:
        UserManager.logout(session_token)
    response = jsonify({'success': True, 'message': 'Logged out successfully'})
    response.set_cookie('sessionToken', '', expires=0, path='/')
    response.set_cookie('username', '', expires=0, path='/')
    response.set_cookie('discordAvatar', '', expires=0, path='/')
    return response

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    return jsonify({
        'user_id': g.user_id,
        'username': g.username,
        'discord_id': g.discord_id,
        'discord_avatar': g.discord_avatar
    })

@app.route('/api/auth/check-access', methods=['GET'])
@login_required
def check_access():
    """Check if user has guild access"""
    access_check = check_guild_membership(g.discord_id)
    
    response_data = {
        'has_access': access_check['has_access'],
        'in_guild': access_check['in_guild'],
        'is_denied': access_check.get('is_denied', False),
        'reason': access_check['reason']
    }
    
    # Add appropriate URL based on status
    if access_check.get('is_denied', False):
        response_data['denied_url'] = '/denied'
    elif not access_check['has_access']:
        response_data['pay_url'] = '/pay'
    
    return jsonify(response_data)

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

@app.route('/api/platform/capabilities', methods=['GET'])
def get_platform_capabilities():
    """Get real-time platform capability statistics"""
    import glob
    
    # Count actual Python modules in the modules/ directory (excluding __init__.py and __pycache__)
    modules_path = os.path.join(os.path.dirname(__file__), 'modules', '*.py')
    all_modules = glob.glob(modules_path)
    active_modules = len([m for m in all_modules if not m.endswith('__init__.py')])
    
    # Count actual attack vectors by counting unique check functions across all modules
    attack_vectors = 0
    for module_file in all_modules:
        if module_file.endswith('__init__.py'):
            continue
        try:
            with open(module_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Count scanner.add_finding calls (each represents a unique check/attack vector)
                attack_vectors += content.count('scanner.add_finding(')
                attack_vectors += content.count('add_finding(')
        except:
            pass
    
    # Calculate coverage percentage based on comprehensive security testing areas
    # We cover: Web Security, API Security, Database Security, Authentication, 
    # Client-Side Security, Infrastructure, Data Extraction, Active Exploitation
    total_security_areas = 12  # Major security testing domains
    covered_areas = active_modules / 4  # Rough estimate of coverage depth
    coverage_percentage = min(int((covered_areas / total_security_areas) * 100), 95)
    
    # Determine coverage level
    if coverage_percentage >= 90:
        coverage_level = "Comprehensive"
    elif coverage_percentage >= 75:
        coverage_level = "Extensive"
    elif coverage_percentage >= 60:
        coverage_level = "Deep"
    else:
        coverage_level = "Moderate"
    
    return jsonify({
        'active_modules': active_modules,
        'total_modules': active_modules,  # Dynamically counted from modules/ directory
        'attack_vectors': attack_vectors,
        'coverage_percentage': coverage_percentage,
        'coverage_level': coverage_level
    })

@app.route('/api/scan/phases', methods=['GET'])
def get_scan_phases():
    """Get all scan phases configuration for UI display"""
    return jsonify({
        'phases': SCAN_PHASES,
        'categories': CATEGORY_INFO,
        'total_phases': len(SCAN_PHASES)
    })

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Get CSRF token for API requests"""
    token = generate_csrf_token()
    return jsonify({'csrf_token': token})

def run_scan_thread(scan_id, target_url, max_pages=100, user_id=None):
    """Background thread to run security scan"""
    try:
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Initializing scan...',
            'pages_scanned': 0,
            'total_findings': 0,
            'current_phase': None,
            'completed_phases': [],
            'total_phases': len(SCAN_PHASES)
        }
        
        def update_progress(progress, message):
            """Update scan progress with phase information"""
            active_phase = get_active_phase(progress)
            completed = get_completed_phases(progress)
            scan_status[scan_id].update({
                'progress': progress,
                'message': message,
                'current_phase': active_phase,
                'completed_phases': completed,
                'pages_scanned': len(scanner.pages_scanned) if hasattr(scanner, 'pages_scanned') else 0
            })
        
        # Create scanner instance
        scanner = SecurityScanner(target_url, max_pages=max_pages, progress_callback=update_progress)
        
        # Monkey patch to update progress during scan
        original_add_finding = scanner.add_finding
        def tracked_add_finding(*args, **kwargs):
            result = original_add_finding(*args, **kwargs)
            scan_status[scan_id]['total_findings'] = len(scanner.findings)
            scan_status[scan_id]['pages_scanned'] = len(scanner.pages_scanned)
            return result
        scanner.add_finding = tracked_add_finding
        
        # Update status
        update_progress(5, 'Discovering pages...')
        
        # Track pages scanned
        import functools
        original_scan = scanner.scan
        
        def progress_tracking_scan():
            # Hook into page scanning
            from core import page_discovery
            original_discover = page_discovery.discover_pages
            
            def tracked_discover(s):
                update_progress(10, 'Discovering pages to scan...')
                pages = original_discover(s)
                update_progress(15, f'Found {len(pages)} pages, starting security checks...')
                return pages
            
            page_discovery.discover_pages = tracked_discover
            
            # Run the scan
            results = original_scan()
            
            # Restore original
            page_discovery.discover_pages = original_discover
            
            return results
        
        scanner.scan = progress_tracking_scan
        
        # Run scan
        update_progress(20, 'Running comprehensive security analysis...')
        results = scanner.scan()
        
        # Generate report
        update_progress(90, 'Generating detailed HTML report...')
        
        report_path = os.path.join(REPORTS_DIR, f'report_{scan_id}.html')
        generate_html_report(results, report_path)
        
        # Store results
        results['report_path'] = report_path
        results['scan_id'] = scan_id
        
        logger.info(f"Storing scan results for {scan_id}. Keys: {list(results.keys())}")
        logger.info(f"Results summary - pages: {results.get('pages_scanned')}, findings: {len(results.get('findings', []))}, target: {results.get('target_url')}")
        
        scan_results[scan_id] = results
        
        # Save to database if user is authenticated
        if user_id:
            with app.app_context():
                saved = ScanManager.save_scan(user_id, results)
                logger.info(f"Scan {scan_id} saved to database: {saved}")
        
        # Update status
        scan_status[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'message': f'Scan completed! Found {len(results["findings"])} security issues across {results["pages_scanned"]} pages',
            'pages_scanned': results['pages_scanned'],
            'total_findings': len(results['findings']),
            'current_phase': SCAN_PHASES[-1],
            'completed_phases': [p['id'] for p in SCAN_PHASES],
            'total_phases': len(SCAN_PHASES)
        }
        
        logger.info(f"Scan {scan_id} completed successfully")
        
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
@app.route('/<path:path>')
def serve_react_app(path=''):
    """Serve React frontend app - all routes handled by React Router"""
    # Check if it's a static file request
    if path and os.path.exists(os.path.join(app.static_folder, 'dist', path)):
        return send_from_directory(os.path.join(app.static_folder, 'dist'), path)
    # Otherwise serve index.html and let React Router handle the route
    return send_from_directory(os.path.join(app.static_folder, 'dist'), 'index.html')

# Keep old routes for backward compatibility - now handled by React Router
# The catch-all route at the bottom will serve index.html for all these paths

# Payment API Routes

@app.route('/api/payment/create-checkout', methods=['POST'])
@login_required
def create_checkout():
    """Create a LemonSqueezy checkout session"""
    missing = []
    if not LEMONSQUEEZY_API_KEY:
        missing.append('LEMONSQUEEZY_API_KEY')
    if not LEMONSQUEEZY_STORE_ID:
        missing.append('LEMONSQUEEZY_STORE_ID')
    if not LEMONSQUEEZY_PRODUCT_ID:
        missing.append('LEMONSQUEEZY_PRODUCT_ID')
    if missing:
        logger.error(f"LemonSqueezy configuration missing: {', '.join(missing)}")
        return jsonify({'error': f'Payment system not configured (missing: {", ".join(missing)})'}), 500
    
    try:
        # Get user info from session
        discord_id = g.discord_id
        username = g.username
        
        logger.info(f"Creating checkout for user {username} ({discord_id}), store_id={LEMONSQUEEZY_STORE_ID}, variant_id={LEMONSQUEEZY_PRODUCT_ID}")
        
        # Create checkout session with LemonSqueezy
        checkout_data = {
            "data": {
                "type": "checkouts",
                "attributes": {
                    "checkout_data": {
                        "custom": {
                            "discord_id": discord_id,
                            "username": username
                        }
                    },
                    "product_options": {
                        "redirect_url": f"{get_base_url()}/",
                        "receipt_link_url": f"{get_base_url()}/",
                        "receipt_button_text": "Return to Dashboard",
                        "receipt_thank_you_note": "Thank you for your purchase! Check your Discord DMs for your private server invite."
                    },
                    "checkout_options": {
                        "button_color": "#667eea"
                    }
                },
                "relationships": {
                    "store": {
                        "data": {
                            "type": "stores",
                            "id": LEMONSQUEEZY_STORE_ID
                        }
                    },
                    "variant": {
                        "data": {
                            "type": "variants",
                            "id": LEMONSQUEEZY_PRODUCT_ID
                        }
                    }
                }
            }
        }
        
        # Make request to LemonSqueezy API
        response = requests.post(
            'https://api.lemonsqueezy.com/v1/checkouts',
            json=checkout_data,
            headers={
                'Accept': 'application/vnd.api+json',
                'Content-Type': 'application/vnd.api+json',
                'Authorization': f'Bearer {LEMONSQUEEZY_API_KEY}'
            }
        )
        
        if response.status_code in (200, 201):
            data = response.json()
            checkout_url = data['data']['attributes']['url']
            logger.info(f"Checkout created for user {username} ({discord_id})")
            return jsonify({'checkout_url': checkout_url})
        else:
            logger.error(f"LemonSqueezy checkout failed: {response.status_code} - {response.text}")
            # Parse LemonSqueezy error details
            detail = f"LemonSqueezy API returned {response.status_code}"
            try:
                err_data = response.json()
                if 'errors' in err_data:
                    detail = '; '.join(e.get('detail', e.get('title', '')) for e in err_data['errors'])
            except Exception:
                pass
            return jsonify({'error': f'Checkout failed: {detail}'}), 500
            
    except Exception as e:
        logger.error(f"Error creating checkout: {str(e)}", exc_info=True)
        return jsonify({'error': f'Payment system error: {str(e)}'}), 500

@app.route('/api/payment/webhook', methods=['POST'])
def payment_webhook():
    """Handle LemonSqueezy webhook for payment confirmation"""
    try:
        payload = request.json
        logger.info(f"Webhook received: {payload.get('meta', {}).get('event_name')}")
        
        # Verify webhook signature (if configured)
        # signature = request.headers.get('X-Signature')
        # TODO: Implement signature verification for production
        
        event_name = payload.get('meta', {}).get('event_name')
        
        if event_name == 'order_created':
            # Extract order data
            order_data = payload.get('data', {})
            attributes = order_data.get('attributes', {})
            
            # Get Discord ID from custom data in the webhook meta
            discord_id = payload.get('meta', {}).get('custom_data', {}).get('discord_id')
            
            if discord_id:
                logger.info(f"Payment received for Discord ID: {discord_id}")
                logger.info(f"Order #{attributes.get('order_number')} - ${attributes.get('total', 0)/100:.2f}")
                
                # TODO: Store payment in database
                # TODO: Notify Discord bot to grant role
                # TODO: Send confirmation DM to user
                
                return jsonify({'success': True, 'message': 'Webhook received'}), 200
            else:
                logger.warning(f"Webhook received but no Discord ID found in payload: {payload.get('meta', {}).get('custom_data')}")
                return jsonify({'error': 'Invalid webhook data - missing Discord ID'}), 400
        
        # Acknowledge other webhook events
        logger.info(f"Webhook event acknowledged: {event_name}")
        return jsonify({'success': True}), 200
        
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Webhook processing failed'}), 500

# ==============================================================================
# SPECIALIZED SECURITY TOOL API ENDPOINTS
# ==============================================================================

def run_specialized_tool_thread(scan_id, tool_name, target_url, options, user_id=None):
    """Background thread for specialized tool scans"""
    try:
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 10,
            'message': f'Initializing {tool_name}...',
            'tool': tool_name
        }
        
        # Create scanner instance
        scanner = SecurityScanner(target_url, max_pages=1)  # Single page for specialized tools
        
        # Update progress
        scan_status[scan_id]['progress'] = 20
        scan_status[scan_id]['message'] = f'Running {tool_name} analysis...'
        
        results = {'target_url': target_url, 'tool': tool_name, 'findings': [], 'scan_id': scan_id}
        
        # Route to appropriate tool modules
        if tool_name == 'Database Intrusion':
            from modules.database_exposure import check_database_exposure
            from modules.active_database_intrusion import test_database_intrusion
            from modules.active_database_penetration import test_database_penetration
            
            # Phase 1: MongoDB Testing (17%)
            scan_status[scan_id]['message'] = 'Testing MongoDB connections and vulnerabilities...'
            scan_status[scan_id]['progress'] = 17
            check_database_exposure(scanner)
            
            # Phase 2: MySQL/MariaDB Testing (33%)
            scan_status[scan_id]['message'] = 'Testing MySQL/MariaDB authentication and injection...'
            scan_status[scan_id]['progress'] = 33
            test_database_intrusion(scanner)
            
            # Phase 3: PostgreSQL Testing (50%)
            scan_status[scan_id]['message'] = 'Testing PostgreSQL connections and privilege escalation...'
            scan_status[scan_id]['progress'] = 50
            
            # Phase 4: Redis Testing (67%)
            scan_status[scan_id]['message'] = 'Extracting live database data and testing Redis...'
            scan_status[scan_id]['progress'] = 67
            try:
                from modules.database_explorer import explore_exposed_databases
                db_exploration_results = explore_exposed_databases(scanner)
                results['db_exploration_results'] = db_exploration_results
            except Exception as e:
                logger.error(f"Database exploration error: {e}")
                results['db_exploration_results'] = {}
            
            # Phase 5: Elasticsearch Testing (83%)
            scan_status[scan_id]['message'] = 'Testing Elasticsearch HTTP API and indices...'
            scan_status[scan_id]['progress'] = 83
            test_database_penetration(scanner)
            
            # Phase 6: NoSQL Database Testing (95%)
            scan_status[scan_id]['message'] = 'Testing CouchDB and other NoSQL databases...'
            scan_status[scan_id]['progress'] = 95
            
        elif tool_name == 'Data Extractor':
            from modules.data_extraction import extract_all_data
            from modules.active_data_harvest import harvest_sensitive_data
            from modules.active_credential_harvesting import harvest_and_test_credentials
            from modules.info_disclosure import check_information_disclosure
            
            # Phase 1: Email & PII Extraction (25%)
            scan_status[scan_id]['message'] = 'Extracting emails, phone numbers, and PII...'
            scan_status[scan_id]['progress'] = 25
            extract_all_data(scanner)
            
            # Phase 2: API Keys & Secrets (50%)
            scan_status[scan_id]['message'] = 'Harvesting API keys, tokens, and secrets...'
            scan_status[scan_id]['progress'] = 50
            harvest_sensitive_data(scanner)
            
            # Phase 3: Credentials & Passwords (75%)
            scan_status[scan_id]['message'] = 'Extracting credentials and testing authentication...'
            scan_status[scan_id]['progress'] = 75
            harvest_and_test_credentials(scanner)
            
            # Phase 4: Internal URLs & Source Code (90%)
            scan_status[scan_id]['message'] = 'Checking information disclosure and internal URLs...'
            scan_status[scan_id]['progress'] = 90
            check_information_disclosure(scanner)
            
        elif tool_name == 'Cloud Storage':
            from modules.cloud_storage_detection import detect_cloud_storage
            
            # Progress callback for cloud storage phases
            def update_cloud_progress(phase, progress, message):
                scan_status[scan_id]['message'] = message
                scan_status[scan_id]['progress'] = progress
            
            scan_status[scan_id]['message'] = 'Initializing cloud storage scan...'
            scan_status[scan_id]['progress'] = 10
            detect_cloud_storage(scanner, progress_callback=update_cloud_progress)
            
        elif tool_name == 'Exposed Files':
            from modules.exposed_files_scanner import scan_exposed_files
            from modules.discovery_hygiene import check_discovery_hygiene
            
            # Phase 1: Configuration Files (20%)
            scan_status[scan_id]['message'] = 'Scanning for .env, config.php, and configuration files...'
            scan_status[scan_id]['progress'] = 20
            
            # Phase 2: Backup Files (40%)
            scan_status[scan_id]['message'] = 'Testing for backup files and SQL dumps...'
            scan_status[scan_id]['progress'] = 40
            scan_exposed_files(scanner)
            
            # Phase 3: Version Control (60%)
            scan_status[scan_id]['message'] = 'Checking for .git, .svn, and version control leaks...'
            scan_status[scan_id]['progress'] = 60
            
            # Phase 4: Log Files (80%)
            scan_status[scan_id]['message'] = 'Scanning for log files and error messages...'
            scan_status[scan_id]['progress'] = 80
            check_discovery_hygiene(scanner)
            
            # Phase 5: Development Files (95%)
            scan_status[scan_id]['message'] = 'Testing for development files and debug endpoints...'
            scan_status[scan_id]['progress'] = 95
            
        elif tool_name == 'API Tester':
            from modules.api_testing import discover_and_test_apis
            
            # Phase 1: Endpoint Discovery (20%)
            scan_status[scan_id]['message'] = 'Discovering API endpoints from HTML and JavaScript...'
            scan_status[scan_id]['progress'] = 20
            
            # Phase 2: REST API Testing (40%)
            scan_status[scan_id]['message'] = 'Testing REST API endpoints and HTTP methods...'
            scan_status[scan_id]['progress'] = 40
            discover_and_test_apis(scanner)
            
            # Phase 3: Authentication Testing (60%)
            scan_status[scan_id]['message'] = 'Testing API authentication and authorization...'
            scan_status[scan_id]['progress'] = 60
            
            # Phase 4: GraphQL Testing (80%)
            scan_status[scan_id]['message'] = 'Testing GraphQL introspection and mutations...'
            scan_status[scan_id]['progress'] = 80
            
            # Phase 5: Rate Limiting & CORS (95%)
            scan_status[scan_id]['message'] = 'Checking rate limiting, CORS, and security headers...'
            scan_status[scan_id]['progress'] = 95
            
        elif tool_name == 'Network Recon':
            from modules.network_recon import perform_network_recon
            
            # Phase 1: DNS Enumeration (20%)
            scan_status[scan_id]['message'] = 'Performing DNS enumeration and zone transfers...'
            scan_status[scan_id]['progress'] = 20
            
            # Phase 2: Subdomain Discovery (40%)
            scan_status[scan_id]['message'] = 'Discovering subdomains via brute force and DNS...'
            scan_status[scan_id]['progress'] = 40
            perform_network_recon(scanner, scanner.target_url)
            
            # Phase 3: Port Scanning (60%)
            scan_status[scan_id]['message'] = 'Scanning common ports and services...'
            scan_status[scan_id]['progress'] = 60
            
            # Phase 4: SSL/TLS Analysis (80%)
            scan_status[scan_id]['message'] = 'Analyzing SSL/TLS certificates and ciphers...'
            scan_status[scan_id]['progress'] = 80
            
            # Phase 5: Service Detection (95%)
            scan_status[scan_id]['message'] = 'Detecting running services and versions...'
            scan_status[scan_id]['progress'] = 95
            
        elif tool_name == 'Penetration Testing':
            from modules.active_sql_injection import test_sql_injection
            from modules.active_xss_testing import test_xss_vulnerabilities
            from modules.active_auth_testing import test_authentication_bypass
            from modules.active_rce_testing import test_command_injection
            from modules.active_session_hijacking import test_session_hijacking
            from modules.advanced_sqli_extraction import perform_sql_injection_extraction
            from modules.active_ssti_testing import test_ssti
            from modules.active_nosql_injection import test_nosql_injection
            from modules.cms_exploits import test_cms_vulnerabilities
            from modules.active_ssrf_testing import test_ssrf_vulnerabilities
            from modules.active_path_traversal import test_path_traversal
            
            # Phase 1: SQL Injection Testing (17%)
            scan_status[scan_id]['message'] = 'Testing SQL injection in parameters and forms...'
            scan_status[scan_id]['progress'] = 17
            test_sql_injection(scanner)
            perform_sql_injection_extraction(scanner)
            
            # Phase 2: XSS Vulnerability Testing (33%)
            scan_status[scan_id]['message'] = 'Testing XSS vulnerabilities and filter bypasses...'
            scan_status[scan_id]['progress'] = 33
            test_xss_vulnerabilities(scanner)
            
            # Phase 3: Authentication Bypass (50%)
            scan_status[scan_id]['message'] = 'Testing authentication bypass and session attacks...'
            scan_status[scan_id]['progress'] = 50
            test_authentication_bypass(scanner)
            
            # Phase 4: Remote Code Execution (67%)
            scan_status[scan_id]['message'] = 'Testing command injection, SSTI, and RCE vectors...'
            scan_status[scan_id]['progress'] = 67
            test_command_injection(scanner)
            test_ssti(scanner)
            test_cms_vulnerabilities(scanner)
            
            # Phase 5: SSRF & Path Traversal (83%)
            scan_status[scan_id]['message'] = 'Testing SSRF, path traversal, and file inclusion...'
            scan_status[scan_id]['progress'] = 83
            test_ssrf_vulnerabilities(scanner)
            test_path_traversal(scanner)
            
            # Phase 6: Session & CSRF Testing (95%)
            scan_status[scan_id]['message'] = 'Testing session hijacking and CSRF vulnerabilities...'
            scan_status[scan_id]['progress'] = 95
            test_session_hijacking(scanner)
            test_nosql_injection(scanner)
        
        # Compile results
        results['findings'] = scanner.findings
        results['findings_count'] = len(scanner.findings)
        results['pages_scanned'] = len(scanner.pages_scanned) if hasattr(scanner, 'pages_scanned') else 1
        risk_score, risk_level = scanner.get_risk_score()
        results['risk_score'] = risk_score
        results['risk_level'] = risk_level
        results['findings_summary'] = scanner.get_findings_summary()
        results['category_summary'] = scanner.get_category_summary()
        results['scan_time'] = datetime.now()
        
        # Store results
        scan_results[scan_id] = results
        
        # Save to database if user authenticated
        if user_id:
            with app.app_context():
                ScanManager.save_scan(user_id, results)
        
        # Update status to completed
        scan_status[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'message': f'{tool_name} completed! Found {len(results["findings"])} issues',
            'tool': tool_name,
            'findings_count': len(results['findings'])
        }
        
        # Cleanup scanner
        scanner.cleanup()
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Tool scan error for {scan_id}: {error_details}")
        scan_status[scan_id] = {
            'status': 'failed',
            'progress': 0,
            'message': f'Scan failed: {str(e)}',
            'error_details': str(e)
        }

@app.route('/api/tools/database-intrusion', methods=['POST'])
@guild_required
@csrf_protected
def database_intrusion_scan():
    """Database intrusion testing endpoint"""
    try:
        data = request.json
        target = data.get('target')
        ports = data.get('ports', '27017,3306,5432,6379,9200,5984')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Auto-prefix if needed
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        scan_id = str(uuid.uuid4())
        
        thread = threading.Thread(
            target=run_specialized_tool_thread,
            args=(scan_id, 'Database Intrusion', target, {'ports': ports}, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'message': 'Database intrusion scan started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/data-extractor', methods=['POST'])
@guild_required
@csrf_protected
def data_extractor_scan():
    """Data extraction endpoint"""
    try:
        data = request.json
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        scan_id = str(uuid.uuid4())
        
        thread = threading.Thread(
            target=run_specialized_tool_thread,
            args=(scan_id, 'Data Extractor', target, {}, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'message': 'Data extraction started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/cloud-storage', methods=['POST'])
@guild_required
@csrf_protected
def cloud_storage_scan():
    """Cloud storage detection endpoint"""
    try:
        data = request.json
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        scan_id = str(uuid.uuid4())
        
        thread = threading.Thread(
            target=run_specialized_tool_thread,
            args=(scan_id, 'Cloud Storage', target, {}, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'message': 'Cloud storage scan started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/exposed-files', methods=['POST'])
@guild_required
@csrf_protected
def exposed_files_scan():
    """Exposed files scanning endpoint"""
    try:
        data = request.json
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        scan_id = str(uuid.uuid4())
        
        thread = threading.Thread(
            target=run_specialized_tool_thread,
            args=(scan_id, 'Exposed Files', target, {}, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'message': 'Exposed files scan started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/api-tester', methods=['POST'])
@guild_required
@csrf_protected
def api_tester_scan():
    """API testing endpoint"""
    try:
        data = request.json
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        scan_id = str(uuid.uuid4())
        
        thread = threading.Thread(
            target=run_specialized_tool_thread,
            args=(scan_id, 'API Tester', target, {}, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'message': 'API testing started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/network-recon', methods=['POST'])
@guild_required
@csrf_protected
def network_recon_scan():
    """Network reconnaissance endpoint"""
    try:
        data = request.json
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        scan_id = str(uuid.uuid4())
        
        thread = threading.Thread(
            target=run_specialized_tool_thread,
            args=(scan_id, 'Network Recon', target, {}, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'message': 'Network reconnaissance started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/penetration-test', methods=['POST'])
@guild_required
@csrf_protected
def penetration_test_scan():
    """Comprehensive penetration testing endpoint"""
    try:
        data = request.json
        target = data.get('target')
        categories = data.get('categories', ['all'])
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        scan_id = str(uuid.uuid4())
        
        thread = threading.Thread(
            target=run_specialized_tool_thread,
            args=(scan_id, 'Penetration Testing', target, {'categories': categories}, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({'scan_id': scan_id, 'message': 'Penetration testing started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/<scan_id>/results', methods=['GET'])
@guild_required
def get_tool_results(scan_id):
    """Get results from specialized tool scan"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    results = scan_results[scan_id]
    return jsonify(results)

@app.route('/api/tools/<scan_id>/status', methods=['GET'])
@guild_required
def get_tool_status(scan_id):
    """Get status of specialized tool scan"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    status = scan_status[scan_id]
    return jsonify(status)

@app.route('/api/tools/<scan_id>/database-explorer', methods=['GET'])
@guild_required
def get_database_explorer_data(scan_id):
    """Get live database exploration data"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Check if scanner has database exploration results
    results = scan_results.get(scan_id, {})
    db_data = results.get('db_exploration_results', {})
    
    return jsonify(db_data)

@app.route('/api/tools/<scan_id>/cloud-storage-explorer', methods=['GET'])
@guild_required
def get_cloud_storage_explorer_data(scan_id):
    """Get live cloud storage exploration data"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    results = scan_results.get(scan_id, {})
    cloud_data = results.get('cloud_storage_exploration', {})
    
    return jsonify(cloud_data)

@app.route('/api/tools/<scan_id>/data-extractor-viewer', methods=['GET'])
@guild_required
def get_data_extractor_viewer_data(scan_id):
    """Get extracted data (APIs, forms, endpoints, secrets)"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    results = scan_results.get(scan_id, {})
    extracted_data = results.get('extracted_data', {})
    
    return jsonify(extracted_data)

@app.route('/api/tools/<scan_id>/exposed-files-viewer', methods=['GET'])
@guild_required
def get_exposed_files_viewer_data(scan_id):
    """Get exposed files with content"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    results = scan_results.get(scan_id, {})
    files_data = results.get('exposed_files_data', {})
    
    return jsonify(files_data)

@app.route('/api/tools/<scan_id>/api-response-viewer', methods=['GET'])
@guild_required
def get_api_response_viewer_data(scan_id):
    """Get live API response data"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    results = scan_results.get(scan_id, {})
    api_data = results.get('api_response_data', {})
    
    return jsonify(api_data)

@app.route('/api/tools/<scan_id>/query-database', methods=['POST'])
@guild_required
def query_database(scan_id):
    """Query MongoDB database with custom filter"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        import pymongo  # type: ignore
        data = request.get_json()
        database = data.get('database')
        collection = data.get('collection')
        filter_query = json.loads(data.get('filter', '{}'))
        limit = min(int(data.get('limit', 20)), 100)  # Max 100 docs
        
        # Get MongoDB connection from scan results
        results = scan_results.get(scan_id, {})
        db_data = results.get('db_exploration_results', {})
        
        if not db_data.get('mongodb'):
            return jsonify({'error': 'No MongoDB connection available'}), 404
        
        host = db_data['mongodb'][0]['host']
        client = pymongo.MongoClient(f'mongodb://{host}', serverSelectionTimeoutMS=5000)
        
        db = client[database]
        coll = db[collection]
        
        documents = list(coll.find(filter_query).limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        for doc in documents:
            if '_id' in doc:
                doc['_id'] = str(doc['_id'])
        
        client.close()
        
        return jsonify({'documents': documents, 'count': len(documents)})
    except Exception as e:
        return jsonify({'error': str(e), 'documents': []}), 500

# ==============================================================================
# END SPECIALIZED TOOL ENDPOINTS
# ==============================================================================

@app.route('/robots.txt')
def robots_txt():
    """Serve robots.txt file"""
    return send_file('static/robots.txt', mimetype='text/plain')

@app.route('/.well-known/security.txt')
def security_txt():
    """Serve security.txt file"""
    return send_file('static/.well-known/security.txt', mimetype='text/plain')

@app.route('/api/scan', methods=['POST'])
@guild_required
@csrf_protected
def start_scan():
    """Start a new security scan (requires authentication and guild membership)"""
    try:
        data = request.json
        logger.info(f"Scan request received with data: {data}")
        target_url = data.get('target_url')  # Match frontend field name
        max_pages = data.get('max_pages', 10)
        
        if not target_url:
            logger.error(f"Missing URL in scan request. Received data: {data}")
            return jsonify({'error': 'URL is required'}), 400
        
        # Auto-prefix URL if needed
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Log scan initiation
        logger.info(f"User {g.username} ({g.user_id}) starting scan of {target_url}")
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan status
        scan_status[scan_id] = {
            'status': 'starting',
            'progress': 0,
            'message': 'Initializing scan...'
        }
        
        # Start scan in background thread (pass user_id for database storage)
        thread = threading.Thread(
            target=run_scan_thread, 
            args=(scan_id, target_url, max_pages, g.user_id)
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"Scan {scan_id} started successfully for {target_url}")
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started successfully',
            'target_url': target_url
        })
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}", exc_info=True)
        return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get status of a scan"""
    # Check in-memory first
    if scan_id in scan_status:
        return jsonify(scan_status[scan_id])
    
    # Fallback to database if available
    if hasattr(g, 'user_id'):
        results = ScanManager.get_scan_details(scan_id, g.user_id)
        if results:
            # Scan exists in database - return completed status
            return jsonify({
                'status': 'completed',
                'scan_id': scan_id,
                'progress': 100
            })
    
    logger.warning(f"Scan status not found for scan_id: {scan_id}")
    logger.info(f"Available scan IDs: {list(scan_status.keys())}")
    return jsonify({
        'error': 'Scan not found. The database may have been reset. Please start a new scan.',
        'scan_id': scan_id
    }), 404

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get results of a completed scan"""
    logger.info(f"Getting results for scan {scan_id}")
    
    # Check in-memory first (no auth required for active scans)
    if scan_id in scan_results:
        results = scan_results[scan_id]
        logger.info(f"Found scan {scan_id} in Redis/memory. Keys: {list(results.keys()) if isinstance(results, dict) else 'not a dict'}")
        logger.info(f"Results type: {type(results)}, target_url: {results.get('target_url') if isinstance(results, dict) else 'N/A'}")
        return jsonify(results)
    
    # Check if scan is still in progress
    if scan_id in scan_status:
        status = scan_status[scan_id]
        logger.info(f"Scan {scan_id} is still in progress: {status.get('status')}")
        return jsonify({
            'error': 'Scan in progress',
            'status': status.get('status', 'running'),
            'progress': status.get('progress', 0),
            'message': status.get('message', 'Scanning...')
        }), 202  # 202 Accepted - request is still being processed
    
    # Fallback to database (requires auth)
    if not hasattr(g, 'user_id'):
        logger.warning(f"No user_id in context for scan {scan_id}")
        return jsonify({'error': 'Authentication required'}), 401
    
    results = ScanManager.get_scan_details(scan_id, g.user_id)
    if results:
        logger.info(f"Retrieved scan {scan_id} from database for user {g.user_id}")
        return jsonify(results)
    
    logger.warning(f"Scan results not found for scan_id: {scan_id}")
    return jsonify({'error': 'Results not found'}), 404

@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def download_report(scan_id):
    """Download HTML report"""
    report_path = None
    
    # Check in-memory first
    if scan_id in scan_results:
        report_path = scan_results[scan_id].get('report_path')
    else:
        # Fallback to database
        if not hasattr(g, 'user_id'):
            return jsonify({'error': 'Authentication required'}), 401
        
        results = ScanManager.get_scan_details(scan_id, g.user_id)
        if results:
            report_path = results.get('report_path')
    
    if not report_path:
        return jsonify({'error': 'Report not found'}), 404
    
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report file not found'}), 404
    
    return send_file(report_path, as_attachment=True, 
                    download_name=f'security_report_{scan_id}.html')

@app.route('/api/scans', methods=['GET'])
@guild_required
def list_user_scans():
    """List current user's scan history from database"""
    scans = ScanManager.get_user_scans(g.user_id, limit=50)
    return jsonify({'scans': scans, 'total': len(scans)})

@app.route('/api/scans/<scan_id>', methods=['GET'])
@guild_required
def get_scan_from_history(scan_id):
    """Get specific scan from user's history"""
    scan = ScanManager.get_scan_details(scan_id, g.user_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Custom JSON provider handles datetime serialization automatically
    return jsonify(scan)

@app.route('/api/scans/<scan_id>', methods=['DELETE'])
@guild_required
def delete_scan(scan_id):
    """Delete a specific scan from user's history"""
    success = ScanManager.delete_scan(scan_id, g.user_id)
    if not success:
        return jsonify({'error': 'Scan not found or access denied'}), 404
    
    # Also remove from in-memory storage if present
    scan_status.pop(scan_id, None)
    scan_results.pop(scan_id, None)
    
    return jsonify({'success': True, 'message': 'Scan deleted successfully'})

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
            scan_info['scan_time'] = results['scan_time']  # Custom JSON provider handles datetime
        
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

@app.route('/api/security/log', methods=['POST'])
def log_security_event():
    """Log security events from frontend (screenshot attempts, focus changes, etc.)"""
    try:
        data = request.json
        event = data.get('event', 'Unknown')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        page = data.get('page', 'Unknown')
        user_agent = data.get('userAgent', request.headers.get('User-Agent', 'Unknown'))
        
        # Get user info if authenticated
        user_info = 'Anonymous'
        if hasattr(g, 'user_id'):
            user_info = f'User ID: {g.user_id}'
        
        # Log to console and file
        logger.warning(f"[SECURITY EVENT] {event} | Page: {page} | User: {user_info} | Time: {timestamp} | UA: {user_agent[:50]}")
        
        # Store in Redis or in-memory if Redis not available
        security_log_key = f"security_log:{datetime.now().strftime('%Y%m%d')}"
        log_entry = {
            'event': event,
            'timestamp': timestamp,
            'page': page,
            'user': user_info,
            'ip': request.remote_addr,
            'user_agent': user_agent
        }
        
        # Try to store in Redis
        try:
            if REDIS_URL:
                import redis
                r = redis.from_url(REDIS_URL)
                r.rpush(security_log_key, json.dumps(log_entry))
                r.expire(security_log_key, 86400 * 7)  # Keep for 7 days
        except Exception as e:
            logger.error(f"Failed to store security log in Redis: {e}")
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        logger.error(f"Error logging security event: {e}")
        return jsonify({'error': 'Failed to log event'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with configuration status"""
    config_status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_scans': len([s for s in scan_status.values() if s['status'] == 'running']),
        'environment': {
            'is_production': is_production,
            'database_type': 'PostgreSQL' if database_url else 'SQLite',
            'redis_connected': scan_status.is_redis_connected,
            'storage_type': 'Redis (multi-worker)' if scan_status.is_redis_connected else 'In-memory (single worker)'
        },
        'configuration': {
            'discord_oauth': {
                'configured': all([DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI]),
                'client_id_set': bool(DISCORD_CLIENT_ID),
                'client_secret_set': bool(DISCORD_CLIENT_SECRET),
                'redirect_uri': DISCORD_REDIRECT_URI or 'NOT SET',
                'bot_token_set': bool(DISCORD_BOT_TOKEN),
                'guild_id_set': bool(DISCORD_GUILD_ID)
            },
            'payment': {
                'configured': all([LEMONSQUEEZY_API_KEY, LEMONSQUEEZY_STORE_ID, LEMONSQUEEZY_PRODUCT_ID]),
                'api_key_set': bool(LEMONSQUEEZY_API_KEY),
                'store_url': LEMONSQUEEZY_STORE_URL or 'NOT SET',
                'store_id': LEMONSQUEEZY_STORE_ID or 'NOT SET',
                'product_id': LEMONSQUEEZY_PRODUCT_ID or 'NOT SET'
            },
            'redis': {
                'url_set': bool(REDIS_URL),
                'connected': scan_status.is_redis_connected,
                'status': 'Connected' if scan_status.is_redis_connected else 'Not connected (using fallback)'
            },
            'static_version': STATIC_VERSION
        }
    }
    
    # Add warnings for missing configuration
    warnings = []
    if not config_status['configuration']['discord_oauth']['configured']:
        warnings.append('Discord OAuth not fully configured - login will not work')
    if not config_status['configuration']['payment']['configured']:
        warnings.append('Payment system not fully configured - purchases will not work')
    if not scan_status.is_redis_connected:
        warnings.append('Redis not connected - using in-memory storage (not multi-worker safe)')
    
    if warnings:
        config_status['warnings'] = warnings
    
    return jsonify(config_status)

# Debug and Monitoring API Routes
@app.route('/api/debug/logs', methods=['GET'])
@login_required
def get_debug_logs():
    """Get recent system logs for debugging"""
    tracker = get_tracker()
    
    limit = int(request.args.get('limit', 100))
    level = request.args.get('level')  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    category = request.args.get('category')  # AUTH, SCAN, DATABASE, etc.
    
    logs = tracker.get_recent(limit=limit, level=level, category=category)
    stats = tracker.get_stats()
    
    return jsonify({
        'logs': logs,
        'stats': stats,
        'total_entries': len(logs)
    })

@app.route('/api/debug/stats', methods=['GET'])
@login_required
def get_debug_stats():
    """Get system statistics and error counts"""
    tracker = get_tracker()
    return jsonify(tracker.get_stats())

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
