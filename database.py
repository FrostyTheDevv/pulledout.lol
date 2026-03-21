"""
Database module for SawSap Security Scanner
Handles user accounts, authentication, and scan history
SQLAlchemy ORM - supports both SQLite (dev) and PostgreSQL (Railway production)
"""

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db = SQLAlchemy()

DATABASE_FILE = 'sawsap.db'


# SQLAlchemy Models

class User(db.Model):
    """User account model - Discord OAuth only"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(100), unique=True, nullable=False, index=True)  # Discord user ID
    discord_username = db.Column(db.String(100), nullable=False)  # Discord username
    discord_avatar = db.Column(db.String(255))  # Discord avatar URL
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationships
    sessions = db.relationship('Session', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, discord_id: str, discord_username: str, discord_avatar: str = None, **kwargs):
        """Initialize User model with Discord data"""
        super(User, self).__init__(
            discord_id=discord_id,
            discord_username=discord_username,
            discord_avatar=discord_avatar,
            **kwargs
        )


class Session(db.Model):
    """User session model"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def __init__(self, user_id: int, session_token: str, expires_at: datetime, **kwargs):
        """Initialize Session model"""
        super(Session, self).__init__(  # type: ignore
            user_id=user_id,
            session_token=session_token,
            expires_at=expires_at,
            **kwargs
        )


class Scan(db.Model):
    """Scan history model"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    pages_scanned = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20))
    findings_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    scan_results = db.Column(db.Text)  # JSON string
    
    def __init__(self, user_id: int, scan_id: str, target_url: str, 
                 pages_scanned: int = 0, risk_score: int = 0, risk_level: Optional[str] = None,
                 findings_count: int = 0, high_count: int = 0, medium_count: int = 0,
                 low_count: int = 0, info_count: int = 0, scan_results: Optional[str] = None, **kwargs):
        """Initialize Scan model"""
        super(Scan, self).__init__(  # type: ignore
            user_id=user_id,
            scan_id=scan_id,
            target_url=target_url,
            pages_scanned=pages_scanned,
            risk_score=risk_score,
            risk_level=risk_level,
            findings_count=findings_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            scan_results=scan_results,
            **kwargs
        )


def init_database(app):
    """Initialize database with Flask app context"""
    db.init_app(app)
    
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database initialized successfully")
            logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}...")
            
            # Log user count for debugging
            user_count = User.query.count()
            logger.info(f"Users in database: {user_count}")
            
            print("[OK] Database initialized successfully")
        except Exception as e:
            # Tables may already exist from previous deployments
            error_msg = str(e)
            if "already exists" in error_msg or "duplicate key" in error_msg:
                logger.info("Using existing database schema")
                print("[OK] Using existing database schema")
            else:
                print(f"[!] Database initialization warning: {e}")
                print("[OK] Continuing with existing schema")


class UserManager:
    """Handles user account operations - Discord OAuth"""
    
    @staticmethod
    def create_or_update_discord_user(discord_id: str, discord_username: str, discord_avatar: str = None) -> Dict:
        """Create new user or update existing user from Discord OAuth"""
        logger.info(f"Discord OAuth - Processing user: {discord_username} (ID: {discord_id})")
        
        try:
            # Check if user exists
            user = User.query.filter_by(discord_id=discord_id).first()
            
            if user:
                # Update existing user info
                user.discord_username = discord_username
                user.discord_avatar = discord_avatar
                user.last_login = datetime.utcnow()
                logger.info(f"Updated existing Discord user: {discord_username}")
            else:
                # Create new user
                user = User(
                    discord_id=discord_id,
                    discord_username=discord_username,
                    discord_avatar=discord_avatar
                )
                user.last_login = datetime.utcnow()
                db.session.add(user)
                logger.info(f"Created new Discord user: {discord_username}")
            
            db.session.commit()
            
            # Create session token
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(days=7)
            
            # Store session
            session = Session(
                user_id=user.id,
                session_token=session_token,
                expires_at=expires_at
            )
            db.session.add(session)
            db.session.commit()
            
            logger.info(f"Discord auth successful for user: {discord_username}")
            return {
                'success': True,
                'user_id': user.id,
                'username': discord_username,
                'discord_id': discord_id,
                'discord_avatar': discord_avatar,
                'session_token': session_token,
                'expires_at': expires_at.isoformat()
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Discord user creation/update error: {str(e)}", exc_info=True)
            return {'success': False, 'error': f'Database error: {str(e)}'}
    
    @staticmethod
    def verify_session(session_token: str) -> Optional[Dict]:
        """Verify session token and return user info"""
        try:
            # Get session with user
            session = Session.query.filter_by(session_token=session_token).first()
            
            if not session:
                return None
            
            # Check expiration
            if session.expires_at < datetime.utcnow():
                db.session.delete(session)
                db.session.commit()
                return None
            
            # Check if user is active
            if not session.user.is_active:
                return None
            
            return {
                'user_id': session.user.id,
                'username': session.user.discord_username,
                'discord_id': session.user.discord_id,
                'discord_avatar': session.user.discord_avatar
            }
            
        except Exception as e:
            print(f"Session verification error: {e}")
            return None
    
    @staticmethod
    def logout(session_token: str) -> bool:
        """Delete session (logout)"""
        try:
            session = Session.query.filter_by(session_token=session_token).first()
            if session:
                db.session.delete(session)
                db.session.commit()
            return True
        except:
            db.session.rollback()
            return False
    
    @staticmethod
    def delete_account(user_id: int) -> bool:
        """Delete user account and all associated data"""
        try:
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)  # Cascade deletes sessions and scans
                db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Delete account error: {e}")
            return False


class ScanManager:
    """Handles scan history and results storage"""
    
    @staticmethod
    def save_scan(user_id: int, scan_data: Dict) -> bool:
        """Save scan results to database"""
        try:
            # Extract summary data
            findings_summary = scan_data.get('findings_summary', {})
            
            scan = Scan(
                user_id=user_id,
                scan_id=str(scan_data.get('scan_id', '')),
                target_url=str(scan_data.get('target_url', '')),
                pages_scanned=scan_data.get('pages_scanned', 0),
                risk_score=scan_data.get('risk_score', 0),
                risk_level=scan_data.get('risk_level', 'Unknown'),
                findings_count=len(scan_data.get('findings', [])),
                high_count=findings_summary.get('HIGH', 0),
                medium_count=findings_summary.get('MEDIUM', 0),
                low_count=findings_summary.get('LOW', 0),
                info_count=findings_summary.get('INFO', 0),
                scan_results=json.dumps(scan_data)
            )
            
            db.session.add(scan)
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"Save scan error: {e}")
            return False
    
    @staticmethod
    def get_user_scans(user_id: int, limit: int = 50) -> List[Dict]:
        """Get user's scan history"""
        try:
            scans = Scan.query.filter_by(user_id=user_id)\
                .order_by(Scan.scan_date.desc())\
                .limit(limit)\
                .all()
            
            return [{
                'scan_id': scan.scan_id,
                'target_url': scan.target_url,
                'scan_date': scan.scan_date.isoformat(),
                'pages_scanned': scan.pages_scanned,
                'risk_score': scan.risk_score,
                'risk_level': scan.risk_level,
                'findings_count': scan.findings_count,
                'high_count': scan.high_count,
                'medium_count': scan.medium_count,
                'low_count': scan.low_count,
                'info_count': scan.info_count
            } for scan in scans]
            
        except Exception as e:
            print(f"Get scans error: {e}")
            return []
    
    @staticmethod
    def get_scan_details(scan_id: str, user_id: int) -> Optional[Dict]:
        """Get full scan results"""
        try:
            scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()
            
            if scan and scan.scan_results:
                return json.loads(scan.scan_results)
            return None
            
        except Exception as e:
            print(f"Get scan details error: {e}")
            return None
