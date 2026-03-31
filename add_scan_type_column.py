"""
Add scan_type column to scans table
Run this once to fix the database schema
"""

import os
from database import db
from web_server import app
import logging
from sqlalchemy import text, inspect

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_scan_type_column():
    """Add scan_type column to scans table if it doesn't exist"""
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            
            # Check if scans table exists
            if 'scans' not in inspector.get_table_names():
                logger.error("scans table does not exist!")
                return False
            
            # Get existing columns
            columns = [col['name'] for col in inspector.get_columns('scans')]
            logger.info(f"Existing columns in scans table: {columns}")
            
            # Check if scan_type already exists
            if 'scan_type' in columns:
                logger.info("scan_type column already exists - no migration needed")
                return True
            
            # Add scan_type column
            logger.info("Adding scan_type column to scans table...")
            
            # Detect database type
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
            is_postgres = 'postgresql://' in db_uri or 'postgres://' in db_uri
            
            if is_postgres:
                # PostgreSQL syntax
                db.session.execute(text(
                    "ALTER TABLE scans ADD COLUMN scan_type VARCHAR(100) DEFAULT 'Comprehensive Scan'"
                ))
            else:
                # SQLite syntax
                db.session.execute(text(
                    "ALTER TABLE scans ADD COLUMN scan_type VARCHAR(100) DEFAULT 'Comprehensive Scan'"
                ))
            
            db.session.commit()
            logger.info("✓ scan_type column added successfully!")
            
            # Verify
            columns_after = [col['name'] for col in inspector.get_columns('scans')]
            if 'scan_type' in columns_after:
                logger.info("✓ Verified: scan_type column exists")
                return True
            else:
                logger.error("✗ Verification failed: scan_type column not found after migration")
                return False
            
        except Exception as e:
            logger.error(f"Migration failed: {e}", exc_info=True)
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("=" * 60)
    print("ADD SCAN_TYPE COLUMN MIGRATION")
    print("=" * 60)
    print("\nThis will add the 'scan_type' column to the scans table.")
    print("Safe to run multiple times (checks if column exists first).")
    print("=" * 60)
    
    success = add_scan_type_column()
    if success:
        print("\n✓ Migration completed successfully!")
        print("You can now run scans without database errors.")
    else:
        print("\n✗ Migration failed. Check logs above.")
