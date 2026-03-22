"""
Database Migration Script
Migrates from old schema (users table) to new schema (user_auth + user_profile)
Run this once to update Railway PostgreSQL database
"""

import os
from database import db, UserAuth, UserProfile, Session, Scan
from web_server import app
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database():
    """Migrate database schema from old to new structure"""
    with app.app_context():
        try:
            # Check if old users table exists
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            logger.info(f"Existing tables: {tables}")
            
            if 'users' in tables:
                logger.info("Old 'users' table found - migrating to new schema...")
                
                # Step 1: Backup data from old users table (if needed)
                result = db.session.execute(text("SELECT COUNT(*) FROM users"))
                old_user_count = result.scalar()
                logger.info(f"Found {old_user_count} users in old table")
                
                # Step 2: Drop old foreign key constraints
                logger.info("Dropping old foreign key constraints...")
                try:
                    db.session.execute(text("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey CASCADE"))
                    db.session.execute(text("ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_user_id_fkey CASCADE"))
                    db.session.commit()
                    logger.info("Dropped foreign key constraints")
                except Exception as e:
                    logger.warning(f"Error dropping constraints: {e}")
                    db.session.rollback()
                
                # Step 3: Drop old tables
                logger.info("Dropping old tables...")
                try:
                    db.session.execute(text("DROP TABLE IF EXISTS sessions CASCADE"))
                    db.session.execute(text("DROP TABLE IF EXISTS scans CASCADE"))
                    db.session.execute(text("DROP TABLE IF EXISTS users CASCADE"))
                    db.session.commit()
                    logger.info("Dropped old tables")
                except Exception as e:
                    logger.error(f"Error dropping tables: {e}")
                    db.session.rollback()
                    return False
                
            # Step 4: Create new schema
            logger.info("Creating new schema...")
            db.create_all()
            logger.info("New schema created successfully!")
            
            # Verify new tables
            inspector = inspect(db.engine)
            new_tables = inspector.get_table_names()
            logger.info(f"New tables: {new_tables}")
            
            expected_tables = ['user_auth', 'user_profile', 'sessions', 'scans']
            for table in expected_tables:
                if table in new_tables:
                    logger.info(f"✓ Table '{table}' created")
                else:
                    logger.error(f"✗ Table '{table}' missing!")
            
            logger.info("Migration completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Migration failed: {e}", exc_info=True)
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("=" * 60)
    print("DATABASE MIGRATION SCRIPT")
    print("=" * 60)
    print("\nThis will:")
    print("1. Drop old 'users' table and related data")
    print("2. Create new 'user_auth' and 'user_profile' tables")
    print("3. Recreate 'sessions' and 'scans' with correct foreign keys")
    print("\nWARNING: All existing user data will be deleted!")
    print("=" * 60)
    
    response = input("\nProceed with migration? (yes/no): ")
    if response.lower() == 'yes':
        success = migrate_database()
        if success:
            print("\n✓ Migration completed successfully!")
        else:
            print("\n✗ Migration failed. Check logs above.")
    else:
        print("\nMigration cancelled.")
