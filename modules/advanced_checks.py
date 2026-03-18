"""
Advanced Vulnerability Scanner - State of the Art
Additional comprehensive security checks for HTTP methods, configurations, etc.
"""

import requests

def run_advanced_scans(scanner):
    """
    Run advanced vulnerability scans
    Tests HTTP methods, configuration issues, and additional security checks
    """
    
    try:
        # ==================== HTTP METHODS TESTING ====================
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS', 'PATCH']
        
        for method in dangerous_methods:
            try:
                response = scanner.session.request(method, scanner.target_url, timeout=5)
                
                if method == 'OPTIONS' and response.status_code < 400:
                    # Check Allow header
                    allow_header = response.headers.get('Allow', '')
                    if allow_header:
                        allowed_methods = [m.strip().upper() for m in allow_header.split(',')]
                        dangerous_allowed = [m for m in allowed_methods if m in ['PUT', 'DELETE', 'TRACE']]
                        
                        if dangerous_allowed:
                            scanner.add_finding(
                                severity='MEDIUM',
                                category='Discovery / Hygiene',
                                title=f'Dangerous HTTP methods enabled',
                                description=f'Server allows potentially dangerous methods: {", ".join(dangerous_allowed)}',
                                url=scanner.target_url,
                                remediation='Disable unnecessary HTTP methods on the web server'
                            )
                
                elif method == 'TRACE' and response.status_code == 200:
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Discovery / Hygiene',
                        title='HTTP TRACE method enabled',
                        description='TRACE method is enabled (XST vulnerability)',
                        url=scanner.target_url,
                        remediation='Disable TRACE method to prevent Cross-Site Tracing attacks'
                    )
                
                elif method in ['PUT', 'DELETE'] and response.status_code < 400:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Discovery / Hygiene',
                        title=f'HTTP {method} method enabled',
                        description=f'{method} method is accessible without authentication',
                        url=scanner.target_url,
                        remediation=f'Disable {method} method or require authentication'
                    )
            except:
                pass
        
        # ==================== X-CONTENT-TYPE-OPTIONS SPECIFIC CHECKS ====================
        response = scanner.session.get(scanner.target_url, timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Additional specific checks that weren't covered
        content_type = headers.get('content-type', '')
        
        # Check if charset is specified
        if 'text/html' in content_type and 'charset' not in content_type.lower():
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Content-Type missing charset',
                description='Content-Type header does not specify character encoding',
                url=scanner.target_url,
                remediation='Add charset to Content-Type header (e.g., text/html; charset=utf-8)'
            )
        
        # ==================== CACHE CONTROL FOR SENSITIVE PAGES ====================
        if 'cache-control' in headers:
            cc = headers['cache-control'].lower()
            # Check for sensitive content being cached
            if 'no-cache' not in cc and 'no-store' not in cc and 'private' not in cc:
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='Cache-Control may allow caching of dynamic content',
                    description='Cache-Control does not prevent caching of potentially sensitive content',
                    url=scanner.target_url,
                    remediation='Add "Cache-Control: no-cache, no-store, must-revalidate, private" for sensitive pages'
                )
        
        # ==================== PRAGMA HEADER ====================
        if 'pragma' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Security Headers',
                title='Missing Pragma header',
                description='Pragma header not set (HTTP/1.0 cache control)',
                url=scanner.target_url,
                remediation='Add "Pragma: no-cache" for HTTP/1.0 compatibility'
            )
        
    except requests.RequestException:
        pass
    except Exception as e:
        pass


def check_server_configuration(scanner):
    """
    Check server configuration and behavior
    """
    
    try:
        response = scanner.session.get(scanner.target_url, timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # ==================== RESPONSE HEADERS COUNT ====================
        security_header_count = sum(1 for h in ['strict-transport-security', 'content-security-policy',
                                                 'x-frame-options', 'x-content-type-options',
                                                 'referrer-policy', 'permissions-policy'] if h in headers)
        
        if security_header_count < 3:
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',  
                title=f'Insufficient security headers ({security_header_count}/6 present)',
                description='Only a few security headers are configured',
                url=scanner.target_url,
                remediation='Implement all recommended security headers'
            )
        
        # ==================== CONTENT-DISPOSITION ====================
        if 'content-disposition' in headers:
            cd = headers['content-disposition']
            if 'attachment' in cd.lower():
                scanner.add_finding(
                    severity='INFO',
                    category='Security Headers',
                    title='Content-Disposition header present',
                    description=f'Content-Disposition is set to: {cd}',
                    url=scanner.target_url,
                    remediation=''
                )
        
        # ==================== X-ROBOTS-TAG ====================
        if 'x-robots-tag' in headers:
            scanner.add_finding(
                severity='INFO',
                category='Security Headers',
                title='X-Robots-Tag header present',
                description='X-Robots-Tag controls search engine indexing',
                url=scanner.target_url,
                remediation=''
            )
        
    except:
        pass
