"""
Detailed HTTP Security Analysis
Checks every HTTP status code, redirect, method, header combination
"""

import requests

def detailed_http_analysis(scanner):
    """Analyze HTTP configuration in extreme detail"""
    
    try:
        # Test various endpoints
        endpoints_to_test = [
            ('/', 'Root'),
            ('/admin', 'Admin panel'),
            ('/login', 'Login page'),
            ('/api', 'API endpoint'),
            ('/test', 'Test page'),
            ('/backup', 'Backup directory'),
            ('/.git', 'Git repository'),
            ('/.env', 'Environment file'),
            ('/config.php', 'Config file'),
            ('/phpinfo.php', 'PHPInfo'),
            ('/server-status', 'Server status'),
            ('/wp-admin', 'WordPress admin'),
        ]
        
        for endpoint, name in endpoints_to_test:
            try:
                url = scanner.target_url.rstrip('/') + endpoint
                response = requests.get(url, timeout=5, allow_redirects=False)
               
                # Check for exposed endpoints
                if response.status_code == 200 and endpoint in ['/.git', '/.env', '/phpinfo.php', '/server-status']:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Information Disclosure',
                        title=f'Sensitive endpoint exposed: {endpoint}',
                        description=f'{name} is publicly accessible',
                        url=url,
                        remediation=f'Restrict access to {endpoint}'
                    )
                
                # Check for directory listing
                if response.status_code == 200 and 'index of' in response.text.lower():
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Information Disclosure',
                        title=f'Directory listing enabled: {endpoint}',
                        description='Directory contents are exposed',
                        url=url,
                        remediation='Disable directory listing'
                    )
                
            except:
                pass
        
        # Test HTTP methods on main URL
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'HEAD', 'PATCH', 'CONNECT']
        
        for method in methods_to_test:
            try:
                response = requests.request(method, scanner.target_url, timeout=5)
                
                if method == 'OPTIONS' and response.status_code == 200:
                    allow = response.headers.get('Allow', '')
                    if allow:
                        scanner.add_finding(
                            severity='INFO',
                            category='Discovery / Hygiene',
                            title=f'HTTP OPTIONS reveals allowed methods',
                            description=f'Allowed methods: {allow}',
                            url=scanner.target_url,
                            remediation='Consider restricting OPTIONS method'
                        )
                
                if method in ['PUT', 'DELETE', 'PATCH'] and response.status_code < 400:
                    scanner.add_finding(
                        severity='HIGH',
                        category='Discovery / Hygiene',
                        title=f'Dangerous HTTP method enabled: {method}',
                        description=f'{method} method is accessible',
                        url=scanner.target_url,
                        remediation=f'Disable {method} method'
                    )
                
                if method == 'TRACE' and response.status_code == 200:
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Discovery / Hygiene',
                        title='HTTP TRACE enabled',
                        description='TRACE method enables XST attacks',
                        url=scanner.target_url,
                        remediation='Disable TRACE method'
                    )
            except:
                pass
        
        # Check redirect behavior
        response = scanner.session.get(scanner.target_url, allow_redirects=False, timeout=10)
        
        if 300 <= response.status_code < 400:
            location = response.headers.get('Location', '')
            if location:
                scanner.add_finding(
                    severity='INFO',
                    category='Transport Security',
                    title=f'HTTP {response.status_code} redirect detected',
                    description=f'Redirects to: {location}',
                    url=scanner.target_url,
                    remediation='Ensure redirect is intentional and secure'
                )
                
                # Check if redirect is to HTTP
                if location.startswith('http://'):
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Transport Security',
                        title='Redirect to HTTP URL',
                        description=f'HTTPS page redirects to HTTP: {location}',
                        url=scanner.target_url,
                        remediation='Redirect to HTTPS only'
                    )
        
        # Check response headers for each request type
        response = scanner.session.get(scanner.target_url, timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Content-Type variations
        content_type = headers.get('content-type', '').lower()
        
        if not content_type:
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Missing Content-Type header',
                description='Content-Type not specified',
                url=scanner.target_url,
                remediation='Add Content-Type header'
            )
        
        if 'charset' not in content_type and 'text/html' in content_type:
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Content-Type missing charset',
                description='Character encoding not specified',
                url=scanner.target_url,
                remediation='Add charset to Content-Type'
            )
        
        # Vary header
        if 'vary' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Security Headers',
                title='Missing Vary header',
                description='Vary header not set',
                url=scanner.target_url,
                remediation='Add Vary header for proper caching'
            )
        
        # ETag
        if 'etag' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Availability / Performance',
                title='Missing ETag header',
                description='ETag not provided for cache validation',
                url=scanner.target_url,
                remediation='Add ETag for better caching'
            )
        
        # Last-Modified
        if 'last-modified' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Availability / Performance',
                title='Missing Last-Modified header',
                description='Last-Modified not provided',
                url=scanner.target_url,
                remediation='Add Last-Modified header'
            )
        
    except Exception as e:
        pass
