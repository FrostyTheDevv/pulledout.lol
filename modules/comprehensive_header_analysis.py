"""
Comprehensive Header Analysis - Ultra-Granular
Every single header directive and attribute gets its own finding
"""

import requests

def ultra_granular_header_scan(scanner):
    """Generate 50+ individual findings for missing headers and directives"""
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # List of ALL security headers - each missing one is a separate finding
        # NOTE: HSTS, CSP, X-Frame-Options are checked in security_headers.py with HIGH severity
        security_headers_required = {
            'x-content-type-options': ('MEDIUM', 'Missing X-Content-Type-Options header'),
            'referrer-policy': ('MEDIUM', 'Missing Referrer-Policy header'),
            'permissions-policy': ('MEDIUM', 'Missing Permissions-Policy header'),
            'x-xss-protection': ('MEDIUM', 'Missing X-XSS-Protection header'),
            'cross-origin-embedder-policy': ('MEDIUM', 'Missing Cross-Origin-Embedder-Policy'),
            'cross-origin-opener-policy': ('MEDIUM', 'Missing Cross-Origin-Opener-Policy'),
            'cross-origin-resource-policy': ('MEDIUM', 'Missing Cross-Origin-Resource-Policy'),
            'x-permitted-cross-domain-policies': ('MEDIUM', 'Missing X-Permitted-Cross-Domain-Policies'),
            'x-download-options': ('MEDIUM', 'Missing X-Download-Options'),
            'expect-ct': ('MEDIUM', 'Missing Expect-CT header'),
            'nel': ('LOW', 'Missing NEL (Network Error Logging) header'),
            'report-to': ('LOW', 'Missing Report-To header'),
        }
        
        for header_name, (severity, title) in security_headers_required.items():
            if header_name not in headers:
                scanner.add_finding(
                    severity=severity,
                    category='Security Headers',
                    title=title,
                    description=f'{header_name} header is not set',
                    url=scanner.target_url,
                    remediation=f'Add {header_name} header with appropriate value'
                )
        
        # CSP Directives - Each missing directive is a separate finding
        if 'content-security-policy' in headers:
            csp = headers['content-security-policy'].lower()
            
            csp_directives = {
                'default-src': ('MEDIUM', 'CSP missing default-src directive'),
                'script-src': ('MEDIUM', 'CSP missing script-src directive'),
                'style-src': ('MEDIUM', 'CSP missing style-src directive'),
                'img-src': ('MEDIUM', 'CSP missing img-src directive'),
                'font-src': ('MEDIUM', 'CSP missing font-src directive'),
                'connect-src': ('MEDIUM', 'CSP missing connect-src directive'),
                'media-src': ('MEDIUM', 'CSP missing media-src directive'),
                'object-src': ('MEDIUM', 'CSP missing object-src directive'),
                'frame-src': ('MEDIUM', 'CSP missing frame-src directive'),
                'frame-ancestors': ('MEDIUM', 'CSP missing frame-ancestors directive'),
                'base-uri': ('MEDIUM', 'CSP missing base-uri directive'),
                'form-action': ('MEDIUM', 'CSP missing form-action directive'),
                'worker-src': ('MEDIUM', 'CSP missing worker-src directive'),
                'manifest-src': ('MEDIUM', 'CSP missing manifest-src directive'),
                'prefetch-src': ('MEDIUM', 'CSP missing prefetch-src directive'),
                'navigate-to': ('MEDIUM', 'CSP missing navigate-to directive'),
            }
            
            for directive, (severity, title) in csp_directives.items():
                if directive not in csp:
                    scanner.add_finding(
                        severity=severity,
                        category='Security Headers',
                        title=title,
                        description=f'CSP does not define {directive}',
                        url=scanner.target_url,
                        remediation=f'Add {directive} to CSP'
                    )
            
            # Check for unsafe values
            if "'unsafe-inline'" in csp:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title="CSP contains 'unsafe-inline'",
                    description="CSP allows inline scripts/styles - XSS risk",
                    url=scanner.target_url,
                    remediation="Remove 'unsafe-inline' and use nonces/hashes"
                )
            
            if "'unsafe-eval'" in csp:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title="CSP contains 'unsafe-eval'",
                    description="CSP allows eval() - code execution risk",
                    url=scanner.target_url,
                    remediation="Remove 'unsafe-eval'"
                )
            
            if "'unsafe-hashes'" in csp:
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title="CSP contains 'unsafe-hashes'",
                    description="CSP allows unsafe hashes",
                    url=scanner.target_url,
                    remediation="Review unsafe-hashes usage"
                )
        
        # HSTS Directives
        if 'strict-transport-security' in headers:
            hsts = headers['strict-transport-security'].lower()
            
            if 'max-age' not in hsts:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='HSTS missing max-age',
                    description='HSTS must include max-age',
                    url=scanner.target_url,
                    remediation='Add max-age directive'
                )
            
            if 'includesubdomains' not in hsts:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='HSTS missing includeSubDomains',
                    description='HSTS should include subdomains',
                    url=scanner.target_url,
                    remediation='Add includeSubDomains'
                )
            
            if 'preload' not in hsts:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='HSTS missing preload',
                    description='HSTS not configured for preload list',
                    url=scanner.target_url,
                    remediation='Add preload directive'
                )
        
        # Permissions-Policy Features - Critical ones should be MEDIUM
        if 'permissions-policy' in headers or 'feature-policy' in headers:
            pp = headers.get('permissions-policy', headers.get('feature-policy', '')).lower()
            
            # Critical features that MUST be restricted
            critical_features = ['geolocation', 'camera', 'microphone', 'payment', 'usb']
            # Less critical but recommended
            other_features = [
                'magnetometer', 'gyroscope', 'accelerometer', 'ambient-light-sensor',
                'autoplay', 'encrypted-media', 'fullscreen', 'picture-in-picture',
                'screen-wake-lock', 'web-share', 'xr-spatial-tracking'
            ]
            
            for feature in critical_features:
                if feature not in pp:
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Security Headers',
                        title=f'Permissions-Policy not restricting {feature}',
                        description=f'CRITICAL: Browser feature "{feature}" is not restricted',
                        url=scanner.target_url,
                        remediation=f'Add {feature}=() to Permissions-Policy'
                    )
            
            for feature in other_features:
                if feature not in pp:
                    scanner.add_finding(
                        severity='LOW',
                        category='Security Headers',
                        title=f'Permissions-Policy not restricting {feature}',
                        description=f'Browser feature "{feature}" is not explicitly restricted',
                        url=scanner.target_url,
                        remediation=f'Add {feature}=() to Permissions-Policy'
                    )
        
        # Server fingerprinting - each header that leaks info
        # Detect hosting providers and exclude their infrastructure headers
        hosting_providers = {
            'railway': ['railway.app', 'railway'],
            'vercel': ['vercel.app', 'vercel', 'now.sh'],  
            'netlify': ['netlify.app', 'netlify'],
            'heroku': ['herokuapp.com', 'heroku'],
            'render': ['render.com', 'onrender.com'],
            'fly': ['fly.dev', 'fly.io'],
            'cloudflare': ['cloudflare', 'cf-ray'],
            'replit': ['replit.dev', 'repl.co', 'replit.app']
        }
        
        # Check if site is on a known hosting provider
        is_hosted_service = False
        hosting_service_name = None
        
        # Check URL for hosting provider patterns (for *.provider.app domains)
        for provider, patterns in hosting_providers.items():
            for pattern in patterns:
                if pattern in scanner.target_url.lower():
                    is_hosted_service = True
                    hosting_service_name = provider.capitalize()
                    break
            if is_hosted_service:
                break
        
        # Check headers for provider signatures (works with custom domains)
        if not is_hosted_service:
            # Railway detection
            if 'server' in headers and 'nginx' in headers['server'].lower():
                # Railway typically uses nginx as reverse proxy
                # Check for Railway-specific patterns or if it's a simple "nginx" value
                server_value = headers['server'].lower()
                if server_value == 'nginx' or 'railway' in server_value:
                    # Additional Railway indicators
                    railway_indicators = ['x-railway-id', 'railway-static-ip']
                    for indicator in railway_indicators:
                        if indicator in headers:
                            is_hosted_service = True
                            hosting_service_name = 'Railway'
                            break
                    
                    # If server header is just "nginx" with no version, likely a managed service
                    if not is_hosted_service and server_value == 'nginx':
                        # Heuristic: If it's HTTPS with just "nginx" header, likely Railway/managed service
                        if scanner.target_url.startswith('https://'):
                            is_hosted_service = True
                            hosting_service_name = 'Managed Hosting Service (likely Railway/Vercel/Render)'
            
            # Cloudflare detection (works with any domain behind CF)
            if 'cf-ray' in headers or 'cf-cache-status' in headers:
                is_hosted_service = True
                hosting_service_name = 'Cloudflare'
            
            # Vercel detection
            if 'x-vercel-id' in headers or 'x-vercel-cache' in headers:
                is_hosted_service = True
                hosting_service_name = 'Vercel'
            
            # Netlify detection
            if 'x-nf-request-id' in headers:
                is_hosted_service = True
                hosting_service_name = 'Netlify'
            
            # Heroku detection
            if 'x-heroku-queue-wait-time' in headers:
                is_hosted_service = True
                hosting_service_name = 'Heroku'
        
        # Add INFO finding about hosting detection
        if is_hosted_service and hosting_service_name:
            scanner.add_finding(
                severity='INFO',
                category='Discovery / Hygiene',
                title=f'Hosted on {hosting_service_name}',
                description=f'Site is deployed on {hosting_service_name} infrastructure. Some headers (like "server") are managed by the hosting provider and cannot be modified at the application level.',
                url=scanner.target_url,
                remediation='Infrastructure headers are managed by hosting provider and cannot be modified'
            )
        
        critical_info_leaks = ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']
        minor_info_leaks = ['server', 'x-drupal-cache', 'x-varnish', 'via']
        
        for header in critical_info_leaks:
            if header in headers:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Information Disclosure',
                    title=f'{header} header exposes technology',
                    description=f'{header}: {headers[header]} - reveals specific technology/version',
                    url=scanner.target_url,
                    remediation=f'Remove {header} header'
                )
        
        # Only flag server header if NOT on a managed hosting provider
        for header in minor_info_leaks:
            if header in headers:
                # Skip server header if it's from a known hosting provider
                if header == 'server':
                    # Check if managed hosting detected
                    if is_hosted_service:
                        continue
                    
                    # Additional heuristics: Skip generic nginx/cloud infrastructure headers
                    server_value = headers['server'].lower()
                    
                    # Skip plain "nginx" or "nginx/version" - almost always managed infrastructure
                    if server_value == 'nginx' or server_value.startswith('nginx/'):
                        # This is managed infrastructure, add INFO instead of LOW
                        scanner.add_finding(
                            severity='INFO',
                            category='Discovery / Hygiene',
                            title='Infrastructure server header detected',
                            description=f'Server header "{headers["server"]}" indicates managed infrastructure (Railway/Vercel/Render/etc). This header is set by the hosting provider and cannot be modified at the application level.',
                            url=scanner.target_url,
                            remediation='No action needed - infrastructure-level header managed by hosting provider'
                        )
                        continue
                    
                    # Skip cloudflare-nginx (Cloudflare)
                    if 'cloudflare' in server_value:
                        continue
                    
                scanner.add_finding(
                    severity='LOW',
                    category='Information Disclosure',
                    title=f'{header} header exposes technology',
                    description=f'{header}: {headers[header]}',
                    url=scanner.target_url,
                    remediation=f'Remove {header} header from application server'
                )
        
        # Cache-Control directives
        if 'cache-control' in headers:
            cc = headers['cache-control'].lower()
            
            if 'public' in cc:
                scanner.add_finding(
                    severity='INFO',
                    category='Security Headers',
                    title='Cache-Control set to public',
                    description='Response can be cached by any cache',
                    url=scanner.target_url,
                    remediation='Use private for sensitive content'
                )
            
            if 'no-store' not in cc and 'no-cache' not in cc:
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='Cache-Control allows caching',
                    description='Response may be cached',
                    url=scanner.target_url,
                    remediation='Add no-store for sensitive pages'
                )
        
    except Exception as e:
        pass
