"""
Security Headers Checker Module - Ultra-Granular Analysis
Each missing header/directive generates a SEPARATE finding to match professional scanners
Based on OWASP Secure Headers Project and industry best practices
"""

import requests

def check_security_headers(scanner):
    """
    Perform ultra-granular security header analysis
    Each missing header attribute generates a separate finding
    """
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Track page
        if scanner.target_url not in scanner.pages_scanned:
            scanner.pages_scanned.append(scanner.target_url)
        
        # ==================== STRICT TRANSPORT SECURITY (HSTS) ====================
        # Check if HSTS header exists at all
        if 'strict-transport-security' not in headers:
            scanner.add_finding(
                severity='HIGH',
                category='Security Headers',
                title='Missing HSTS header',
                description='HTTP Strict-Transport-Security header is not set. Site is vulnerable to SSL stripping attacks.',
                url=scanner.target_url,
                remediation='Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
            )
            # Since header is missing, also report each missing directive separately
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',
                title='HSTS max-age not configured',
                description='HSTS max-age directive is not configured.',
                url=scanner.target_url,
                remediation='Set HSTS max-age to at least 31536000'
            )
            # Note: includeSubDomains and preload checks are in comprehensive_header_analysis.py
        else:
            hsts_value = headers['strict-transport-security']
            
            # Check max-age separately
            if 'max-age' not in hsts_value.lower():
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='HSTS missing max-age directive',
                    description='HSTS header exists but lacks max-age directive',
                    url=scanner.target_url,
                    remediation='Add max-age directive'
                )
            else:
                try:
                    max_age_part = [p for p in hsts_value.split(';') if 'max-age' in p.lower()][0]
                    max_age = int(max_age_part.split('=')[1].strip())
                    if max_age < 31536000:
                        scanner.add_finding(
                            severity='MEDIUM',
                            category='Security Headers',
                            title='HSTS max-age too short',
                            description=f'HSTS max-age is {max_age} seconds (recommended: 31536000)',
                            url=scanner.target_url,
                            remediation='Increase to 31536000 seconds'
                        )
                except:
                    pass
            
            # Check includeSubDomains separately
            if 'includesubdomains' not in hsts_value.lower():
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='HSTS missing includeSubDomains',
                    description='HSTS does not include subdomains',
                    url=scanner.target_url,
                    remediation='Add includeSubDomains directive'
                )
            
            # Check preload separately
            if 'preload' not in hsts_value.lower():
                scanner.add_finding(
                    severity='INFO',
                    category='Security Headers',
                    title='HSTS missing preload',
                    description='HSTS not configured for preload',
                    url=scanner.target_url,
                    remediation='Add preload directive'
                )
        
        # ==================== CONTENT SECURITY POLICY (CSP) ====================
        if 'content-security-policy' not in headers and 'content-security-policy-report-only' not in headers:
            # CSP header completely missing - report each missing directive separately
            scanner.add_finding(
                severity='HIGH',
                category='Security Headers',
                title='Missing CSP header',
                description='Content-Security-Policy header is not set. Site is vulnerable to XSS and code injection attacks.',
                url=scanner.target_url,
                remediation='Add Content-Security-Policy header with restrictive directives'
            )
            # Report each critical directive as missing
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',
                title='CSP default-src not configured',
                description='CSP default-src directive is not configured.',
                url=scanner.target_url,
                remediation='Add default-src directive to CSP'
            )
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',
                title='CSP script-src not configured',
                description='CSP script-src directive is not configured.',
                url=scanner.target_url,
                remediation='Add script-src directive to CSP'
            )
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='CSP object-src not configured',
                description='CSP object-src directive is not configured.',
                url=scanner.target_url,
                remediation='Add object-src directive to CSP'
            )
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='CSP base-uri not configured',
                description='CSP base-uri directive is not configured.',
                url=scanner.target_url,
                remediation='Add base-uri directive to CSP'
            )
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='CSP form-action not configured',
                description='CSP form-action directive is not configured.',
                url=scanner.target_url,
                remediation='Add form-action directive to CSP'
            )
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='CSP frame-ancestors not configured',
                description='CSP frame-ancestors directive is not configured.',
                url=scanner.target_url,
                remediation='Add frame-ancestors directive to CSP'
            )
        elif 'content-security-policy-report-only' in headers and 'content-security-policy' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Security Headers',
                title='CSP in report-only mode',
                description='CSP is in report-only mode and not enforcing',
                url=scanner.target_url,
                remediation='Change to enforcing mode'
            )
        else:
            csp_value = headers.get('content-security-policy', '')
            
            # Note: unsafe-inline and unsafe-eval are checked in comprehensive_header_analysis.py at HIGH severity
            
            # Check each directive separately
            if 'default-src' not in csp_value.lower():
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='CSP missing default-src',
                    description='CSP does not define default-src directive',
                    url=scanner.target_url,
                    remediation='Add default-src directive'
                )
            
            if 'script-src' not in csp_value.lower():
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='CSP missing script-src',
                    description='CSP does not define script-src directive',
                    url=scanner.target_url,
                    remediation='Add script-src directive'
                )
            
            if 'object-src' not in csp_value.lower():
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='CSP missing object-src',
                    description='CSP does not define object-src directive',
                    url=scanner.target_url,
                    remediation='Add object-src directive'
                )
            
            if 'base-uri' not in csp_value.lower():
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='CSP missing base-uri',
                    description='CSP does not define base-uri directive',
                    url=scanner.target_url,
                    remediation='Add base-uri directive'
                )
            
            if 'form-action' not in csp_value.lower():
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='CSP missing form-action',
                    description='CSP does not restrict form submissions',
                    url=scanner.target_url,
                    remediation='Add form-action directive'
                )
            
            if 'frame-ancestors' not in csp_value.lower():
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='CSP missing frame-ancestors',
                    description='CSP does not control frame embedding',
                    url=scanner.target_url,
                    remediation='Add frame-ancestors directive'
                )
        
        # ==================== X-FRAME-OPTIONS ====================
        if 'x-frame-options' not in headers:
            scanner.add_finding(
                severity='HIGH',
                category='Security Headers',
                title='Missing X-Frame-Options header',
                description='X-Frame-Options header is not set. Site is vulnerable to clickjacking attacks.',
                url=scanner.target_url,
                remediation='Add header: X-Frame-Options: DENY or SAMEORIGIN'
            )
        else:
            xfo = headers['x-frame-options'].upper().strip()
            if xfo not in ['DENY', 'SAMEORIGIN']:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='Invalid X-Frame-Options value',
                    description=f'X-Frame-Options has invalid value: {xfo}',
                    url=scanner.target_url,
                    remediation='Set to DENY or SAMEORIGIN'
                )
        
        # ==================== X-CONTENT-TYPE-OPTIONS ====================
        if 'x-content-type-options' not in headers:
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',
                title='Missing X-Content-Type-Options header',
                description='X-Content-Type-Options header is not set.',
                url=scanner.target_url,
                remediation='Add header: X-Content-Type-Options: nosniff'
            )
        elif headers['x-content-type-options'].lower().strip() != 'nosniff':
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',
                title='Invalid X-Content-Type-Options',
                description='X-Content-Type-Options should be "nosniff"',
                url=scanner.target_url,
                remediation='Set to nosniff'
            )
        
        # ==================== REFERRER-POLICY ====================
        if 'referrer-policy' not in headers:
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',
                title='Missing Referrer-Policy header',
                description='Referrer-Policy header is not set.',
                url=scanner.target_url,
                remediation='Add header: Referrer-Policy: strict-origin-when-cross-origin'
            )
        else:
            ref_policy = headers['referrer-policy'].lower().strip()
            if ref_policy in ['unsafe-url', 'no-referrer-when-downgrade']:
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='Weak Referrer-Policy',
                    description=f'Referrer-Policy is set to weak value: {ref_policy}',
                    url=scanner.target_url,
                    remediation='Use stricter policy'
                )
        
        # ==================== PERMISSIONS-POLICY ====================
        if 'permissions-policy' not in headers and 'feature-policy' not in headers:
            scanner.add_finding(
                severity='MEDIUM',
                category='Security Headers',
                title='Missing Permissions-Policy header',
                description='Permissions-Policy header is not set.',
                url=scanner.target_url,
                remediation='Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()'
            )
        
        # ==================== X-XSS-PROTECTION ====================
        if 'x-xss-protection' not in headers:
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Missing X-XSS-Protection header',
                description='X-XSS-Protection header is not set.',
                url=scanner.target_url,
                remediation='Add header: X-XSS-Protection: 1; mode=block'
            )
        else:
            xxp = headers['x-xss-protection']
            if '0' in xxp:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Security Headers',
                    title='X-XSS-Protection disabled',
                    description='X-XSS-Protection is disabled',
                    url=scanner.target_url,
                    remediation='Set to: 1; mode=block'
                )
            elif 'mode=block' not in xxp.lower():
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='X-XSS-Protection not in block mode',
                    description='X-XSS-Protection should use mode=block',
                    url=scanner.target_url,
                    remediation='Add mode=block'
                )
        
        # ==================== CROSS-ORIGIN HEADERS ====================
        if 'cross-origin-embedder-policy' not in headers:
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Missing Cross-Origin-Embedder-Policy',
                description='COEP header is not set.',
                url=scanner.target_url,
                remediation='Add header: Cross-Origin-Embedder-Policy: require-corp'
            )
        
        if 'cross-origin-opener-policy' not in headers:
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Missing Cross-Origin-Opener-Policy',
                description='COOP header is not set.',
                url=scanner.target_url,
                remediation='Add header: Cross-Origin-Opener-Policy: same-origin'
            )
        
        if 'cross-origin-resource-policy' not in headers:
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Missing Cross-Origin-Resource-Policy',
                description='CORP header is not set.',
                url=scanner.target_url,
                remediation='Add header: Cross-Origin-Resource-Policy: same-origin'
            )
        
        # ==================== ADDITIONAL HEADERS ====================
        if 'expect-ct' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Security Headers',
                title='Missing Expect-CT header',
                description='Expect-CT header is not set.',
                url=scanner.target_url,
                remediation='Add header: Expect-CT: max-age=86400, enforce'
            )
        
        if 'x-permitted-cross-domain-policies' not in headers:
            scanner.add_finding(
                severity='LOW',
                category='Security Headers',
                title='Missing X-Permitted-Cross-Domain-Policies',
                description='X-Permitted-Cross-Domain-Policies header is not set.',
                url=scanner.target_url,
                remediation='Add header: X-Permitted-Cross-Domain-Policies: none'
            )
        
        if 'x-download-options' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Security Headers',
                title='Missing X-Download-Options',
                description='X-Download-Options header is not set.',
                url=scanner.target_url,
                remediation='Add header: X-Download-Options: noopen'
            )
        
        # ==================== CORS CHECKS ====================
        if 'access-control-allow-origin' in headers:
            acao = headers['access-control-allow-origin']
            if acao == '*':
                scanner.add_finding(
                    severity='HIGH',
                    category='Security Headers',
                    title='CORS wildcard allows any origin',
                    description='Access-Control-Allow-Origin: * - CRITICAL data exposure risk',
                    url=scanner.target_url,
                    remediation='Restrict to specific trusted origins or remove if not needed'
                )
            
            if 'access-control-allow-credentials' in headers:
                if headers['access-control-allow-credentials'].lower() == 'true' and acao == '*':
                    scanner.add_finding(
                        severity='HIGH',
                        category='Security Headers',
                        title='CORS misconfiguration: credentials with wildcard',
                        description='Dangerous CORS configuration',
                        url=scanner.target_url,
                        remediation='Use specific origin with credentials'
                    )
        
        # ==================== TIMING CHECKS ====================
        if 'timing-allow-origin' in headers:
            if '*' in headers['timing-allow-origin']:
                scanner.add_finding(
                    severity='LOW',
                    category='Security Headers',
                    title='Timing-Allow-Origin set to wildcard',
                    description='Timing information exposed to all origins',
                    url=scanner.target_url,
                    remediation='Restrict to specific origins'
                )
        
        # ==================== DNS PREFETCH ====================
        if 'x-dns-prefetch-control' in headers:
            if headers['x-dns-prefetch-control'].lower() == 'on':
                scanner.add_finding(
                    severity='INFO',
                    category='Security Headers',
                    title='DNS prefetching enabled',
                    description='DNS prefetching may leak information',
                    url=scanner.target_url,
                    remediation='Consider disabling for sensitive apps'
                )
        
    except Exception as e:
        scanner.add_finding(
            severity='INFO',
            category='Security Headers',
            title='Error checking headers',
            description=f'Error during header analysis: {str(e)}',
            url=scanner.target_url,
            remediation='Review server configuration'
        )
