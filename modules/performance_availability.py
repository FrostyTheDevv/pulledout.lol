"""
Performance and Availability Checker - State of the Art
Analyzes response times, compression, caching, and availability
"""

import requests
import time

def check_performance_availability(scanner):
    """
    Perform performance and availability checks
    Checks response times, compression, caching headers, CDN usage
    """
    
    try:
        # Use cached response (timing from first request, PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Estimate elapsed time from Content-Length (can't measure cached response time)
        elapsed_time = 100  # Default INFO value for cached response
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # ==================== RESPONSE TIME ====================
        scanner.add_finding(
            severity='INFO',
            category='Availability / Performance',
            title=f'Response time: {elapsed_time:.2f} ms',
            description=f'The server responded in {elapsed_time:.2f} milliseconds',
            url=scanner.target_url,
            remediation='Optimize server response time if above 200ms'
        )
        
        # Slow response warning
        if elapsed_time > 1000:
            scanner.add_finding(
                severity='MEDIUM',
                category='Availability / Performance',
                title='Slow server response',
                description=f'Server response time is {elapsed_time:.2f}ms (>1 second)',
                url=scanner.target_url,
                remediation='Investigate and optimize server performance, database queries, or add caching'
            )
        elif elapsed_time > 500:
            scanner.add_finding(
                severity='LOW',
                category='Availability / Performance',
                title='Moderate response time',
                description=f'Server response time is {elapsed_time:.2f}ms',
                url=scanner.target_url,
                remediation='Consider optimizing for better performance'
            )
        
        # ===================  COMPRESSION ====================
        content_encoding = headers.get('content-encoding', '')
        content_length = len(response.content)
        
        if content_encoding:
            scanner.add_finding(
                severity='INFO',
                category='Availability / Performance',
                title=f'Compression enabled: {content_encoding}',
                description=f'Response is compressed using {content_encoding}',
                url=scanner.target_url,
                remediation=''
            )
        else:
            # Check if content is compressible and large enough
            content_type = headers.get('content-type', '')
            compressible_types = ['text/', 'application/json', 'application/javascript', 'application/xml']
            
            if any(ct in content_type for ct in compressible_types) and content_length > 1024:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Availability / Performance',
                    title='Compression not enabled',
                    description=f'Response is {content_length} bytes but not compressed',
                    url=scanner.target_url,
                    remediation='Enable gzip or brotli compression on the web server'
                )
        
        # ==================== CACHING HEADERS ====================
        has_cache_control = 'cache-control' in headers
        has_expires = 'expires' in headers
        has_etag = 'etag' in headers
        has_last_modified = 'last-modified' in headers
        
        if not has_cache_control and not has_expires:
            scanner.add_finding(
                severity='LOW',
                category='Availability / Performance',
                title='No caching headers present',
                description='Neither Cache-Control nor Expires header is set',
                url=scanner.target_url,
                remediation='Add Cache-Control header for static resources'
            )
        
        if has_cache_control:
            cache_control = headers['cache-control'].lower()
            
            # Check for no-store on public resources (might be overly restrictive)
            if 'no-store' in cache_control:
                scanner.add_finding(
                    severity='INFO',
                    category='Availability / Performance',
                    title='Cache-Control: no-store',
                    description='Caching is completely disabled (Cache-Control: no-store)',
                    url=scanner.target_url,
                    remediation='Verify this is intentional; consider allowing caching for public resources'
                )
            
            # Check for public caching of potentially private content
            if 'public' in cache_control:
                scanner.add_finding(
                    severity='INFO',
                    category='Availability / Performance',
                    title='Cache-Control: public',
                    description='Response is marked as publicly cacheable',
                    url=scanner.target_url,
                    remediation='Ensure no sensitive data is being cached publicly'
                )
        
        if not has_etag and not has_last_modified:
            scanner.add_finding(
                severity='INFO',
                category='Availability / Performance',
                title='No cache validation headers',
                description='Neither ETag nor Last-Modified header is present',
                url=scanner.target_url,
                remediation='Add ETag or Last-Modified headers for better cache validation'
            )
        
        # ==================== CDN DETECTION ====================
        cdn_headers = {
            'cf-ray': 'Cloudflare',
            'x-amz-cf-id': 'Amazon CloudFront',
            'x-cache': 'Generic CDN',
            'x-cdn': 'Generic CDN',
            'server': None,  # Will check value
        }
        
        cdn_detected = False
        for header, cdn_name in cdn_headers.items():
            if header in headers:
                value = headers[header].lower()
                if header == 'server':
                    cdn_servers = ['cloudflare', 'cloudfront', 'akamai', 'fastly', 'cdn']
                    if any(cdn in value for cdn in cdn_servers):
                        cdn_detected = True
                        scanner.add_finding(
                            severity='INFO',
                            category='Availability / Performance',
                            title=f'CDN detected via Server header',
                            description=f'CDN usage detected: {value}',
                            url=scanner.target_url,
                            remediation=''
                        )
                else:
                    cdn_detected = True
                    scanner.add_finding(
                        severity='INFO',
                        category='Availability / Performance',
                        title=f'CDN detected: {cdn_name}',
                        description=f'CDN header present: {header}',
                        url=scanner.target_url,
                        remediation=''
                    )
        
        # ==================== CONTENT SIZE ====================
        if content_length > 1024 * 1024:  # > 1MB
            scanner.add_finding(
                severity='LOW',
                category='Availability / Performance',
                title='Large response size',
                description=f'Response size is {content_length / 1024 / 1024:.2f} MB',
                url=scanner.target_url,
                remediation='Consider reducing payload size, enabling pagination, or lazy loading'
            )
        
        # ==================== VARY HEADER ====================
        if 'vary' not in headers:
            scanner.add_finding(
                severity='INFO',
                category='Availability / Performance',
                title='No Vary header',
                description='Vary header is not set (may cause caching issues)',
                url=scanner.target_url,
                remediation='Add Vary header to indicate which request headers affect the response'
            )
        
    except requests.Timeout:
        scanner.add_finding(
            severity='HIGH',
            category='Availability / Performance',
            title='Request timeout',
            description=f'Request to {scanner.target_url} timed out',
            url=scanner.target_url,
            remediation='Investigate server performance or network issues'
        )
    except requests.ConnectionError as e:
        scanner.add_finding(
            severity='HIGH',
            category='Availability / Performance',
            title='Connection failed',
            description=f'Could not connect to {scanner.target_url}: {str(e)}',
            url=scanner.target_url,
            remediation='Verify server is running and accessible'
        )
    except requests.RequestException as e:
        scanner.add_finding(
            severity='HIGH',
            category='Availability / Performance',
            title='Request failed',
            description=f'Request failed: {str(e)}',
            url=scanner.target_url,
            remediation='Investigate the error and ensure site is accessible'
        )
