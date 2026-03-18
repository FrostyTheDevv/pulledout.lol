"""
SawSap - Ultra-Granular Resource Analysis
Every single resource (script, image, CSS, font) gets individual security findings
Target: 30-50 findings per page with moderate resources
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re

def ultra_granular_resource_scan(scanner):
    """
    Analyze every single resource on the page individually
    Generate findings for scripts, images, styles, fonts, iframes
    """
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(scanner.target_url)
    except:
        return
    
    # ==================== SCRIPT ANALYSIS ====================
    scripts = soup.find_all('script')
    
    for script in scripts:
        src = script.get('src')
        
        if src:  # External script
            # Resolve relative URLs
            if not src.startswith(('http://', 'https://', '//')):
                src = urljoin(scanner.target_url, src)
            
            parsed_src = urlparse(src)
            
            # Check 1: Script loaded over HTTP (HIGH)
            if parsed_src.scheme == 'http':
                scanner.add_finding(
                    severity='HIGH',
                    category='Resource Security',
                    title=f'Script loaded over insecure HTTP',
                    description=f'JavaScript file loaded without encryption: {src[:100]}',
                    url=scanner.target_url,
                    remediation='Load all scripts over HTTPS'
                )
            
            # Check 2: Third-party script without SRI (MEDIUM)
            if parsed_src.netloc and parsed_src.netloc != parsed_url.netloc:
                if not script.get('integrity'):
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Resource Security',
                        title=f'Third-party script without integrity check',
                        description=f'External script from {parsed_src.netloc} lacks Subresource Integrity (SRI)',
                        url=scanner.target_url,
                        remediation='Add integrity attribute with SRI hash'
                    )
            
            # Check 3: Script without async/defer (INFO)
            if not script.get('async') and not script.get('defer'):
                scanner.add_finding(
                    severity='INFO',
                    category='Resource Security',
                    title=f'Script blocks page rendering',
                    description=f'Script from {parsed_src.netloc or "same origin"} lacks async/defer attributes',
                    url=scanner.target_url,
                    remediation='Add async or defer attribute for non-critical scripts'
                )
        
        else:  # Inline script
            script_content = script.string or ''
            
            # Check 4: Inline script detected (INFO - count them)
            if len(script_content.strip()) > 20:
                scanner.add_finding(
                    severity='INFO',
                    category='Resource Security',
                    title=f'Inline JavaScript detected',
                    description=f'Inline script found ({len(script_content)} characters) - violates CSP best practices',
                    url=scanner.target_url,
                    remediation='Move inline scripts to external files or use CSP nonces'
                )
            
            # Check 5: Dangerous functions in inline scripts (MEDIUM)
            dangerous_patterns = {
                r'eval\s*\(': 'eval()',
                r'innerHTML\s*=': 'innerHTML assignment',
                r'document\.write': 'document.write',
                r'setTimeout\s*\(["\']': 'setTimeout with string',
                r'setInterval\s*\(["\']': 'setInterval with string',
            }
            
            for pattern, name in dangerous_patterns.items():
                if re.search(pattern, script_content):
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Resource Security',
                        title=f'Dangerous pattern in inline script: {name}',
                        description=f'Inline script uses {name} which may introduce XSS vulnerabilities',
                        url=scanner.target_url,
                        remediation=f'Avoid {name}, use safer alternatives'
                    )
                    break  # Only report once per script
    
    # ==================== STYLESHEET ANALYSIS ====================
    stylesheets = soup.find_all('link', rel='stylesheet')
    
    for stylesheet in stylesheets:
        href = stylesheet.get('href')
        if href:
            # Resolve relative URLs
            if not href.startswith(('http://', 'https://', '//')):
                href = urljoin(scanner.target_url, href)
            
            parsed_href = urlparse(href)
            
            # Check 6: Stylesheet over HTTP (MEDIUM)
            if parsed_href.scheme == 'http':
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Resource Security',
                    title=f'Stylesheet loaded over insecure HTTP',
                    description=f'CSS file loaded without encryption: {href[:100]}',
                    url=scanner.target_url,
                    remediation='Load all stylesheets over HTTPS'
                )
            
            # Check 7: Third-party stylesheet without SRI (MEDIUM)
            if parsed_href.netloc and parsed_href.netloc != parsed_url.netloc:
                if not stylesheet.get('integrity'):
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Resource Security',
                        title=f'Third-party stylesheet without integrity check',
                        description=f'External CSS from {parsed_href.netloc} lacks SRI',
                        url=scanner.target_url,
                        remediation='Add integrity attribute with SRI hash'
                    )
    
    # ==================== IMAGE ANALYSIS ====================
    images = soup.find_all('img')
    insecure_images = 0
    missing_alt = 0
    lazy_load_missing = 0
    
    for img in images:
        src = img.get('src') or img.get('data-src')
        if src:
            # Resolve relative URLs
            if not src.startswith(('http://', 'https://', '//', 'data:')):
                src = urljoin(scanner.target_url, src)
            
            parsed_img = urlparse(src)
            
            # Check 8: Image over HTTP (LOW - aggregate)
            if parsed_img.scheme == 'http':
                insecure_images += 1
            
            # Check 9: Missing alt attribute (INFO - aggregate)
            if not img.get('alt'):
                missing_alt += 1
            
            # Check 10: Missing lazy loading (INFO - aggregate)
            if not img.get('loading'):
                lazy_load_missing += 1
    
    if insecure_images > 0:
        scanner.add_finding(
            severity='LOW',
            category='Resource Security',
            title=f'{insecure_images} image(s) loaded over insecure HTTP',
            description=f'Found {insecure_images} images loaded without encryption',
            url=scanner.target_url,
            remediation='Serve all images over HTTPS'
        )
    
    if missing_alt > 3:  # Only report if significant
        scanner.add_finding(
            severity='INFO',
            category='Resource Security',
            title=f'{missing_alt} images missing alt attributes',
            description=f'Accessibility and SEO issue: {missing_alt} images lack alt text',
            url=scanner.target_url,
            remediation='Add descriptive alt attributes to all images'
        )
    
    if lazy_load_missing > 5:  # Only report if significant
        scanner.add_finding(
            severity='INFO',
            category='Resource Security',
            title=f'{lazy_load_missing} images without lazy loading',
            description=f'Performance issue: {lazy_load_missing} images lack loading="lazy"',
            url=scanner.target_url,
            remediation='Add loading="lazy" to below-the-fold images'
        )
    
    # ==================== IFRAME ANALYSIS ====================
    iframes = soup.find_all('iframe')
    
    for iframe in iframes:
        src = iframe.get('src')
        if src:
            parsed_iframe = urlparse(src)
            
            # Check 11: Iframe over HTTP (HIGH)
            if parsed_iframe.scheme == 'http':
                scanner.add_finding(
                    severity='HIGH',
                    category='Resource Security',
                    title=f'Iframe loaded over insecure HTTP',
                    description=f'Iframe source is unencrypted: {src[:100]}',
                    url=scanner.target_url,
                    remediation='Use HTTPS for all iframe sources'
                )
            
            # Check 12: Iframe without sandbox (MEDIUM)
            if not iframe.get('sandbox'):
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Resource Security',
                    title=f'Iframe without sandbox attribute',
                    description=f'Iframe from {parsed_iframe.netloc or "same origin"} lacks sandbox restrictions',
                    url=scanner.target_url,
                    remediation='Add sandbox attribute with appropriate permissions'
                )
    
    # ==================== FONT ANALYSIS ====================
    fonts = soup.find_all('link', rel=lambda x: x and 'font' in x.lower() if x else False)
    
    for font in fonts:
        href = font.get('href')
        if href:
            parsed_font = urlparse(href)
            
            # Check 13: Font over HTTP (LOW)
            if parsed_font.scheme == 'http':
                scanner.add_finding(
                    severity='LOW',
                    category='Resource Security',
                    title=f'Font loaded over insecure HTTP',
                    description=f'Font file loaded without encryption from {parsed_font.netloc}',
                    url=scanner.target_url,
                    remediation='Load fonts over HTTPS'
                )
