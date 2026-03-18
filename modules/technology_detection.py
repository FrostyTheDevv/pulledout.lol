"""
Technology Detection and Fingerprinting
Detects frameworks, libraries, servers, and generates findings for each
"""

import requests
import re
from bs4 import BeautifulSoup

def detect_technologies(scanner):
    """Detect and report every technology used"""
    
    try:
        # Use cached response to avoid duplicate requests (PERFORMANCE BOOST)
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text.lower()
        
        # Server detection
        technologies = {
            'nginx': ('Server', 'nginx'),
            'apache': ('Server', 'Apache'),
            'iis': ('Server', 'Microsoft IIS'),
            'cloudflare': ('CDN', 'Cloudflare'),
            'litespeed': ('Server', 'LiteSpeed'),
            'tomcat': ('Server', 'Apache Tomcat'),
        }
        
        server = headers.get('server', '').lower()
        for tech, (cat, name) in technologies.items():
            if tech in server:
                scanner.add_finding(
                    severity='INFO',
                    category='Information Disclosure',
                    title=f'{cat} technology detected: {name}',
                    description=f'Server identified as {name}',
                    url=scanner.target_url,
                    remediation='Consider obfuscating server identity'
                )
        
        # Framework detection
        frameworks = {
            'wordpress': 'WordPress CMS',
            'wp-content': 'WordPress CMS',
            'wp-includes': 'WordPress CMS',
            'drupal': 'Drupal CMS',
            'joomla': 'Joomla CMS',
            'django': 'Django Framework',
            'laravel': 'Laravel Framework',
            'react': 'React Library',
            'angular': 'Angular Framework',
            'vue': 'Vue.js Framework',
            'bootstrap': 'Bootstrap Framework',
            'jquery': 'jQuery Library',
        }
        
        for tech, name in frameworks.items():
            if tech in html:
                scanner.add_finding(
                    severity='INFO',
                    category='Information Disclosure',
                    title=f'Framework detected: {name}',
                    description=f'Application uses {name}',
                    url=scanner.target_url,
                    remediation='Ensure framework is up to date'
                )
        
        # Analytics and tracking
        tracking = {
            'google-analytics': 'Google Analytics',
            'gtag': 'Google Tag Manager',
            'facebook.com/tr': 'Facebook Pixel',
            'hotjar': 'Hotjar',
            'segment.com': 'Segment',
        }
        
        for tracker, name in tracking.items():
            if tracker in html:
                scanner.add_finding(
                    severity='INFO',
                    category='Information Disclosure',
                    title=f'Tracking detected: {name}',
                    description=f'Site uses {name} tracking',
                    url=scanner.target_url,
                    remediation='Ensure compliance with privacy regulations'
                )
        
        # Check for common vulnerable libraries
        vulnerable_patterns = {
            r'jquery-(\d+\.)?1\.': 'jQuery 1.x (outdated)',
            r'jquery-(\d+\.)?2\.': 'jQuery 2.x (outdated)',
            r'angular@1\.': 'AngularJS 1.x (end of life)',
            r'bootstrap@3\.': 'Bootstrap 3 (outdated)',
        }
        
        for pattern, desc in vulnerable_patterns.items():
            if re.search(pattern, html):
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Information Disclosure',
                    title=f'Outdated library: {desc}',
                    description=f'Detected {desc}',
                    url=scanner.target_url,
                    remediation='Update to latest version'
                )
        
        # Check for development artifacts
        dev_artifacts = {
            'sourcemappingurl': 'Source map exposed',
            '.map': 'JavaScript source map',
            'webpack://': 'Webpack configuration exposed',
            'console.log': 'Debug logging in production',
            'debugger;': 'JavaScript debugger statements',
        }
        
        for artifact, desc in dev_artifacts.items():
            if artifact in html:
                scanner.add_finding(
                    severity='LOW',
                    category='Information Disclosure',
                    title=f'Development artifact: {desc}',
                    description=f'Found {desc} in production',
                    url=scanner.target_url,
                    remediation='Remove development artifacts from production'
                )
        
    except Exception as e:
        pass
