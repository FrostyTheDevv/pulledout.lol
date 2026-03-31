"""
Scan Phase Tracking Configuration
Maps all security scanning phases to progress percentages and display info
"""

SCAN_PHASES = [
    # Phase 1: Discovery & Reconnaissance (0-20%)
    {
        'id': 1, 'name': 'Page Discovery', 'progress': 5, 'icon': 'search', 'category': 'discovery',
        'actions': ['Crawling internal links', 'Testing common paths', 'Discovering sitemap', 'Analyzing robots.txt', 'Mapping site structure']
    },
    {
        'id': 2, 'name': 'Transport Security', 'progress': 8, 'icon': 'shield', 'category': 'discovery',
        'actions': ['Checking HTTPS enforcement', 'Testing HTTP to HTTPS redirect', 'Analyzing mixed content', 'Verifying HSTS headers', 'Testing protocol downgrade']
    },
    {
        'id': 3, 'name': 'SSL/TLS Configuration', 'progress': 11, 'icon': 'lock', 'category': 'discovery',
        'actions': ['Validating certificate chain', 'Testing cipher suites', 'Checking protocol versions', 'Analyzing certificate expiry', 'Testing weak ciphers']
    },
    {
        'id': 4, 'name': 'Discovery & Hygiene', 'progress': 14, 'icon': 'clipboard', 'category': 'discovery',
        'actions': ['Scanning backup files', 'Detecting version control leaks', 'Finding debug endpoints', 'Testing directory listings', 'Checking error pages']
    },
    {
        'id': 5, 'name': 'Technology Detection', 'progress': 17, 'icon': 'cpu', 'category': 'discovery',
        'actions': ['Fingerprinting web server', 'Detecting frameworks', 'Identifying CMS platforms', 'Analyzing response headers', 'Detecting JavaScript libraries']
    },
    {
        'id': 6, 'name': 'HTTP Security Analysis', 'progress': 20, 'icon': 'activity', 'category': 'discovery',
        'actions': ['Testing HTTP methods', 'Analyzing security headers', 'Checking CORS configuration', 'Testing OPTIONS verb', 'Verifying cache control']
    },
    
    # Phase 2: Infrastructure Scanning (20-35%)
    {
        'id': 7, 'name': 'Server Configuration', 'progress': 22, 'icon': 'server', 'category': 'infrastructure',
        'actions': ['Testing server info disclosure', 'Checking default pages', 'Analyzing error messages', 'Testing admin interfaces', 'Detecting misconfigurations']
    },
    {
        'id': 8, 'name': 'Network Reconnaissance', 'progress': 25, 'icon': 'globe', 'category': 'infrastructure',
        'actions': ['DNS enumeration', 'Subdomain discovery', 'Port scanning', 'Zone transfer attempts', 'Network mapping']
    },
    {
        'id': 9, 'name': 'Exposed Files Scanner', 'progress': 28, 'icon': 'folder', 'category': 'infrastructure',
        'actions': ['Scanning .env files', 'Testing config files', 'Finding SQL dumps', 'Detecting log files', 'Checking backup archives']
    },
    {
        'id': 10, 'name': 'Cloud Storage Detection', 'progress': 31, 'icon': 'cloud', 'category': 'infrastructure',
        'actions': ['Testing S3 buckets', 'Checking Azure blobs', 'Scanning GCS buckets', 'Detecting exposed CDNs', 'Testing bucket permissions']
    },
    {
        'id': 11, 'name': 'Database Exposure', 'progress': 34, 'icon': 'database', 'category': 'infrastructure',
        'actions': ['Scanning MongoDB', 'Testing MySQL exposure', 'Checking PostgreSQL', 'Testing Redis', 'Detecting Elasticsearch']
    },
    
    # Phase 3: CMS & Platform Testing (35-50%)
    {
        'id': 12, 'name': 'CMS Exploitation', 'progress': 37, 'icon': 'zap', 'category': 'exploitation',
        'actions': ['Testing WordPress', 'Scanning Drupal', 'Checking Joomla', 'Plugin enumeration', 'Theme vulnerability testing']
    },
    {
        'id': 13, 'name': 'Database Intrusion', 'progress': 40, 'icon': 'terminal', 'category': 'exploitation',
        'actions': ['Unauthorized access attempts', 'Testing default credentials', 'Brute force testing', 'Authentication bypass', 'Privilege escalation']
    },
    {
        'id': 14, 'name': 'Database Penetration', 'progress': 43, 'icon': 'crosshair', 'category': 'exploitation',
        'actions': ['Schema extraction', 'Data exfiltration', 'Table enumeration', 'Column discovery', 'Row dumping']
    },
    {
        'id': 15, 'name': 'SQL Injection Testing', 'progress': 46, 'icon': 'code', 'category': 'exploitation',
        'actions': ['Error-based injection', 'Union-based injection', 'Boolean blind testing', 'Time-based blind', 'Stacked queries']
    },
    {
        'id': 16, 'name': 'Advanced SQLi Extraction', 'progress': 49, 'icon': 'download', 'category': 'exploitation',
        'actions': ['Database version extraction', 'User enumeration', 'Password hash dumping', 'File read attempts', 'Command execution']
    },
    
    # Phase 4: Web Application Attacks (50-65%)
    {
        'id': 17, 'name': 'XSS Vulnerabilities', 'progress': 52, 'icon': 'alert-triangle', 'category': 'web-attacks',
        'actions': ['Reflected XSS testing', 'Stored XSS detection', 'DOM-based XSS', 'Testing input sanitization', 'Context-aware payloads']
    },
    {
        'id': 18, 'name': 'Authentication Bypass', 'progress': 55, 'icon': 'unlock', 'category': 'web-attacks',
        'actions': ['Testing login forms', 'Session fixation', 'Password reset flaws', 'OAuth misconfiguration', 'JWT vulnerabilities']
    },
    {
        'id': 19, 'name': 'Command Injection & RCE', 'progress': 58, 'icon': 'terminal', 'category': 'web-attacks',
        'actions': ['OS command injection', 'Code execution testing', 'Shell metacharacters', 'File upload exploitation', 'Deserialization attacks']
    },
    {
        'id': 20, 'name': 'Data Harvesting', 'progress': 61, 'icon': 'layers', 'category': 'web-attacks',
        'actions': ['Extracting metadata', 'Harvesting emails', 'Finding API keys', 'Collecting credentials', 'Discovering tokens']
    },
    {
        'id': 21, 'name': 'Credential Extraction', 'progress': 64, 'icon': 'key', 'category': 'web-attacks',
        'actions': ['Password field analysis', 'Auto-complete extraction', 'Browser storage review', 'Hidden credentials', 'Hardcoded secrets']
    },
    
    # Phase 5: Advanced Exploitation (65-80%)
    {
        'id': 22, 'name': 'Template Injection (SSTI)', 'progress': 67, 'icon': 'file-text', 'category': 'advanced',
        'actions': ['Jinja2 testing', 'Twig exploitation', 'Freemarker testing', 'Velocity checks', 'Expression evaluation']
    },
    {
        'id': 23, 'name': 'NoSQL Injection', 'progress': 70, 'icon': 'database', 'category': 'advanced',
        'actions': ['MongoDB injection', 'CouchDB testing', 'Cassandra queries', 'Operator injection', 'JSON manipulation']
    },
    {
        'id': 24, 'name': 'SSRF Testing', 'progress': 73, 'icon': 'link-2', 'category': 'advanced',
        'actions': ['Internal network scanning', 'Cloud metadata access', 'Port scanning', 'Protocol smuggling', 'Blind SSRF detection']
    },
    {
        'id': 25, 'name': 'Path Traversal', 'progress': 76, 'icon': 'folder-open', 'category': 'advanced',
        'actions': ['Directory traversal', 'File inclusion testing', 'LFI exploitation', 'RFI detection', 'Null byte injection']
    },
    {
        'id': 26, 'name': 'Session Hijacking', 'progress': 79, 'icon': 'user-x', 'category': 'advanced',
        'actions': ['Session fixation', 'Cookie theft testing', 'CSRF token bypass', 'Session prediction', 'Replay attacks']
    },
    
    # Phase 6: Per-Page Deep Scans (80-95%)
    {
        'id': 27, 'name': 'Security Headers Analysis', 'progress': 81, 'icon': 'file-check', 'category': 'per-page',
        'actions': ['CSP validation', 'X-Frame-Options', 'HSTS verification', 'Referrer-Policy', 'Permissions-Policy']
    },
    {
        'id': 28, 'name': 'Cookie Security Audit', 'progress': 83, 'icon': 'shield-check', 'category': 'per-page',
        'actions': ['Secure flag testing', 'HttpOnly validation', 'SameSite attribute', 'Cookie scope analysis', 'Session cookies']
    },
    {
        'id': 29, 'name': 'Resource Security', 'progress': 85, 'icon': 'package', 'category': 'per-page',
        'actions': ['SRI validation', 'Third-party resources', 'CDN security', 'Resource integrity', 'External dependencies']
    },
    {
        'id': 30, 'name': 'Form Security Analysis', 'progress': 87, 'icon': 'edit', 'category': 'per-page',
        'actions': ['Input validation', 'CSRF protection', 'Autocomplete review', 'Hidden field analysis', 'Form submission testing']
    },
    {
        'id': 31, 'name': 'Deep Data Extraction', 'progress': 89, 'icon': 'hard-drive', 'category': 'per-page',
        'actions': ['Source code analysis', 'Comment extraction', 'Metadata collection', 'Sensitive data discovery', 'Endpoint mapping']
    },
    {
        'id': 32, 'name': 'API Discovery & Testing', 'progress': 91, 'icon': 'git-branch', 'category': 'per-page',
        'actions': ['API endpoint discovery', 'GraphQL testing', 'REST API analysis', 'Authentication testing', 'Rate limiting checks']
    },
    {
        'id': 33, 'name': 'Client-Side Security', 'progress': 93, 'icon': 'monitor', 'category': 'per-page',
        'actions': ['JavaScript analysis', 'DOM XSS testing', 'Prototype pollution', 'Client storage review', 'WebSocket security']
    },
    {
        'id': 34, 'name': 'Information Disclosure', 'progress': 94, 'icon': 'alert-circle', 'category': 'per-page',
        'actions': ['Version disclosure', 'Stack traces', 'Debug information', 'Internal IPs', 'Email addresses']
    },
    {
        'id': 35, 'name': 'Performance & Availability', 'progress': 95, 'icon': 'trending-up', 'category': 'per-page',
        'actions': ['DoS vulnerability testing', 'Resource exhaustion', 'Rate limit bypass', 'Slowloris testing', 'XML bomb detection']
    },
    {
        'id': 36, 'name': 'Maximum Coverage Scan', 'progress': 97, 'icon': 'target', 'category': 'per-page',
        'actions': ['Comprehensive fuzzing', 'Edge case testing', 'Boundary analysis', 'Encoding variations', 'Full payload matrix']
    },
    
    # Phase 7: Finalization (95-100%)
    {
        'id': 37, 'name': 'Advanced Vulnerability Scans', 'progress': 98, 'icon': 'search', 'category': 'finalization',
        'actions': ['CVE cross-referencing', 'Zero-day detection', 'Logic flaw analysis', 'Business logic testing', 'Report generation']
    },
]

CATEGORY_INFO = {
    'discovery': {
        'name': 'Discovery & Reconnaissance',
        'description': 'Initial reconnaissance and information gathering'
    },
    'infrastructure': {
        'name': 'Infrastructure Scanning',
        'description': 'Server and infrastructure security assessment'
    },
    'exploitation': {
        'name': 'Active Exploitation',
        'description': 'Active penetration testing and exploitation'
    },
    'web-attacks': {
        'name': 'Web Application Attacks',
        'description': 'Common web vulnerability testing'
    },
    'advanced': {
        'name': 'Advanced Techniques',
        'description': 'Advanced attack vectors and techniques'
    },
    'per-page': {
        'name': 'Deep Page Analysis',
        'description': 'Comprehensive per-page security audit'
    },
    'finalization': {
        'name': 'Finalization',
        'description': 'Final checks and report generation'
    }
}

def get_phase_by_progress(progress):
    """Get the current phase based on progress percentage"""
    for phase in reversed(SCAN_PHASES):
        if progress >= phase['progress']:
            return phase
    return SCAN_PHASES[0]

def get_completed_phases(progress):
    """Get list of completed phase IDs"""
    return [p['id'] for p in SCAN_PHASES if p['progress'] <= progress]

def get_active_phase(progress):
    """Get the currently active phase"""
    completed = get_completed_phases(progress)
    for phase in SCAN_PHASES:
        if phase['id'] not in completed:
            return phase
    return SCAN_PHASES[-1]
