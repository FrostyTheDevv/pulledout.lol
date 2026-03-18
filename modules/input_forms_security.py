"""
SawSap - Input/Forms Security Module
Comprehensive form and input field security analysis
Target: 7+ findings per page with forms (matching professional scanner)
"""

from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

def check_input_forms_security(scanner):
    """
    Analyze forms and input fields for security vulnerabilities
    Integrates with scanner object to add findings
    """
    
    try:
        response = scanner.session.get(scanner.target_url, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.content, 'html.parser')
    except:
        return
    
    # Find all forms
    forms = soup.find_all('form')
    
    if not forms:
        # No forms found - report as INFO
        scanner.add_finding(
            severity='INFO',
            category='Input / Forms',
            title='No forms detected on page',
            description='No HTML forms found on this page',
            url=scanner.target_url,
            remediation='If forms are dynamically loaded, ensure they follow security best practices'
        )
        return
    
    for i, form in enumerate(forms, 1):
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        form_id = form.get('id', f'form-{i}')
        
        # Check 1: Form without CSRF protection (MEDIUM)
        csrf_found = False
        csrf_patterns = ['csrf', '_token', 'authenticity_token', 'anti-forgery', '__RequestVerificationToken']
        for input_field in form.find_all('input'):
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            if any(pattern in input_name for pattern in csrf_patterns) or input_type == 'hidden' and 'token' in input_name:
                csrf_found = True
                break
        
        if not csrf_found and form_method == 'post':
            scanner.add_finding(
                severity='MEDIUM',
                category='Input / Forms',
                title=f'Form missing CSRF protection',
                description=f'Form #{i} ({form_id}) appears to lack CSRF token protection. POST forms without CSRF tokens are vulnerable to Cross-Site Request Forgery attacks.',
                url=scanner.target_url,
                remediation='Add CSRF token to all POST forms. Use framework-provided CSRF protection (Django, Flask-WTF, etc.)'
            )
        
        # Check 2: Form action to external domain (MEDIUM)
        if form_action:
            try:
                parsed_form_action = urlparse(form_action)
                parsed_url = urlparse(scanner.target_url)
                if parsed_form_action.netloc and parsed_form_action.netloc != parsed_url.netloc:
                    scanner.add_finding(
                        severity='MEDIUM',
                        category='Input / Forms',
                        title=f'Form submits to external domain',
                        description=f'Form #{i} submits data to external domain: {parsed_form_action.netloc}. This may leak sensitive user data.',
                        url=scanner.target_url,
                        remediation='Avoid submitting forms to external domains. Keep form processing on your own domain.'
                    )
            except:
                pass
        
        # Check 3: Form over HTTP (HIGH severity if found)
        if form_action and form_action.startswith('http://'):
            scanner.add_finding(
                severity='HIGH',
                category='Input / Forms',
                title=f'Form submits over insecure HTTP',
                description=f'Form #{i} submits data over unencrypted HTTP connection: {form_action}',
                url=scanner.target_url,
                remediation='Change form action to HTTPS to protect submitted data in transit'
            )
        
        # Analyze individual input fields
        inputs = form.find_all(['input', 'textarea'])
        password_fields = [inp for inp in inputs if inp.get('type', '') == 'password']
        
        # Check 4: Password field without autocomplete="off" (MEDIUM)
        for pwd_field in password_fields:
            autocomplete = pwd_field.get('autocomplete', '').lower()
            field_name = pwd_field.get('name', 'password')
            if autocomplete not in ['off', 'new-password', 'current-password']:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Input / Forms',
                    title=f'Password field allows autocomplete',
                    description=f'Password input "{field_name}" in form #{i} does not disable autocomplete. Browsers may store passwords insecurely.',
                    url=scanner.target_url,
                    remediation='Add autocomplete="off" or autocomplete="new-password" to password fields'
                )
        
        # Check 5: Sensitive inputs with autocomplete enabled (LOW)
        sensitive_names = ['ssn', 'social-security', 'credit-card', 'card-number', 'cvv', 'ccv', 'account', 'routing']
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            autocomplete = input_field.get('autocomplete', '').lower()
            
            if any(sens in input_name for sens in sensitive_names) and autocomplete not in ['off', 'false']:
                scanner.add_finding(
                    severity='LOW',
                    category='Input / Forms',
                    title=f'Sensitive input field allows autocomplete',
                    description=f'Input field "{input_name}" in form #{i} may contain sensitive data but allows autocomplete',
                    url=scanner.target_url,
                    remediation='Add autocomplete="off" to sensitive input fields like SSN, credit card numbers, etc.'
                )
        
        # Check 6: Hidden inputs (may contain secrets) (LOW)
        hidden_inputs = [inp for inp in inputs if inp.get('type', '') == 'hidden']
        for hidden in hidden_inputs:
            hidden_name = hidden.get('name', 'hidden')
            hidden_value = hidden.get('value', '')
            
            # Check if hidden field might contain sensitive data
            is_token = any(tok in hidden_name.lower() for tok in ['token', 'csrf', 'nonce', 'authenticity'])
            if not is_token and len(hidden_value) > 10:
                scanner.add_finding(
                    severity='LOW',
                    category='Input / Forms',
                    title=f'Hidden input with non-token data',
                    description=f'Form #{i} contains hidden input "{hidden_name}" with value that may expose data in HTML source',
                    url=scanner.target_url,
                    remediation='Avoid storing sensitive data in hidden fields. Use server-side session storage instead.'
                )
                break  # Only report once per form
        
        # Check 7: File upload without type restrictions (MEDIUM)
        file_inputs = [inp for inp in inputs if inp.get('type', '') == 'file']
        for file_input in file_inputs:
            accept_attr = file_input.get('accept', '')
            if not accept_attr:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Input / Forms',
                    title=f'File upload without type restrictions',
                    description=f'Form #{i} has file upload input without "accept" attribute. May allow malicious file uploads.',
                    url=scanner.target_url,
                    remediation='Add accept attribute to restrict file types. Validate file types server-side.'
                )
        
        # Check 8: Forms using GET method for sensitive data (MEDIUM)
        if form_method == 'get':
            has_sensitive = False
            for inp in inputs:
                input_type = inp.get('type', 'text').lower()
                input_name = inp.get('name', '').lower()
                if input_type == 'password' or any(sens in input_name for sens in ['password', 'pwd', 'ssn', 'credit']):
                    has_sensitive = True
                    break
            
            if has_sensitive:
                scanner.add_finding(
                    severity='MEDIUM',
                    category='Input / Forms',
                    title=f'Sensitive form uses GET method',
                    description=f'Form #{i} contains sensitive fields but uses GET method. Data will appear in URL and server logs.',
                    url=scanner.target_url,
                    remediation='Change form method to POST for any forms containing passwords or sensitive data'
                )
    
    # Check 9: Input fields outside forms (INFO)
    all_page_inputs = soup.find_all(['input', 'textarea'])
    orphan_inputs = []
    for input_field in all_page_inputs:
        if not input_field.find_parent('form'):
            input_type = input_field.get('type', 'text')
            if input_type not in ['hidden', 'button', 'submit']:
                orphan_inputs.append(input_type)
    
    if orphan_inputs and len(orphan_inputs) >= 2:
        scanner.add_finding(
            severity='INFO',
            category='Input / Forms',
            title=f'Input fields outside forms detected',
            description=f'Found {len(orphan_inputs)} input field(s) not wrapped in <form> tags. May indicate JavaScript-based form handling.',
            url=scanner.target_url,
            remediation='Ensure all inputs are in proper <form> tags or use data-* attributes for JS frameworks'
        )
