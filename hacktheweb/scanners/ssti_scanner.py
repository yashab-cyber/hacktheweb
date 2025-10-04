"""
SSTI (Server-Side Template Injection) Scanner
Detects template injection vulnerabilities in various template engines
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class SSTIScanner:
    """Scanner for Server-Side Template Injection vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize SSTI scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # SSTI payloads for different template engines
        self.ssti_payloads = {
            'jinja2': [
                '{{7*7}}',
                '{{7*\'7\'}}',
                '{{config}}',
                '{{config.items()}}',
                '{{request}}',
                '{%print(7*7)%}',
            ],
            'freemarker': [
                '${7*7}',
                '#{7*7}',
                '${7*7}{{7*7}}',
                '${class.getClassLoader()}',
            ],
            'velocity': [
                '#set($x=7*7)$x',
                '$class.inspect("java.lang.Runtime")',
            ],
            'smarty': [
                '{$smarty.version}',
                '{php}echo 7*7;{/php}',
                '{7*7}',
            ],
            'twig': [
                '{{7*7}}',
                '{{7*\'7\'}}',
                '{{_self}}',
                '{{app}}',
            ],
            'erb': [
                '<%= 7*7 %>',
                '<%= system("id") %>',
                '<%= File.open(\'/etc/passwd\').read %>',
            ],
            'tornado': [
                '{{7*7}}',
                '{%import os%}{{os.system("id")}}',
            ],
        }
        
        # Expected results for calculation payloads
        self.calculation_results = {
            '7*7': '49',
            '7*\'7\'': '7777777',
            '7*"7"': '7777777',
        }
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for SSTI vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[*] SSTI Scanner: Testing {target}")
        
        # Test forms
        if recon_data.get('forms'):
            for form in recon_data['forms']:
                await self._scan_form(target, form)
        
        # Test URL parameters
        parsed = urlparse(target)
        if parsed.query:
            await self._scan_url_params(target)
        
        return self.vulnerabilities
    
    async def _scan_form(self, target: str, form: Dict[str, Any]):
        """Test form for SSTI vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # Build form URL
        if action:
            form_url = urljoin(target, action)
        else:
            form_url = target
        
        # Test each input field
        for input_field in inputs:
            input_name = input_field.get('name', '')
            
            if not input_name:
                continue
            
            # Skip certain input types
            input_type = input_field.get('type', '').lower()
            if input_type in ['hidden', 'submit', 'button']:
                continue
            
            await self._test_ssti_form(form_url, method, input_name, inputs)
    
    async def _scan_url_params(self, url: str):
        """Test URL parameters for SSTI"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            await self._test_ssti_url(url, param_name)
    
    async def _test_ssti_form(self, url: str, method: str, param: str,
                             all_inputs: List[Dict]):
        """Test form parameter for SSTI"""
        
        # Build base data
        data = {}
        for inp in all_inputs:
            name = inp.get('name', '')
            if name:
                data[name] = inp.get('value', 'test')
        
        # Test each template engine
        for engine, payloads in self.ssti_payloads.items():
            for payload in payloads[:2]:  # Limit payloads per engine
                test_data = data.copy()
                test_data[param] = payload
                
                is_vulnerable, evidence = await self._check_ssti(url, method, test_data, payload)
                
                if is_vulnerable:
                    self.vulnerabilities.append({
                        'type': 'ssti',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'template_engine': engine,
                        'evidence': evidence,
                        'description': f'Server-Side Template Injection ({engine}) vulnerability',
                        'remediation': 'Never use user input directly in templates. Use sandboxed template engines. Implement strict input validation.',
                        'cwe': 'CWE-1336',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return  # Found SSTI, stop testing this parameter
    
    async def _test_ssti_url(self, url: str, param: str):
        """Test URL parameter for SSTI"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test simple calculation payloads
        test_payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '{7*7}']
        
        for payload in test_payloads:
            test_params = params.copy()
            test_params[param] = [payload]
            
            # Build test URL
            parsed_parts = list(parsed)
            parsed_parts[4] = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_parts)
            
            is_vulnerable, evidence = await self._check_ssti(test_url, 'GET', None, payload)
            
            if is_vulnerable:
                # Determine engine
                engine = 'unknown'
                if '{{' in payload:
                    engine = 'jinja2/twig/tornado'
                elif '${' in payload:
                    engine = 'freemarker'
                elif '<%=' in payload:
                    engine = 'erb'
                elif '{' in payload and not '{{' in payload:
                    engine = 'smarty'
                
                self.vulnerabilities.append({
                    'type': 'ssti',
                    'severity': 'critical',
                    'url': url,
                    'parameter': param,
                    'method': 'GET',
                    'payload': payload,
                    'template_engine': engine,
                    'evidence': evidence,
                    'description': f'Server-Side Template Injection vulnerability in URL parameter',
                    'remediation': 'Never use user input directly in templates. Use sandboxed engines and strict validation.',
                    'cwe': 'CWE-1336',
                    'owasp': 'A03:2021 - Injection',
                })
                return
    
    async def _check_ssti(self, url: str, method: str, data: Dict, payload: str) -> tuple:
        """Check if SSTI payload was executed"""
        try:
            if method == 'POST':
                async with self.session.post(url, data=data, timeout=10) as response:
                    content = await response.text()
            else:
                async with self.session.get(url, timeout=10) as response:
                    content = await response.text()
            
            # Check for calculation results
            if '7*7' in payload or '7*\'7\'' in payload or '7*"7"' in payload:
                # Look for result of 7*7 = 49
                if '49' in content:
                    # Make sure it's not just part of another number
                    if re.search(r'\b49\b', content):
                        return True, 'Mathematical expression evaluated: 7*7 = 49'
                
                # Look for 7777777 (string multiplication)
                if '7777777' in content:
                    return True, 'String multiplication executed: 7*"7" = 7777777'
            
            # Check for template-specific output
            template_indicators = {
                'config': r'<Config',
                'request': r'<Request',
                '_self': r'__main__',
                'smarty.version': r'Smarty',
                'app': r'<.*App.*>',
            }
            
            for indicator, pattern in template_indicators.items():
                if indicator in payload:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True, f'Template object exposed: {indicator}'
            
            # Check if payload is reflected without execution
            # (to avoid false positives)
            if payload in content:
                # Payload reflected but not executed
                return False, ''
            
        except Exception:
            pass
        
        return False, ''
