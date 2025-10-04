"""
XSS (Cross-Site Scripting) Scanner
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs
import html
from ..utils.data_loader import data_loader


class XSSScanner:
    """Scanner for XSS vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize XSS scanner"""
        self.config = config
        self.session = session
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads from data file"""
        # Load payloads from data file
        file_payloads = data_loader.load_xss_payloads()
        
        # Basic fallback payloads if file is empty
        basic_payloads = [
            # Basic payloads
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            
            # Event handlers
            '<div onmouseover=alert(1)>test</div>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            
            # Encoded payloads
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            
            # Special contexts
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '</script><script>alert(1)</script>',
            
            # DOM-based
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            
            # Polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//',
        ]
        
        # Use file payloads if available, otherwise use basic payloads
        return file_payloads if file_payloads else basic_payloads
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        
        # Scan forms
        for form in recon_data.get('forms', []):
            form_vulns = await self._scan_form(target, form)
            vulnerabilities.extend(form_vulns)
        
        # Scan URL parameters
        for param in recon_data.get('inputs', []):
            if param.get('type') == 'url_param':
                param_vulns = await self._scan_url_param(target, param)
                vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    async def _scan_form(self, base_url: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan form for XSS"""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Build form URL
        if action:
            from urllib.parse import urljoin
            form_url = urljoin(base_url, action)
        else:
            form_url = base_url
        
        # Test each input field
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            if not input_name:
                continue
            
            # Skip certain input types
            if input_field.get('type') in ['submit', 'button', 'hidden', 'file']:
                continue
            
            # Test with each payload
            for payload in self.payloads[:5]:  # Use top 5 payloads
                try:
                    # Build form data
                    form_data = {}
                    for inp in form.get('inputs', []):
                        inp_name = inp.get('name')
                        if inp_name:
                            if inp_name == input_name:
                                form_data[inp_name] = payload
                            else:
                                form_data[inp_name] = inp.get('value', 'test')
                    
                    # Send request
                    if method == 'POST':
                        async with self.session.post(form_url, data=form_data) as response:
                            content = await response.text()
                    else:
                        async with self.session.get(form_url, params=form_data) as response:
                            content = await response.text()
                    
                    # Check if payload is reflected
                    if self._is_vulnerable(payload, content):
                        vulnerabilities.append({
                            'type': 'xss',
                            'severity': 'high',
                            'url': form_url,
                            'method': method,
                            'parameter': input_name,
                            'payload': payload,
                            'evidence': self._extract_evidence(payload, content),
                            'description': f'XSS vulnerability found in form parameter "{input_name}"',
                            'remediation': 'Implement proper input validation and output encoding',
                            'cwe': 'CWE-79',
                            'owasp': 'A03:2021 - Injection',
                        })
                        break  # Found vulnerability, move to next parameter
                
                except Exception as e:
                    print(f"[!] XSS scan error: {e}")
                    continue
        
        return vulnerabilities
    
    async def _scan_url_param(self, url: str, param: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan URL parameter for XSS"""
        vulnerabilities = []
        
        param_name = param.get('name')
        if not param_name:
            return vulnerabilities
        
        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test each payload
        for payload in self.payloads[:5]:
            try:
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                # Send request
                async with self.session.get(test_url) as response:
                    content = await response.text()
                
                # Check if vulnerable
                if self._is_vulnerable(payload, content):
                    vulnerabilities.append({
                        'type': 'xss',
                        'severity': 'high',
                        'url': test_url,
                        'method': 'GET',
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': self._extract_evidence(payload, content),
                        'description': f'XSS vulnerability found in URL parameter "{param_name}"',
                        'remediation': 'Implement proper input validation and output encoding',
                        'cwe': 'CWE-79',
                        'owasp': 'A03:2021 - Injection',
                    })
                    break
            
            except Exception as e:
                print(f"[!] XSS URL param scan error: {e}")
                continue
        
        return vulnerabilities
    
    def _is_vulnerable(self, payload: str, content: str) -> bool:
        """Check if XSS payload is reflected in content"""
        # Check for exact payload reflection
        if payload in content:
            return True
        
        # Check for HTML-encoded payload
        encoded_payload = html.escape(payload)
        if encoded_payload not in content and payload in content:
            return True
        
        # Check for script execution patterns
        dangerous_patterns = [
            r'<script[^>]*>.*?alert\(1\).*?</script>',
            r'onerror\s*=\s*["\']?alert\(1\)',
            r'onload\s*=\s*["\']?alert\(1\)',
            r'javascript:alert\(1\)',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    def _extract_evidence(self, payload: str, content: str, context_length: int = 100) -> str:
        """Extract evidence of vulnerability"""
        try:
            index = content.index(payload)
            start = max(0, index - context_length)
            end = min(len(content), index + len(payload) + context_length)
            return content[start:end]
        except ValueError:
            return "Payload reflected in response"
