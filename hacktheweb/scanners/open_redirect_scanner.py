"""
Open Redirect Scanner
Detects URL redirection and header injection vulnerabilities
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class OpenRedirectScanner:
    """Scanner for Open Redirect vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize Open Redirect scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # Common redirect parameter names
        self.redirect_params = [
            'url', 'redirect', 'redirect_url', 'redirect_uri', 'return_url',
            'returnurl', 'return', 'next', 'continue', 'dest', 'destination',
            'redir', 'goto', 'target', 'view', 'out', 'link', 'page',
            'forward', 'callback', 'callback_url', 'ref', 'referrer',
        ]
        
        # Test payloads
        self.redirect_payloads = [
            'https://evil.com',
            'http://evil.com',
            '//evil.com',
            '///evil.com',
            '////evil.com',
            '/\\evil.com',
            '\\\\evil.com',
            'https:evil.com',
            'http:evil.com',
            '//google.com',
            '@evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
        ]
        
        # Detection patterns
        self.redirect_indicators = [
            'evil.com',
            'google.com',
            'Location:',
            'href=',
        ]
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for Open Redirect vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[*] Open Redirect Scanner: Testing {target}")
        
        # Test URL parameters
        parsed = urlparse(target)
        if parsed.query:
            await self._scan_url_params(target)
        
        # Test forms
        if recon_data.get('forms'):
            for form in recon_data['forms']:
                await self._scan_form(target, form)
        
        return self.vulnerabilities
    
    async def _scan_url_params(self, url: str):
        """Test URL parameters for open redirect"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            # Check if parameter looks like a redirect parameter
            if any(redir in param_name.lower() for redir in self.redirect_params):
                await self._test_redirect_param(url, param_name, 'GET')
    
    async def _scan_form(self, target: str, form: Dict[str, Any]):
        """Test form for open redirect vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # Build form URL
        if action:
            form_url = urljoin(target, action)
        else:
            form_url = target
        
        # Find redirect-like inputs
        for input_field in inputs:
            input_name = input_field.get('name', '')
            
            if not input_name:
                continue
            
            # Check if input looks like a redirect parameter
            if any(redir in input_name.lower() for redir in self.redirect_params):
                await self._test_redirect_param(form_url, input_name, method, inputs)
    
    async def _test_redirect_param(self, url: str, param: str, method: str = 'GET',
                                   all_inputs: List[Dict] = None):
        """Test parameter for open redirect"""
        
        # Build base data
        if all_inputs:
            data = {}
            for inp in all_inputs:
                name = inp.get('name', '')
                if name:
                    data[name] = inp.get('value', 'test')
        else:
            parsed = urlparse(url)
            data = parse_qs(parsed.query)
            # Convert lists to single values
            data = {k: v[0] if isinstance(v, list) else v for k, v in data.items()}
        
        for payload in self.redirect_payloads:
            if method == 'GET':
                test_data = data.copy()
                test_data[param] = payload
                
                # Build test URL
                parsed = urlparse(url)
                parsed_parts = list(parsed)
                parsed_parts[4] = urlencode(test_data)
                test_url = urlunparse(parsed_parts)
                
                await self._check_redirect(test_url, 'GET', None, param, payload)
            
            else:  # POST
                test_data = data.copy()
                test_data[param] = payload
                
                await self._check_redirect(url, 'POST', test_data, param, payload)
    
    async def _check_redirect(self, url: str, method: str, data: Dict, 
                             param: str, payload: str):
        """Check if redirect is vulnerable"""
        try:
            # Don't follow redirects automatically
            if method == 'POST':
                async with self.session.post(url, data=data, allow_redirects=False, timeout=10) as response:
                    await self._analyze_redirect_response(response, url, param, payload, method)
            else:
                async with self.session.get(url, allow_redirects=False, timeout=10) as response:
                    await self._analyze_redirect_response(response, url, param, payload, method)
        
        except Exception:
            pass
    
    async def _analyze_redirect_response(self, response, url: str, param: str, 
                                        payload: str, method: str):
        """Analyze response for redirect vulnerability"""
        
        # Check for redirect status codes
        if response.status in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            
            # Check if our payload is in the Location header
            if 'evil.com' in location or 'google.com' in location:
                self.vulnerabilities.append({
                    'type': 'open_redirect',
                    'severity': 'medium',
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'payload': payload,
                    'evidence': f'Location header: {location}',
                    'description': 'Open Redirect vulnerability - Unvalidated redirect to external site',
                    'remediation': 'Validate redirect URLs against a whitelist. Use relative URLs when possible.',
                    'cwe': 'CWE-601',
                    'owasp': 'A01:2021 - Broken Access Control',
                })
        
        # Check for meta refresh or JavaScript redirect
        else:
            try:
                content = await response.text()
                
                # Check for meta refresh
                meta_refresh = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']0;url=([^"\']+)["\']', 
                                       content, re.IGNORECASE)
                if meta_refresh:
                    redirect_url = meta_refresh.group(1)
                    if 'evil.com' in redirect_url or 'google.com' in redirect_url:
                        self.vulnerabilities.append({
                            'type': 'open_redirect',
                            'severity': 'medium',
                            'url': url,
                            'parameter': param,
                            'method': method,
                            'payload': payload,
                            'evidence': f'Meta refresh: {redirect_url}',
                            'description': 'Open Redirect vulnerability via meta refresh',
                            'remediation': 'Validate redirect URLs against a whitelist.',
                            'cwe': 'CWE-601',
                            'owasp': 'A01:2021 - Broken Access Control',
                        })
                
                # Check for JavaScript redirect
                js_redirect = re.search(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']*evil\.com[^"\']*)["\']', 
                                      content, re.IGNORECASE)
                if js_redirect:
                    redirect_url = js_redirect.group(1)
                    self.vulnerabilities.append({
                        'type': 'open_redirect',
                        'severity': 'medium',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': f'JavaScript redirect: {redirect_url}',
                        'description': 'Open Redirect vulnerability via JavaScript',
                        'remediation': 'Validate redirect URLs against a whitelist.',
                        'cwe': 'CWE-601',
                        'owasp': 'A01:2021 - Broken Access Control',
                    })
                
                # Check for XSS via javascript: protocol
                if 'javascript:' in payload and 'javascript:alert' in content.lower():
                    self.vulnerabilities.append({
                        'type': 'open_redirect',
                        'severity': 'high',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': 'JavaScript protocol injection detected',
                        'description': 'Open Redirect with XSS via javascript: protocol',
                        'remediation': 'Validate redirect URLs. Block javascript: and data: protocols.',
                        'cwe': 'CWE-601',
                        'owasp': 'A01:2021 - Broken Access Control',
                    })
            
            except Exception:
                pass
