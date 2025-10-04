"""
IDOR (Insecure Direct Object Reference) Scanner
Detects access control vulnerabilities and unauthorized access
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class IDORScanner:
    """Scanner for Insecure Direct Object Reference vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize IDOR scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # Common ID parameter names
        self.id_params = [
            'id', 'user_id', 'userid', 'uid', 'user',
            'account', 'account_id', 'acc_id',
            'file', 'file_id', 'doc', 'document', 'doc_id',
            'order', 'order_id', 'transaction', 'trans_id',
            'profile', 'profile_id', 'page', 'page_id',
            'item', 'item_id', 'product', 'product_id',
            'post', 'post_id', 'comment', 'comment_id',
            'invoice', 'invoice_id', 'ticket', 'ticket_id',
        ]
        
        # Test values for ID manipulation
        self.test_values = {
            'increment': lambda x: str(int(x) + 1) if x.isdigit() else x,
            'decrement': lambda x: str(int(x) - 1) if x.isdigit() and int(x) > 0 else x,
            'zero': lambda x: '0',
            'negative': lambda x: '-1',
            'high_value': lambda x: '99999',
            'guid_manipulation': lambda x: self._manipulate_guid(x),
        }
        
        # Sensitive data patterns in responses
        self.sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'api_key': r'api[_-]?key[\s:=]+[\'"]?([a-zA-Z0-9_\-]+)[\'"]?',
            'password': r'password[\s:=]+[\'"]?([^\'"\s]+)[\'"]?',
            'token': r'token[\s:=]+[\'"]?([a-zA-Z0-9_\-\.]+)[\'"]?',
        }
        
    def _manipulate_guid(self, guid: str) -> str:
        """Manipulate GUID/UUID values"""
        if len(guid) == 36 and guid.count('-') == 4:
            # Try changing last character
            return guid[:-1] + ('0' if guid[-1] != '0' else '1')
        return guid
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for IDOR vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[*] IDOR Scanner: Testing {target}")
        
        # Test URL parameters
        parsed = urlparse(target)
        if parsed.query:
            await self._scan_url_params(target)
        
        # Test forms with ID fields
        if recon_data.get('forms'):
            for form in recon_data['forms']:
                await self._scan_form(target, form)
        
        # Test common endpoints with ID manipulation
        await self._scan_common_endpoints(target)
        
        return self.vulnerabilities
    
    async def _scan_url_params(self, url: str):
        """Test URL parameters for IDOR"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name, param_values in params.items():
            # Check if parameter looks like an ID
            if any(id_name in param_name.lower() for id_name in self.id_params):
                original_value = param_values[0] if param_values else ''
                
                # Get baseline response
                baseline_response = await self._get_response(url, 'GET')
                if not baseline_response:
                    continue
                
                baseline_content, baseline_status = baseline_response
                
                # Test different ID manipulations
                for test_name, test_func in self.test_values.items():
                    new_value = test_func(original_value)
                    
                    if new_value == original_value:
                        continue
                    
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [new_value]
                    
                    parsed_parts = list(parsed)
                    parsed_parts[4] = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed_parts)
                    
                    # Test manipulated URL
                    test_response = await self._get_response(test_url, 'GET')
                    if not test_response:
                        continue
                    
                    test_content, test_status = test_response
                    
                    # Analyze response
                    is_vulnerable = await self._analyze_idor_response(
                        baseline_content, baseline_status,
                        test_content, test_status,
                        url, param_name, original_value, new_value
                    )
                    
                    if is_vulnerable:
                        break  # Found vulnerability, no need to test more
    
    async def _scan_form(self, target: str, form: Dict[str, Any]):
        """Test form for IDOR vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # Build form URL
        if action:
            form_url = urljoin(target, action)
        else:
            form_url = target
        
        # Find ID-like inputs
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_value = input_field.get('value', '')
            
            if not input_name or not input_value:
                continue
            
            # Check if input looks like an ID
            if any(id_name in input_name.lower() for id_name in self.id_params):
                # Build form data
                data = {}
                for inp in inputs:
                    name = inp.get('name', '')
                    value = inp.get('value', 'test')
                    if name:
                        data[name] = value
                
                # Get baseline
                baseline_response = await self._get_response(form_url, method, data)
                if not baseline_response:
                    continue
                
                baseline_content, baseline_status = baseline_response
                
                # Test manipulations
                for test_name, test_func in self.test_values.items():
                    test_data = data.copy()
                    test_data[input_name] = test_func(input_value)
                    
                    if test_data[input_name] == input_value:
                        continue
                    
                    test_response = await self._get_response(form_url, method, test_data)
                    if not test_response:
                        continue
                    
                    test_content, test_status = test_response
                    
                    is_vulnerable = await self._analyze_idor_response(
                        baseline_content, baseline_status,
                        test_content, test_status,
                        form_url, input_name, input_value, test_data[input_name]
                    )
                    
                    if is_vulnerable:
                        break
    
    async def _scan_common_endpoints(self, target: str):
        """Scan common API/web endpoints for IDOR"""
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common endpoint patterns
        endpoints = [
            '/api/user/{id}',
            '/api/users/{id}',
            '/api/profile/{id}',
            '/api/account/{id}',
            '/user/{id}',
            '/profile/{id}',
            '/account/{id}',
            '/api/order/{id}',
            '/api/document/{id}',
        ]
        
        # Test with sequential IDs
        test_ids = ['1', '2', '100', '1000']
        
        for endpoint_template in endpoints[:3]:  # Limit to avoid too many requests
            for test_id in test_ids[:2]:  # Test 2 IDs per endpoint
                endpoint = endpoint_template.replace('{id}', test_id)
                test_url = urljoin(base_url, endpoint)
                
                try:
                    async with self.session.get(test_url, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for sensitive data exposure
                            for pattern_name, pattern in self.sensitive_patterns.items():
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                if matches:
                                    self.vulnerabilities.append({
                                        'type': 'idor',
                                        'severity': 'high',
                                        'url': test_url,
                                        'parameter': 'id',
                                        'method': 'GET',
                                        'evidence': f'Exposed {pattern_name}: {matches[0][:50]}...',
                                        'description': f'IDOR vulnerability - Exposed {pattern_name} in predictable endpoint',
                                        'remediation': 'Implement proper access control checks. Use non-sequential IDs or verify user authorization.',
                                        'cwe': 'CWE-639',
                                        'owasp': 'A01:2021 - Broken Access Control',
                                    })
                                    break
                
                except Exception:
                    pass
    
    async def _analyze_idor_response(self, baseline_content: str, baseline_status: int,
                                    test_content: str, test_status: int,
                                    url: str, param: str, 
                                    original_value: str, test_value: str) -> bool:
        """Analyze responses for IDOR indicators"""
        
        # If test returns 200 but different content, likely IDOR
        if test_status == 200 and baseline_status == 200:
            # Check if content is different (different user/object)
            if len(test_content) > 100 and test_content != baseline_content:
                # Check similarity (should be structurally similar but with different data)
                similarity = self._calculate_similarity(baseline_content, test_content)
                
                # If 30-90% similar, likely same structure but different data
                if 0.3 <= similarity <= 0.9:
                    # Check for sensitive data in response
                    sensitive_found = []
                    for pattern_name, pattern in self.sensitive_patterns.items():
                        if re.search(pattern, test_content, re.IGNORECASE):
                            sensitive_found.append(pattern_name)
                    
                    evidence = f'Modified {param} from {original_value} to {test_value}. '
                    evidence += f'Response similarity: {similarity:.2%}. '
                    if sensitive_found:
                        evidence += f'Sensitive data found: {", ".join(sensitive_found)}'
                    
                    self.vulnerabilities.append({
                        'type': 'idor',
                        'severity': 'high' if sensitive_found else 'medium',
                        'url': url,
                        'parameter': param,
                        'method': 'GET',
                        'original_value': original_value,
                        'test_value': test_value,
                        'evidence': evidence,
                        'description': 'IDOR vulnerability - Unauthorized access to other objects/users',
                        'remediation': 'Implement proper authorization checks. Verify user has permission to access requested resource.',
                        'cwe': 'CWE-639',
                        'owasp': 'A01:2021 - Broken Access Control',
                    })
                    return True
        
        # If baseline was 403/401 but test is 200, clear IDOR
        elif baseline_status in [401, 403] and test_status == 200:
            self.vulnerabilities.append({
                'type': 'idor',
                'severity': 'critical',
                'url': url,
                'parameter': param,
                'method': 'GET',
                'original_value': original_value,
                'test_value': test_value,
                'evidence': f'Baseline: {baseline_status}, Test: {test_status}. Authorization bypass detected.',
                'description': 'IDOR vulnerability - Authorization bypass',
                'remediation': 'Implement proper authorization checks for all resources.',
                'cwe': 'CWE-639',
                'owasp': 'A01:2021 - Broken Access Control',
            })
            return True
        
        return False
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate simple similarity between two texts"""
        if not text1 or not text2:
            return 0.0
        
        # Simple word-based similarity
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0
    
    async def _get_response(self, url: str, method: str = 'GET', 
                           data: Dict = None) -> tuple:
        """Get HTTP response"""
        try:
            if method == 'POST':
                async with self.session.post(url, data=data, timeout=10) as response:
                    content = await response.text()
                    return content, response.status
            else:
                async with self.session.get(url, timeout=10) as response:
                    content = await response.text()
                    return content, response.status
        
        except Exception:
            return None
