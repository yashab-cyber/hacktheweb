"""
SSRF (Server-Side Request Forgery) Scanner
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs


class SSRFScanner:
    """Scanner for SSRF vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize SSRF scanner"""
        self.config = config
        self.session = session
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[Dict[str, str]]:
        """Load SSRF payloads"""
        return [
            # Local network
            {'payload': 'http://127.0.0.1', 'type': 'localhost'},
            {'payload': 'http://localhost', 'type': 'localhost'},
            {'payload': 'http://0.0.0.0', 'type': 'localhost'},
            {'payload': 'http://[::1]', 'type': 'localhost-ipv6'},
            
            # Internal IP ranges
            {'payload': 'http://192.168.1.1', 'type': 'private-ip'},
            {'payload': 'http://10.0.0.1', 'type': 'private-ip'},
            {'payload': 'http://172.16.0.1', 'type': 'private-ip'},
            
            # Cloud metadata endpoints
            {'payload': 'http://169.254.169.254/latest/meta-data/', 'type': 'aws-metadata'},
            {'payload': 'http://metadata.google.internal/computeMetadata/v1/', 'type': 'gcp-metadata'},
            
            # Protocol wrappers
            {'payload': 'file:///etc/passwd', 'type': 'file-protocol'},
            {'payload': 'file:///c:/windows/win.ini', 'type': 'file-protocol'},
            {'payload': 'dict://127.0.0.1:11211/stat', 'type': 'dict-protocol'},
            {'payload': 'gopher://127.0.0.1:25/', 'type': 'gopher-protocol'},
            
            # DNS rebinding bypass
            {'payload': 'http://spoofed.burpcollaborator.net', 'type': 'dns-rebinding'},
        ]
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for SSRF vulnerabilities"""
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
        """Scan form for SSRF"""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Build form URL
        if action:
            from urllib.parse import urljoin
            form_url = urljoin(base_url, action)
        else:
            form_url = base_url
        
        # Look for URL-related input fields
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', 'text').lower()
            
            # Check if field might accept URLs
            url_indicators = ['url', 'link', 'uri', 'redirect', 'fetch', 'download', 'proxy', 'image', 'img']
            if not any(indicator in input_name for indicator in url_indicators):
                continue
            
            # Test with SSRF payloads
            for payload_info in self.payloads[:5]:  # Use top 5 payloads
                payload = payload_info['payload']
                payload_type = payload_info['type']
                
                try:
                    # Build form data
                    form_data = {}
                    for inp in form.get('inputs', []):
                        inp_name = inp.get('name')
                        if inp_name:
                            if inp_name == input_field.get('name'):
                                form_data[inp_name] = payload
                            else:
                                form_data[inp_name] = inp.get('value', 'test')
                    
                    # Send request
                    if method == 'POST':
                        async with self.session.post(form_url, data=form_data) as response:
                            content = await response.text()
                            status = response.status
                    else:
                        async with self.session.get(form_url, params=form_data) as response:
                            content = await response.text()
                            status = response.status
                    
                    # Check for SSRF indicators
                    if self._is_vulnerable(payload, payload_type, content, status):
                        vulnerabilities.append({
                            'type': 'ssrf',
                            'severity': 'high',
                            'url': form_url,
                            'method': method,
                            'parameter': input_field.get('name'),
                            'payload': payload,
                            'ssrf_type': payload_type,
                            'description': f'SSRF vulnerability found in form parameter "{input_field.get("name")}"',
                            'evidence': self._extract_evidence(payload_type, content),
                            'remediation': 'Implement URL whitelist validation and disable unnecessary URL schemes',
                            'cwe': 'CWE-918',
                            'owasp': 'A10:2021 - Server-Side Request Forgery',
                        })
                        break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    async def _scan_url_param(self, url: str, param: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan URL parameter for SSRF"""
        vulnerabilities = []
        
        param_name = param.get('name', '').lower()
        
        # Check if parameter might accept URLs
        url_indicators = ['url', 'link', 'uri', 'redirect', 'fetch', 'download', 'proxy', 'image', 'img']
        if not any(indicator in param_name for indicator in url_indicators):
            return vulnerabilities
        
        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test with SSRF payloads
        for payload_info in self.payloads[:5]:
            payload = payload_info['payload']
            payload_type = payload_info['type']
            
            try:
                # Build test URL
                test_params = params.copy()
                test_params[param.get('name')] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                # Send request
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    status = response.status
                
                # Check for SSRF
                if self._is_vulnerable(payload, payload_type, content, status):
                    vulnerabilities.append({
                        'type': 'ssrf',
                        'severity': 'high',
                        'url': test_url,
                        'method': 'GET',
                        'parameter': param.get('name'),
                        'payload': payload,
                        'ssrf_type': payload_type,
                        'description': f'SSRF vulnerability found in URL parameter "{param.get("name")}"',
                        'evidence': self._extract_evidence(payload_type, content),
                        'remediation': 'Implement URL whitelist validation and disable unnecessary URL schemes',
                        'cwe': 'CWE-918',
                        'owasp': 'A10:2021 - Server-Side Request Forgery',
                    })
                    break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _is_vulnerable(self, payload: str, payload_type: str, content: str, status: int) -> bool:
        """Check if SSRF vulnerability exists"""
        
        # AWS metadata indicators
        if payload_type == 'aws-metadata':
            aws_indicators = ['ami-id', 'instance-id', 'iam/security-credentials', 'public-ipv4']
            if any(indicator in content.lower() for indicator in aws_indicators):
                return True
        
        # GCP metadata indicators
        if payload_type == 'gcp-metadata':
            gcp_indicators = ['instance/id', 'instance/name', 'project/project-id']
            if any(indicator in content.lower() for indicator in gcp_indicators):
                return True
        
        # File protocol indicators
        if payload_type == 'file-protocol':
            file_indicators = ['root:', 'bin/bash', '[extensions]', 'for 16-bit app support']
            if any(indicator in content.lower() for indicator in file_indicators):
                return True
        
        # Localhost/private IP indicators
        if payload_type in ['localhost', 'private-ip', 'localhost-ipv6']:
            # Look for signs of internal service responses
            internal_indicators = [
                'apache', 'nginx', 'iis', 'admin', 'dashboard',
                'unauthorized', 'forbidden', '404', 'index of',
                'welcome to', 'default page'
            ]
            if any(indicator in content.lower() for indicator in internal_indicators):
                return True
            
            # Check for successful status code indicating accessible endpoint
            if status == 200 and len(content) > 100:
                return True
        
        return False
    
    def _extract_evidence(self, payload_type: str, content: str, max_length: int = 200) -> str:
        """Extract evidence of SSRF"""
        if len(content) > max_length:
            return content[:max_length] + '...'
        return content if content else f'SSRF detected via {payload_type}'
