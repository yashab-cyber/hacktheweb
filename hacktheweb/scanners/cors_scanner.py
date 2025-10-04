"""
CORS (Cross-Origin Resource Sharing) Scanner
Detects CORS misconfigurations and security issues
"""

import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse


class CORSScanner:
    """Scanner for CORS misconfiguration vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize CORS scanner"""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # Test origins
        self.test_origins = [
            'https://evil.com',
            'http://evil.com',
            'null',
            'https://attacker.com',
        ]
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for CORS misconfigurations
        """
        self.vulnerabilities = []
        
        print(f"[*] CORS Scanner: Testing {target}")
        
        # Test main target
        await self._test_cors(target)
        
        # Test API endpoints if found
        if recon_data.get('links'):
            api_endpoints = [link for link in recon_data['links'] 
                           if '/api/' in link.lower()]
            
            for endpoint in api_endpoints[:5]:  # Test first 5 API endpoints
                await self._test_cors(endpoint)
        
        return self.vulnerabilities
    
    async def _test_cors(self, url: str):
        """Test URL for CORS misconfigurations"""
        
        # Test 1: Reflected Origin
        for origin in self.test_origins:
            headers = {'Origin': origin}
            
            try:
                async with self.session.get(url, headers=headers, timeout=10) as response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    # Critical: Reflects arbitrary origin with credentials
                    if acao == origin and acac.lower() == 'true':
                        self.vulnerabilities.append({
                            'type': 'cors',
                            'severity': 'high',
                            'url': url,
                            'evidence': f'Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}',
                            'description': f'CORS misconfiguration - Reflects origin "{origin}" with credentials enabled',
                            'remediation': 'Do not reflect arbitrary origins. Use a whitelist of allowed origins. Never use credentials with wildcard.',
                            'cwe': 'CWE-942',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                        })
                    
                    # High: Reflects origin without credentials (still risky)
                    elif acao == origin:
                        self.vulnerabilities.append({
                            'type': 'cors',
                            'severity': 'medium',
                            'url': url,
                            'evidence': f'Access-Control-Allow-Origin: {acao}',
                            'description': f'CORS misconfiguration - Reflects arbitrary origin "{origin}"',
                            'remediation': 'Use a whitelist of allowed origins instead of reflecting user input.',
                            'cwe': 'CWE-942',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                        })
                    
                    # Critical: Null origin with credentials
                    elif origin == 'null' and acao == 'null' and acac.lower() == 'true':
                        self.vulnerabilities.append({
                            'type': 'cors',
                            'severity': 'high',
                            'url': url,
                            'evidence': f'Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: {acac}',
                            'description': 'CORS misconfiguration - Allows null origin with credentials',
                            'remediation': 'Never allow null origin. It can be exploited via sandboxed iframes.',
                            'cwe': 'CWE-942',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                        })
            
            except Exception:
                pass
        
        # Test 2: Wildcard with credentials (impossible but check anyway)
        try:
            async with self.session.get(url, timeout=10) as response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Wildcard with credentials is invalid but dangerous if browsers support it
                if acao == '*' and acac.lower() == 'true':
                    self.vulnerabilities.append({
                        'type': 'cors',
                        'severity': 'high',
                        'url': url,
                        'evidence': f'Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: {acac}',
                        'description': 'CORS misconfiguration - Wildcard origin with credentials (invalid but dangerous)',
                        'remediation': 'Never use wildcard (*) with credentials. Use specific origins.',
                        'cwe': 'CWE-942',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                
                # Wildcard alone is informational
                elif acao == '*':
                    self.vulnerabilities.append({
                        'type': 'cors',
                        'severity': 'low',
                        'url': url,
                        'evidence': f'Access-Control-Allow-Origin: *',
                        'description': 'CORS misconfiguration - Wildcard origin allows any domain to access resource',
                        'remediation': 'Consider using specific origins if the resource contains sensitive data.',
                        'cwe': 'CWE-942',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
        
        except Exception:
            pass
        
        # Test 3: Pre-flight request misconfigurations
        await self._test_preflight(url)
    
    async def _test_preflight(self, url: str):
        """Test CORS pre-flight (OPTIONS) request"""
        
        headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'PUT',
            'Access-Control-Request-Headers': 'X-Custom-Header',
        }
        
        try:
            async with self.session.options(url, headers=headers, timeout=10) as response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acam = response.headers.get('Access-Control-Allow-Methods', '')
                acah = response.headers.get('Access-Control-Allow-Headers', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Check if dangerous methods are allowed
                dangerous_methods = ['PUT', 'DELETE', 'PATCH']
                allowed_methods = acam.upper().split(',')
                allowed_methods = [m.strip() for m in allowed_methods]
                
                dangerous_allowed = [m for m in dangerous_methods if m in allowed_methods]
                
                if dangerous_allowed and acao == 'https://evil.com':
                    self.vulnerabilities.append({
                        'type': 'cors',
                        'severity': 'medium',
                        'url': url,
                        'evidence': f'Access-Control-Allow-Methods: {acam}, Origin: {acao}',
                        'description': f'CORS misconfiguration - Allows dangerous methods ({", ".join(dangerous_allowed)}) from arbitrary origin',
                        'remediation': 'Restrict allowed methods and validate origins strictly.',
                        'cwe': 'CWE-942',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                
                # Check if arbitrary headers are allowed
                if acah == '*' or 'evil' in acah.lower():
                    self.vulnerabilities.append({
                        'type': 'cors',
                        'severity': 'low',
                        'url': url,
                        'evidence': f'Access-Control-Allow-Headers: {acah}',
                        'description': 'CORS misconfiguration - Allows arbitrary headers',
                        'remediation': 'Specify exact allowed headers instead of using wildcard.',
                        'cwe': 'CWE-942',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
        
        except Exception:
            pass
