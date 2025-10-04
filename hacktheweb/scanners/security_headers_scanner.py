"""
Security Headers Scanner
Checks for missing or misconfigured security headers
"""

import asyncio
from typing import List, Dict, Any


class SecurityHeadersScanner:
    """Scanner for security headers vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize security headers scanner"""
        self.config = config
        self.session = session
        self.security_headers = self._get_security_headers()
        
    def _get_security_headers(self) -> Dict[str, Dict[str, Any]]:
        """Define security headers to check"""
        return {
            'Strict-Transport-Security': {
                'severity': 'medium',
                'description': 'HTTP Strict Transport Security (HSTS) missing',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                'cwe': 'CWE-319',
            },
            'X-Frame-Options': {
                'severity': 'medium',
                'description': 'X-Frame-Options header missing - vulnerable to Clickjacking',
                'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
                'cwe': 'CWE-1021',
            },
            'X-Content-Type-Options': {
                'severity': 'low',
                'description': 'X-Content-Type-Options header missing',
                'recommendation': 'Add: X-Content-Type-Options: nosniff',
                'cwe': 'CWE-693',
            },
            'Content-Security-Policy': {
                'severity': 'high',
                'description': 'Content Security Policy (CSP) header missing',
                'recommendation': 'Add: Content-Security-Policy: default-src \'self\'',
                'cwe': 'CWE-693',
            },
            'X-XSS-Protection': {
                'severity': 'low',
                'description': 'X-XSS-Protection header missing',
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block',
                'cwe': 'CWE-79',
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Referrer-Policy header missing',
                'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
                'cwe': 'CWE-200',
            },
            'Permissions-Policy': {
                'severity': 'low',
                'description': 'Permissions-Policy header missing',
                'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
                'cwe': 'CWE-693',
            },
        }
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for missing security headers"""
        vulnerabilities = []
        
        try:
            # Get headers from recon data or fetch
            if 'headers' in recon_data:
                headers = recon_data['headers']
            else:
                async with self.session.get(target) as response:
                    headers = dict(response.headers)
            
            # Check each security header
            for header_name, header_info in self.security_headers.items():
                if header_name not in headers:
                    vulnerabilities.append({
                        'type': 'security_headers',
                        'severity': header_info['severity'],
                        'url': target,
                        'header_name': header_name,
                        'description': header_info['description'],
                        'remediation': header_info['recommendation'],
                        'cwe': header_info['cwe'],
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                else:
                    # Header exists, check if configured correctly
                    header_value = headers[header_name]
                    issues = self._check_header_value(header_name, header_value)
                    
                    if issues:
                        vulnerabilities.append({
                            'type': 'security_headers',
                            'severity': 'low',
                            'url': target,
                            'header_name': header_name,
                            'header_value': header_value,
                            'description': f'{header_name} header misconfigured: {issues}',
                            'remediation': header_info['recommendation'],
                            'cwe': header_info['cwe'],
                            'owasp': 'A05:2021 - Security Misconfiguration',
                        })
            
            # Check for insecure headers
            insecure_headers = self._check_insecure_headers(headers)
            vulnerabilities.extend(insecure_headers)
            
        except Exception as e:
            print(f"[!] Security headers scan error: {e}")
        
        return vulnerabilities
    
    def _check_header_value(self, header_name: str, header_value: str) -> str:
        """Check if header value is configured correctly"""
        header_value_lower = header_value.lower()
        
        if header_name == 'Strict-Transport-Security':
            if 'max-age=' not in header_value_lower:
                return 'Missing max-age directive'
            # Extract max-age value
            try:
                max_age_str = header_value_lower.split('max-age=')[1].split(';')[0]
                max_age = int(max_age_str.strip())
                if max_age < 31536000:  # Less than 1 year
                    return f'max-age too low ({max_age} seconds, recommend 31536000)'
            except:
                pass
        
        elif header_name == 'X-Frame-Options':
            if header_value_lower not in ['deny', 'sameorigin']:
                return f'Weak value: {header_value} (recommend DENY or SAMEORIGIN)'
        
        elif header_name == 'X-XSS-Protection':
            if '1' not in header_value_lower:
                return 'XSS Protection disabled'
        
        elif header_name == 'Content-Security-Policy':
            if 'unsafe-inline' in header_value_lower or 'unsafe-eval' in header_value_lower:
                return 'Contains unsafe directives (unsafe-inline or unsafe-eval)'
        
        return ''
    
    def _check_insecure_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for presence of insecure headers"""
        vulnerabilities = []
        
        # Headers that should not be present
        insecure_headers = {
            'Server': {
                'severity': 'info',
                'description': 'Server header reveals server information',
                'recommendation': 'Remove or obscure Server header',
            },
            'X-Powered-By': {
                'severity': 'info',
                'description': 'X-Powered-By header reveals technology stack',
                'recommendation': 'Remove X-Powered-By header',
            },
            'X-AspNet-Version': {
                'severity': 'info',
                'description': 'X-AspNet-Version header reveals framework version',
                'recommendation': 'Remove X-AspNet-Version header',
            },
        }
        
        for header_name, header_info in insecure_headers.items():
            if header_name in headers:
                vulnerabilities.append({
                    'type': 'information_disclosure',
                    'severity': header_info['severity'],
                    'header_name': header_name,
                    'header_value': headers[header_name],
                    'description': header_info['description'],
                    'remediation': header_info['recommendation'],
                    'cwe': 'CWE-200',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                })
        
        return vulnerabilities
