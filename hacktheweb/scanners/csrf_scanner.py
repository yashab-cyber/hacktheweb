"""
CSRF (Cross-Site Request Forgery) Scanner
"""

import asyncio
import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup


class CSRFScanner:
    """Scanner for CSRF vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize CSRF scanner"""
        self.config = config
        self.session = session
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for CSRF vulnerabilities"""
        vulnerabilities = []
        
        # Scan forms
        for form in recon_data.get('forms', []):
            form_vulns = await self._scan_form(target, form)
            vulnerabilities.extend(form_vulns)
        
        # Check cookies for SameSite attribute
        cookie_vulns = self._scan_cookies(recon_data.get('cookies', []))
        vulnerabilities.extend(cookie_vulns)
        
        return vulnerabilities
    
    async def _scan_form(self, base_url: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan form for CSRF protection"""
        vulnerabilities = []
        
        method = form.get('method', 'GET').upper()
        
        # CSRF is mainly a concern for state-changing operations (POST, PUT, DELETE)
        if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return vulnerabilities
        
        # Check for CSRF tokens
        has_csrf_token = False
        token_patterns = [
            r'csrf',
            r'token',
            r'_token',
            r'authenticity_token',
            r'__requestverificationtoken',
            r'anti-forgery',
        ]
        
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            # Check if this is a CSRF token field
            for pattern in token_patterns:
                if pattern in input_name:
                    has_csrf_token = True
                    break
            
            if has_csrf_token:
                break
        
        # If no CSRF token found, it's vulnerable
        if not has_csrf_token:
            action = form.get('action', '')
            if action:
                from urllib.parse import urljoin
                form_url = urljoin(base_url, action)
            else:
                form_url = base_url
            
            vulnerabilities.append({
                'type': 'csrf',
                'severity': 'medium',
                'url': form_url,
                'method': method,
                'description': f'CSRF protection missing on {method} form',
                'evidence': 'No CSRF token found in form',
                'remediation': 'Implement anti-CSRF tokens for all state-changing operations',
                'cwe': 'CWE-352',
                'owasp': 'A01:2021 - Broken Access Control',
            })
        
        return vulnerabilities
    
    def _scan_cookies(self, cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check cookies for security attributes"""
        vulnerabilities = []
        
        for cookie in cookies:
            cookie_name = cookie.get('name', '')
            
            # Check session cookies
            session_cookie_patterns = ['session', 'sess', 'token', 'auth', 'login']
            is_session_cookie = any(pattern in cookie_name.lower() for pattern in session_cookie_patterns)
            
            if is_session_cookie:
                issues = []
                
                # Check for SameSite attribute
                if not cookie.get('samesite'):
                    issues.append('Missing SameSite attribute')
                
                # Check for Secure flag
                if not cookie.get('secure'):
                    issues.append('Missing Secure flag')
                
                # Check for HttpOnly flag
                if not cookie.get('httponly'):
                    issues.append('Missing HttpOnly flag')
                
                if issues:
                    vulnerabilities.append({
                        'type': 'csrf',
                        'severity': 'medium',
                        'cookie_name': cookie_name,
                        'description': f'Session cookie "{cookie_name}" missing security attributes',
                        'evidence': ', '.join(issues),
                        'remediation': 'Set SameSite=Strict/Lax, Secure, and HttpOnly flags on session cookies',
                        'cwe': 'CWE-1275',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
        
        return vulnerabilities
