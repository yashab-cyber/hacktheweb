"""
Core Scanner Module - Orchestrates all scanning activities
"""

import asyncio
import aiohttp
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import time
from fake_useragent import UserAgent
from hacktheweb.recon import ReconEngine


class Scanner:
    """Main scanner orchestrator"""
    
    def __init__(self, config, ai_engine):
        """Initialize scanner"""
        self.config = config
        self.ai_engine = ai_engine
        self.session = None
        self.results = {
            'target': None,
            'start_time': None,
            'end_time': None,
            'vulnerabilities': [],
            'recon_data': {},
            'statistics': {},
        }
    async def scan(self, target: str, scan_type: str = 'full') -> Dict[str, Any]:
        """
        Main scan orchestration
        """
        from hacktheweb.utils import EnterpriseLogger
        EnterpriseLogger.log('info', f"Starting scan on target: {target}")
        EnterpriseLogger.audit('scan_start', target, 'initiated')
        
        self.results['target'] = target
        self.results['start_time'] = datetime.now().isoformat()
        
        # Initialize session
        await self._init_session()
        
        try:
            # Phase 1: Initial reconnaissance
            EnterpriseLogger.log('info', "Entering Phase 1: Reconnaissance")
            EnterpriseLogger.audit('reconnaissance_start', target, 'running')
            recon_data = await self._reconnaissance_phase(target)
            self.results['recon_data'] = recon_data
            EnterpriseLogger.audit('reconnaissance_complete', target, 'success', {
                'domains_resolved': len(recon_data.get('dns', {}).get('a_records', [])),
                'open_ports': len(recon_data.get('ports', []))
            })
            
            # Phase 2: AI Analysis
            EnterpriseLogger.log('info', "Entering Phase 2: AI Analysis")
            EnterpriseLogger.audit('ai_analysis_start', target, 'running')
            analysis = self.ai_engine.analyze_target(recon_data)
            EnterpriseLogger.audit('ai_analysis_complete', target, 'success', {
                'priority_vulnerability_classes': [v['type'] for v in analysis.get('priority_vulnerabilities', [])]
            })
            
            # Phase 3: Vulnerability Scanning
            EnterpriseLogger.log('info', "Entering Phase 3: Vulnerability Scanning")
            EnterpriseLogger.audit('scanning_start', target, 'running')
            vulnerabilities = await self._scanning_phase(target, analysis)
            self.results['vulnerabilities'] = vulnerabilities
            EnterpriseLogger.audit('scanning_complete', target, 'success', {
                'vulnerabilities_identified_count': len(vulnerabilities)
            })
            
            # Phase 4: Statistics
            self.results['statistics'] = self._calculate_statistics()
            EnterpriseLogger.log('info', "Scan finished successfully")
            
        except Exception as err:
            EnterpriseLogger.log('error', f"Critical failure during scan execution: {err}")
            EnterpriseLogger.audit('scan_failure', target, 'error', {'error_message': str(err)})
            raise
        finally:
            await self._close_session()
            self.results['end_time'] = datetime.now().isoformat()
            EnterpriseLogger.audit('scan_end', target, 'completed')
        
        return self.results
    
    async def _init_session(self):
        """Initialize HTTP session"""
        ua = UserAgent()
        user_agent = self.config.get('general.user_agent', ua.random)
        
        timeout = aiohttp.ClientTimeout(total=self.config.get('general.timeout', 30))
        connector = aiohttp.TCPConnector(
            ssl=False if not self.config.get('general.verify_ssl', False) else None
        )
        
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers
        )
    
    async def _close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def _reconnaissance_phase(self, target: str) -> Dict[str, Any]:
        """Perform reconnaissance"""
        recon_data = {
            'url': target,
            'headers': {},
            'forms': [],
            'inputs': [],
            'links': [],
            'technologies': [],
            'cookies': [],
        }
        
        try:
            # Gather DNS, SSL, Ports, etc. using ReconEngine
            recon_engine = ReconEngine(self.config, self.session)
            recon_details = await recon_engine.gather_info(target)
            recon_data.update(recon_details)
            
            # Fetch initial page
            async with self.session.get(target) as response:
                recon_data['status_code'] = response.status
                recon_data['headers'] = dict(response.headers)
                
                # Get cookies
                for cookie in response.cookies.values():
                    recon_data['cookies'].append({
                        'name': cookie.key,
                        'value': cookie.value,
                        'domain': cookie.get('domain', ''),
                        'path': cookie.get('path', '/'),
                        'secure': cookie.get('secure', False),
                        'httponly': cookie.get('httponly', False),
                    })
                
                html_content = await response.text()
                recon_data['html_content'] = html_content
                
                # Parse HTML
                soup = BeautifulSoup(html_content, 'lxml')
                
                # Extract forms
                for form in soup.find_all('form'):
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET'),
                        'inputs': [],
                    }
                    
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        form_data['inputs'].append({
                            'type': input_tag.get('type', 'text'),
                            'name': input_tag.get('name', ''),
                            'value': input_tag.get('value', ''),
                        })
                    
                    recon_data['forms'].append(form_data)
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    absolute_url = urljoin(target, href)
                    if urlparse(absolute_url).netloc == urlparse(target).netloc:
                        recon_data['links'].append(absolute_url)
                
                # Extract URL parameters
                if '?' in target:
                    query_string = urlparse(target).query
                    for param in query_string.split('&'):
                        if '=' in param:
                            name, value = param.split('=', 1)
                            recon_data['inputs'].append({
                                'type': 'url_param',
                                'name': name,
                                'value': value,
                            })
        
        except Exception as e:
            print(f"[!] Reconnaissance error: {e}")
        
        return recon_data
    
    async def _scanning_phase(self, target: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform vulnerability scanning"""
        vulnerabilities = []
        
        # Get scan strategy from AI
        strategy = analysis.get('scan_strategy', {})
        priority_vulns = analysis.get('priority_vulnerabilities', [])
        
        # Import scanner modules
        from hacktheweb.scanners.xss_scanner import XSSScanner
        from hacktheweb.scanners.sqli_scanner import SQLiScanner
        from hacktheweb.scanners.csrf_scanner import CSRFScanner
        from hacktheweb.scanners.ssrf_scanner import SSRFScanner
        from hacktheweb.scanners.lfi_scanner import LFIScanner
        from hacktheweb.scanners.security_headers_scanner import SecurityHeadersScanner
        from hacktheweb.scanners.xxe_scanner import XXEScanner
        from hacktheweb.scanners.rce_scanner import RCEScanner
        from hacktheweb.scanners.idor_scanner import IDORScanner
        from hacktheweb.scanners.open_redirect_scanner import OpenRedirectScanner
        from hacktheweb.scanners.cors_scanner import CORSScanner
        from hacktheweb.scanners.path_traversal_scanner import PathTraversalScanner
        from hacktheweb.scanners.nosqli_scanner import NoSQLiScanner
        from hacktheweb.scanners.ldapi_scanner import LDAPIScanner
        from hacktheweb.scanners.ssti_scanner import SSTIScanner
        
        # Initialize scanners
        scanners = {
            'xss': XSSScanner(self.config, self.session),
            'sqli': SQLiScanner(self.config, self.session),
            'csrf': CSRFScanner(self.config, self.session),
            'ssrf': SSRFScanner(self.config, self.session),
            'lfi': LFIScanner(self.config, self.session),
            'security_headers': SecurityHeadersScanner(self.config, self.session),
            'xxe': XXEScanner(self.config, self.session),
            'rce': RCEScanner(self.config, self.session),
            'idor': IDORScanner(self.config, self.session),
            'open_redirect': OpenRedirectScanner(self.config, self.session),
            'cors': CORSScanner(self.config, self.session),
            'path_traversal': PathTraversalScanner(self.config, self.session),
            'nosqli': NoSQLiScanner(self.config, self.session),
            'ldapi': LDAPIScanner(self.config, self.session),
            'ssti': SSTIScanner(self.config, self.session),
        }
        
        # Determine allowed scanner keys based on configured techniques
        configured_techniques = self.config.get('scanning.techniques', [])
        allowed_scanner_keys = set()
        
        # Map techniques to scanner keys
        tech_to_scanner = {
            'xss': ['xss'],
            'sqli': ['sqli'],
            'csrf': ['csrf'],
            'ssrf': ['ssrf'],
            'lfi': ['lfi'],
            'rfi': ['lfi'],
            'xxe': ['xxe'],
            'rce': ['rce'],
            'idor': ['idor'],
            'open_redirect': ['open_redirect'],
            'cors': ['cors'],
            'path_traversal': ['path_traversal'],
            'nosqli': ['nosqli'],
            'ldapi': ['ldapi'],
            'ssti': ['ssti'],
            'security_headers': ['security_headers'],
        }
        
        for tech in configured_techniques:
            tech_lower = tech.lower()
            if tech_lower in tech_to_scanner:
                allowed_scanner_keys.update(tech_to_scanner[tech_lower])
        
        # Determine scanners to run based on mode and explicit request
        scan_mode = self.config.get('scanning.scan_mode', 'smart')
        is_explicit = self.config.get('scanning.techniques_explicit', False)
        
        scanners_to_run = []
        
        if is_explicit or scan_mode == 'thorough':
            # Run all allowed scanners
            scanners_to_run = [k for k in scanners.keys() if k in allowed_scanner_keys]
        else:
            # Filter/Prioritize based on mode
            passive_scanners = {'security_headers', 'cors'}
            
            # 1. Start with passive / fast scanners if allowed
            active_passives = [k for k in passive_scanners if k in allowed_scanner_keys]
            scanners_to_run.extend(active_passives)
            
            # 2. Get prioritized scanners
            prioritized_keys = []
            for vuln_info in priority_vulns:
                vuln_type = vuln_info['type'].lower()
                if vuln_type in allowed_scanner_keys and vuln_type not in scanners_to_run:
                    prioritized_keys.append(vuln_type)
            
            if scan_mode == 'fast':
                # Run top 3 prioritized scanners
                scanners_to_run.extend(prioritized_keys[:3])
                # If prioritized is empty, fall back to a default fast set of active scanners
                if not prioritized_keys:
                    default_fast = ['xss', 'csrf']
                    for k in default_fast:
                        if k in allowed_scanner_keys and k not in scanners_to_run:
                            scanners_to_run.append(k)
            else:  # smart
                # Run top 5 prioritized scanners
                scanners_to_run.extend(prioritized_keys[:5])
                # If prioritized is empty, fall back to a default smart set of active scanners
                if not prioritized_keys:
                    default_smart = ['xss', 'sqli', 'csrf', 'ssrf', 'lfi', 'open_redirect']
                    for k in default_smart:
                        if k in allowed_scanner_keys and k not in scanners_to_run:
                            scanners_to_run.append(k)
                            
        # Print strategy summary using strategy to silence the ruff warning
        mode_label = strategy.get('mode', scan_mode)
        print(f"[*] AI Scan Strategy ({mode_label}): running {len(scanners_to_run)} scanners: {', '.join(scanners_to_run)}")
        
        # Run selected scanners
        for vuln_type in scanners_to_run:
            if vuln_type in scanners:
                print(f"[*] Scanning for {vuln_type.upper()}...")
                try:
                    scanner_results = await scanners[vuln_type].scan(
                        target,
                        self.results['recon_data']
                    )
                    vulnerabilities.extend(scanner_results)
                except Exception as e:
                    print(f"[!] Error scanning {vuln_type}: {e}")
                    
        return vulnerabilities
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate scan statistics"""
        stats = {
            'total_vulnerabilities': len(self.results['vulnerabilities']),
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0,
            },
            'by_type': {},
            'scan_duration': 0,
        }
        
        # Count by severity
        for vuln in self.results['vulnerabilities']:
            severity = vuln.get('severity', 'info')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            vuln_type = vuln.get('type', 'unknown')
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
        
        # Calculate duration
        if self.results['start_time'] and self.results['end_time']:
            start = datetime.fromisoformat(self.results['start_time'])
            end = datetime.fromisoformat(self.results['end_time'])
            stats['scan_duration'] = (end - start).total_seconds()
        
        return stats


class HTTPClient:
    """HTTP client with rate limiting and retry logic"""
    
    def __init__(self, config):
        """Initialize HTTP client"""
        self.config = config
        self.last_request_time = 0
        
    async def get(self, session: aiohttp.ClientSession, url: str, **kwargs) -> aiohttp.ClientResponse:
        """GET request with rate limiting"""
        await self._rate_limit()
        return await self._retry_request(session.get, url, **kwargs)
    
    async def post(self, session: aiohttp.ClientSession, url: str, **kwargs) -> aiohttp.ClientResponse:
        """POST request with rate limiting"""
        await self._rate_limit()
        return await self._retry_request(session.post, url, **kwargs)
    
    async def _rate_limit(self):
        """Apply rate limiting"""
        if self.config.get('rate_limiting.enabled', True):
            requests_per_second = self.config.get('rate_limiting.requests_per_second', 10)
            min_interval = 1.0 / requests_per_second
            
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            self.last_request_time = time.time()
    
    async def _retry_request(self, method, url: str, **kwargs):
        """Retry request on failure"""
        max_retries = self.config.get('general.max_retries', 3)
        
        for attempt in range(max_retries):
            try:
                response = await method(url, **kwargs)
                return response
            except Exception:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
