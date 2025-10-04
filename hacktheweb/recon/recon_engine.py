"""
Reconnaissance Module - Information Gathering
"""

import asyncio
import socket
import ssl
from typing import Dict, List, Any
from urllib.parse import urlparse
import dns.resolver


class ReconEngine:
    """Reconnaissance and information gathering"""
    
    def __init__(self, config, session):
        """Initialize recon engine"""
        self.config = config
        self.session = session
        
    async def gather_info(self, target: str) -> Dict[str, Any]:
        """Gather comprehensive information about target"""
        info = {
            'target': target,
            'dns': {},
            'ssl': {},
            'headers': {},
            'technologies': [],
            'ports': [],
        }
        
        parsed = urlparse(target)
        domain = parsed.netloc
        
        # DNS enumeration
        if self.config.get('recon.subdomain_enum', True):
            info['dns'] = await self._dns_enumeration(domain)
        
        # SSL/TLS analysis
        if self.config.get('recon.ssl_analysis', True) and parsed.scheme == 'https':
            info['ssl'] = await self._ssl_analysis(domain)
        
        # Port scanning
        if self.config.get('recon.port_scan', True):
            info['ports'] = await self._port_scan(domain)
        
        # Technology detection
        if self.config.get('recon.tech_detection', True):
            info['technologies'] = await self._detect_technologies(target)
        
        return info
    
    async def _dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform DNS enumeration"""
        dns_info = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
        }
        
        try:
            resolver = dns.resolver.Resolver()
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(rdata.exchange) for rdata in answers]
            except:
                pass
            
            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
            except:
                pass
                
        except Exception as e:
            print(f"[!] DNS enumeration error: {e}")
        
        return dns_info
    
    async def _ssl_analysis(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_info = {
            'valid': False,
            'issuer': '',
            'subject': '',
            'version': '',
            'cipher': '',
            'expires': '',
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()[0]
                    ssl_info['expires'] = cert.get('notAfter', '')
                    
        except Exception as e:
            print(f"[!] SSL analysis error: {e}")
        
        return ssl_info
    
    async def _port_scan(self, domain: str) -> List[int]:
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            
            # Scan ports
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        open_ports.append(port)
                    
                    sock.close()
                    
                except:
                    continue
                    
        except Exception as e:
            print(f"[!] Port scan error: {e}")
        
        return open_ports
    
    async def _detect_technologies(self, target: str) -> List[Dict[str, str]]:
        """Detect web technologies"""
        technologies = []
        
        try:
            async with self.session.get(target) as response:
                headers = response.headers
                html = await response.text()
                
                # Check headers
                if 'X-Powered-By' in headers:
                    technologies.append({
                        'name': headers['X-Powered-By'],
                        'category': 'Backend',
                        'confidence': 'high'
                    })
                
                if 'Server' in headers:
                    technologies.append({
                        'name': headers['Server'],
                        'category': 'Web Server',
                        'confidence': 'high'
                    })
                
                # Check HTML patterns
                tech_patterns = {
                    'WordPress': r'wp-content|wp-includes',
                    'Drupal': r'drupal',
                    'Joomla': r'joomla',
                    'React': r'react',
                    'Angular': r'ng-app|angular',
                    'Vue.js': r'vue',
                    'jQuery': r'jquery',
                    'Bootstrap': r'bootstrap',
                }
                
                import re
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, html, re.IGNORECASE):
                        technologies.append({
                            'name': tech,
                            'category': 'Framework',
                            'confidence': 'medium'
                        })
                
        except Exception as e:
            print(f"[!] Technology detection error: {e}")
        
        return technologies
