"""
AI Engine - Rule-based intelligent decision making system
"""

import re
import hashlib
import json
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from datetime import datetime


class AIEngine:
    """
    Rule-based AI Engine for intelligent pentesting decisions.
    No ML models required - uses heuristics, pattern matching, and adaptive algorithms.
    """
    
    def __init__(self, config):
        """Initialize AI Engine"""
        self.config = config
        self.knowledge_base = KnowledgeBase()
        self.pattern_matcher = PatternMatcher()
        self.decision_maker = DecisionMaker(config)
        self.learning_engine = LearningEngine()
        
    def analyze_target(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze target and create intelligent scan strategy
        """
        analysis = {
            'target': target_info.get('url'),
            'timestamp': datetime.now().isoformat(),
            'technology_stack': [],
            'attack_surface': [],
            'recommended_scans': [],
            'priority_vulnerabilities': [],
            'scan_strategy': {},
        }
        
        # Detect technologies
        if 'headers' in target_info:
            analysis['technology_stack'] = self._detect_technologies(target_info['headers'])
        
        # Identify attack surface
        if 'forms' in target_info:
            analysis['attack_surface'].extend(self._analyze_forms(target_info['forms']))
        
        if 'inputs' in target_info:
            analysis['attack_surface'].extend(self._analyze_inputs(target_info['inputs']))
        
        # Generate recommendations based on detected technologies
        analysis['recommended_scans'] = self._recommend_scans(analysis['technology_stack'])
        
        # Prioritize vulnerabilities based on tech stack
        analysis['priority_vulnerabilities'] = self._prioritize_vulnerabilities(
            analysis['technology_stack'],
            analysis['attack_surface']
        )
        
        # Create adaptive scan strategy
        analysis['scan_strategy'] = self.decision_maker.create_scan_strategy(analysis)
        
        return analysis
    
    def _detect_technologies(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Detect web technologies from headers"""
        technologies = []
        
        # Technology signatures
        tech_signatures = {
            'server': {
                'nginx': r'nginx',
                'apache': r'Apache',
                'iis': r'Microsoft-IIS',
                'tomcat': r'Tomcat',
                'express': r'Express',
            },
            'framework': {
                'php': r'PHP',
                'asp.net': r'ASP\.NET',
                'django': r'Django',
                'rails': r'Rails',
                'laravel': r'Laravel',
                'wordpress': r'WordPress',
            },
            'language': {
                'python': r'Python',
                'ruby': r'Ruby',
                'nodejs': r'Node\.js',
                'java': r'Java',
            }
        }
        
        for header, value in headers.items():
            header_lower = header.lower()
            value_lower = value.lower()
            
            # Check server signatures
            if header_lower == 'server':
                for tech, pattern in tech_signatures['server'].items():
                    if re.search(pattern, value, re.IGNORECASE):
                        technologies.append({
                            'type': 'server',
                            'name': tech,
                            'version': self._extract_version(value),
                            'confidence': 0.95
                        })
            
            # Check framework signatures
            if 'x-powered-by' in header_lower:
                for tech, pattern in tech_signatures['framework'].items():
                    if re.search(pattern, value, re.IGNORECASE):
                        technologies.append({
                            'type': 'framework',
                            'name': tech,
                            'version': self._extract_version(value),
                            'confidence': 0.90
                        })
        
        return technologies
    
    def _extract_version(self, text: str) -> str:
        """Extract version number from text"""
        version_pattern = r'(\d+\.[\d\.]+)'
        match = re.search(version_pattern, text)
        return match.group(1) if match else 'unknown'
    
    def _analyze_forms(self, forms: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze forms for potential attack vectors"""
        attack_vectors = []
        
        for form in forms:
            vector = {
                'type': 'form',
                'action': form.get('action'),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'vulnerabilities': [],
            }
            
            # Analyze each input field
            for input_field in form.get('inputs', []):
                input_type = input_field.get('type', 'text')
                input_name = input_field.get('name', '')
                
                vector['inputs'].append({
                    'name': input_name,
                    'type': input_type,
                })
                
                # Identify potential vulnerabilities based on input patterns
                if input_type in ['text', 'search', 'url']:
                    vector['vulnerabilities'].extend(['xss', 'sqli', 'ssrf'])
                
                if 'email' in input_name.lower():
                    vector['vulnerabilities'].append('email_injection')
                
                if 'file' in input_type:
                    vector['vulnerabilities'].extend(['file_upload', 'xxe'])
                
                if input_type == 'hidden' and 'token' not in input_name.lower():
                    vector['vulnerabilities'].append('csrf')
            
            attack_vectors.append(vector)
        
        return attack_vectors
    
    def _analyze_inputs(self, inputs: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze input parameters for vulnerabilities"""
        attack_vectors = []
        
        for input_param in inputs:
            name = input_param.get('name', '')
            value = input_param.get('value', '')
            
            vector = {
                'type': 'parameter',
                'name': name,
                'value': value,
                'vulnerabilities': [],
            }
            
            # Pattern-based vulnerability detection
            if re.search(r'(id|user|page|cat|file)', name, re.IGNORECASE):
                vector['vulnerabilities'].extend(['sqli', 'idor'])
            
            if re.search(r'(url|redirect|return|next)', name, re.IGNORECASE):
                vector['vulnerabilities'].extend(['open_redirect', 'ssrf'])
            
            if re.search(r'(file|path|dir|document)', name, re.IGNORECASE):
                vector['vulnerabilities'].extend(['lfi', 'path_traversal'])
            
            if re.search(r'(cmd|exec|command)', name, re.IGNORECASE):
                vector['vulnerabilities'].append('rce')
            
            attack_vectors.append(vector)
        
        return attack_vectors
    
    def _recommend_scans(self, tech_stack: List[Dict]) -> List[str]:
        """Recommend scans based on technology stack"""
        recommendations = set()
        
        # Default scans
        recommendations.update(['xss', 'sqli', 'csrf'])
        
        for tech in tech_stack:
            tech_name = tech['name'].lower()
            
            # PHP-specific
            if tech_name == 'php':
                recommendations.update(['lfi', 'rfi', 'file_inclusion'])
            
            # WordPress-specific
            if tech_name == 'wordpress':
                recommendations.update(['wp_scan', 'plugin_scan', 'xmlrpc'])
            
            # Java-specific
            if tech_name in ['tomcat', 'java']:
                recommendations.update(['xxe', 'deserialization', 'jndi'])
            
            # Node.js-specific
            if tech_name == 'nodejs':
                recommendations.update(['nosql_injection', 'prototype_pollution'])
            
            # ASP.NET-specific
            if tech_name == 'asp.net':
                recommendations.update(['viewstate', 'xxe'])
        
        return list(recommendations)
    
    def _prioritize_vulnerabilities(self, tech_stack: List[Dict], 
                                   attack_surface: List[Dict]) -> List[Dict[str, Any]]:
        """Prioritize vulnerabilities based on context"""
        priorities = []
        
        # Collect all potential vulnerabilities
        vuln_map = defaultdict(lambda: {'count': 0, 'contexts': [], 'severity': 'medium'})
        
        for surface in attack_surface:
            for vuln in surface.get('vulnerabilities', []):
                vuln_map[vuln]['count'] += 1
                vuln_map[vuln]['contexts'].append(surface.get('type'))
        
        # Assign severity based on technology and prevalence
        severity_rules = {
            'rce': 'critical',
            'sqli': 'critical',
            'deserialization': 'critical',
            'ssti': 'critical',
            'nosqli': 'high',
            'xxe': 'high',
            'ssrf': 'high',
            'xss': 'high',
            'ldapi': 'high',
            'path_traversal': 'high',
            'csrf': 'medium',
            'lfi': 'high',
            'idor': 'medium',
            'open_redirect': 'medium',
            'cors': 'medium',
            'security_headers': 'low',
        }
        
        for vuln_type, data in vuln_map.items():
            priorities.append({
                'type': vuln_type,
                'severity': severity_rules.get(vuln_type, 'medium'),
                'occurrences': data['count'],
                'contexts': data['contexts'],
                'priority_score': self._calculate_priority_score(
                    vuln_type, data['count'], severity_rules.get(vuln_type, 'medium')
                ),
            })
        
        # Sort by priority score
        priorities.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priorities
    
    def _calculate_priority_score(self, vuln_type: str, occurrences: int, severity: str) -> float:
        """Calculate priority score for vulnerability"""
        severity_weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 2.0,
            'info': 1.0,
        }
        
        base_score = severity_weights.get(severity, 1.0)
        occurrence_multiplier = min(1.0 + (occurrences * 0.2), 3.0)
        
        return base_score * occurrence_multiplier


class KnowledgeBase:
    """Knowledge base for vulnerability patterns and signatures"""
    
    def __init__(self):
        """Initialize knowledge base"""
        self.vulnerability_patterns = self._load_patterns()
        self.exploit_database = self._load_exploits()
    
    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability patterns"""
        return {
            'xss': [
                r'<script>',
                r'onerror=',
                r'onload=',
                r'javascript:',
                r'<img.*src=',
            ],
            'sqli': [
                r"'.*OR.*'",
                r"'.*AND.*'",
                r'UNION.*SELECT',
                r'1=1',
                r"'--",
            ],
            'lfi': [
                r'\.\./\.\.',
                r'etc/passwd',
                r'windows/win\.ini',
                r'proc/self/environ',
            ],
            'ssrf': [
                r'localhost',
                r'127\.0\.0\.1',
                r'169\.254',
                r'file://',
            ],
        }
    
    def _load_exploits(self) -> Dict[str, Dict]:
        """Load exploit templates"""
        return {
            'xss': {
                'basic': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
                'advanced': ['<svg/onload=alert(1)>', '<iframe src=javascript:alert(1)>'],
            },
            'sqli': {
                'basic': ["' OR '1'='1", "' UNION SELECT NULL--"],
                'advanced': ["' AND 1=2 UNION SELECT table_name FROM information_schema.tables--"],
            },
        }
    
    def get_patterns(self, vuln_type: str) -> List[str]:
        """Get patterns for vulnerability type"""
        return self.vulnerability_patterns.get(vuln_type, [])
    
    def get_exploits(self, vuln_type: str, level: str = 'basic') -> List[str]:
        """Get exploits for vulnerability type"""
        exploits = self.exploit_database.get(vuln_type, {})
        return exploits.get(level, [])


class PatternMatcher:
    """Pattern matching for vulnerability detection"""
    
    def match_response(self, response_text: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """Match patterns in response text"""
        matches = []
        
        for pattern in patterns:
            regex_matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in regex_matches:
                matches.append({
                    'pattern': pattern,
                    'matched': match.group(0),
                    'position': match.start(),
                    'confidence': 0.8,
                })
        
        return matches


class DecisionMaker:
    """Make intelligent decisions about scanning strategies"""
    
    def __init__(self, config):
        """Initialize decision maker"""
        self.config = config
    
    def create_scan_strategy(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create adaptive scan strategy"""
        scan_mode = self.config.get('scanning.scan_mode', 'smart')
        
        strategy = {
            'mode': scan_mode,
            'phases': [],
            'resource_allocation': {},
            'estimated_time': 0,
        }
        
        # Phase 1: Reconnaissance
        strategy['phases'].append({
            'name': 'reconnaissance',
            'techniques': ['tech_detection', 'subdomain_enum', 'port_scan'],
            'priority': 1,
        })
        
        # Phase 2: Vulnerability Scanning (prioritized)
        priority_vulns = analysis.get('priority_vulnerabilities', [])
        scan_techniques = [v['type'] for v in priority_vulns[:5]]  # Top 5
        
        strategy['phases'].append({
            'name': 'vulnerability_scanning',
            'techniques': scan_techniques,
            'priority': 2,
        })
        
        # Phase 3: Exploitation (if enabled)
        if scan_mode == 'thorough':
            strategy['phases'].append({
                'name': 'exploitation',
                'techniques': ['auto_exploit'],
                'priority': 3,
            })
        
        # Resource allocation based on priority
        total_vulns = len(priority_vulns)
        for vuln in priority_vulns:
            weight = 1.0 / (priority_vulns.index(vuln) + 1)
            strategy['resource_allocation'][vuln['type']] = weight / total_vulns
        
        return strategy


class LearningEngine:
    """Learning from scan results to improve future scans"""
    
    def __init__(self):
        """Initialize learning engine"""
        self.success_patterns = defaultdict(int)
        self.failure_patterns = defaultdict(int)
    
    def learn_from_result(self, vuln_type: str, payload: str, success: bool) -> None:
        """Learn from scan result"""
        pattern_hash = hashlib.md5(f"{vuln_type}:{payload}".encode()).hexdigest()
        
        if success:
            self.success_patterns[pattern_hash] += 1
        else:
            self.failure_patterns[pattern_hash] += 1
    
    def get_success_rate(self, vuln_type: str, payload: str) -> float:
        """Get success rate for payload"""
        pattern_hash = hashlib.md5(f"{vuln_type}:{payload}".encode()).hexdigest()
        
        successes = self.success_patterns.get(pattern_hash, 0)
        failures = self.failure_patterns.get(pattern_hash, 0)
        total = successes + failures
        
        if total == 0:
            return 0.5  # Unknown
        
        return successes / total
