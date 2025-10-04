"""
Configuration Management for HackTheWeb
"""

import os
import yaml
from typing import Dict, Any, List
from pathlib import Path


class Config:
    """Configuration manager for HackTheWeb"""
    
    def __init__(self, config_file: str = None):
        """Initialize configuration"""
        self.base_dir = Path(__file__).parent.parent.parent
        self.config_dir = self.base_dir / 'config'
        self.data_dir = self.base_dir / 'data'
        
        # Default configuration
        self.config = {
            'general': {
                'threads': 10,
                'timeout': 30,
                'delay': 0,
                'user_agent': 'HackTheWeb/1.0 (Automated Security Scanner)',
                'follow_redirects': True,
                'verify_ssl': False,
                'max_retries': 3,
            },
            'scanning': {
                'max_depth': 3,
                'max_urls': 1000,
                'scan_mode': 'smart',  # smart, fast, thorough
                'techniques': ['xss', 'sqli', 'csrf', 'ssrf', 'xxe', 'lfi', 'rce', 'idor'],
            },
            'ai': {
                'learning_enabled': True,
                'confidence_threshold': 0.7,
                'adaptive_scanning': True,
                'smart_payload_selection': True,
                'pattern_recognition': True,
            },
            'recon': {
                'subdomain_enum': True,
                'port_scan': True,
                'tech_detection': True,
                'directory_brute': True,
                'ssl_analysis': True,
            },
            'reporting': {
                'format': 'html',  # html, json, pdf, markdown
                'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
                'include_screenshots': False,
                'include_payloads': True,
            },
            'proxy': {
                'enabled': False,
                'http': None,
                'https': None,
            },
            'rate_limiting': {
                'enabled': True,
                'requests_per_second': 10,
                'burst': 50,
            },
        }
        
        # Load custom config if provided
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str) -> None:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                custom_config = yaml.safe_load(f)
                self._merge_config(self.config, custom_config)
        except FileNotFoundError:
            print(f"[!] Config file not found: {config_file}")
        except yaml.YAMLError as e:
            print(f"[!] Error parsing config file: {e}")
    
    def _merge_config(self, base: Dict, custom: Dict) -> None:
        """Recursively merge custom config into base config"""
        for key, value in custom.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by dot notation key"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save_config(self, output_file: str) -> None:
        """Save current configuration to YAML file"""
        try:
            with open(output_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            print(f"[+] Configuration saved to: {output_file}")
        except Exception as e:
            print(f"[!] Error saving config: {e}")
    
    def get_wordlist(self, wordlist_type: str) -> List[str]:
        """Load wordlist from data directory"""
        wordlist_path = self.data_dir / f'{wordlist_type}.txt'
        
        if not wordlist_path.exists():
            return []
        
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading wordlist {wordlist_type}: {e}")
            return []
