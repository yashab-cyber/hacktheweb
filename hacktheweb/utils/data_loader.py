"""
Data Loader Utility
Loads payloads, wordlists, and other data files for scanners
"""

import os
from typing import List, Dict, Any
from pathlib import Path


class DataLoader:
    """Utility to load data files for scanners"""
    
    def __init__(self):
        """Initialize data loader"""
        # Get the project root directory
        self.project_root = Path(__file__).parent.parent.parent
        self.data_dir = self.project_root / 'data'
        
    def load_file_lines(self, filename: str, skip_comments: bool = True, skip_empty: bool = True) -> List[str]:
        """
        Load lines from a data file
        
        Args:
            filename: Name of the file in data/ directory
            skip_comments: Skip lines starting with #
            skip_empty: Skip empty lines
            
        Returns:
            List of lines from the file
        """
        filepath = self.data_dir / filename
        
        if not filepath.exists():
            return []
            
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = []
                for line in f:
                    line = line.strip()
                    
                    # Skip comments
                    if skip_comments and line.startswith('#'):
                        continue
                        
                    # Skip empty lines
                    if skip_empty and not line:
                        continue
                        
                    lines.append(line)
                        
                return lines
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return []
    
    def load_xss_payloads(self) -> List[str]:
        """Load XSS payloads from data file"""
        payloads = self.load_file_lines('xss_payloads.txt')
        
        # If file doesn't exist or is empty, return basic payloads
        if not payloads:
            return [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
            ]
            
        return payloads
    
    def load_sqli_payloads(self) -> List[str]:
        """Load SQL injection payloads from data file"""
        payloads = self.load_file_lines('sqli_payloads.txt')
        
        # If file doesn't exist or is empty, return basic payloads
        if not payloads:
            return [
                "'",
                "' OR '1'='1",
                "' OR 1=1--",
            ]
            
        return payloads
    
    def load_sensitive_files_linux(self) -> List[str]:
        """Load Linux sensitive file paths"""
        return self.load_file_lines('sensitive_files_linux.txt')
    
    def load_sensitive_files_windows(self) -> List[str]:
        """Load Windows sensitive file paths"""
        return self.load_file_lines('sensitive_files_windows.txt')
    
    def load_file_extensions(self) -> List[str]:
        """Load common file extensions"""
        return self.load_file_lines('file_extensions.txt')
    
    def load_user_agents(self) -> List[str]:
        """Load user agent strings"""
        agents = self.load_file_lines('user_agents.txt')
        
        # Default user agent if file doesn't exist
        if not agents:
            return ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']
            
        return agents
    
    def load_common_usernames(self) -> List[str]:
        """Load common usernames for testing"""
        return self.load_file_lines('common_usernames.txt')
    
    def load_common_passwords(self) -> List[str]:
        """Load common passwords for testing"""
        return self.load_file_lines('common_passwords.txt')
    
    def load_common_endpoints(self) -> List[str]:
        """Load common API endpoints"""
        return self.load_file_lines('common_endpoints.txt')
    
    def load_technology_fingerprints(self) -> Dict[str, str]:
        """
        Load technology fingerprints
        
        Returns:
            Dict mapping detection strings to technology names
        """
        lines = self.load_file_lines('technology_fingerprints.txt')
        fingerprints = {}
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                fingerprints[key.strip()] = value.strip()
                
        return fingerprints
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent string"""
        import random
        agents = self.load_user_agents()
        return random.choice(agents) if agents else 'Mozilla/5.0'


# Global instance
data_loader = DataLoader()
