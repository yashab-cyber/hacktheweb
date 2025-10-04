"""
HackTheWeb - AI-Powered Web Application Penetration Testing Tool
"""

__version__ = '1.0.0'
__author__ = 'YashAB Cyber Security'
__license__ = 'MIT'

from hacktheweb.core.ai_engine import AIEngine
from hacktheweb.core.scanner import Scanner
from hacktheweb.core.config import Config

__all__ = ['AIEngine', 'Scanner', 'Config']
