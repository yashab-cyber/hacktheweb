#!/usr/bin/env python3
"""
HackTheWeb - AI-Powered Web Application Penetration Testing Tool
"""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='hacktheweb',
    version='1.0.0',
    description='AI-Powered Web Application Penetration Testing Tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='YashAB Cyber Security',
    author_email='contact@hacktheweb.io',
    url='https://github.com/yashab-cyber/hacktheweb',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests>=2.31.0',
        'urllib3>=2.0.0',
        'beautifulsoup4>=4.12.0',
        'lxml>=4.9.0',
        'aiohttp>=3.9.0',
        'flask>=3.0.0',
        'flask-cors>=4.0.0',
        'dnspython>=2.4.0',
        'python-nmap>=0.7.1',
        'scapy>=2.5.0',
        'cryptography>=41.0.0',
        'pyOpenSSL>=23.0.0',
        'pyyaml>=6.0.0',
        'jinja2>=3.1.0',
        'reportlab>=4.0.0',
        'click>=8.1.0',
        'colorama>=0.4.6',
        'rich>=13.0.0',
        'validators>=0.22.0',
        'fake-useragent>=1.4.0',
    ],
    entry_points={
        'console_scripts': [
            'hacktheweb=hacktheweb.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.8',
    keywords='pentesting security web-security vulnerability-scanner ai-powered',
)
