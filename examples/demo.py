#!/usr/bin/env python3
"""
HackTheWeb - Example Usage
Demonstrates various features and capabilities
"""

import asyncio
from hacktheweb.core.config import Config
from hacktheweb.core.ai_engine import AIEngine
from hacktheweb.core.scanner import Scanner
from hacktheweb.reporting.report_generator import ReportGenerator


async def example_basic_scan():
    """Example: Basic scan"""
    print("\n" + "="*70)
    print("Example 1: Basic Scan")
    print("="*70)
    
    # Initialize components
    config = Config()
    config.set('scanning.scan_mode', 'fast')
    
    ai_engine = AIEngine(config)
    scanner = Scanner(config, ai_engine)
    
    # Run scan
    target = 'http://testphp.vulnweb.com'
    print(f"Scanning: {target}")
    
    results = await scanner.scan(target)
    
    # Display results
    print(f"\nVulnerabilities found: {len(results['vulnerabilities'])}")
    for vuln in results['vulnerabilities'][:3]:  # Show first 3
        print(f"  - {vuln['type'].upper()}: {vuln['description']}")
    
    return results


async def example_custom_config():
    """Example: Using custom configuration"""
    print("\n" + "="*70)
    print("Example 2: Custom Configuration")
    print("="*70)
    
    # Create custom config
    config = Config()
    config.set('scanning.scan_mode', 'smart')
    config.set('scanning.techniques', ['xss', 'sqli'])
    config.set('general.threads', 5)
    config.set('rate_limiting.requests_per_second', 5)
    
    print("Configuration:")
    print(f"  Scan Mode: {config.get('scanning.scan_mode')}")
    print(f"  Techniques: {config.get('scanning.techniques')}")
    print(f"  Threads: {config.get('general.threads')}")
    
    ai_engine = AIEngine(config)
    scanner = Scanner(config, ai_engine)
    
    # Note: Actual scan would be run here
    print("\n(Scan would run here with custom configuration)")


def example_report_generation():
    """Example: Generate reports in different formats"""
    print("\n" + "="*70)
    print("Example 3: Report Generation")
    print("="*70)
    
    # Sample results
    sample_results = {
        'target': 'http://example.com',
        'start_time': '2025-10-04T10:00:00',
        'end_time': '2025-10-04T10:15:30',
        'vulnerabilities': [
            {
                'type': 'xss',
                'severity': 'high',
                'url': 'http://example.com/search',
                'method': 'GET',
                'parameter': 'q',
                'payload': '<script>alert(1)</script>',
                'description': 'XSS vulnerability found in search parameter',
                'remediation': 'Implement proper input validation and output encoding',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021 - Injection',
            }
        ],
        'statistics': {
            'total_vulnerabilities': 1,
            'by_severity': {'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'info': 0},
            'scan_duration': 930.5
        }
    }
    
    config = Config()
    report_gen = ReportGenerator(config)
    
    # Generate different formats
    formats = ['json', 'html', 'markdown']
    
    for fmt in formats:
        try:
            report_path = report_gen.generate(sample_results, fmt)
            print(f"  ✓ {fmt.upper()} report: {report_path}")
        except Exception as e:
            print(f"  ✗ {fmt.upper()} report: {e}")


def example_ai_analysis():
    """Example: AI target analysis"""
    print("\n" + "="*70)
    print("Example 4: AI-Powered Target Analysis")
    print("="*70)
    
    config = Config()
    ai_engine = AIEngine(config)
    
    # Sample target info
    target_info = {
        'url': 'http://example.com',
        'headers': {
            'Server': 'Apache/2.4.41 (Ubuntu)',
            'X-Powered-By': 'PHP/7.4.3'
        },
        'forms': [
            {
                'action': '/login',
                'method': 'POST',
                'inputs': [
                    {'name': 'username', 'type': 'text'},
                    {'name': 'password', 'type': 'password'}
                ]
            }
        ],
        'inputs': [
            {'name': 'id', 'type': 'url_param', 'value': '1'},
            {'name': 'page', 'type': 'url_param', 'value': 'home'}
        ]
    }
    
    # Analyze target
    analysis = ai_engine.analyze_target(target_info)
    
    print(f"\nTarget: {analysis['target']}")
    print(f"\nDetected Technologies:")
    for tech in analysis['technology_stack']:
        print(f"  - {tech['name']} ({tech['type']})")
    
    print(f"\nRecommended Scans:")
    for scan in analysis['recommended_scans'][:5]:
        print(f"  - {scan.upper()}")
    
    print(f"\nTop Priority Vulnerabilities:")
    for vuln in analysis['priority_vulnerabilities'][:3]:
        print(f"  - {vuln['type'].upper()} (Severity: {vuln['severity']})")


async def main():
    """Run all examples"""
    print("\n" + "="*70)
    print("HackTheWeb - Example Usage Demonstrations")
    print("="*70)
    
    # Example 1: Basic scan
    # Uncomment to run actual scan
    # await example_basic_scan()
    
    # Example 2: Custom configuration
    await example_custom_config()
    
    # Example 3: Report generation
    example_report_generation()
    
    # Example 4: AI analysis
    example_ai_analysis()
    
    print("\n" + "="*70)
    print("Examples completed!")
    print("="*70)
    print("\nFor more information, see the documentation or run:")
    print("  hacktheweb --help")
    print()


if __name__ == '__main__':
    asyncio.run(main())
