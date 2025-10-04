#!/usr/bin/env python3
"""
HackTheWeb - CLI Interface
Main command-line interface for the pentesting tool
"""

import sys
import asyncio
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint
from pathlib import Path

from hacktheweb.core.config import Config
from hacktheweb.core.ai_engine import AIEngine
from hacktheweb.core.scanner import Scanner
from hacktheweb.reporting.report_generator import ReportGenerator

console = Console()


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    HackTheWeb - AI-Powered Web Application Penetration Testing Tool
    
    A comprehensive security testing framework for web applications.
    """
    pass


@cli.command()
@click.argument('target')
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--output', '-o', type=click.Path(), help='Output directory for reports')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'pdf', 'markdown']), 
              default='html', help='Report format')
@click.option('--scan-mode', '-m', type=click.Choice(['fast', 'smart', 'thorough']), 
              default='smart', help='Scan mode')
@click.option('--threads', '-t', type=int, default=10, help='Number of threads')
@click.option('--delay', '-d', type=float, default=0, help='Delay between requests (seconds)')
@click.option('--techniques', multiple=True, 
              type=click.Choice(['xss', 'sqli', 'csrf', 'ssrf', 'lfi', 'rfi', 'xxe', 'rce']),
              help='Specific techniques to use')
def scan(target, config, output, format, scan_mode, threads, delay, techniques):
    """
    Scan a target web application for vulnerabilities
    
    TARGET: The URL of the target web application (e.g., https://example.com)
    """
    
    # Display banner
    display_banner()
    
    # Validate target
    if not target.startswith(('http://', 'https://')):
        console.print("[red][!] Error: Target must start with http:// or https://[/red]")
        sys.exit(1)
    
    # Load configuration
    cfg = Config(config) if config else Config()
    
    # Apply CLI options
    if scan_mode:
        cfg.set('scanning.scan_mode', scan_mode)
    if threads:
        cfg.set('general.threads', threads)
    if delay:
        cfg.set('general.delay', delay)
    if techniques:
        cfg.set('scanning.techniques', list(techniques))
    
    # Initialize components
    ai_engine = AIEngine(cfg)
    scanner = Scanner(cfg, ai_engine)
    
    # Run scan
    console.print(f"\n[bold cyan]🎯 Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]📋 Scan Mode:[/bold cyan] {scan_mode}")
    console.print(f"[bold cyan]🧵 Threads:[/bold cyan] {threads}")
    console.print()
    
    try:
        with console.status("[bold green]Scanning in progress...", spinner="dots"):
            results = asyncio.run(scanner.scan(target))
        
        # Display results summary
        display_results_summary(results)
        
        # Generate report
        report_gen = ReportGenerator(cfg)
        report_path = report_gen.generate(results, format)
        
        console.print(f"\n[bold green]✅ Report generated:[/bold green] {report_path}")
        
        # Display vulnerability details
        if results.get('vulnerabilities'):
            display_vulnerabilities(results['vulnerabilities'])
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Error during scan: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', type=click.Path(), default='config/default_config.yaml',
              help='Output path for configuration file')
def init_config(output):
    """
    Initialize a default configuration file
    """
    cfg = Config()
    cfg.save_config(output)
    console.print(f"[green]✅ Configuration file created: {output}[/green]")


@cli.command()
def list_techniques():
    """
    List all available scanning techniques
    """
    console.print("\n[bold cyan]Available Scanning Techniques:[/bold cyan]\n")
    
    techniques = [
        ("XSS", "Cross-Site Scripting", "Detects reflected, stored, and DOM-based XSS", "✅ Implemented"),
        ("SQLi", "SQL Injection", "Tests for SQL injection vulnerabilities", "✅ Implemented"),
        ("CSRF", "Cross-Site Request Forgery", "Checks for missing CSRF protection", "✅ Implemented"),
        ("SSRF", "Server-Side Request Forgery", "Tests for SSRF vulnerabilities", "✅ Implemented"),
        ("LFI", "Local File Inclusion", "Detects local file inclusion vulnerabilities", "✅ Implemented"),
        ("Security Headers", "Security Headers Check", "Validates security HTTP headers", "✅ Implemented"),
        ("XXE", "XML External Entity", "Checks for XXE vulnerabilities", "✅ Implemented"),
        ("RCE", "Remote Code Execution", "Tests for command injection and code execution", "✅ Implemented"),
        ("IDOR", "Insecure Direct Object Reference", "Detects IDOR vulnerabilities", "✅ Implemented"),
        ("Open Redirect", "URL Redirection", "Tests for open redirect vulnerabilities", "✅ Implemented"),
        ("CORS", "CORS Misconfiguration", "Checks for CORS security issues", "✅ Implemented"),
        ("Path Traversal", "Directory Traversal", "Tests for path traversal issues", "✅ Implemented"),
        ("NoSQLi", "NoSQL Injection", "Detects MongoDB and NoSQL injection", "✅ Implemented"),
        ("LDAPi", "LDAP Injection", "Tests for LDAP injection vulnerabilities", "✅ Implemented"),
        ("SSTI", "Server-Side Template Injection", "Detects template injection flaws", "✅ Implemented"),
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Technique", style="cyan", width=20)
    table.add_column("Full Name", style="green", width=30)
    table.add_column("Description", style="white", width=40)
    table.add_column("Status", style="yellow", width=15)
    
    for tech, name, desc, status in techniques:
        table.add_row(tech, name, desc, status)
    
    console.print(table)
    console.print(f"\n[bold green]Total Scanners: {len(techniques)}[/bold green]\n")


@cli.command()
@click.argument('report_file', type=click.Path(exists=True))
def view_report(report_file):
    """
    View a previously generated report
    """
    import json
    
    with open(report_file, 'r') as f:
        if report_file.endswith('.json'):
            results = json.load(f)
            display_results_summary(results)
            if results.get('vulnerabilities'):
                display_vulnerabilities(results['vulnerabilities'])
        else:
            console.print("[yellow]Only JSON reports can be viewed in CLI[/yellow]")


@cli.command()
def web():
    """
    Launch the web dashboard interface
    """
    console.print("[bold cyan]🌐 Launching HackTheWeb Web Dashboard...[/bold cyan]")
    console.print("[yellow]Note: Web interface is under development[/yellow]")
    # TODO: Implement web dashboard


def display_banner():
    """Display ASCII banner"""
    banner = """
[bold cyan]
██╗  ██╗ █████╗  ██████╗██╗  ██╗████████╗██╗  ██╗███████╗██╗    ██╗███████╗██████╗ 
██║  ██║██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██║  ██║██╔════╝██║    ██║██╔════╝██╔══██╗
███████║███████║██║     █████╔╝    ██║   ███████║█████╗  ██║ █╗ ██║█████╗  ██████╔╝
██╔══██║██╔══██║██║     ██╔═██╗    ██║   ██╔══██║██╔══╝  ██║███╗██║██╔══╝  ██╔══██╗
██║  ██║██║  ██║╚██████╗██║  ██╗   ██║   ██║  ██║███████╗╚███╔███╔╝███████╗██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═════╝ 
[/bold cyan]
[bold white]AI-Powered Web Application Penetration Testing Tool v1.0[/bold white]
[dim]By YashAB Cyber Security[/dim]
"""
    console.print(banner)


def display_results_summary(results):
    """Display scan results summary"""
    stats = results.get('statistics', {})
    
    # Summary panel
    summary_text = f"""
[bold]Target:[/bold] {results.get('target', 'N/A')}
[bold]Duration:[/bold] {stats.get('scan_duration', 0):.2f} seconds
[bold]Total Vulnerabilities:[/bold] {stats.get('total_vulnerabilities', 0)}
"""
    
    console.print(Panel(summary_text, title="[bold cyan]Scan Summary[/bold cyan]", 
                       border_style="cyan"))
    
    # Severity breakdown table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=15)
    table.add_column("Count", justify="right", style="cyan", width=10)
    
    severity_colors = {
        'critical': 'red',
        'high': 'orange1',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'white',
    }
    
    by_severity = stats.get('by_severity', {})
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = by_severity.get(severity, 0)
        color = severity_colors.get(severity, 'white')
        table.add_row(f"[{color}]{severity.upper()}[/{color}]", str(count))
    
    console.print("\n")
    console.print(table)


def display_vulnerabilities(vulnerabilities):
    """Display vulnerability details"""
    console.print("\n[bold cyan]📋 Vulnerability Details:[/bold cyan]\n")
    
    severity_colors = {
        'critical': 'red',
        'high': 'orange1',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'white',
    }
    
    for i, vuln in enumerate(vulnerabilities, 1):
        severity = vuln.get('severity', 'info')
        color = severity_colors.get(severity, 'white')
        
        vuln_text = f"""
[bold]{i}. {vuln.get('type', 'Unknown').upper()}[/bold] - [{color}]{severity.upper()}[/{color}]

[bold]URL:[/bold] {vuln.get('url', 'N/A')}
[bold]Parameter:[/bold] {vuln.get('parameter', 'N/A')}
[bold]Description:[/bold] {vuln.get('description', 'N/A')}
[bold]Remediation:[/bold] {vuln.get('remediation', 'N/A')}
"""
        
        console.print(Panel(vuln_text, border_style=color, expand=False))


def main():
    """Main entry point"""
    try:
        cli()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()
