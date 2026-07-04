# HackTheWeb

<div align="center">

![HackTheWeb Logo](https://img.shields.io/badge/HackTheWeb-v1.0-blue?style=for-the-badge)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=for-the-badge)](https://www.linux.org/)

**AI-Powered Web Application Penetration Testing Tool**

*Automated security testing with intelligent decision-making*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation)

</div>

---

## 🎯 Overview

**HackTheWeb** is a production-ready, AI-powered web application penetration testing tool designed for security professionals and ethical hackers. It uses rule-based artificial intelligence (no external ML models required) to intelligently scan web applications for vulnerabilities, adapt scanning strategies, and generate comprehensive security reports.

### Key Highlights

- **🤖 AI-Powered:** Intelligent scanning with adaptive algorithms
- **🚀 Production-Ready:** Fully functional and battle-tested
- **🔧 No ML Models:** Pure rule-based AI - no external dependencies
- **🐧 Linux Optimized:** Works on Kali, Ubuntu, Debian, and all security-focused distros
- **📊 Comprehensive Reporting:** HTML, PDF, JSON, and Markdown reports
- **⚡ Fast & Efficient:** Asynchronous scanning with rate limiting
- **🎨 Beautiful CLI:** Rich terminal interface with real-time progress

---

## ✨ Features

### Vulnerability Scanning

- **XSS (Cross-Site Scripting)** - Reflected, Stored, and DOM-based ✅
- **SQL Injection** - Error-based, Boolean-based, Time-based, UNION-based ✅
- **CSRF (Cross-Site Request Forgery)** - Token validation and cookie analysis ✅
- **SSRF (Server-Side Request Forgery)** - Internal network probing ✅
- **LFI/RFI (File Inclusion)** - Local and remote file inclusion ✅
- **XXE (XML External Entity)** - XML injection attacks ✅
- **Security Headers** - Validates HTTP security headers (HSTS, CSP, etc.) ✅
- **RCE (Remote Code Execution)** - Command injection and code execution ✅
- **IDOR (Insecure Direct Object Reference)** - Access control issues ✅
- **Open Redirect** - URL redirection vulnerabilities ✅
- **CORS Misconfiguration** - Cross-origin resource sharing issues ✅
- **Path Traversal** - Directory traversal detection ✅
- **NoSQL Injection** - MongoDB and NoSQL database attacks ✅
- **LDAP Injection** - LDAP query injection ✅
- **SSTI** - Server-Side Template Injection ✅

### AI Intelligence

- **Smart Target Analysis** - Technology stack detection
- **Adaptive Scanning** - Prioritizes high-impact vulnerabilities
- **Pattern Recognition** - Learns from scan results
- **Resource Optimization** - Efficient payload selection
- **Context-Aware Testing** - Technology-specific vulnerability checks

### Reporting

- **Multiple Formats** - HTML, PDF, JSON, Markdown
- **Severity Classification** - Critical, High, Medium, Low, Info
- **OWASP & CWE Mapping** - Industry-standard categorization
- **Remediation Guidance** - Actionable fix recommendations
- **Beautiful Visualizations** - Charts and statistics

### 📊 Enterprise Logging & Fingerprinting

- **Structured JSON Logging** - Native JSON logs optimized for Splunk, ELK, and other SIEM log collectors.
- **Audit Trails** - Secure trace logging of scanner phases, resolving domains, and vulnerabilities detected for operational security auditing.
- **Dynamic Technology Fingerprinting** - Heuristic fingerprinting mapping response headers, framework cookies (like `PHPSESSID`, `JSESSIONID`, `laravel_session`), and DOM patterns (such as React and Angular markers).

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Linux-based OS (Kali Linux, Ubuntu, Debian, etc.)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yashab-cyber/hacktheweb.git
cd hacktheweb

# Run installation script
chmod +x scripts/install.sh
./scripts/install.sh
```

### Manual Installation

```bash
# Install system dependencies (Debian/Ubuntu/Kali)
sudo apt-get update
sudo apt-get install python3-pip python3-venv python3-dev build-essential \
                     libssl-dev libffi-dev libxml2-dev libxslt1-dev nmap

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install HackTheWeb
pip install -e .

# Initialize configuration
hacktheweb init-config
```

### Docker Installation (Coming Soon)

```bash
docker pull hacktheweb/hacktheweb:latest
docker run -it hacktheweb/hacktheweb scan https://example.com
```

---

## 🚀 Usage

### Basic Scan

```bash
# Simple scan
hacktheweb scan https://example.com

# Scan with HTML report
hacktheweb scan https://example.com --format html
```

### Advanced Scanning

```bash
# Thorough scan with custom threads
hacktheweb scan https://example.com --scan-mode thorough --threads 20

# Specific vulnerability tests
hacktheweb scan https://example.com --techniques xss sqli csrf

# Custom configuration
hacktheweb scan https://example.com --config custom_config.yaml

# Multiple output formats
hacktheweb scan https://example.com --format pdf --output ./reports
```

### CLI Commands

```bash
# List all available techniques
hacktheweb list-techniques

# View a report
hacktheweb view-report reports/report_20231025_143022.json

# Initialize default config
hacktheweb init-config --output config/myconfig.yaml

# Launch web dashboard (coming soon)
hacktheweb web
```

### Python API

```python
import asyncio
from hacktheweb.core.config import Config
from hacktheweb.core.ai_engine import AIEngine
from hacktheweb.core.scanner import Scanner
from hacktheweb.reporting.report_generator import ReportGenerator

# Initialize components
config = Config()
ai_engine = AIEngine(config)
scanner = Scanner(config, ai_engine)

# Run scan
results = asyncio.run(scanner.scan('https://example.com'))

# Generate report
report_gen = ReportGenerator(config)
report_path = report_gen.generate(results, format='html')

print(f"Report generated: {report_path}")
```

---

## 📚 Documentation

### Configuration

HackTheWeb uses YAML configuration files. Generate a default config:

```bash
hacktheweb init-config --output config/myconfig.yaml
```

**Sample Configuration:**

```yaml
general:
  threads: 10
  timeout: 30
  delay: 0
  verify_ssl: false

scanning:
  max_depth: 3
  scan_mode: smart  # fast, smart, thorough
  techniques:
    - xss
    - sqli
    - csrf
    - ssrf

ai:
  learning_enabled: true
  confidence_threshold: 0.7
  adaptive_scanning: true

reporting:
  format: html
  include_payloads: true

rate_limiting:
  enabled: true
  requests_per_second: 10
```

### Scan Modes

- **Fast:** Quick scan with minimal payloads
- **Smart (Default):** AI-optimized scanning strategy
- **Thorough:** Comprehensive scan with all techniques

### Report Formats

- **HTML:** Interactive web-based report with styling
- **PDF:** Professional PDF document
- **JSON:** Machine-readable format for automation
- **Markdown:** Text-based report for documentation

---

## 🛡️ Security & Ethics

### Legal Disclaimer

⚠️ **IMPORTANT:** This tool is for authorized security testing only. 

- ✅ **DO:** Get written permission before testing
- ✅ **DO:** Use on your own systems or with explicit authorization
- ✅ **DO:** Follow responsible disclosure practices
- ❌ **DON'T:** Test systems without permission
- ❌ **DON'T:** Use for illegal activities
- ❌ **DON'T:** Cause damage or disruption

**By using HackTheWeb, you agree to use it responsibly and ethically.**

### Responsible Usage

1. Always obtain written authorization
2. Respect scope limitations
3. Handle sensitive data carefully
4. Report findings responsibly
5. Follow local laws and regulations

---

## 💾 Data & Payloads

HackTheWeb comes with comprehensive payload databases and wordlists in the `data/` directory:

### Payload Databases
- **XSS Payloads** - 28+ injection vectors (basic, encoded, polyglot, DOM-based)
- **SQLi Payloads** - 42+ SQL injection patterns (MySQL, PostgreSQL, MSSQL)
- **Sensitive Files** - 40+ Linux/Windows file paths for LFI/Path Traversal

### Discovery & Testing
- **Common Endpoints** - 30+ API endpoints and admin panels
- **User Agents** - 8 modern browser user-agent strings
- **Usernames/Passwords** - Common credentials for authentication testing
- **File Extensions** - 35+ extensions for file inclusion testing
- **Technology Fingerprints** - 40+ patterns for technology detection

### Customization
Add your own payloads by editing files in the `data/` directory:

```bash
# Add custom XSS payload
echo '<custom>payload</custom>' >> data/xss_payloads.txt

# Add organization-specific file path
echo '/var/www/myapp/config.php' >> data/sensitive_files_linux.txt
```

Scanners automatically load payloads from these files, giving you **500+ payloads** out of the box!

📖 **Learn More:** See [DATA_INTEGRATION_COMPLETE.md](DATA_INTEGRATION_COMPLETE.md)

---

## 🏗️ Architecture

```
hacktheweb/
├── core/              # Core engine and AI logic
│   ├── ai_engine.py   # Rule-based AI engine
│   ├── scanner.py     # Main scanning orchestrator
│   └── config.py      # Configuration management
├── scanners/          # Vulnerability scanners (15 total)
│   ├── xss_scanner.py
│   ├── sqli_scanner.py
│   ├── csrf_scanner.py
│   ├── ssrf_scanner.py
│   ├── lfi_scanner.py
│   ├── rce_scanner.py
│   ├── idor_scanner.py
│   └── ...            # 8 more scanners
├── utils/             # Utility modules
│   └── data_loader.py # Loads payloads from data/
├── data/              # Payload databases & wordlists ✨ NEW
│   ├── xss_payloads.txt
│   ├── sqli_payloads.txt
│   ├── sensitive_files_linux.txt
│   ├── sensitive_files_windows.txt
│   └── ...            # More data files
├── recon/             # Reconnaissance modules
├── exploits/          # Exploit framework
├── reporting/         # Report generators
│   └── report_generator.py
├── web/               # Web dashboard (coming soon)
└── cli.py             # Command-line interface
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone and install in development mode
git clone https://github.com/yashab-cyber/hacktheweb.git
cd hacktheweb
pip install -e ".[dev]"

# Run tests
pytest tests/

# Check code quality
flake8 hacktheweb/
black hacktheweb/
```

---

## 📝 Roadmap

- [x] Core AI engine
- [x] Basic vulnerability scanners
- [x] Report generation
- [x] CLI interface
- [ ] Web dashboard
- [ ] API server
- [ ] Plugin system
- [ ] Custom payload editor
- [ ] Collaboration features
- [ ] CI/CD integration
- [ ] Browser automation
- [ ] Mobile app testing

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Authors

**YashAB Cyber Security (Yashab Alam)**

- GitHub: [@yashab-cyber](https://github.com/yashab-cyber)
- Website: [hacktheweb.io](https://hacktheweb.io)
- Instagram: [@yashabcyber](https://www.instagram.com/yashabcyber)
- X (formerly Twitter): [@Yashab_cyber](https://x.com/Yashab_cyber)
- LinkedIn: [Yashab Alam](https://www.linkedin.com/in/yashab-alam)
- Threads: [@yashabcyber](https://www.threads.net/@yashabcyber)

---

## 🙏 Acknowledgments

- Inspired by industry-leading security tools
- Built with modern Python best practices
- Community-driven development

---

## 📞 Support & Inquiries

For support, feedback, or custom inquiries:
- **GitHub Issues:** [Issues](https://github.com/yashab-cyber/hacktheweb/issues)
- **GitHub Discussions:** [Discussions](https://github.com/yashab-cyber/hacktheweb/discussions)
- **Primary Email:** [yashabalam9@gmail.com](mailto:yashabalam9@gmail.com)
- **Secondary Email:** [yashabalam707@gmail.com](mailto:yashabalam707@gmail.com)
- **Donation Enquiries:** Please see [DONATE.md](DONATE.md) for more details.

---

<div align="center">

**Made with ❤️ by security professionals, for security professionals**

⭐ Star this repository if you find it useful!

</div>