# Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/yashab-cyber/hacktheweb.git
cd hacktheweb

# Run installation
chmod +x scripts/install.sh
./scripts/install.sh
```

## First Scan

```bash
# Basic scan
hacktheweb scan http://testphp.vulnweb.com

# With HTML report
hacktheweb scan http://testphp.vulnweb.com --format html
```

## Common Commands

### List Available Techniques
```bash
hacktheweb list-techniques
```

### Scan with Specific Techniques
```bash
hacktheweb scan http://example.com --techniques xss sqli csrf
```

### Custom Scan Mode
```bash
# Fast scan
hacktheweb scan http://example.com --scan-mode fast

# Smart scan (default)
hacktheweb scan http://example.com --scan-mode smart

# Thorough scan
hacktheweb scan http://example.com --scan-mode thorough
```

### Generate Configuration
```bash
hacktheweb init-config --output myconfig.yaml
```

### Scan with Custom Config
```bash
hacktheweb scan http://example.com --config myconfig.yaml
```

## Report Formats

```bash
# HTML report (default)
hacktheweb scan http://example.com --format html

# JSON report
hacktheweb scan http://example.com --format json

# Markdown report
hacktheweb scan http://example.com --format markdown

# PDF report
hacktheweb scan http://example.com --format pdf
```

## Advanced Usage

### Custom Threading and Rate Limiting
```bash
hacktheweb scan http://example.com \
  --threads 20 \
  --delay 0.5
```

### View Previous Report
```bash
hacktheweb view-report reports/report_20231025_143022.json
```

## Python API

```python
import asyncio
from hacktheweb.core.config import Config
from hacktheweb.core.ai_engine import AIEngine
from hacktheweb.core.scanner import Scanner

# Initialize
config = Config()
ai_engine = AIEngine(config)
scanner = Scanner(config, ai_engine)

# Scan
results = asyncio.run(scanner.scan('http://example.com'))

# Process results
print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
```

## Tips

1. **Always get permission** before scanning any target
2. **Start with fast mode** to get quick results
3. **Use smart mode** for balanced scanning
4. **Use thorough mode** for comprehensive testing
5. **Review HTML reports** for detailed analysis
6. **Export JSON** for automation and integration

## Common Issues

### Permission Denied
```bash
# Make scripts executable
chmod +x scripts/*.sh
```

### Module Not Found
```bash
# Activate virtual environment
source venv/bin/activate

# Or reinstall
pip install -e .
```

### SSL Errors
```bash
# Disable SSL verification in config
verify_ssl: false
```

## Next Steps

- Read the [full documentation](../README.md)
- Explore [examples](../examples/demo.py)
- Customize [configuration](../config/default_config.yaml)
- Join the community discussions
