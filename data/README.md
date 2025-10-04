# README: Data Directory

## Purpose
The `data/` directory contains various wordlists and payload databases used by HackTheWeb scanners to enhance their detection capabilities.

## Files

### Authentication & Testing
- **common_usernames.txt** - Common usernames for authentication bypass testing
- **common_passwords.txt** - Common passwords for brute force testing

### File Testing
- **file_extensions.txt** - Common file extensions for LFI/RFI testing
- **sensitive_files_linux.txt** - Sensitive Linux/Unix file paths
- **sensitive_files_windows.txt** - Sensitive Windows file paths

### Payloads
- **xss_payloads.txt** - Extended XSS payload database
- **sqli_payloads.txt** - Extended SQL injection payloads

### Discovery
- **common_endpoints.txt** - Common API and web endpoints
- **technology_fingerprints.txt** - Technology detection patterns
- **user_agents.txt** - User-Agent strings for rotation

## Usage

Scanners automatically load these files when needed. You can extend any of these files with custom payloads or paths relevant to your testing needs.

### Example: Adding Custom XSS Payloads
```bash
echo '<custom>payload</custom>' >> data/xss_payloads.txt
```

### Example: Using in Scanner
```python
# In a scanner
with open('data/xss_payloads.txt', 'r') as f:
    payloads = [line.strip() for line in f if line.strip()]
```

## Customization

Feel free to:
- Add new payload variations
- Include organization-specific paths
- Add custom endpoints for testing
- Extend wordlists with domain-specific terms

## Security Note

These files contain potentially dangerous payloads. Use only in authorized testing environments. Never use against systems you don't have permission to test.
