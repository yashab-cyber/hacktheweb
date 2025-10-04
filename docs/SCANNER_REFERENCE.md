# 🎯 HackTheWeb - Complete Scanner Reference Guide

## 📚 Quick Reference - All 15 Scanners

This guide provides detailed information about all 15 vulnerability scanners in HackTheWeb.

---

## 1️⃣ XSS Scanner (Cross-Site Scripting)

**Severity**: HIGH | **Type**: Injection | **CWE**: CWE-79 | **OWASP**: A03:2021

### What It Detects
- Reflected XSS (user input reflected in response)
- Stored XSS (persistent malicious scripts)
- DOM-based XSS (client-side code injection)

### Payloads Used
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- Event handlers: `onclick`, `onerror`, `onload`

### How It Works
1. Injects XSS payloads into forms and URL parameters
2. Checks if payloads are reflected in HTML response
3. Verifies script execution is possible

---

## 2️⃣ SQLi Scanner (SQL Injection)

**Severity**: CRITICAL | **Type**: Injection | **CWE**: CWE-89 | **OWASP**: A03:2021

### What It Detects
- Error-based SQL injection
- Boolean-based blind SQL injection  
- Time-based blind SQL injection
- UNION-based SQL injection

### Techniques
- **Error-based**: `' OR '1'='1`, `" OR "1"="1`
- **Time-based**: `' AND SLEEP(5)--`, `'; WAITFOR DELAY '00:00:05'--`
- **Boolean**: `' AND 1=1--`, `' AND 1=2--`
- **UNION**: `' UNION SELECT NULL--`

### Database Support
- MySQL
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite

---

## 3️⃣ CSRF Scanner (Cross-Site Request Forgery)

**Severity**: MEDIUM | **Type**: Authentication | **CWE**: CWE-352 | **OWASP**: A01:2021

### What It Detects
- Missing CSRF tokens in forms
- Weak or predictable tokens
- Insecure cookie attributes (missing SameSite)
- No anti-CSRF headers

### Checks Performed
- Token presence in forms
- Token randomness
- Cookie `SameSite` attribute
- Cookie `Secure` flag
- Cookie `HttpOnly` flag

---

## 4️⃣ SSRF Scanner (Server-Side Request Forgery)

**Severity**: HIGH | **Type**: Network | **CWE**: CWE-918 | **OWASP**: A10:2021

### What It Detects
- Access to internal services (localhost, 127.0.0.1)
- Cloud metadata endpoints (AWS, GCP, Azure)
- File protocol access (`file://`)
- Internal IP ranges (10.x, 192.168.x, 172.16-31.x)

### Payloads
- `http://localhost:22`
- `http://169.254.169.254/latest/meta-data/`
- `http://metadata.google.internal/`
- `file:///etc/passwd`

---

## 5️⃣ LFI Scanner (Local File Inclusion)

**Severity**: HIGH | **Type**: File Access | **CWE**: CWE-98 | **OWASP**: A03:2021

### What It Detects
- Direct file inclusion
- Path traversal for file access
- Null byte injection
- Filter bypass techniques

### Payloads
- `../../../etc/passwd`
- `..\\..\\..\\windows\\win.ini`
- URL encoded: `..%2F..%2F..%2Fetc%2Fpasswd`
- Null byte: `../../../etc/passwd%00`

---

## 6️⃣ Security Headers Scanner

**Severity**: LOW | **Type**: Configuration | **CWE**: CWE-16 | **OWASP**: A05:2021

### Headers Checked
1. **Strict-Transport-Security (HSTS)**
   - Forces HTTPS connections
   - Checks max-age value

2. **Content-Security-Policy (CSP)**
   - Prevents XSS and data injection
   - Detects unsafe directives

3. **X-Frame-Options**
   - Prevents clickjacking
   - Values: DENY, SAMEORIGIN

4. **X-Content-Type-Options**
   - Prevents MIME sniffing
   - Value: nosniff

5. **X-XSS-Protection**
   - Browser XSS filter
   - Value: 1; mode=block

6. **Referrer-Policy**
   - Controls referer information

7. **Permissions-Policy**
   - Feature policy controls

### Also Detects
- Information disclosure headers (Server, X-Powered-By)

---

## 7️⃣ XXE Scanner (XML External Entity)

**Severity**: HIGH | **Type**: Injection | **CWE**: CWE-611 | **OWASP**: A05:2021

### What It Detects
- File disclosure via XXE
- SSRF via XXE
- Denial of Service (Billion Laughs attack)
- Out-of-band data exfiltration

### Techniques
- External entity file reading
- Parameter entity attacks
- DTD-based attacks
- Billion Laughs (XML bomb)

---

## 8️⃣ RCE Scanner (Remote Code Execution) ⭐NEW

**Severity**: CRITICAL | **Type**: Injection | **CWE**: CWE-78, CWE-94 | **OWASP**: A03:2021

### What It Detects
- Command injection (OS commands)
- Code execution (eval, exec)
- Template injection (basic)

### Payloads
**Unix:**
- `;sleep 5`, `| sleep 5`, `$(sleep 5)`
- `;id`, `;cat /etc/passwd`

**Windows:**
- `& timeout 5`, `| whoami`
- `; ping -n 5 127.0.0.1`

**Code Execution:**
- `phpinfo()`, `<?php system('id'); ?>`
- `${7*7}`, `{{7*7}}`

### Detection Methods
- Time-based (sleep/timeout delays)
- Content-based (command output detection)

---

## 9️⃣ IDOR Scanner (Insecure Direct Object Reference) ⭐NEW

**Severity**: HIGH | **Type**: Access Control | **CWE**: CWE-639 | **OWASP**: A01:2021

### What It Detects
- Unauthorized access to other users' data
- Predictable resource IDs
- Missing authorization checks
- Sensitive data exposure

### Testing Strategy
1. Identifies ID parameters (user_id, account_id, file_id)
2. Tests ID manipulation (increment, decrement, negative)
3. Checks for access control bypass
4. Detects sensitive data exposure

### Sensitive Data Patterns
- Email addresses
- Phone numbers
- SSN
- Credit cards
- API keys
- Passwords

---

## 🔟 Open Redirect Scanner ⭐NEW

**Severity**: MEDIUM | **Type**: Access Control | **CWE**: CWE-601 | **OWASP**: A01:2021

### What It Detects
- Unvalidated redirects to external sites
- Header injection
- JavaScript protocol exploitation
- Meta refresh tag redirects

### Payloads
- `https://evil.com`
- `//evil.com`, `///evil.com`
- `javascript:alert(1)`
- `data:text/html,<script>alert(1)</script>`

### Detection Methods
- Location header analysis
- Meta refresh tag detection
- JavaScript redirect detection

---

## 1️⃣1️⃣ CORS Scanner ⭐NEW

**Severity**: MEDIUM-HIGH | **Type**: Configuration | **CWE**: CWE-942 | **OWASP**: A05:2021

### What It Detects
- Reflected arbitrary origins
- Null origin acceptance
- Wildcard with credentials
- Dangerous methods allowed
- Arbitrary headers allowed

### Tests Performed
1. Origin reflection test
2. Null origin test
3. Pre-flight request analysis
4. Credentials check
5. Dangerous methods (PUT, DELETE)

---

## 1️⃣2️⃣ Path Traversal Scanner ⭐NEW

**Severity**: HIGH | **Type**: File Access | **CWE**: CWE-22 | **OWASP**: A01:2021

### What It Detects
- Directory traversal attacks
- File system access via path manipulation
- Bypass techniques

### Payloads
- Basic: `../../../etc/passwd`
- URL encoded: `..%2F..%2F..%2Fetc%2Fpasswd`
- Double encoded: `..%252F..%252F`
- Null byte: `../../../etc/passwd%00`
- Unicode: `..%c0%af..%c0%af`

### Target Files
- Linux: `/etc/passwd`, `/etc/shadow`, `/etc/hosts`
- Windows: `C:\windows\win.ini`, `C:\boot.ini`

---

## 1️⃣3️⃣ NoSQLi Scanner (NoSQL Injection) ⭐NEW

**Severity**: HIGH | **Type**: Injection | **CWE**: CWE-943 | **OWASP**: A03:2021

### What It Detects
- MongoDB operator injection
- Authentication bypass
- JSON injection
- Query manipulation

### Payloads
**Operators:**
- `{"$ne": null}` - Not equal
- `{"$gt": ""}` - Greater than
- `{"$regex": ".*"}` - Regex match
- `{"$exists": true}` - Field exists

**String Injection:**
- `'||'1'=='1`
- `'; return true; var foo='`

### Detection
- Authentication bypass indicators
- Response content changes
- Status code changes (401/403 → 200)

---

## 1️⃣4️⃣ LDAPi Scanner (LDAP Injection) ⭐NEW

**Severity**: HIGH | **Type**: Injection | **CWE**: CWE-90 | **OWASP**: A03:2021

### What It Detects
- LDAP query injection
- Authentication bypass
- Filter manipulation
- Blind LDAP injection

### Payloads
- `*` - Wildcard
- `*)(&` - Filter bypass
- `*)(objectClass=*` - Boolean injection
- `admin*)((|userPassword=*` - Admin bypass

### Detection Methods
- Error-based (LDAP exceptions)
- Authentication bypass
- Content-based (response changes)

---

## 1️⃣5️⃣ SSTI Scanner (Server-Side Template Injection) ⭐NEW

**Severity**: CRITICAL | **Type**: Injection | **CWE**: CWE-1336 | **OWASP**: A03:2021

### What It Detects
- Template injection in various engines
- Code execution via templates
- Object exposure

### Template Engines Supported
1. **Jinja2** (Python) - `{{7*7}}`
2. **Freemarker** (Java) - `${7*7}`
3. **Velocity** (Java) - `#set($x=7*7)$x`
4. **Smarty** (PHP) - `{$smarty.version}`
5. **Twig** (PHP) - `{{7*7}}`
6. **ERB** (Ruby) - `<%= 7*7 %>`
7. **Tornado** (Python) - `{{7*7}}`

### Detection
- Mathematical expression evaluation (7*7=49)
- String multiplication (7*'7'=7777777)
- Object exposure ({{config}}, {{request}})

---

## 📊 Scanner Priority Matrix

| Scanner | Severity | OWASP | Priority |
|---------|----------|-------|----------|
| RCE | CRITICAL | A03 | ⭐⭐⭐⭐⭐ |
| SSTI | CRITICAL | A03 | ⭐⭐⭐⭐⭐ |
| SQLi | CRITICAL | A03 | ⭐⭐⭐⭐⭐ |
| XXE | HIGH | A05 | ⭐⭐⭐⭐ |
| SSRF | HIGH | A10 | ⭐⭐⭐⭐ |
| LFI | HIGH | A03 | ⭐⭐⭐⭐ |
| NoSQLi | HIGH | A03 | ⭐⭐⭐⭐ |
| LDAPi | HIGH | A03 | ⭐⭐⭐⭐ |
| Path Traversal | HIGH | A01 | ⭐⭐⭐⭐ |
| IDOR | MEDIUM | A01 | ⭐⭐⭐ |
| CORS | MEDIUM | A05 | ⭐⭐⭐ |
| Open Redirect | MEDIUM | A01 | ⭐⭐⭐ |
| CSRF | MEDIUM | A01 | ⭐⭐⭐ |
| XSS | HIGH | A03 | ⭐⭐⭐⭐ |
| Security Headers | LOW | A05 | ⭐⭐ |

---

## 🎯 Usage Examples

### Run All Scanners
```bash
python3 -m hacktheweb.cli scan https://target.com
```

### Scan with Specific Scanners (Future Feature)
```bash
python3 -m hacktheweb.cli scan https://target.com --scanners xss,sqli,rce
```

### List All Available Scanners
```bash
python3 -m hacktheweb.cli list-techniques
```

### Generate Reports
```bash
python3 -m hacktheweb.cli scan https://target.com --format json
python3 -m hacktheweb.cli scan https://target.com --format html
python3 -m hacktheweb.cli scan https://target.com --format pdf
```

---

## 🔍 How Scanners Work Together

### AI-Powered Prioritization
The AI engine analyzes the target and prioritizes scanners based on:

1. **Technology Detection**
   - PHP detected → High priority for RCE, LFI, SSTI
   - Database detected → High priority for SQLi, NoSQLi
   - XML processing → High priority for XXE
   - APIs detected → High priority for IDOR, CORS

2. **Attack Surface Analysis**
   - Many forms → XSS, CSRF, SQLi priority
   - File parameters → LFI, Path Traversal priority
   - Redirect parameters → Open Redirect priority

3. **Severity-Based Scanning**
   - Critical scanners run first (RCE, SSTI, SQLi)
   - High-severity scanners next
   - Medium/Low last

---

## 🛡️ Remediation Quick Guide

| Vulnerability | Quick Fix |
|--------------|-----------|
| **XSS** | Encode output, use Content-Security-Policy |
| **SQLi** | Use parameterized queries, ORM |
| **CSRF** | Implement CSRF tokens, SameSite cookies |
| **SSRF** | Whitelist allowed hosts, validate URLs |
| **LFI** | Validate file paths, use whitelist |
| **XXE** | Disable external entities in XML parser |
| **RCE** | Never pass user input to system commands |
| **IDOR** | Implement access control checks |
| **Open Redirect** | Validate redirect URLs against whitelist |
| **CORS** | Use specific origins, no wildcards with credentials |
| **Path Traversal** | Canonicalize paths, use whitelist |
| **NoSQLi** | Validate input, use parameterized queries |
| **LDAPi** | Escape LDAP special characters |
| **SSTI** | Never use user input in templates |
| **Headers** | Configure proper security headers |

---

## 📚 Further Reading

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**HackTheWeb - Complete vulnerability scanner with 15 professional-grade scanners!** 🚀
