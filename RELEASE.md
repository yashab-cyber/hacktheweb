# 🚀 Release v1.1.0 - Enterprise Logging, Dynamic Fingerprinting & Premium Web Showcase

Welcome to the **v1.1.0** release of **HackTheWeb**! This release introduces professional logging features, advanced dynamic technology detection, and a stunning cyberpunk product landing page.

---

## 🌟 What's New

### 📊 Enterprise Structured JSON Logging & Auditing
- **JSON Telemetry:** Core scan actions now log standard JSON lines suitable for automated integration with ELK stack, Splunk, and enterprise SIEMs.
- **Audit Trails:** Created an operational security audit trail logging scan checkpoints (`scan_start`, `reconnaissance_complete`, `ai_analysis_complete`, `scanning_complete`) along with metadata such as ports found, domains resolved, and vulnerability counts.
- **Centralized Logger:** Unified logger architecture in `hacktheweb.utils.EnterpriseLogger`.

### 🔍 Dynamic Technology Fingerprinting
- **Cookie Mapping:** Added dynamic framework checks parsing target cookie names (e.g. `PHPSESSID`, `JSESSIONID`, `connect.sid`, `laravel_session`, `_rails_admin_session`) to resolve backends even when server headers are stripped.
- **HTML DOM Parsing:** Signatures mapping HTML structures (e.g. `data-reactroot` for React, `ng-version` for Angular, `v-cloak` for Vue.js, `wp-content` for WordPress) dynamically resolve frontend libraries.
- **Deduplication:** Dynamic matching merges discoveries from headers, cookies, and DOM structures, prioritizing highest-confidence detections.

### 🌐 Cyberpunk Landing Page & Live Simulator
- **Responsive Web UI:** Clean, responsive cyberpunk single-page app placed under the `/website` folder.
- **Interactive Simulator CLI:** Landing page features a simulated terminal run reproducing live JSON logs, audit trails, and scanner results.
- **Auto-Deployment:** Enabled subtree pushing targeting `origin gh-pages`. Live site is hosted at: [https://yashab-cyber.github.io/hacktheweb/](https://yashab-cyber.github.io/hacktheweb/)

---

## 🛠️ Key Bug Fixes & Refactoring

- **Scanner Activation Gap:** Fixed a critical bug where scanners like `security_headers`, `cors`, `nosqli`, `ldapi`, and `ssti` were never run. Default techniques list now includes all 15 active modules.
- **CLI Technique Selections:** Click choices in the CLI command parser updated to support all 15 techniques.
- **Scan Strategy Optimization:** Solved the issue where target domains with no landing-page forms or URL params resulted in 0 scans. Fallbacks now activate to run applicable scanners depending on mode (`smart`, `fast`, `thorough`).
- **Recon Engine Connection:** Re-established `ReconEngine.gather_info()` inside the core scanner lifecycle to collect DNS records, SSL status, and port scans.
- **Lint Cleans:** Resolved 65+ style warnings (removed bare `except:` clauses, cleaned unused imports, removed redundant variables).
- **Expanded Test Suite:** Upgraded `test_integration.py` with full mock classes to cover async context managers, cookie headers, and technology analysis.

---

## 👥 Authors & Support

* Maintainer: **YashAB Cyber Security (Yashab Alam)**
* Instagram: [@yashabcyber](https://www.instagram.com/yashabcyber)
* X: [@Yashab_cyber](https://x.com/Yashab_cyber)
* LinkedIn: [Yashab Alam](https://www.linkedin.com/in/yashab-alam)
* Threads: [@yashabcyber](https://www.threads.net/@yashabcyber)
* Contact Email: [yashabalam9@gmail.com](mailto:yashabalam9@gmail.com)
