ScanXSS v1.3.1 — Web Vulnerability Scanner
==========================================

QUICK START
-----------
1. Launch ScanXSS from the Start Menu or Desktop shortcut
2. Enter the target URL (e.g. https://example.com/)
3. Configure depth, rate limit, and modules
4. Click "Start Scan"
5. Results appear in the Vulnerabilities tab
6. Export report via File → Export Report (HTML/JSON/CSV)

SCAN MODES
----------
• subdomain  — scan all subdomains of the target (recommended)
• domain     — only the exact domain
• folder     — only pages in the same URL folder
• url        — only the single URL

MODULES
-------
• XSS       — Cross-Site Scripting
• SQLi      — SQL Injection
• LFI       — Local File Inclusion
• RCE       — Remote Code Execution
• SSRF      — Server-Side Request Forgery
• Redirect  — Open Redirect
• CRLF      — CRLF Header Injection

DATABASE
--------
Results are stored in scan.db next to scanxss-gui.exe.
View history: Database → Scan History

REPORTS
-------
Reports are saved to the reports\ folder next to the executable.
Format: HTML (recommended), JSON, CSV

LEGAL
-----
Use only on systems you own or have written permission to test.
Unauthorized scanning may be illegal.

GPL-2.0 License — https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
