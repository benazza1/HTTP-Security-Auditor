HTTP Security Auditor

Version: "1.0.0"
Language: Python 3
Platform: Termux / Linux

A lightweight Python tool for analyzing HTTP security headers on authorized websites. It identifies missing or improperly configured security headers and generates readable security reports.

Features

- HTTP and HTTPS URL normalization
- Initial DNS and public IP validation
- HSTS and Content-Security-Policy analysis
- Clickjacking protection checks
- X-Content-Type-Options and Referrer-Policy checks
- Severity classification and text reports
- Connection timeouts and response size limits
- TLS certificate verification
- Command-line interface

Requirements

- Python 3
- Requests
- Termux or Linux

Installation

Clone the repository:

git clone https://github.com/benazza1/HTTP-Security-Auditor.git
cd HTTP-Security-Auditor
pip install -r requirements.txt

Usage

Display the help menu:

python main.py

Display the version:

python main.py --version

Scan an authorized website:

python main.py https://example.com

Important: Only scan websites you own or have explicit permission to test.

Demo – Scan Output

The following is an example of a real scan performed against "https://example.com":

HTTP SECURITY AUDITOR
Version: 1.0.0

Target:        https://example.com/
HTTP Status:   200
Response Time: 0.424s
Findings:      5

SECURITY FINDINGS

1. Strict-Transport-Security
   Severity: Medium
   Classification: WARNING

2. Content-Security-Policy
   Severity: Medium
   Classification: WARNING

3. Clickjacking Protection
   Severity: Medium
   Classification: WARNING

4. X-Content-Type-Options
   Severity: Low
   Classification: WARNING

5. Referrer-Policy
   Severity: Low
   Classification: INFO

[SUCCESS] Scan completed.

These findings indicate missing security headers in the tested response. They do not necessarily represent confirmed vulnerabilities.

Reports

Reports are saved in the "reports/" directory and include:

- Target URL
- HTTP status
- Response time
- Scan date
- Security findings
- Severity summary
- Evidence and recommendations

Security Limitations

- Findings are configuration observations, not necessarily confirmed vulnerabilities.
- DNS validation is an initial protection layer and does not fully prevent DNS rebinding or SSRF.
- Automatic redirects are disabled.
- This is not a complete penetration-testing framework.

Project Structure

HTTP-Security-Auditor/
├── core/
├── modules/
├── reports/
├── backups/
├── tests/
├── main.py
├── test_scan.py
├── requirements.txt
├── README.md
└── LICENSE

Testing

Run the unit tests:

python -m unittest discover -s tests -t . -v

Check Python syntax:

python -m py_compile main.py core/*.py modules/*.py

License

This project is distributed under the MIT License. See the "LICENSE" (LICENSE) file.

Support the Project

If you find this project useful and would like to support its development, voluntary financial contributions are welcome.

Your support helps maintain and improve this open-source project.

Thank you for supporting independent development!
