# HTTP Security Auditor

**Version:** 1.0.0

A lightweight Python tool for analyzing HTTP security headers on authorized websites.

## Features

- HTTP and HTTPS URL normalization
- Initial DNS and public IP validation
- HSTS and Content-Security-Policy analysis
- Clickjacking protection checks
- X-Content-Type-Options and Referrer-Policy checks
- Severity classification and text reports
- Connection timeouts and response size limits
- TLS certificate verification
- Command-line interface

## Requirements

- Python 3
- Requests
- Termux or Linux

## Installation

Clone the repository:

    git clone https://github.com/benazza1/HTTP-Security-Auditor.git
    cd HTTP-Security-Auditor
    pip install -r requirements.txt

## Usage

    python main.py
    python main.py --version
    python main.py https://example.com

Only scan websites you own or have explicit permission to test.

## Reports

Reports are saved in the reports/ directory and include the target URL, HTTP status, response time, scan date, findings, severity summary, evidence, and recommendations.

## Security Limitations

- Findings are configuration observations, not necessarily confirmed vulnerabilities.
- DNS validation is an initial protection layer and does not fully prevent DNS rebinding or SSRF.
- Automatic redirects are disabled.
- This is not a complete penetration-testing framework.

## Project Structure

    HTTP-Security-Auditor/
    ├── core/
    ├── modules/
    ├── reports/
    ├── tests/
    ├── backups/
    ├── main.py
    ├── test_scan.py
    └── requirements.txt

## Testing

    python -m unittest discover -s tests -t . -v
    python -m py_compile main.py core/*.py modules/*.py

## License

See the LICENSE file.

## Support the Project

If you find this project useful and would like to support its development,
voluntary financial contributions are welcome.

Your support helps maintain and improve this open-source project.

Thank you for supporting independent development!
