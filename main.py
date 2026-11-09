import argparse
import sys

from core.scanner import scan_url, ScanError
from core.reporter import save_report
from modules.headers_analyzer import analyze_headers


VERSION = "1.0.0"


class Colors:
    enabled = (
        sys.stdout.isatty()
        and "NO_COLOR" not in __import__("os").environ
    )

    RESET = "\033[0m" if enabled else ""
    RED = "\033[91m" if enabled else ""
    GREEN = "\033[92m" if enabled else ""
    YELLOW = "\033[93m" if enabled else ""
    BLUE = "\033[94m" if enabled else ""
    CYAN = "\033[96m" if enabled else ""


def color(text, code):
    return f"{code}{text}{Colors.RESET}"


def print_banner():
    print(color("=" * 52, Colors.CYAN))
    print(color("          HTTP SECURITY AUDITOR", Colors.CYAN))
    print(color(f"                    v{VERSION}", Colors.CYAN))
    print(color("=" * 52, Colors.CYAN))


def run_scan(target):

    print(f"\n{color('[INFO]', Colors.BLUE)} Target: {target}")
    print(color("[INFO] Starting security scan...", Colors.BLUE))

    try:
        result = scan_url(target)

        findings = analyze_headers(
            result.headers,
            result.final_url
        )

        print("\n[SCAN SUMMARY]")
        print("-" * 52)
        print(f"Target:        {result.final_url}")
        print(f"HTTP Status:   {result.status_code}")
        print(f"Response Time: {result.elapsed_seconds:.3f}s")
        print(f"Findings:      {len(findings)}")

        print("\n[SECURITY FINDINGS]")
        print("-" * 52)

        if not findings:
            print(color("[PASS] No findings detected.", Colors.GREEN))

        for index, item in enumerate(findings, start=1):

            severity = item["severity"]

            severity_color = {
                "High": Colors.RED,
                "Medium": Colors.YELLOW,
                "Low": Colors.CYAN
            }.get(severity, Colors.RESET)

            print(f"\n{index}. {item['name']}")
            print(f"   Severity:      {color(severity, severity_color)}")
            print(f"   Classification:{item['classification']}")
            print(f"   Evidence:      {item['evidence']}")
            print(f"   Recommendation:{item['recommendation']}")

        report_path = save_report(
            result.final_url,
            result.status_code,
            result.elapsed_seconds,
            findings
        )

        print("\n" + color("=" * 52, Colors.CYAN))
        print(color("[SUCCESS] Scan completed.", Colors.GREEN))
        print(f"[REPORT] {report_path}")
        print(color("=" * 52, Colors.CYAN))

        return 0

    except ScanError as error:
        print(
            color(f"\n[SCAN ERROR] {error}", Colors.RED),
            file=sys.stderr
        )
        return 1

    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
        return 130

    except Exception as error:
        print(
            color(f"\n[ERROR] Unexpected error: {error}", Colors.RED),
            file=sys.stderr
        )
        return 1


def main():

    parser = argparse.ArgumentParser(
        prog="HTTP-Security-Auditor",
        description="Analyze HTTP security headers on authorized targets."
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Website URL you own or are authorized to test."
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    args = parser.parse_args()

    print_banner()

    if not args.target:
        parser.print_help()
        return 0

    return run_scan(args.target)


if __name__ == "__main__":
    sys.exit(main())
