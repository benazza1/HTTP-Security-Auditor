from core.scanner import scan_url
from modules.headers_analyzer import analyze_headers
from core.reporter import save_report

url = "https://example.com"

try:
    result = scan_url(url)

    findings = analyze_headers(
        result.headers,
        result.final_url
    )

    report_path = save_report(
        result.final_url,
        result.status_code,
        result.elapsed_seconds,
        findings
    )

    print("\n=== SCAN SUMMARY ===")
    print("Target:", result.final_url)
    print("Status:", result.status_code)
    print("Total findings:", len(findings))
    print("Report saved:", report_path)

except Exception as error:
    print("[ERROR]", error)
