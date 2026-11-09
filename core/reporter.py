from datetime import datetime
from pathlib import Path


def save_report(url, status_code, elapsed_seconds, findings):

    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    scan_date = datetime.now()
    timestamp = scan_date.strftime("%Y-%m-%d_%H-%M-%S_%f")

    filename = reports_dir / f"scan_{timestamp}.txt"

    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    classification_counts = {
        "WARNING": 0,
        "INFO": 0
    }

    for item in findings:
        severity = item.get("severity", "Unknown")
        classification = item.get("classification", "Unknown")

        if severity in severity_counts:
            severity_counts[severity] += 1

        if classification in classification_counts:
            classification_counts[classification] += 1

    with filename.open("w", encoding="utf-8") as report:

        report.write("HTTP SECURITY AUDITOR\n")
        report.write("=" * 55 + "\n")

        report.write(f"Target: {url}\n")
        report.write(f"HTTP Status: {status_code}\n")
        report.write(f"Response Time: {elapsed_seconds:.3f}s\n")
        report.write(f"Scan Date: {scan_date}\n")

        report.write("\nSCAN SUMMARY\n")
        report.write("=" * 55 + "\n")

        report.write(f"Total Findings: {len(findings)}\n")

        report.write("\nSeverity Summary:\n")
        for severity, count in severity_counts.items():
            report.write(f"  {severity}: {count}\n")

        report.write("\nClassification Summary:\n")
        for classification, count in classification_counts.items():
            report.write(f"  {classification}: {count}\n")

        report.write("\nSECURITY FINDINGS\n")
        report.write("=" * 55 + "\n")

        if not findings:
            report.write("No findings detected.\n")

        for index, item in enumerate(findings, start=1):

            report.write(f"\n[{index}] {item['name']}\n")
            report.write("-" * 40 + "\n")
            report.write(f"Severity: {item['severity']}\n")
            report.write(f"Classification: {item['classification']}\n")
            report.write(f"Evidence: {item['evidence']}\n")
            report.write(f"Recommendation: {item['recommendation']}\n")

        report.write("\n" + "=" * 55 + "\n")
        report.write(f"Total Findings: {len(findings)}\n")
        report.write("END OF REPORT\n")

    return filename
