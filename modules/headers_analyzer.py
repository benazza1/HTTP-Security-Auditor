
from urllib.parse import urlsplit


def analyze_headers(headers, final_url=""):

    findings = []

    # Normalize HTTP header names
    normalized = {
        str(name).lower(): str(value).strip()
        for name, value in headers.items()
    }

    def valid_frame_source(source):

        if source in ("'self'", "'none'"):
            return True

        if source.startswith(("https://", "http://")):
            parsed = urlsplit(source)

            return bool(
                parsed.scheme in ("https", "http")
                and parsed.netloc
                and parsed.hostname
            )

        if source.startswith("*."):
            domain = source[2:]

            return (
                "." in domain
                and all(domain.split("."))
                and all(
                    char.isalnum() or char in "-."
                    for char in domain
                )
            )

        return False

    def add_finding(
        name,
        severity,
        classification,
        evidence,
        recommendation
    ):
        findings.append({
            "name": name,
            "severity": severity,
            "classification": classification,
            "evidence": evidence,
            "recommendation": recommendation
        })

    # 1. Strict-Transport-Security
    is_https = urlsplit(final_url).scheme.lower() == "https"

    if is_https:

        hsts = normalized.get("strict-transport-security", "")

        if not hsts:
            add_finding(
                "Strict-Transport-Security",
                "Medium",
                "WARNING",
                "Header is missing from HTTPS response.",
                "Configure an appropriate HSTS policy."
            )

        else:
            directives = [
                item.strip().lower()
                for item in hsts.split(";")
            ]

            max_age_values = [
                item.split("=", 1)[1].strip()
                for item in directives
                if item.startswith("max-age=")
            ]

            if (
                len(max_age_values) != 1
                or not max_age_values[0].isdigit()
            ):
                add_finding(
                    "Strict-Transport-Security",
                    "Medium",
                    "WARNING",
                    "HSTS max-age is missing, duplicated, or invalid.",
                    "Configure exactly one valid numeric max-age directive."
                )

            elif int(max_age_values[0]) == 0:
                add_finding(
                    "Strict-Transport-Security",
                    "Medium",
                    "WARNING",
                    "HSTS max-age is zero, which disables the policy.",
                    "Configure a positive max-age value."
                )

            elif int(max_age_values[0]) < 31536000:
                add_finding(
                    "Strict-Transport-Security",
                    "Low",
                    "INFO",
                    "HSTS max-age is shorter than one year.",
                    "Consider using max-age of at least 31536000 seconds."
                )

    # 2. Content-Security-Policy
    csp = normalized.get("content-security-policy", "")

    if not csp:
        add_finding(
            "Content-Security-Policy",
            "Medium",
            "WARNING",
            "Content Security Policy is missing.",
            "Define a suitable CSP policy."
        )

    # 3. Clickjacking Protection
    has_frame_ancestors = False
    frame_ancestors_found = False

    for directive in csp.split(";"):
        parts = directive.strip().lower().split()

        if parts and parts[0] == "frame-ancestors":

            # Only the first occurrence is effective
            if frame_ancestors_found:
                continue

            frame_ancestors_found = True
            sources = parts[1:]

            if sources == ["'none'"]:
                has_frame_ancestors = True

            elif sources and "'none'" not in sources:
                valid_sources = all(
                    valid_frame_source(source)
                    for source in sources
                )

                if valid_sources:
                    has_frame_ancestors = True

    xfo = normalized.get("x-frame-options", "").upper()

    valid_xfo = xfo in ("DENY", "SAMEORIGIN")

    if not valid_xfo and not has_frame_ancestors:
        add_finding(
            "Clickjacking Protection",
            "Medium",
            "WARNING",
            "Neither a valid X-Frame-Options nor a valid CSP frame-ancestors directive was detected.",
            "Configure X-Frame-Options or a valid CSP frame-ancestors directive."
        )

    # 4. X-Content-Type-Options
    xcto = normalized.get("x-content-type-options", "").lower()

    if xcto != "nosniff":
        add_finding(
            "X-Content-Type-Options",
            "Low",
            "WARNING",
            f"Expected 'nosniff', received: {xcto or 'missing'}.",
            "Set X-Content-Type-Options: nosniff."
        )

    # 5. Referrer-Policy
    referrer_policy = normalized.get("referrer-policy", "")

    valid_referrer_policies = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url"
    }

    if not referrer_policy:
        add_finding(
            "Referrer-Policy",
            "Low",
            "INFO",
            "Referrer-Policy header is missing.",
            "Configure an appropriate Referrer-Policy."
        )

    else:
        policy_tokens = [
            token.strip().lower()
            for token in referrer_policy.split(",")
        ]

        recognized_policies = [
            token for token in policy_tokens
            if token in valid_referrer_policies
        ]

        if not recognized_policies:
            add_finding(
                "Referrer-Policy",
                "Low",
                "WARNING",
                f"No recognized Referrer-Policy value found: {referrer_policy}",
                "Configure one of the eight recognized Referrer-Policy values."
            )

    return findings

