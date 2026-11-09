
import unittest

from modules.headers_analyzer import analyze_headers


class TestHeadersAnalyzer(unittest.TestCase):

    def get_findings(self, headers):
        return analyze_headers(
            headers,
            "https://example.com"
        )

    def get_named_findings(self, findings, name):
        return [
            item for item in findings
            if item["name"] == name
        ]

    # =========================
    # HSTS TESTS
    # =========================

    def test_hsts_missing(self):
        result = self.get_named_findings(
            self.get_findings({}),
            "Strict-Transport-Security"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    def test_hsts_valid(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "Strict-Transport-Security"
        )

        self.assertEqual(len(result), 0)

    def test_hsts_zero(self):
        headers = {
            "Strict-Transport-Security": "max-age=0"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "Strict-Transport-Security"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    def test_hsts_invalid(self):
        headers = {
            "Strict-Transport-Security": "max-age=abc"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "Strict-Transport-Security"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    def test_hsts_duplicate(self):
        headers = {
            "Strict-Transport-Security":
                "max-age=31536000; max-age=0"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "Strict-Transport-Security"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    # =========================
    # CSP TESTS
    # =========================

    def test_csp_missing(self):
        result = self.get_named_findings(
            self.get_findings({}),
            "Content-Security-Policy"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    def test_csp_frame_none(self):
        headers = {
            "Content-Security-Policy":
                "default-src 'self'; frame-ancestors 'none'"
        }

        findings = self.get_findings(headers)

        self.assertEqual(
            len(self.get_named_findings(
                findings,
                "Content-Security-Policy"
            )),
            0
        )

        self.assertEqual(
            len(self.get_named_findings(
                findings,
                "Clickjacking Protection"
            )),
            0
        )

    def test_csp_frame_self(self):
        headers = {
            "Content-Security-Policy":
                "default-src 'self'; frame-ancestors 'self'"
        }

        findings = self.get_findings(headers)

        self.assertEqual(
            len(self.get_named_findings(
                findings,
                "Clickjacking Protection"
            )),
            0
        )

    def test_csp_invalid_source(self):
        headers = {
            "Content-Security-Policy":
                "frame-ancestors https://"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "Clickjacking Protection"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    def test_csp_empty_frame_ancestors(self):
        headers = {
            "Content-Security-Policy":
                "default-src 'self'; frame-ancestors"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "Clickjacking Protection"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    # =========================
    # X-FRAME-OPTIONS TESTS
    # =========================

    def test_xfo_deny(self):
        headers = {"X-Frame-Options": "DENY"}

        result = self.get_named_findings(
            self.get_findings(headers),
            "Clickjacking Protection"
        )

        self.assertEqual(len(result), 0)

    def test_xfo_sameorigin(self):
        headers = {"X-Frame-Options": "SAMEORIGIN"}

        result = self.get_named_findings(
            self.get_findings(headers),
            "Clickjacking Protection"
        )

        self.assertEqual(len(result), 0)

    def test_xfo_invalid(self):
        headers = {"X-Frame-Options": "ALLOWALL"}

        result = self.get_named_findings(
            self.get_findings(headers),
            "Clickjacking Protection"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    def test_xfo_missing(self):
        result = self.get_named_findings(
            self.get_findings({}),
            "Clickjacking Protection"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    # =========================
    # X-CONTENT-TYPE-OPTIONS
    # =========================

    def test_xcto_valid(self):
        headers = {
            "X-Content-Type-Options": "nosniff"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "X-Content-Type-Options"
        )

        self.assertEqual(len(result), 0)

    def test_xcto_missing(self):
        result = self.get_named_findings(
            self.get_findings({}),
            "X-Content-Type-Options"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )

    def test_xcto_invalid(self):
        headers = {
            "X-Content-Type-Options": "invalid"
        }

        result = self.get_named_findings(
            self.get_findings(headers),
            "X-Content-Type-Options"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["classification"],
            "WARNING"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

