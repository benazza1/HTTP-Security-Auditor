
import requests
from urllib.parse import urlsplit, urlunsplit
from dataclasses import dataclass


MAX_BODY_SIZE = 1024 * 1024  # 1 MB


@dataclass
class ScanResult:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict
    elapsed_seconds: float
    body: bytes
    truncated: bool


class ScanError(Exception):
    pass


def normalize_url(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported protocol")

        if not parsed.hostname:
            raise ValueError("Missing hostname")

        if parsed.username or parsed.password:
            raise ValueError("URL credentials are not allowed")

        return urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

    except ValueError as error:
        raise ScanError(f"Invalid URL: {error}")


def scan_url(url):

    from core.validator import validate_target

    target = validate_target(url)

    try:
        with requests.get(
            target,
            timeout=(5, 10),
            allow_redirects=False,
            verify=True,
            stream=True,
            headers={
                "User-Agent": "HTTP-Security-Auditor/1.0"
            }
        ) as response:

            body = bytearray()
            truncated = False

            for chunk in response.iter_content(16384):

                remaining = MAX_BODY_SIZE - len(body)

                if len(chunk) > remaining:
                    body.extend(chunk[:remaining])
                    truncated = True
                    break

                body.extend(chunk)

                if len(body) >= MAX_BODY_SIZE:
                    truncated = True
                    break

            return ScanResult(
                requested_url=target,
                final_url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                elapsed_seconds=response.elapsed.total_seconds(),
                body=bytes(body),
                truncated=truncated
            )

    except requests.exceptions.RequestException as error:
        raise ScanError(f"Connection failed: {error}")
