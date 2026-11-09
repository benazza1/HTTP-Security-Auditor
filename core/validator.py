
import socket
import ipaddress
from urllib.parse import urlsplit

from core.scanner import normalize_url, ScanError


def validate_target(url):

    target = normalize_url(url)
    parsed = urlsplit(target)

    hostname = parsed.hostname

    # منع أسماء الأجهزة المحلية
    if hostname.lower() == "localhost":
        raise ScanError("Localhost targets are blocked")

    try:
        port = parsed.port
    except ValueError:
        raise ScanError("Invalid port")

    if port is not None and not 1 <= port <= 65535:
        raise ScanError("Invalid port")

    try:
        # إذا كان العنوان IP مباشرة
        addresses = [ipaddress.ip_address(hostname)]

    except ValueError:
        try:
            # استخراج عناوين IP المرتبطة باسم النطاق
            records = socket.getaddrinfo(
                hostname,
                port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM
            )

            addresses = list({
                ipaddress.ip_address(record[4][0])
                for record in records
            })

        except socket.gaierror:
            raise ScanError("Hostname could not be resolved")

    if not addresses:
        raise ScanError("No IP addresses found")

    # السماح بالعناوين العامة فقط
    for address in addresses:
        if not address.is_global:
            raise ScanError(
                f"Non-public IP address blocked: {address}"
            )

    return target
