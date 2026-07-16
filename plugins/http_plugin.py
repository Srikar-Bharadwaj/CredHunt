"""
HTTP plugin: issues a single passive GET request, captures the Server
banner header, and scans the response body/headers for exposed secrets.
No auth, no crawling, no repeated requests -- one request per target.
"""

import urllib.request
import urllib.error
from plugins.base import ScannerPlugin, Finding
from core.patterns import find_patterns


class HTTPPlugin(ScannerPlugin):
    name = "http"
    default_port = 80

    def scan(self, target, port=None):
        port = port or self.default_port
        url = f"http://{target}:{port}/"
        findings = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CredHunt-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = dict(resp.getheaders())
                body = resp.read(65536).decode(errors="ignore")

                server_banner = headers.get("Server")
                if server_banner:
                    findings.append(Finding(
                        target=target, port=port, protocol="http",
                        finding_type="banner", raw_value=server_banner,
                        context="Server header", severity="info", plugin=self.name,
                    ))

                for pattern_name, matched in find_patterns(body) + find_patterns(str(headers)):
                    findings.append(Finding(
                        target=target, port=port, protocol="http",
                        finding_type=pattern_name, raw_value=matched,
                        context="response body/headers", severity="high", plugin=self.name,
                    ))
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            pass  # unreachable / closed port is a normal, non-error result
        return findings
