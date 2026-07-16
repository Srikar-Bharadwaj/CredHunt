from plugins.base import ScannerPlugin, Finding
from plugins._banner_utils import grab_banner
from core.patterns import find_patterns


class SSHPlugin(ScannerPlugin):
    name = "ssh"
    default_port = 22

    def scan(self, target, port=None):
        port = port or self.default_port
        findings = []
        try:
            banner = grab_banner(target, port, self.timeout)
            if banner:
                findings.append(Finding(
                    target=target, port=port, protocol="ssh",
                    finding_type="banner", raw_value=banner,
                    context="SSH version string", severity="info", plugin=self.name,
                ))
                for pattern_name, matched in find_patterns(banner):
                    findings.append(Finding(
                        target=target, port=port, protocol="ssh",
                        finding_type=pattern_name, raw_value=matched,
                        context="SSH banner", severity="high", plugin=self.name,
                    ))
        except (OSError, TimeoutError, ConnectionError):
            pass
        return findings
