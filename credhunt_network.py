"""
CredHunt network scan mode: multi-protocol, concurrent credential/banner
exposure scanning across a target list. Requires explicit consent before
any network activity -- this tool must only be run against hosts you own
or have written permission to test.
"""

import ipaddress
import sys

from core.orchestrator import Orchestrator
from plugins.http_plugin import HTTPPlugin
from plugins.ftp_plugin import FTPPlugin
from plugins.smtp_plugin import SMTPPlugin
from plugins.ssh_plugin import SSHPlugin

ALL_PLUGINS = {
    "http": HTTPPlugin(),
    "ftp": FTPPlugin(),
    "smtp": SMTPPlugin(),
    "ssh": SSHPlugin(),
}


def expand_targets(raw: str) -> list[str]:
    """Accepts a single host, a comma-separated list, or a CIDR range."""
    raw = raw.strip()
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        return [str(ip) for ip in net.hosts()]
    return [t.strip() for t in raw.split(",") if t.strip()]


def get_consent() -> bool:
    print("=" * 70)
    print("CredHunt only scans hosts you own or have explicit written")
    print("permission to test. Scanning systems without authorization")
    print("may be illegal in your jurisdiction.")
    print("=" * 70)
    answer = input("Type YES to confirm you have permission to scan these targets: ")
    return answer.strip().upper() == "YES"


def main():
    if not get_consent():
        print("Consent not given. Exiting.")
        sys.exit(1)

    raw_targets = input("Enter target(s) -- single host, comma-separated list, or CIDR: ")
    targets = expand_targets(raw_targets)

    protocols_input = input(f"Protocols to scan {list(ALL_PLUGINS.keys())} "
                             f"(comma-separated, blank = all): ").strip()
    protocols = [p.strip() for p in protocols_input.split(",")] if protocols_input else list(ALL_PLUGINS.keys())

    threads_input = input("Max concurrent workers (default 10): ").strip()
    max_workers = int(threads_input) if threads_input else 10

    safe_mode_input = input("Safe mode rate-limiting? (Y/n): ").strip().lower()
    safe_mode = safe_mode_input != "n"

    orchestrator = Orchestrator(ALL_PLUGINS, max_workers=max_workers, safe_mode=safe_mode)
    orchestrator.run(targets, protocols=protocols)
    orchestrator.evidence.save_json("reports/network_scan_evidence.json")
    print("Evidence saved to reports/network_scan_evidence.json")


if __name__ == "__main__":
    main()
