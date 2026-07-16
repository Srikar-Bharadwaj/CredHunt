"""
Shared helper: connect to a TCP port and read whatever greeting/banner the
service sends first, without sending any credentials or commands.
FTP, SMTP, and SSH servers all send a plaintext banner immediately on
connect -- this is passive, standard, and does not require authentication.
"""

import socket


def grab_banner(target: str, port: int, timeout: float = 3.0, read_bytes: int = 256) -> str:
    with socket.create_connection((target, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        data = sock.recv(read_bytes)
        return data.decode(errors="ignore").strip()
