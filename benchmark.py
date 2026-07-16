import time
import threading

from core.orchestrator import Orchestrator
from plugins.http_plugin import HTTPPlugin
from plugins.ftp_plugin import FTPPlugin
from plugins.smtp_plugin import SMTPPlugin
from plugins.ssh_plugin import SSHPlugin
import test_mock_servers


def run_benchmark():
    # 1. Start mock servers in background
    test_mock_servers.start_http_server(8081)
    test_mock_servers.start_banner_server(2121, "220 MockFTP Server ready. password=Sup3rS3cretFTP!\r\n")
    test_mock_servers.start_banner_server(2525, "220 mockmail.local ESMTP Postfix\r\n")
    test_mock_servers.start_banner_server(2222, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
    
    time.sleep(1) # Give mock servers time to bind

    plugins = {
        "http": HTTPPlugin(),
        "ftp": FTPPlugin(),
        "smtp": SMTPPlugin(),
        "ssh": SSHPlugin(),
    }
    plugins["http"].default_port = 8081
    plugins["ftp"].default_port = 2121
    plugins["smtp"].default_port = 2525
    plugins["ssh"].default_port = 2222

    # Simulate scanning 100 hosts by targeting 127.0.0.1 100 times
    targets = ["127.0.0.1"] * 50

    print("Starting Sequential Scan Benchmark (1 worker)...")
    start_seq = time.time()
    orch_seq = Orchestrator(plugins, max_workers=1, safe_mode=False)
    orch_seq.run(targets)
    seq_time = time.time() - start_seq
    print(f"Sequential scan completed in: {seq_time:.2f} seconds\n")

    print("Starting Concurrent Scan Benchmark (8 workers)...")
    start_conc = time.time()
    orch_conc = Orchestrator(plugins, max_workers=8, safe_mode=False)
    orch_conc.run(targets)
    conc_time = time.time() - start_conc
    print(f"Concurrent scan completed in: {conc_time:.2f} seconds\n")

    speedup = seq_time / conc_time
    print(f"Speedup Multiplier: {speedup:.2f}x")

    return speedup

if __name__ == "__main__":
    run_benchmark()
