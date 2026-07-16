"""
Spins up local mock HTTP/FTP/SMTP/SSH-like servers on localhost so the
plugins can be tested against real sockets without touching any real
external host. Not part of the shipped tool -- test harness only.
"""

import http.server
import socketserver
import socket
import threading
import time


class MockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "MockServer/1.0 (Test)")
        self.end_headers()
        body = b'{"status": "ok", "debug_api_key": "api_key=sk_test_12345EXAMPLEKEY67890"}'
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # silence request logging


def start_http_server(port=8081):
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), MockHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def start_banner_server(port, banner: str):
    """Generic raw-socket server that sends `banner` immediately on connect,
    used to simulate FTP/SMTP/SSH greeting behavior."""
    def serve():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        while True:
            conn, _ = srv.accept()
            try:
                conn.sendall(banner.encode())
            finally:
                conn.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()


if __name__ == "__main__":
    start_http_server(8081)
    start_banner_server(2121, "220 MockFTP Server ready. password=Sup3rS3cretFTP!\r\n")
    start_banner_server(2525, "220 mockmail.local ESMTP Postfix\r\n")
    start_banner_server(2222, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
    print("Mock servers running on 127.0.0.1: HTTP:8081 FTP:2121 SMTP:2525 SSH:2222")
    while True:
        time.sleep(1)
