# FAKE services for ports where the real thing is dangerous or too heavy on a laptop.
# They answer like the real product so NSE and curl have something to find, but they
# control nothing. A real unauthenticated Docker API would hand over the whole laptop.
import json
import os
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert.pem")
DOCKER_VERSION = {"Version": "20.10.7", "ApiVersion": "1.41", "GitCommit": "b0f5bc3",
                  "GoVersion": "go1.13.15", "Os": "linux", "Arch": "amd64",
                  "KernelVersion": "5.10.16-seclab-mock"}
DOCKER = {"/version": DOCKER_VERSION,
          "/containers/json": [{"Id": "fake0001", "Image": "seclab/payments:1.0",
                                "Names": ["/payments"], "State": "running"}]}
KUBERNETES = {"/version": {"major": "1", "minor": "21", "gitVersion": "v1.21.0",
                           "platform": "linux/amd64"},
              "/api/v1/namespaces": {"kind": "NamespaceList",
                                     "items": [{"metadata": {"name": "payments-prod"}}]}}
KUBELET = {"/pods": {"kind": "PodList", "items": [{"metadata": {"name": "payments-7d9f"}}]},
           "/healthz": "ok"}
ETCD = {"/version": {"etcdserver": "3.4.0", "etcdcluster": "3.4.0"},
        "/v2/keys": {"action": "get", "node": {"dir": True, "nodes": [
            {"key": "/db_password", "value": "fake-changeme"}]}}}
ADMIN_PAGE = ("<!DOCTYPE html><html><head><title>Storage Admin Console</title></head>"
              "<body><h1>Storage Admin Console</h1><p>No login configured.</p></body></html>")


def make_handler(routes, server_name):
    class Handler(BaseHTTPRequestHandler):
        server_version = server_name
        sys_version = ""

        def do_GET(self):
            body = routes.get(self.path)
            is_html = isinstance(body, str) and body.startswith("<!DOCTYPE")
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Type", "text/html" if is_html else "application/json")
            self.end_headers()
            if body is None:
                body = {"message": "page not found"}
            self.wfile.write((body if is_html else json.dumps(body)).encode())

        def log_message(self, *args):
            pass

    return Handler


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # scanners send plain HTTP to the TLS ports and hang up mid-request


def serve_http(port, routes, server_name, use_tls=False):
    server = QuietServer(("0.0.0.0", port), make_handler(routes, server_name))
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT)
        server.socket = context.wrap_socket(server.socket, server_side=True,
                                            do_handshake_on_connect=False)
    server.serve_forever()


def serve_vnc(port):
    # Only the RFB handshake: offers "None" authentication, then hangs up
    listener = socket.create_server(("0.0.0.0", port))
    while True:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            try:
                conn.sendall(b"RFB 003.008\n")
                conn.recv(12)
                conn.sendall(bytes([1, 1]))
            except OSError:
                pass


if __name__ == "__main__":
    services = [
        (serve_http, (2375, DOCKER, "Docker/20.10.7")),
        (serve_http, (2376, DOCKER, "Docker/20.10.7", True)),
        (serve_http, (2379, ETCD, "etcd/3.4.0")),
        (serve_http, (6443, KUBERNETES, "kube-apiserver", True)),
        (serve_http, (10250, KUBELET, "kubelet", True)),
        (serve_http, (9000, {"/": ADMIN_PAGE}, "AdminConsole/1.0")),
        (serve_vnc, (5900,)),
    ]
    threads = [threading.Thread(target=fn, args=args, daemon=True) for fn, args in services]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
