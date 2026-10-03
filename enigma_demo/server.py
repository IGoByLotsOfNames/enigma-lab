# Path: enigma_demo/server.py
"""Loopback-only HTTP adapter with fixed assets and same-origin mutations."""

import hmac
import json
import re
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .jobs import BusyError, ClosedError, JobManager
from .service import MAX_BODY_BYTES, MAX_TEXT_LETTERS, prepare_search, transform_payload

PACKAGE = Path(__file__).resolve().parent
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
JOB_ROUTE = re.compile(r"/api/search/([0-9a-f]{32})(/cancel)?\Z")
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
)


class RequestError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class EnigmaServer(ThreadingHTTPServer):
    daemon_threads = True
    # HTTPServer enables address reuse by default. On Windows that can permit
    # two live servers on one port, making application/session routing ambiguous.
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, port, job_manager=None):
        super().__init__(("127.0.0.1", port), Handler)
        actual_port = self.server_address[1]
        self.authority = "127.0.0.1" if actual_port == 80 else f"127.0.0.1:{actual_port}"
        self.origin = f"http://{self.authority}"
        self.url = self.origin + "/"
        self.token = secrets.token_urlsafe(32)
        self.job_manager = job_manager if job_manager is not None else JobManager()
        self._serving = threading.Event()

    def serve_forever(self, poll_interval=0.1):
        self._serving.set()
        try:
            super().serve_forever(poll_interval)
        finally:
            self._serving.clear()

    def close(self, job_timeout=5.0) -> bool:
        if self._serving.is_set():
            self.shutdown()
        self.server_close()
        return self.job_manager.close(timeout=job_timeout)


class Handler(BaseHTTPRequestHandler):
    server_version = "EnigmaLocal"
    sys_version = ""

    def log_message(self, format, *args):
        # Requests can contain personal text/settings; do not log request details.
        pass

    def _send(self, status, payload, content_type="application/json; charset=utf-8"):
        if isinstance(payload, bytes):
            content = payload
        else:
            content = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def _guard(self, *, mutate=False):
        hosts = self.headers.get_all("Host", [])
        if hosts != [self.server.authority]:
            raise RequestError(403, "This application accepts its local address only.")
        origins = self.headers.get_all("Origin", [])
        if origins and origins != [self.server.origin]:
            raise RequestError(403, "The request origin is not allowed.")
        if mutate:
            if origins != [self.server.origin]:
                raise RequestError(403, "A same-origin request is required.")
            tokens = self.headers.get_all("X-Enigma-Token", [])
            if (
                len(tokens) != 1
                or not tokens[0].isascii()
                or not hmac.compare_digest(tokens[0], self.server.token)
            ):
                raise RequestError(403, "The application session token is missing or invalid.")

    def _json_body(self):
        if self.headers.get("Transfer-Encoding") is not None:
            raise RequestError(400, "Transfer encoding is not supported.")
        if (
            self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            raise RequestError(415, "Use application/json content type.")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            raise RequestError(400, "A valid Content-Length is required.")
        length = int(lengths[0])
        if length > MAX_BODY_BYTES:
            raise RequestError(413, "The request body is too large.")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise RequestError(400, "The JSON body is incomplete.")
        try:

            def invalid_constant(value):
                raise ValueError("Non-finite JSON number")

            return json.loads(raw.decode("utf-8"), parse_constant=invalid_constant)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise RequestError(400, "The request body must be valid UTF-8 JSON.") from exc

    def _path(self):
        if not self.path.startswith("/"):
            raise RequestError(400, "Use a local request path.")
        return urlsplit(self.path).path

    def do_GET(self):
        self._dispatch(False)

    def do_POST(self):
        self._dispatch(True)

    def _dispatch(self, mutate):
        try:
            self.connection.settimeout(5.0)
            self._guard(mutate=mutate)
            path = self._path()
            if not mutate:
                if path in ASSETS:
                    name, content_type = ASSETS[path]
                    self._send(200, (PACKAGE / "static" / name).read_bytes(), content_type)
                elif path == "/api/bootstrap":
                    samples = json.loads((PACKAGE / "samples.json").read_text(encoding="utf-8"))
                    self._send(
                        200,
                        {
                            "token": self.server.token,
                            "samples": samples,
                            "limits": {
                                "max_text_letters": MAX_TEXT_LETTERS,
                                "max_body_bytes": MAX_BODY_BYTES,
                            },
                            "strategies": ["baseline", "early"],
                        },
                    )
                else:
                    route = JOB_ROUTE.fullmatch(path)
                    if route and route.group(2) is None:
                        job = self.server.job_manager.get(route.group(1))
                        if job is None:
                            raise RequestError(404, "The search was not found or has expired.")
                        self._send(200, job)
                    else:
                        raise RequestError(404, "Not found.")
            else:
                payload = self._json_body()
                if path == "/api/transform":
                    self._send(200, transform_payload(payload))
                elif path == "/api/search":
                    self._send(202, self.server.job_manager.submit(prepare_search(payload)))
                else:
                    route = JOB_ROUTE.fullmatch(path)
                    if route and route.group(2) == "/cancel":
                        if payload != {}:
                            raise ValueError("The cancel request body must be an empty object.")
                        job = self.server.job_manager.cancel(route.group(1))
                        if job is None:
                            raise RequestError(404, "The search was not found or has expired.")
                        self._send(200, job)
                    else:
                        raise RequestError(404, "Not found.")
        except RequestError as exc:
            self._send(exc.status, {"error": exc.message})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except BusyError as exc:
            self._send(409, {"error": str(exc)})
        except ClosedError as exc:
            self._send(503, {"error": str(exc)})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except TimeoutError:
            self.close_connection = True
        except Exception:
            self._send(500, {"error": "The local application could not complete this request."})

    def _unsupported(self):
        try:
            self._guard()
            self._send(405, {"error": "Method not allowed."})
        except RequestError as exc:
            self._send(exc.status, {"error": exc.message})

    do_HEAD = _unsupported
    do_PUT = _unsupported
    do_DELETE = _unsupported
    do_PATCH = _unsupported
    do_OPTIONS = _unsupported


def create_server(port=0, *, job_manager=None) -> EnigmaServer:
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("Port must be an integer from 0 to 65535.")
    return EnigmaServer(port, job_manager)
