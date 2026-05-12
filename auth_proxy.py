"""OpenHost trusted-header auth-proxy for FreshRSS.

Sits between the OpenHost router and FreshRSS' upstream Apache
listener.  This is Pattern A from the OpenHost SSO playbook:

  1. The OpenHost router has already verified the visitor's
     ``zone_auth`` JWT and stamped ``X-OpenHost-Is-Owner: true``
     on owner requests before they reach us.
  2. This proxy strips any client-supplied ``X-OpenHost-*`` and
     ``X-WebAuth-User`` / ``Remote-User`` headers as defence in
     depth — the router strips them on inbound, but a hostile
     actor who somehow bypassed the router must not be able to
     impersonate the admin by injecting their own header.
  3. If the request is owner-stamped we add
     ``X-WebAuth-User: admin`` to the forwarded request.
     FreshRSS' ``auth_type = http_auth`` mode reads
     ``$_SERVER['HTTP_X_WEBAUTH_USER']`` directly and treats the
     value as the authenticated username.
  4. Auto-registration on FreshRSS' side means the ``admin`` user
     is created the first time an owner request lands;
     subsequent visits log them straight back in.

There's no auto-login dance (no /login POST, no session cookie
minting) because FreshRSS consults the header on every request.

Defence in depth: ALWAYS strip client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` /
``X-WebAuth-User`` / ``Remote-User`` headers before forwarding.

Implementation cribbed from openhost-dokuwiki/auth_proxy.py, which
has the same Pattern-A shape.
"""

from __future__ import annotations

import http.client
import logging
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"
WEBAUTH_USER_HEADER_NAME = "X-WebAuth-User"

# Username we stamp on owner requests.  bootstrap_freshrss.sh
# pre-creates an ``admin`` user in FreshRSS' data dir so the first
# owner visit lands on the dashboard, not the install wizard.
OWNER_USERNAME = os.environ.get("AUTH_PROXY_OWNER_USERNAME", "admin")

HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Headers a hostile client must never be able to inject.  ALWAYS
# stripped from inbound requests so we can safely stamp our own.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower()
    for h in (
        OWNER_HEADER_NAME,
        USER_HEADER_NAME,
        WEBAUTH_USER_HEADER_NAME,
        "Remote-User",  # alternate form FreshRSS also accepts
    )
)

CLIENT_READ_TIMEOUT_SECONDS = 60

# 50 MiB body cap.  FreshRSS' OPML upload endpoint accepts large
# subscription dumps but anything bigger than this almost certainly
# isn't a legitimate FreshRSS API call.
MAX_BODY_BYTES = 50 * 1024 * 1024

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8800

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path.startswith("/healthz"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        path_only = self.path.split("?", 1)[0]
        if path_only == "/healthz":
            try:
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except OSError as exc:
                log.debug("/healthz client disconnected: %s", exc)
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        self._proxy(stamp_webauth_user=is_owner)

    def _proxy(self, *, stamp_webauth_user: bool) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        # Preserve X-Forwarded-Host as Host so FreshRSS' URL
        # generation matches the public OpenHost zone domain.
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        # FreshRSS / Apache need to see HTTPS so generated links
        # use the right scheme; OpenHost terminates TLS.
        cleaned_headers.append(("X-Forwarded-Proto", "https"))
        if stamp_webauth_user:
            cleaned_headers.append((WEBAUTH_USER_HEADER_NAME, OWNER_USERNAME))

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=120
        )
        try:
            try:
                # skip_host=True so http.client doesn't auto-inject
                # ``Host: 127.0.0.1:8800`` — we add the right one
                # via cleaned_headers above.
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8800)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (owner=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        OWNER_USERNAME,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
