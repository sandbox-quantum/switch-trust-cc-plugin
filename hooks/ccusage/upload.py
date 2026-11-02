"""HTTP POST of length-delimited protobuf Events to the ingestion endpoint."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from typing import Any

from . import wire
from .config import (
    BREAKER_BACKOFF_S,
    BREAKER_THRESHOLD,
    EVENTS_PATH,
    HTTP_TIMEOUT_S,
)
from .events import build_session_open_event
from .identity import slot_id
from .log import log
from .state import opened_path, read_health, write_health, write_private_file

# Not a plugin setting -- a plain local-dev env var toggle for extra logging,
# set directly in the shell rather than through Claude Code's /config.
_DEBUG_ENV_VAR = "SWITCH_TRUST_CCUSAGE_DEBUG"

# Hosts the ingestion endpoint may resolve to.
#
# Each entry is matched exactly or as a parent suffix (a `.<entry>`
# subdomain) -- the leading dot is what stops a look-alike host like
# "evilswitchagents.ai" from matching a bare substring check.
ALLOWED_INGESTION_HOSTS = ("switchagents.ai",)

# The only hosts a cleartext http:// endpoint is accepted for -- local
# development only. Exact match: no "*.localhost" (DNS-resolvable, could
# point off-box) wildcarding.
_LOCAL_HTTP_HOSTS = ("localhost", "127.0.0.1")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib's default handler re-sends Authorization to any redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# macOS ships a usable CA bundle here independent of which Python interpreter
# is running this script. python.org's own installer, by contrast, bundles
# its own empty trust store until the user runs "Install Certificates.command",
# so its default ssl context has zero CA certs loaded.
_MACOS_SYSTEM_CA_BUNDLE = "/etc/ssl/cert.pem"


def _context_has_ca_certs(context: ssl.SSLContext) -> bool:
    try:
        return context.cert_store_stats().get("x509_ca", 0) > 0
    except Exception:
        return True  # can't tell -- don't override a context we can't introspect


@lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext | None:
    """Build the SSL context for HTTPS POSTs, falling back when the default has no CA bundle.

    Tried in order once the stdlib default context turns out to be unusable:
    `certifi` (if installed), then the macOS system bundle. Returns the
    original (possibly unusable) default context if neither is available, so
    behavior outside the broken-CA case is unchanged.
    """
    try:
        context = ssl.create_default_context()
    except Exception:
        return None
    if _context_has_ca_certs(context):
        return context
    try:
        import certifi  # noqa: PLC0415 - optional dependency, only imported if present

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    if os.path.isfile(_MACOS_SYSTEM_CA_BUNDLE):
        try:
            return ssl.create_default_context(cafile=_MACOS_SYSTEM_CA_BUNDLE)
        except Exception:
            pass
    return context


def _opener(url: str) -> urllib.request.OpenerDirector:
    """Loopback skips env proxies: urllib only bypasses localhost if NO_PROXY lists it."""
    handlers: list[Any] = [_NoRedirect]
    context = _ssl_context()
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    if _host(url) in _LOCAL_HTTP_HOSTS:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def _is_allowed_endpoint(endpoint: str) -> bool:
    """Fail closed: require https on an allowlisted host, or http to localhost.

    The `switch_trust_environment` setting ends up here however it was set, so
    this is the one place that stands between a bad value and sending the API
    key and conversation content over the wire -- to an attacker-controlled
    host, or in cleartext.
    """
    try:
        parsed = urllib.parse.urlsplit(endpoint)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if parsed.scheme == "http" and host in _LOCAL_HTTP_HOSTS:
        return True
    if parsed.scheme != "https":
        return False
    return any(
        host == allowed or host.endswith(f".{allowed}")
        for allowed in ALLOWED_INGESTION_HOSTS
    )


def length_delimited(event: bytes) -> bytes:
    """Prefix a serialized `event` with a protobuf varint length, for streaming."""
    return wire.varint_prefixed(event)


def build_events_url(endpoint: str, repo_url: str | None = None) -> str:
    """Build the ingestion URL from a base or full endpoint.

    Accepts either a base URL (e.g. https://host) or a full endpoint that
    already includes the path and/or slotid query. Ensures the path is
    exactly /agent/events/v1 and a single slotid param is present, so
    the switch_trust_environment setting can be either form without double-appending.
    """
    parts = urllib.parse.urlsplit(endpoint)
    path = parts.path or ""
    if not path.rstrip("/").endswith(EVENTS_PATH):
        path = f"{path.rstrip('/')}/{EVENTS_PATH}"
    # Normalize query so slotid appears exactly once.
    query = dict(urllib.parse.parse_qsl(parts.query))
    query.setdefault("slotid", slot_id(repo_url))
    new_query = urllib.parse.urlencode(query)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, new_query, ""))


def is_permanent_rejection(status: int) -> bool:
    """True if resending can never succeed; auth, path and rate-limit 4xx are retried."""
    return 400 <= status < 500 and status not in (401, 403, 404, 408, 429)


def is_success(status: int) -> bool:
    return 200 <= status < 300


def post_event_status(
    endpoint: str,
    api_key: str,
    event: bytes,
    repo_url: str | None = None,
    timeout: float = HTTP_TIMEOUT_S,
) -> int:
    """POST a length-delimited Event; return the HTTP status, or 0 if none arrived in time.

    urllib's timeout is per socket operation (and skips DNS), so the request runs
    in a daemon thread joined for `timeout` to bound its wall time.
    """
    if not _is_allowed_endpoint(endpoint):
        log(f"refusing to send to disallowed endpoint={endpoint!r}")
        _record_outcome(endpoint, api_key, 0, {"reason": "disallowed endpoint"})
        return 0
    result: list[tuple[int, dict]] = [(0, {"reason": "no response"})]

    def _send() -> None:
        try:
            result[0] = _send_event(endpoint, api_key, event, repo_url, timeout)
        except Exception as exc:
            log(f"POST raised {type(exc).__name__}")
            result[0] = (0, {"reason": "client error"})

    sender = threading.Thread(target=_send, daemon=True)
    sender.start()
    sender.join(timeout)
    if sender.is_alive():
        log(f"POST still running after {timeout:.1f}s; abandoning it")
        result[0] = (0, {"reason": "timed out"})
    status, detail = result[0]
    _record_outcome(endpoint, api_key, status, detail)
    return status


def post_event(
    endpoint: str,
    api_key: str,
    event: bytes,
    repo_url: str | None = None,
    timeout: float = HTTP_TIMEOUT_S,
) -> bool:
    """POST a length-delimited Event to the ingestion endpoint. Returns success."""
    return is_success(post_event_status(endpoint, api_key, event, repo_url, timeout))


def _without_query(url: str | None) -> str:
    try:
        parts = urllib.parse.urlsplit(url or "")
    except ValueError:
        return ""
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _host(url: str | None) -> str:
    try:
        return urllib.parse.urlsplit(url or "").hostname or ""
    except ValueError:
        return ""


def _auth_failure_reason(body: str) -> str:
    """Classify a 401 by the message authv2lib puts in `{"error": {"message": ...}}`."""
    try:
        message = str(json.loads(body)["error"]["message"])
    except Exception:
        message = body
    if message.startswith("invalid API key"):
        return "invalid key"
    if message.startswith("API key validation request failed"):
        return "request failed"
    if message.startswith("Unauthorized"):
        return "unauthorized"
    return "other"


def _send_event(
    endpoint: str, api_key: str, event: bytes, repo_url: str | None, timeout: float
) -> tuple[int, dict]:
    url = build_events_url(endpoint, repo_url)
    data = length_delimited(event)
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/protobuf")
    req.add_header("Authorization", f"ApiKey {api_key}")
    try:
        with _opener(url).open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if resp.geturl() != url:
                location = _host(resp.geturl())
                log(f"POST redirected to host {location} (status={status})")
                return 0, {"reason": "redirected", "location_host": location}
            body = b""
            try:
                body = resp.read(512)
            except Exception:
                pass
            if not is_success(status):
                log(
                    f"ingestion status={status} url={_without_query(url)} "
                    f"body={body[:200].decode('utf-8', 'replace')}"
                )
                return status, {}
            if os.environ.get(_DEBUG_ENV_VAR) == "1":
                log(
                    f"ingestion ok status={status} url={_without_query(url)} "
                    f"body={body[:200].decode('utf-8', 'replace')}"
                )
            return status, {}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(2048).decode("utf-8", "replace")
        except Exception:
            pass
        log(
            f"POST HTTPError status={exc.code} url={_without_query(exc.filename)} body={detail[:200]}"
        )
        if exc.filename != url:
            return 0, {"reason": "redirected", "location_host": _host(exc.filename)}
        info: dict = {}
        if 300 <= exc.code < 400:
            location_host = _host((exc.headers or {}).get("Location"))
            info["location_host"] = location_host
            log(
                f"POST redirect refused status={exc.code} "
                f"endpoint_host={_host(endpoint)!r} location_host={location_host!r}"
            )
        elif exc.code == 401:
            info["reason"] = _auth_failure_reason(detail)
        return exc.code, info
    except ssl.SSLCertVerificationError as exc:
        log(f"POST TLS verify failed url={_without_query(url)} err={exc}")
        return 0, {"reason": "no CA bundle"}
    except Exception as exc:
        log(f"POST failed url={_without_query(url)} err={exc}")
        return 0, {"reason": "connection failed"}


def _health_id(endpoint: str, api_key: str) -> str:
    return hashlib.sha256(f"{endpoint}\n{api_key}".encode()).hexdigest()[:16]


_run_state = {"failure_counted": False}


def begin_run() -> None:
    """Start a hook run: the breaker counts at most one failure per run, not per POST."""
    _run_state["failure_counted"] = False


def _number(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return number if number == number else 0.0


def current_health(
    endpoint: str, api_key: str, state_dir_override: str | None = None
) -> dict:
    """health.json for this endpoint+key, sanitised: bad values close the breaker."""
    health = read_health(state_dir_override)
    if health.get("id") != _health_id(endpoint, api_key):
        fresh = {"id": _health_id(endpoint, api_key), "retry_at": 0.0, "consecutive": 0}
        return {**fresh, "stale": bool(health)}
    retry_at = min(_number(health.get("retry_at")), time.time() + BREAKER_BACKOFF_S[-1])
    health["retry_at"] = max(retry_at, 0.0)
    health["consecutive"] = max(int(_number(health.get("consecutive"))), 0)
    if not isinstance(health.get("last_failure"), dict):
        health.pop("last_failure", None)
    return health


def breaker_retry_at(endpoint: str, api_key: str) -> float:
    """Epoch seconds before which POSTs are skipped; 0 when the breaker is closed."""
    return current_health(endpoint, api_key)["retry_at"]


def _record_outcome(endpoint: str, api_key: str, status: int, detail: dict) -> None:
    health = current_health(endpoint, api_key)
    stale = health.pop("stale", False)
    if is_success(status):
        if stale or health["consecutive"] or health["retry_at"]:
            health.update(consecutive=0, retry_at=0)
            write_health(health)
        return
    now = time.time()
    health["last_failure"] = {"status": status, "at": now, **detail}
    if not is_permanent_rejection(status) and not _run_state["failure_counted"]:
        _run_state["failure_counted"] = True
        failures = health["consecutive"] + 1
        health["consecutive"] = failures
        if failures >= BREAKER_THRESHOLD:
            step = min(failures - BREAKER_THRESHOLD, len(BREAKER_BACKOFF_S) - 1)
            health["retry_at"] = now + BREAKER_BACKOFF_S[step]
    write_health(health)


def ensure_session_open(
    endpoint: str,
    api_key: str,
    session_id: str,
    repo_url: str | None = None,
    timeout: float = HTTP_TIMEOUT_S,
) -> bool | None:
    """Send a session-open event once per session; None if already sent, else POST success."""
    marker = opened_path(session_id)
    if os.path.isfile(marker):
        return None
    event = build_session_open_event(repo_url)
    if not post_event(endpoint, api_key, event, repo_url, timeout):
        return False
    try:
        write_private_file(marker, "1")
    except Exception:
        pass
    return True
