"""Tests for hooks/ccusage/upload.py's ingestion URL construction."""

from __future__ import annotations

import http.server
import os
import sys
import threading
import urllib.request

import pytest

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage import upload  # noqa: E402
from ccusage.identity import slot_id  # noqa: E402
from ccusage.upload import build_events_url  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "state"))
    for scheme in ("http", "https", "all", "no"):
        monkeypatch.delenv(f"{scheme}_proxy", raising=False)
        monkeypatch.delenv(f"{scheme.upper()}_PROXY", raising=False)
    urllib.request.install_opener(None)


def test_allows_https_on_default_host() -> None:
    assert upload._is_allowed_endpoint("https://ingestion.switchagents.ai")


def test_allows_https_on_subdomain_of_allowed_host() -> None:
    assert upload._is_allowed_endpoint("https://ingestion.staging.switchagents.ai")


def test_rejects_http_on_allowed_host() -> None:
    """http:// to a real host would send the API key in cleartext -- refuse it."""
    assert not upload._is_allowed_endpoint("http://ingestion.switchagents.ai")


def test_rejects_https_on_disallowed_host() -> None:
    assert not upload._is_allowed_endpoint("https://attacker.example")


def test_rejects_lookalike_host() -> None:
    """A bare substring/prefix check would be fooled here; the suffix check isn't."""
    assert not upload._is_allowed_endpoint("https://evilswitchagents.ai")
    assert not upload._is_allowed_endpoint("https://switchagents.ai.attacker.example")


def test_allows_http_localhost_for_local_dev() -> None:
    assert upload._is_allowed_endpoint("http://localhost:8080")
    assert upload._is_allowed_endpoint("http://127.0.0.1:8080")


def test_rejects_malformed_endpoint() -> None:
    assert not upload._is_allowed_endpoint("not-a-url")
    assert not upload._is_allowed_endpoint("")


def test_post_event_refuses_disallowed_endpoint_without_sending(monkeypatch) -> None:
    """A disallowed endpoint must never reach the opener -- not even once."""
    called = {"n": 0}

    def _fail_if_called(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("opener must not be called for a disallowed endpoint")

    monkeypatch.setattr(upload, "_opener", _fail_if_called)

    ok = upload.post_event("http://attacker.example", "sk_test", b"event-bytes")

    assert ok is False
    assert called["n"] == 0


def test_build_events_url_appends_path_and_slotid() -> None:
    """A bare base URL gets the ingestion path and a repo-derived slotid appended."""
    repo_url = "https://github.com/acme/widgets.git"
    url = build_events_url("https://wut.example.com", repo_url)
    assert url == f"https://wut.example.com/agent/events/v1?slotid={slot_id(repo_url)}"


def test_build_events_url_idempotent_on_full_url() -> None:
    """A URL that already has the path and slotid is left unchanged."""
    existing = f"https://wut.example.com/agent/events/v1?slotid={slot_id(None)}"
    url = build_events_url(existing, "https://github.com/acme/widgets.git")
    assert url == existing


def test_build_events_url_defaults_slotid_for_unknown_repo() -> None:
    """No repo context still yields a deterministic slotid, not an error."""
    url = build_events_url("https://wut.example.com", None)
    assert url == f"https://wut.example.com/agent/events/v1?slotid={slot_id(None)}"


class _Recorder(http.server.BaseHTTPRequestHandler):
    status = 200
    location = None

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.server.requests.append(
            (self.command, self.path, dict(self.headers), self.rfile.read(length))
        )
        self.send_response(self.status)
        if self.location:
            self.send_header("Location", self.location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = _handle

    def log_message(self, *_args) -> None:
        pass


@pytest.fixture
def serve():
    servers = []

    def _start(status=200, location=None):
        handler = type("H", (_Recorder,), {"status": status, "location": location})
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        server.requests = []
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()
        servers.append(server)
        return server

    yield _start
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("code", [300, 301, 302, 303, 304, 307, 308])
def test_post_event_does_not_follow_redirect(serve, code, capsys) -> None:
    target = serve()
    target_url = f"http://localhost:{target.server_port}/x?token=secret-path"
    origin = serve(status=code, location=target_url)

    ok = upload.post_event(
        f"http://127.0.0.1:{origin.server_port}", "sk_test", b"event-bytes"
    )

    assert ok is False
    assert [r[0] for r in origin.requests] == ["POST"]
    assert target.requests == []
    err = capsys.readouterr().err
    assert f"status={code} endpoint_host='127.0.0.1' location_host='localhost'" in err
    assert "sk_test" not in err
    assert "secret-path" not in err


def test_post_event_reports_on_200(serve) -> None:
    server = serve()

    ok = upload.post_event(
        f"http://127.0.0.1:{server.server_port}", "sk_test", b"event-bytes"
    )

    assert ok is True
    [(method, path, headers, body)] = server.requests
    assert method == "POST"
    assert path.startswith("/agent/events/v1?slotid=")
    assert headers["Authorization"] == "ApiKey sk_test"
    assert body == upload.length_delimited(b"event-bytes")


def test_post_event_fails_on_redirect_without_location(serve, capsys) -> None:
    origin = serve(status=302)

    ok = upload.post_event(
        f"http://127.0.0.1:{origin.server_port}", "sk_test", b"event-bytes"
    )

    assert ok is False
    assert "status=302 endpoint_host='127.0.0.1' location_host=''" in (
        capsys.readouterr().err
    )


def test_post_event_bypasses_env_proxy_for_loopback(serve, monkeypatch) -> None:
    proxy = serve()
    origin = serve()
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_port}")

    ok = upload.post_event(
        f"http://127.0.0.1:{origin.server_port}", "sk_test", b"event-bytes"
    )

    assert ok is True
    assert proxy.requests == []
    assert [r[0] for r in origin.requests] == ["POST"]


def _patch_opener(monkeypatch, fn) -> None:
    """Stub what `_opener(url).open(req, timeout=...)` returns/raises.

    `_send_event` no longer calls `urllib.request.urlopen` directly.
    """

    class _Opener:
        def open(self, req, timeout):
            return fn(req, timeout)

    monkeypatch.setattr(upload, "_opener", lambda _url: _Opener())


def test_string_field_encodes_lone_surrogate() -> None:
    from ccusage import wire  # noqa: PLC0415

    assert wire.string_field(1, "a\ud800b") == b"\x0a\x03a?b"


def test_permanent_rejection_classification() -> None:
    for permanent in (400, 413, 415, 422):
        assert upload.is_permanent_rejection(permanent)
    for transient in (0, 200, 401, 403, 404, 408, 429, 500, 503):
        assert not upload.is_permanent_rejection(transient)


def test_post_event_status_bounds_wall_time(monkeypatch) -> None:
    import time  # noqa: PLC0415

    def _hangs(*_args, **_kwargs):
        time.sleep(2)
        return 200

    monkeypatch.setattr(upload, "_send_event", _hangs)
    started = time.monotonic()

    status = upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x", None, 0.2)

    assert status == 0
    assert time.monotonic() - started < 1.0


def test_post_event_status_returns_http_error_code(monkeypatch) -> None:
    import io  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415

    def _rejects(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 413, "too big", {}, io.BytesIO())

    _patch_opener(monkeypatch, _rejects)

    assert upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x") == 413
    assert upload.post_event("http://127.0.0.1:1", "sk_test", b"x") is False


class _RedirectedResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self) -> str:
        return "http://127.0.0.1:1/moved"

    def read(self, _n: int = -1) -> bytes:
        return b""


def test_redirected_success_is_transient(monkeypatch) -> None:
    _patch_opener(monkeypatch, lambda req, timeout: _RedirectedResponse())

    assert upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x") == 0


def test_redirected_error_is_transient_not_permanent(monkeypatch) -> None:
    import io  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415

    def _redirect_then_405(req, timeout):
        raise urllib.error.HTTPError(
            "http://127.0.0.1:1/moved", 405, "no GET", {}, io.BytesIO()
        )

    _patch_opener(monkeypatch, _redirect_then_405)

    assert upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x") == 0


def test_any_2xx_is_success() -> None:
    for ok in (200, 201, 202, 204):
        assert upload.is_success(ok)
    for not_ok in (0, 199, 300, 400, 500):
        assert not upload.is_success(not_ok)


def test_exception_in_post_thread_is_transient_without_traceback(monkeypatch) -> None:
    import threading  # noqa: PLC0415

    hook_calls = []
    monkeypatch.setattr(threading, "excepthook", hook_calls.append)

    def _explodes(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(upload, "_send_event", _explodes)

    assert upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x") == 0
    assert hook_calls == []


def _fail_with(monkeypatch, status: int, detail: dict | None = None) -> None:
    monkeypatch.setattr(upload, "_send_event", lambda *_a: (status, detail or {}))


def test_breaker_opens_after_three_failures_and_backs_off(monkeypatch) -> None:
    import time  # noqa: PLC0415

    _fail_with(monkeypatch, 503)
    endpoint, key = "http://127.0.0.1:1", "sk_test"
    waits = []
    for _ in range(8):
        upload.begin_run()
        upload.post_event_status(endpoint, key, b"x")
        retry_at = upload.breaker_retry_at(endpoint, key)
        waits.append(round(retry_at - time.time()) if retry_at else 0)

    assert waits == [0, 0, 60, 120, 240, 480, 900, 900]


def test_breaker_resets_on_success_and_on_key_change(monkeypatch) -> None:
    endpoint = "http://127.0.0.1:1"
    _fail_with(monkeypatch, 0)
    for _ in range(3):
        upload.begin_run()
        upload.post_event_status(endpoint, "sk_a", b"x")
    assert upload.breaker_retry_at(endpoint, "sk_a") > 0
    assert upload.breaker_retry_at(endpoint, "sk_b") == 0
    assert upload.breaker_retry_at("http://localhost:1", "sk_a") == 0

    _fail_with(monkeypatch, 202)
    upload.post_event_status(endpoint, "sk_a", b"x")
    assert upload.breaker_retry_at(endpoint, "sk_a") == 0


def test_permanent_rejection_does_not_trip_breaker(monkeypatch) -> None:
    _fail_with(monkeypatch, 400)
    for _ in range(5):
        upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x")

    assert upload.breaker_retry_at("http://127.0.0.1:1", "sk_test") == 0


def test_health_file_is_owner_only_and_has_no_key(monkeypatch, tmp_path) -> None:
    _fail_with(monkeypatch, 401, {"reason": "invalid key"})
    upload.post_event_status("http://127.0.0.1:1", "sk_test_secretvalue", b"x")

    path = tmp_path / "state" / "health.json"
    if sys.platform != "win32":
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert "secretvalue" not in path.read_text()


def test_auth_failure_reason_from_backend_bodies() -> None:
    def body(message: str) -> str:
        return '{"error":{"code":401,"message":"%s"}}\n' % message

    assert upload._auth_failure_reason(body("invalid API key")) == "invalid key"
    assert (
        upload._auth_failure_reason(
            body("API key validation request failed: context deadline exceeded")
        )
        == "request failed"
    )
    assert upload._auth_failure_reason(body("Unauthorized")) == "unauthorized"
    assert upload._auth_failure_reason(body("org o1 has no tenant_id")) == "other"
    assert upload._auth_failure_reason("not json") == "other"


def test_401_and_unfollowed_redirect_details(monkeypatch) -> None:
    import io  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415

    def _raise(code, headers, body):
        def _urlopen(req, timeout):
            raise urllib.error.HTTPError(
                req.full_url, code, "x", headers, io.BytesIO(body)
            )

        return _urlopen

    _patch_opener(
        monkeypatch,
        _raise(401, {}, b'{"error":{"code":401,"message":"invalid API key"}}'),
    )
    assert upload._send_event("http://127.0.0.1:1", "k", b"x", None, 1) == (
        401,
        {"reason": "invalid key"},
    )

    _patch_opener(
        monkeypatch,
        _raise(307, {"Location": "https://sso.example/login?next=x"}, b""),
    )
    assert upload._send_event("http://127.0.0.1:1", "k", b"x", None, 1) == (
        307,
        {"location_host": "sso.example"},
    )


def test_logged_urls_drop_query_string(monkeypatch, tmp_path) -> None:
    import io  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415

    def _rejects(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "x", {}, io.BytesIO(b""))

    _patch_opener(monkeypatch, _rejects)

    upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x")

    log_text = (tmp_path / "state" / "ccusage.log").read_text()
    assert "url=http://127.0.0.1:1/agent/events/v1 " in log_text
    assert "slotid" not in log_text


def test_breaker_counts_one_failure_per_run(monkeypatch) -> None:
    _fail_with(monkeypatch, 503)
    upload.begin_run()
    for _ in range(3):
        upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x")
    upload.begin_run()
    upload.post_event_status("http://127.0.0.1:1", "sk_test", b"x")

    health = upload.current_health("http://127.0.0.1:1", "sk_test")
    assert health["consecutive"] == 2
    assert health["retry_at"] == 0


def test_success_after_key_change_rewrites_health(monkeypatch, tmp_path) -> None:
    import json  # noqa: PLC0415

    endpoint = "http://127.0.0.1:1"
    _fail_with(monkeypatch, 0)
    for _ in range(3):
        upload.begin_run()
        upload.post_event_status(endpoint, "sk_old", b"x")

    _fail_with(monkeypatch, 200)
    upload.begin_run()
    upload.post_event_status(endpoint, "sk_new", b"x")

    stored = json.loads((tmp_path / "state" / "health.json").read_text())
    assert stored["id"] == upload._health_id(endpoint, "sk_new")
    assert stored["retry_at"] == 0
    assert "last_failure" not in stored


def test_corrupt_or_future_health_is_sanitised(monkeypatch) -> None:
    import time  # noqa: PLC0415

    from ccusage import state  # noqa: PLC0415

    endpoint, key = "http://127.0.0.1:1", "sk_test"
    hid = upload._health_id(endpoint, key)
    state.write_health({"id": hid, "retry_at": time.time() + 10**9, "consecutive": 9})
    assert upload.breaker_retry_at(endpoint, key) <= time.time() + 900

    state.write_health({"id": hid, "retry_at": "soon", "consecutive": "many"})
    assert upload.current_health(endpoint, key)["retry_at"] == 0
    assert upload.current_health(endpoint, key)["consecutive"] == 0

    with open(state.health_path(), "w") as fh:
        fh.write("{not json")
    assert upload.breaker_retry_at(endpoint, key) == 0
