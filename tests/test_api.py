"""HTTP surface: limits, errors and the streaming contract (deterministic mode, no keys)."""

import json

import pytest
from fastapi.testclient import TestClient

import backend.app as app_mod
from backend.limits import DailyBudget, RateLimiter


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_mod, "RATE", RateLimiter(limit=3, window_s=60))
    return TestClient(app_mod.app)


def _events(body: str) -> list[dict]:
    return [json.loads(line[5:]) for line in body.splitlines() if line.startswith("data:")]


def test_stream_ends_with_a_result(client):
    r = client.post(
        "/api/analyze/stream", data={"text": "Pay the fee now at http://parcel-fee.top/pay"}
    )
    events = _events(r.text)
    assert r.status_code == 200 and events[-1]["type"] == "result"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_unknown_sample_is_404(client):
    assert client.get("/api/samples/nope").status_code == 404


def test_oversized_text_is_refused(client):
    r = client.post("/api/analyze/stream", data={"text": "a" * 7000})
    assert r.status_code == 413 and "characters" in r.json()["error"]


def test_non_image_upload_is_refused(client):
    files = {"images": ("x.txt", b"hello", "text/plain")}
    assert client.post("/api/analyze/stream", files=files).status_code == 415


def test_rate_limit_returns_429_with_retry_after(client):
    for _ in range(3):
        assert client.post("/api/analyze", json={"text": "hello there friend"}).status_code == 200
    r = client.post("/api/analyze", json={"text": "hello there friend"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


def test_empty_request_is_422(client):
    assert client.post("/api/analyze", json={}).status_code == 422


def test_rate_limiter_window_slides():
    rl = RateLimiter(limit=2, window_s=10)
    assert rl.allow("a", now=0) and rl.allow("a", now=1) and not rl.allow("a", now=2)
    assert rl.allow("a", now=10.5) and rl.allow("b", now=2)


def test_daily_budget_runs_out():
    b = DailyBudget(per_day=2)
    assert [b.take(), b.take(), b.take()] == [True, True, False]
