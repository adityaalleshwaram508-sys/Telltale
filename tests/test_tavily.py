"""Research planning and result handling, with Tavily replaced by httpx.MockTransport."""

import json

import httpx
import pytest

from backend.config import get_settings
from backend.detectors.entities import extract_entities
from backend.tavily import gather_evidence, plan_queries

MSG = "India Post: pay at https://indiapost-redelivery.top/track or call +91 98765 43210"


@pytest.fixture
def tavily_key(monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_queries_target_the_messages_own_entities():
    queries = plan_queries(extract_entities(MSG), "India Post")
    assert queries[0].about == "indiapost-redelivery.top" and queries[0].exact
    assert queries[0].exclude == ("indiapost-redelivery.top",)
    assert '"9876543210"' in queries[1].text  # +91 is dropped so reports match


def test_genuine_domains_are_not_searched():
    queries = plan_queries(extract_entities("Track at https://www.amazon.in/orders"), "Amazon")
    assert [q.about for q in queries] == ["pattern"]


async def test_results_are_attributed_and_the_suspect_site_is_dropped(tavily_key):
    seen = []

    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        results = [
            {
                "url": "https://indiapost-redelivery.top/track",
                "title": "Track",
                "content": "the scam page",
            },
            {
                "url": "https://example.org/alert",
                "title": "Alert",
                "content": "Readers reported indiapost-redelivery.top as a fake fee site.",
            },
            {
                "url": "https://example.org/generic",
                "title": "Courier scams",
                "content": "Fee texts are common.",
            },
        ]
        return httpx.Response(200, json={"results": results, "usage": {"credits": 2}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        research = await gather_evidence(extract_entities(MSG), "India Post", "IN", client=client)

    assert all(body["exact_match"] and body["country"] == "india" for body in seen)
    urls = [s.url for s in research.sources]
    assert "https://indiapost-redelivery.top/track" not in urls
    alert = next(s for s in research.sources if s.url.endswith("/alert"))
    generic = next(s for s in research.sources if s.url.endswith("/generic"))
    assert alert.mentions == ["indiapost-redelivery.top"] and generic.mentions == []
    assert research.trace[0].credits == 2 and not research.failed


async def test_refused_parameters_fall_back_to_a_plain_search(tavily_key):
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        if "exact_match" in body:
            return httpx.Response(400, json={"detail": {"error": "bad"}})
        return httpx.Response(200, json={"results": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        research = await gather_evidence(extract_entities(MSG), "India Post", None, client=client)
    assert not research.failed and any("exact_match" not in c for c in calls)


async def test_failed_search_is_reported_not_hidden(tavily_key):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(500))
    ) as client:
        research = await gather_evidence(extract_entities(MSG), "India Post", None, client=client)
    assert research.failed and "unknown, not clear" in research.notes[0]
