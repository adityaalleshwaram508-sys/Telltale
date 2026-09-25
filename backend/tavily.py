"""Live checks with Tavily.

Detectors know patterns. They can't know that a particular link, number or UPI handle was
reported by other people this year. Research covers that in two tiers.

  entity   exact-match searches for the message's own link, phone number or UPI handle,
           so a result only comes back if it names that thing
  pattern  when there's nothing specific to look up, one search on the claimed sender;
           verify.py lets these results back general claims only

The suspect domain is excluded from its own results, so the scam site can never be cited as
evidence about itself. Searches run concurrently and each one is recorded in the run trace.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
import time
from typing import NamedTuple

import httpx

from backend.config import get_settings
from backend.detectors.domains import is_bank_in, is_ip, registrable_domain
from backend.detectors.entities import entities_mentioned
from backend.knowledge import genuine_domains
from backend.schemas import Entities, Source, TraceEntry

ENDPOINT = "https://api.tavily.com/search"
MAX_RESULTS = 5

_COUNTRY = {
    "IN": "india",
    "US": "united states",
    "GB": "united kingdom",
    "AU": "australia",
    "CA": "canada",
    "SG": "singapore",
}
# Claimed senders too generic to search for: the results would be news, not reports.
_GENERIC_SENDERS = (
    "police",
    "cyber crime",
    "crime branch",
    "cybercrime",
    "government",
    "bank",
    "court",
    "customs",
    "income tax",
    "tax department",
    "rbi",
    "department",
    "officer",
    "inspector",
    "agency",
    "helpline",
    "unknown",
)


class Query(NamedTuple):
    text: str
    about: str  # the entity searched for, or "pattern"
    exact: bool
    exclude: tuple[str, ...] = ()


class Research(NamedTuple):
    sources: list[Source]
    notes: list[str]
    queries: list[str]
    trace: list[TraceEntry]
    failed: bool


def _phone_key(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    return digits[-10:] if len(digits) == 12 and digits.startswith("91") else digits


def plan_queries(entities: Entities, claimed_sender: str) -> list[Query]:
    """At most three look-ups: an unfamiliar domain, a phone number, a UPI handle."""
    year = dt.date.today().year
    genuine = genuine_domains()
    queries: list[Query] = []
    for host in entities.domains:
        reg = registrable_domain(host)
        if is_ip(host) or is_bank_in(host) or reg in genuine or host in genuine:
            continue
        queries.append(
            Query(f'"{host}" scam OR fraud OR phishing OR complaint {year}', host, True, (reg,))
        )
        break
    if entities.phones:
        queries.append(
            Query(
                f'"{_phone_key(entities.phones[0])}" scam OR fraud OR spam',
                entities.phones[0],
                True,
            )
        )
    if entities.upi_ids:
        queries.append(Query(f'"{entities.upi_ids[0]}" scam OR fraud', entities.upi_ids[0], True))
    sender = (claimed_sender or "").strip()
    if not queries and sender and not any(g in sender.lower() for g in _GENERIC_SENDERS):
        queries.append(Query(f'"{sender}" scam OR fraud warning {year}', "pattern", False))
    return queries[:3]


def _payload(q: Query, region: str | None, depth: str) -> dict:
    payload: dict = {
        "query": q.text,
        "search_depth": depth,
        "max_results": MAX_RESULTS,
        "topic": "general",
        "include_usage": True,
    }
    if q.exact:
        payload["exact_match"] = True
    if q.exclude:
        payload["exclude_domains"] = list(q.exclude)
    if region and region.upper() in _COUNTRY:
        payload["country"] = _COUNTRY[region.upper()]
    return payload


async def _search(
    client: httpx.AsyncClient, q: Query, region: str | None
) -> tuple[dict, TraceEntry]:
    s = get_settings()
    headers = {"Authorization": f"Bearer {s.tavily_api_key}"}
    started = time.perf_counter()
    note = ""
    try:
        r = await client.post(ENDPOINT, json=_payload(q, region, s.tavily_depth), headers=headers)
        if r.status_code == 400:
            # Fall back to the plain request if an optional parameter is refused.
            note = "optional parameters refused; retried plain"
            plain = {"query": q.text, "search_depth": s.tavily_depth, "max_results": MAX_RESULTS}
            r = await client.post(ENDPOINT, json=plain, headers=headers)
        r.raise_for_status()
        data = r.json()
        ok = True
    except (httpx.HTTPError, ValueError) as exc:
        data, ok, note = {}, False, type(exc).__name__
    entry = TraceEntry(
        kind="search",
        stage="research",
        name="tavily",
        detail=q.text,
        ms=int((time.perf_counter() - started) * 1000),
        results=len(data.get("results", [])),
        credits=float((data.get("usage") or {}).get("credits", 0) or 0),
        ok=ok,
        note=note,
    )
    return data, entry


async def gather_evidence(
    entities: Entities,
    claimed_sender: str,
    region: str | None,
    *,
    client: httpx.AsyncClient | None = None,
) -> Research:
    s = get_settings()
    if not s.has_tavily:
        note = (
            "Live verification skipped: no Tavily API key is configured, so the links and "
            "numbers weren't checked online."
        )
        return Research([], [note], [], [], False)

    queries = plan_queries(entities, claimed_sender)
    if not queries:
        note = "Nothing external to verify (no unfamiliar links, numbers, or named company)."
        return Research([], [note], [], [], False)

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=s.tavily_timeout)
    try:
        replies = await asyncio.gather(*(_search(client, q, region) for q in queries))
    finally:
        if owns_client:
            await client.aclose()

    suspects = {registrable_domain(d) for d in entities.domains}
    sources: list[Source] = []
    notes: list[str] = []
    seen: set[str] = set()
    for q, (data, entry) in zip(queries, replies, strict=True):
        if not entry.ok:
            notes.append(
                f"A live check failed ({entry.note}); treat the online reputation as unknown, not clear."
            )
            continue
        for r in data.get("results", []):
            url = r.get("url") or ""
            host = re.sub(r"^https?://", "", url).split("/")[0].lower()
            if not url or url in seen or (host and registrable_domain(host) in suspects):
                continue
            seen.add(url)
            title = (r.get("title") or url)[:200]
            snippet = " ".join((r.get("content") or "").split())[:500]
            sources.append(
                Source(
                    id=f"src{len(sources) + 1}",
                    title=title,
                    url=url,
                    snippet=snippet,
                    score=r.get("score"),
                    about=q.about,
                    mentions=entities_mentioned(f"{title} {snippet}", entities),
                )
            )
    if not sources and not notes:
        notes.append("Live search found no public reports on these links or numbers, either way.")
    failed = any(not e.ok for _, e in replies)
    return Research(sources, notes, [q.text for q in queries], [e for _, e in replies], failed)
