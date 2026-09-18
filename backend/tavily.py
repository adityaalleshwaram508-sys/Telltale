"""Live verification via Tavily.

The deterministic detectors know *patterns*; they can't know that a specific
domain, phone number, or "investment platform" has already been reported by other
victims or flagged by a regulator this year. That's what Tavily is for.

Design choices that keep it honest and cheap:
  * Queries are year-aware ("... scam 2026") so fresh reports rank first.
  * We only look up things worth looking up — an unfamiliar domain, a phone/UPI
    handle, a claimed company — never burn a search on google.com.
  * Every result becomes a Source with a stable id the verdict can cite. If a
    claim can't point at a returned source, it doesn't get to use Tavily as
    backing.
  * No key? We say so in the coverage notes instead of pretending we checked.
"""
from __future__ import annotations

import datetime as _dt

import httpx

from backend.config import get_settings
from backend.knowledge import genuine_domains
from backend.schemas import Entities, Source

_ENDPOINT = "https://api.tavily.com/search"


def _year() -> int:
    return _dt.date.today().year


async def _search(query: str, *, max_results: int = 5, depth: str = "basic") -> list[dict]:
    s = get_settings()
    headers = {"Authorization": f"Bearer {s.tavily_api_key}"}
    payload = {
        "query": query,
        "search_depth": depth,
        "max_results": max_results,
        "topic": "general",
    }
    async with httpx.AsyncClient(timeout=s.tavily_timeout) as client:
        r = await client.post(_ENDPOINT, json=payload, headers=headers)
        r.raise_for_status()
        return r.json().get("results", [])


def _plan_queries(entities: Entities, claimed_sender: str, region_hint: str | None) -> list[str]:
    """Decide the handful of look-ups worth doing for this message."""
    year = _year()
    genuine = genuine_domains()
    queries: list[str] = []

    # Unfamiliar domains are the highest-value thing to verify.
    for host in entities.domains:
        core = ".".join(host.split(".")[-2:])
        if core in genuine or host in genuine:
            continue
        queries.append(f'"{host}" scam OR fraud OR phishing OR complaint {year}')
        break  # one domain look-up is usually enough for a single message

    # Phone numbers and UPI handles are widely reported by other victims.
    if entities.phones:
        queries.append(f'"{entities.phones[0]}" scam OR fraud OR spam report')
    if entities.upi_ids:
        queries.append(f'"{entities.upi_ids[0]}" scam OR fraud')

    # A named company/platform with no domain is worth checking — but skip generic
    # authority roles ("cyber crime branch", "police", a bank), which just return
    # news and dilute the evidence. Those are better judged by the tells.
    generic = ("police", "cyber crime", "crime branch", "cybercrime", "government",
               "bank", "court", "customs", "income tax", "tax department", "rbi",
               "department", "officer", "inspector", "agency", "helpline", "unknown")
    if not queries and claimed_sender:
        cs = claimed_sender.lower().strip()
        if cs and not any(g in cs for g in generic):
            loc = f" {region_hint}" if region_hint else ""
            queries.append(f'"{claimed_sender}" scam OR legit OR review{loc} {year}')

    return queries[:3]     # keep latency and credit spend in check


async def gather_evidence(
    entities: Entities, claimed_sender: str, region_hint: str | None
) -> tuple[list[Source], list[str], list[str]]:
    """Returns (sources, coverage_notes, queries_run)."""
    s = get_settings()
    if not s.has_tavily:
        return [], ["Live verification skipped — no Tavily API key configured, so "
                    "reputation of the links/numbers wasn't checked online."], []

    queries = _plan_queries(entities, claimed_sender, region_hint)
    if not queries:
        return [], ["Nothing external to verify (no unfamiliar links, numbers, or "
                    "named company in the message)."], []

    sources: list[Source] = []
    seen_urls: set[str] = set()
    notes: list[str] = []

    for q in queries:
        try:
            results = await _search(q, depth="advanced", max_results=5)
        except Exception as e:
            notes.append(f"A live check failed ({type(e).__name__}); treat the online "
                         f"reputation as unknown, not clear.")
            continue
        for r in results:
            url = r.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            snippet = (r.get("content") or "").strip().replace("\n", " ")
            sources.append(Source(
                id=f"src{len(sources) + 1}",
                title=(r.get("title") or url)[:200],
                url=url,
                snippet=snippet[:500],
                score=r.get("score"),
            ))

    if not sources and not notes:
        notes.append("Live search returned nothing on the links/numbers — no public "
                     "reports either way.")
    return sources, notes, queries
