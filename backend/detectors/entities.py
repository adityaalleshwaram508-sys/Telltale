"""Pull structured entities out of raw message text.

Everything here is regex + string work, no model. The point is to get a
reliable, checkable inventory of the things a scam hangs on — links, phone
numbers, UPI IDs, wallet addresses, money amounts — so later steps can reason
about concrete objects instead of vibes.
"""
from __future__ import annotations

import re

from backend.knowledge import brands
from backend.schemas import Entities

# A URL with a scheme, or a bare "www."/domain-looking token. The second branch
# is intentionally loose because scam texts rarely bother with https://.
_URL_RE = re.compile(
    r"""(?xi)
    \b(
        https?://[^\s<>"')]+                     # scheme URLs
        |
        (?:www\.)[^\s<>"')]+                     # www.something
        |
        (?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+   # domain labels
        [a-z]{2,24}                              # tld
        (?:/[^\s<>"')]*)?                        # optional path
    )
    """,
)

_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")

# UPI handle: name@psp where the psp part has no dot (that's what separates a UPI
# id like ravi@okhdfcbank from an email like ravi@gmail.com).
_UPI_RE = re.compile(r"(?i)\b[a-z0-9.\-_]{2,}@[a-z]{2,20}\b")

_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Money: a currency marker next to a number, in either order.
_AMOUNT_RE = re.compile(
    r"""(?xi)
    (
        (?:₹|rs\.?|inr|\$|usd|£|gbp|€|eur|aed|sgd)\s?[\d,]+(?:\.\d+)?(?:\s?(?:lakh|lakhs|crore|cr|k|million|m))?
        |
        [\d,]+(?:\.\d+)?\s?(?:rupees|dollars|lakh|lakhs|crore|pounds|euros)
    )
    """,
)

# Phone: +CC and/or 7-15 digits with common separators. We validate the digit
# count afterwards so we don't grab order IDs or amounts.
_PHONE_RE = re.compile(r"(?:(?<=\D)|^)(\+?\d[\d\s\-().]{6,16}\d)(?=\D|$)")


def _registrable(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _host_from_url(url: str) -> str:
    u = url.strip().strip(".,)")
    u = re.sub(r"^https?://", "", u, flags=re.I)
    host = u.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1]        # drop any user:pass@
    host = host.split(":")[0]         # drop port
    return _registrable(host)


def _looks_like_phone(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    return 7 <= len(digits) <= 15


def extract_entities(text: str) -> Entities:
    urls_raw = [m.group(1) for m in _URL_RE.finditer(text)]

    # Emails first so we can subtract them from UPI candidates.
    emails = sorted({m.group(0) for m in _EMAIL_RE.finditer(text)}, key=str.lower)

    # Bare-domain matches from _URL_RE that are actually emails/UPI get filtered.
    urls, domains = [], []
    seen_domains = set()
    for u in urls_raw:
        u = u.strip().strip(".,)")
        host = _host_from_url(u)
        if not host or "." not in host:
            continue
        if any(u.lower() in e.lower() for e in emails):
            continue
        if u.lower() not in (x.lower() for x in urls):
            urls.append(u)
        if host not in seen_domains:
            seen_domains.add(host)
            domains.append(host)

    upi_ids = []
    for m in _UPI_RE.finditer(text):
        cand = m.group(0)
        if cand in emails:
            continue
        # UPI suffix has no dot; emails do.
        suffix = cand.split("@")[1]
        if "." in suffix:
            continue
        upi_ids.append(cand.lower())
    upi_ids = sorted(set(upi_ids))

    crypto = sorted(
        {m.group(0) for m in _BTC_RE.finditer(text)}
        | {m.group(0) for m in _ETH_RE.finditer(text)}
    )

    amounts = []
    for m in _AMOUNT_RE.finditer(text):
        amounts.append(" ".join(m.group(1).split()))
    amounts = list(dict.fromkeys(amounts))   # dedupe, keep order

    phones = []
    for m in _PHONE_RE.finditer(text):
        cand = m.group(1).strip()
        if _looks_like_phone(cand) and cand not in phones:
            # don't double-count something already captured as an amount
            if not any(cand in a for a in amounts):
                phones.append(cand)

    # Word-boundary match so short keywords like "sbi" or "irs" don't fire inside
    # ordinary words ("first", "message").
    lower = text.lower()

    def _kw_present(kw: str) -> bool:
        return re.search(rf"\b{re.escape(kw)}\b", lower) is not None

    mentioned = sorted(
        {b.name for b in brands() if any(_kw_present(kw) for kw in b.keywords)}
    )

    return Entities(
        urls=urls,
        domains=domains,
        emails=emails,
        phones=phones,
        upi_ids=upi_ids,
        crypto_addresses=crypto,
        amounts=amounts,
        brands_mentioned=mentioned,
    )
