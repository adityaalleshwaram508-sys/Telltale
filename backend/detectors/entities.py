"""Pull structured entities out of raw message text.

Regex and string work only, no model: a checkable inventory of what a scam hangs on (links,
phone numbers, UPI IDs, wallet addresses, money amounts) so later steps reason about
concrete objects.
"""

from __future__ import annotations

import re

from backend.detectors.domains import has_public_suffix, registrable_domain
from backend.knowledge import brands
from backend.schemas import Entities

# A URL with a scheme, or a bare "www."/domain-looking token. The second branch is loose on
# purpose because scam texts rarely bother with https://.
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
    """
)
_EXPLICIT_URL = re.compile(r"(?i)^(?:https?://|www\.)")

_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")

# UPI handle: name@psp where the psp part has no dot (that's what separates a UPI id like
# ravi@okhdfcbank from an email like ravi@gmail.com).
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
    """
)

# Phone: +CC and/or 7-15 digits with common separators. The digit count is validated
# afterwards so order IDs and amounts aren't grabbed.
_PHONE_RE = re.compile(r"(?:(?<=\D)|^)(\+?\d[\d\s\-().]{6,16}\d)(?=\D|$)")


def _normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _host_from_url(url: str) -> str:
    u = re.sub(r"^https?://", "", url.strip().strip(".,)"), flags=re.I)
    host = u.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1]  # drop any user:pass@
    host = host.split(":")[0]  # drop port
    return _normalize_host(host)


def _looks_like_phone(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    return 7 <= len(digits) <= 15


def extract_entities(text: str) -> Entities:
    urls_raw = [m.group(1) for m in _URL_RE.finditer(text)]

    # Emails first so they can be subtracted from URL and UPI candidates.
    emails = sorted({m.group(0) for m in _EMAIL_RE.finditer(text)}, key=str.lower)

    urls, domains = [], []
    seen_domains = set()
    for u in urls_raw:
        u = u.strip().strip(".,)")
        host = _host_from_url(u)
        if not host or "." not in host:
            continue
        if any(u.lower() in e.lower() for e in emails):
            continue
        # A bare word.word only counts as a link if it ends in a real public suffix. In
        # chat-style texts "message.pandy" or "i.ll" is a missing space, not a domain.
        if not _EXPLICIT_URL.match(u) and not has_public_suffix(host):
            continue
        if u.lower() not in (x.lower() for x in urls):
            urls.append(u)
        if host not in seen_domains:
            seen_domains.add(host)
            domains.append(host)

    upi_ids = []
    for m in _UPI_RE.finditer(text):
        cand = m.group(0)
        if cand in emails or "." in cand.split("@")[1]:
            continue
        upi_ids.append(cand.lower())
    upi_ids = sorted(set(upi_ids))

    crypto = sorted(
        {m.group(0) for m in _BTC_RE.finditer(text)} | {m.group(0) for m in _ETH_RE.finditer(text)}
    )

    amounts = list(dict.fromkeys(" ".join(m.group(1).split()) for m in _AMOUNT_RE.finditer(text)))

    phones = []
    for m in _PHONE_RE.finditer(text):
        cand = m.group(1).strip()
        if _looks_like_phone(cand) and cand not in phones and not any(cand in a for a in amounts):
            phones.append(cand)

    # Word-boundary match so short keywords like "sbi" or "irs" don't fire inside ordinary
    # words ("first", "message").
    lower = text.lower()

    def _kw_present(kw: str) -> bool:
        return re.search(rf"\b{re.escape(kw)}\b", lower) is not None

    mentioned = sorted({b.name for b in brands() if any(_kw_present(kw) for kw in b.keywords)})

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


def _contains(text: str, needle: str) -> bool:
    return re.search(rf"(?<![a-z0-9-]){re.escape(needle)}(?![a-z0-9-])", text) is not None


def entities_mentioned(text: str, entities: Entities) -> list[str]:
    """The message's links, numbers and handles that also appear in `text`.

    Used on search results (does this report name the thing we looked up?) and on the
    model's claims (does this finding name a specific link or number?). Phone numbers are
    compared on their last ten digits so +91 98765 43210 matches 9876543210.
    """
    low = text.lower()
    digits = re.sub(r"[\s\-().+]", "", low)
    found: list[str] = []
    for host in entities.domains:
        reg = registrable_domain(host)
        if _contains(low, host) or (reg != host and _contains(low, reg)):
            found.append(host)
    for phone in entities.phones:
        d = re.sub(r"\D", "", phone)
        key = d[-10:]
        if len(key) >= 7 and key in digits:
            found.append(phone)
    for item in (*entities.upi_ids, *entities.emails, *entities.crypto_addresses):
        if item.lower() in low:
            found.append(item)
    return found
