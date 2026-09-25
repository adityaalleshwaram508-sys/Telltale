"""Link and domain heuristics.

The link is usually the most reliable tell: it names a brand but points somewhere the brand
doesn't own, sits a keystroke away from the real domain, or hides behind a shortener.
"""

from __future__ import annotations

import re

from backend.detectors.domains import host_tokens, is_bank_in, is_ip, registrable_domain, split_host
from backend.knowledge import (
    brand_by_name,
    brands,
    genuine_domains,
    suspicious_tlds,
    url_shorteners,
)
from backend.schemas import Entities, Signal

URL_SIGNAL_IDS = (
    "url.ip_address",
    "url.punycode",
    "url.suspicious_tld",
    "url.shortener",
    "url.fake_bank_in",
    "url.lookalike",
    "url.brand_in_subdomain",
    "url.brand_mismatch",
)

# Fold common digit and symbol swaps so paypa1.com and g00gle.com compare equal to the real name.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "5": "s", "|": "l", "$": "s"})

# Hosts dressed up as RBI's bank-only suffix: hdfc-bank.in, sbi.bank.in.kyc-update.top
_FAKE_BANK_IN = re.compile(r"(?:^|[.\-])bank[.\-]in(?:[.\-]|$)")


def _fold(name: str) -> str:
    return name.lower().translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _lookalike_of(reg: str, genuine: set[str]) -> tuple[str, int] | None:
    """The genuine domain `reg` imitates, with the edit distance after folding.

    Short names get no edit slack: one edit from ssa.gov is usa.gov, which is real. They are
    only matched on a pure character swap (paypa1.com, 1rs.gov).
    """
    folded = _fold(reg)
    for g in sorted(genuine):
        if abs(len(folded) - len(g)) > 2:
            continue
        name_len = len(split_host(g)[1])
        allowed = 0 if name_len < 5 else 1 if name_len < 8 else 2
        dist = _levenshtein(folded, g)
        if dist == 0 and folded != reg.lower():
            return g, 0
        if 1 <= dist <= allowed:
            return g, dist
    return None


# Phishing hosts glue an action word onto the brand: verifyapple, securepaypal, myhdfcbank.
_PHISH_AFFIXES = (
    "verify",
    "secure",
    "login",
    "signin",
    "update",
    "account",
    "support",
    "confirm",
    "billing",
    "service",
    "online",
    "help",
    "auth",
    "my",
)


def _keyword_in_host(slug: str, tokens: list[str]) -> bool:
    """A brand keyword as a whole host label, or leading/trailing one when it's long enough
    not to turn up inside ordinary words (chase in purchase, irs in firstpost)."""
    for t in tokens:
        rest = next(
            (t[len(a) :] for a in _PHISH_AFFIXES if t.startswith(a) and len(t) > len(a)), ""
        )
        if (
            t == slug
            or rest == slug
            or (len(slug) >= 5 and (t.startswith(slug) or rest.startswith(slug)))
            or (len(slug) >= 6 and t.endswith(slug))
        ):
            return True
    return False


def analyze_urls(text: str, entities: Entities) -> list[Signal]:
    signals: list[Signal] = []
    genuine = genuine_domains()
    shorteners = set(url_shorteners())

    for host in entities.domains:
        if is_ip(host):
            signals.append(
                Signal(
                    id="url.ip_address",
                    category="url",
                    label="Link uses a raw IP address",
                    detail=f"{host} is a bare IP, which legitimate services almost never use in links.",
                    severity=2,
                    evidence_text=host,
                )
            )
            continue

        reg = registrable_domain(host)
        official = reg in genuine or host in genuine or is_bank_in(host)

        if "xn--" in host:
            signals.append(
                Signal(
                    id="url.punycode",
                    category="url",
                    label="Internationalised (punycode) domain",
                    detail=f"{host} uses punycode, a common trick for look-alike domains.",
                    severity=2,
                    evidence_text=host,
                )
            )

        tld = "." + host.rsplit(".", 1)[-1]
        if tld in suspicious_tlds() and not official:
            signals.append(
                Signal(
                    id="url.suspicious_tld",
                    category="url",
                    label="Uncommon / cheap top-level domain",
                    detail=f"{host} uses {tld}, a TLD disproportionately used by throwaway scam sites.",
                    severity=1,
                    evidence_text=host,
                )
            )

        if reg in shorteners or host in shorteners:
            signals.append(
                Signal(
                    id="url.shortener",
                    category="url",
                    label="Hidden behind a link shortener",
                    detail=f"{host} is a URL shortener, so the real destination is concealed.",
                    severity=1,
                    evidence_text=host,
                )
            )
            continue  # the destination can't be judged any further

        if not is_bank_in(host) and _FAKE_BANK_IN.search(host):
            signals.append(
                Signal(
                    id="url.fake_bank_in",
                    category="url",
                    label="Imitates the bank-only .bank.in address",
                    detail=(
                        f"{host} only looks like a .bank.in address. RBI reserves .bank.in for "
                        "regulated Indian banks, so a real bank link ends exactly in .bank.in."
                    ),
                    severity=3,
                    evidence_text=host,
                )
            )

        if official:
            continue

        look = _lookalike_of(reg, genuine)
        if look:
            g, dist = look
            how = (
                "uses look-alike characters for"
                if dist == 0
                else f"is only {dist} character(s) off"
            )
            signals.append(
                Signal(
                    id="url.lookalike",
                    category="url",
                    label="Look-alike of a real domain",
                    detail=f"{host} {how} {g}, a hallmark of spoofed links.",
                    severity=3,
                    evidence_text=host,
                )
            )

        tokens = host_tokens(host)
        for b in brands():
            if reg in b.domains:
                continue
            kw = next((k for k in b.keywords if _keyword_in_host(k.replace(" ", ""), tokens)), None)
            if kw:
                signals.append(
                    Signal(
                        id="url.brand_in_subdomain",
                        category="url",
                        label=f"Impersonates {b.name} in the link",
                        detail=f"{host} carries '{kw}' but the registered domain is {reg}, not {b.name}'s.",
                        severity=3,
                        evidence_text=host,
                    )
                )
                break

    # A brand is mentioned in the text, but no link goes to that brand.
    if entities.brands_mentioned and entities.domains:
        for name in entities.brands_mentioned:
            b = brand_by_name(name)
            if not b or not b.domains:
                continue
            if b.indian_bank and any(is_bank_in(d) for d in entities.domains):
                continue
            if any(registrable_domain(d) in b.domains or d in b.domains for d in entities.domains):
                continue
            signals.append(
                Signal(
                    id="url.brand_mismatch",
                    category="url",
                    label=f"Claims to be {b.name} but links elsewhere",
                    detail=(
                        f"The message invokes {b.name}, yet none of its links point to "
                        f"{b.name}'s real site ({', '.join(b.domains)})."
                    ),
                    severity=2,
                    evidence_text=", ".join(entities.domains),
                )
            )

    seen, out = set(), []
    for s in signals:
        key = (s.id, s.evidence_text)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out
