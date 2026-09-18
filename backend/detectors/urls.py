"""Link and domain heuristics.

The most reliable scam tell is almost always the link: it name-drops a brand but
points somewhere the brand doesn't own, or it's one keystroke off the real
domain, or it hides behind a shortener. None of that needs a model to see.
"""
from __future__ import annotations

import re

from backend.knowledge import brands, genuine_domains, suspicious_tlds, url_shorteners
from backend.schemas import Entities, Signal

_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Cheap homoglyph fold so "paypaI.com" / "g00gle.com" collapse toward the real
# thing before we measure edit distance.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "5": "s", "|": "l", "$": "s"})


def _fold(host: str) -> str:
    h = host.lower().translate(_HOMOGLYPHS)
    h = h.replace("rn", "m").replace("vv", "w")
    return h


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


def _core(host: str) -> str:
    """The registrable-ish domain, e.g. secure-login.top from a.b.secure-login.top.
    Not PSL-accurate, but good enough for look-alike scoring."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_urls(text: str, entities: Entities) -> list[Signal]:
    signals: list[Signal] = []
    genuine = genuine_domains()

    for host in entities.domains:
        core = _core(host)

        if _IP_HOST_RE.match(host):
            signals.append(Signal(
                id="url.ip_address", category="url",
                label="Link uses a raw IP address",
                detail=f"{host} is a bare IP, which legitimate services almost never use in links.",
                severity=2, evidence_text=host,
            ))

        if "xn--" in host:
            signals.append(Signal(
                id="url.punycode", category="url",
                label="Internationalised (punycode) domain",
                detail=f"{host} uses punycode, a common trick for look-alike domains.",
                severity=2, evidence_text=host,
            ))

        tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in suspicious_tlds() and core not in genuine:
            signals.append(Signal(
                id="url.suspicious_tld", category="url",
                label="Uncommon / cheap top-level domain",
                detail=f"{host} uses {tld}, a TLD disproportionately used by throwaway scam sites.",
                severity=1, evidence_text=host,
            ))

        if any(host == s or host.endswith("." + s) or core == s for s in url_shorteners()):
            signals.append(Signal(
                id="url.shortener", category="url",
                label="Hidden behind a link shortener",
                detail=f"{host} is a URL shortener, so the real destination is concealed.",
                severity=1, evidence_text=host,
            ))
            continue  # can't judge the destination further

        # Look-alike of a genuine domain (one or two edits away after folding).
        if core not in genuine:
            folded = _fold(core)
            for g in genuine:
                if abs(len(folded) - len(g)) > 2:
                    continue
                dist = _levenshtein(folded, g)
                # dist==0 after folding means a pure homoglyph swap (paypa1.com ->
                # paypal.com); 1-2 means a near-miss typo-squat. Both are spoofs.
                if dist <= 2 and (dist >= 1 or folded != core):
                    how = ("uses look-alike characters for" if dist == 0
                           else f"is only {dist} character(s) off")
                    signals.append(Signal(
                        id="url.lookalike", category="url",
                        label="Look-alike of a real domain",
                        detail=f"{host} {how} {g}, a hallmark of spoofed links.",
                        severity=3, evidence_text=host,
                    ))
                    break

        # Brand name hidden as a label of an unrelated domain, e.g. paypal.secure.top
        if core not in genuine:
            for b in brands():
                if core in b.domains:
                    continue
                for kw in b.keywords:
                    kw_slug = kw.replace(" ", "")
                    if kw_slug and kw_slug in host.replace("-", "").replace(".", ""):
                        signals.append(Signal(
                            id="url.brand_in_subdomain", category="url",
                            label=f"Impersonates {b.name} in the link",
                            detail=f"{host} puts '{kw}' in the address but the real domain is {core}, not {b.name}'s.",
                            severity=3, evidence_text=host,
                        ))
                        break
                else:
                    continue
                break

    # Brand mentioned in the text, but no link actually goes to that brand.
    if entities.brands_mentioned and entities.domains:
        for name in entities.brands_mentioned:
            b = next((x for x in brands() if x.name == name), None)
            if not b or not b.domains:
                continue
            if not any(_core(d) in b.domains or d in b.domains for d in entities.domains):
                signals.append(Signal(
                    id="url.brand_mismatch", category="url",
                    label=f"Claims to be {b.name} but links elsewhere",
                    detail=(f"The message invokes {b.name}, yet none of its links point to "
                            f"{b.name}'s real site ({', '.join(b.domains)})."),
                    severity=2, evidence_text=", ".join(entities.domains),
                ))

    # De-dupe by id+evidence so we never show the same finding twice.
    seen, out = set(), []
    for s in signals:
        key = (s.id, s.evidence_text)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out
