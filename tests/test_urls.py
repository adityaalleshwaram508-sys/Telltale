from backend.detectors.entities import extract_entities
from backend.detectors.urls import analyze_urls


def _ids(text):
    ents = extract_entities(text)
    return {s.id for s in analyze_urls(text, ents)}, ents


def test_lookalike_domain():
    ids, _ = _ids("Login now at http://paypa1.com/secure")  # 1 -> l lookalike
    assert "url.lookalike" in ids


def test_brand_hidden_in_subdomain():
    ids, _ = _ids("India Post: pay the fee at https://indiapost-redelivery.top/track")
    assert "url.brand_in_subdomain" in ids


def test_suspicious_tld():
    ids, _ = _ids("Join at https://gtx-globaltrade.xyz/join")
    assert "url.suspicious_tld" in ids


def test_shortener_flagged():
    ids, _ = _ids("Claim here: https://bit.ly/3xScam")
    assert "url.shortener" in ids


def test_brand_mismatch_when_link_is_elsewhere():
    ids, _ = _ids("Your PayPal account is limited. Restore it: https://account-verify.top/pp")
    assert "url.brand_mismatch" in ids or "url.brand_in_subdomain" in ids


def test_genuine_domain_is_clean():
    ids, _ = _ids("Your Amazon order shipped, track at https://amazon.in/orders")
    assert not any(i.startswith("url.lookalike") or i == "url.brand_in_subdomain" for i in ids)
