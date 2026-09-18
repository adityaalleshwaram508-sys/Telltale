from backend.detectors.entities import extract_entities


def test_pulls_link_and_domain():
    e = extract_entities("Track your parcel at https://indiapost-redelivery.top/track now")
    assert "indiapost-redelivery.top" in e.domains
    assert any("indiapost-redelivery.top" in u for u in e.urls)


def test_upi_vs_email_are_not_confused():
    e = extract_entities("Send it to ravi@okhdfcbank or email me at ravi@gmail.com")
    assert "ravi@okhdfcbank" in e.upi_ids
    assert "ravi@gmail.com" in e.emails
    assert "ravi@gmail.com" not in e.upi_ids       # email must not leak into UPI
    assert "ravi@okhdfcbank" not in e.emails


def test_amount_extraction():
    e = extract_entities("Pay ₹4,999 now and get $200 back")
    joined = " ".join(e.amounts).lower()
    assert "4,999" in joined
    assert "200" in joined


def test_brand_keywords_respect_word_boundaries():
    # "irs" inside "first" and "ssa" inside "message" must NOT match brands.
    e = extract_entities("First message: your order is fine.")
    assert "IRS" not in e.brands_mentioned
    assert "Social Security (SSA)" not in e.brands_mentioned


def test_real_brand_is_detected():
    e = extract_entities("This is from your SBI bank account team")
    assert "State Bank of India" in e.brands_mentioned


def test_crypto_address():
    e = extract_entities("Send 0.1 ETH to 0x52908400098527886E0F7030069857D2E4169EE7 today")
    assert e.crypto_addresses
