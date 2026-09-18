from backend.detectors.entities import extract_entities
from backend.detectors.payments import analyze_payments


def _ids(text):
    return {s.id for s in analyze_payments(text, extract_entities(text))}


def test_gift_card():
    assert "payment.gift_card" in _ids("Pay using a Google Play gift card and send the redeem code")


def test_crypto_keyword():
    assert "payment.crypto" in _ids("Deposit in bitcoin to start trading")


def test_upi_collect():
    assert "payment.upi_collect" in _ids("Just scan this QR to receive your refund")


def test_wire_to_account():
    assert "payment.wire" in _ids("Transfer the amount to this verification account immediately")


def test_clean_text_has_no_payment_signal():
    assert _ids("Your package will arrive Thursday, no action needed.") == set()
