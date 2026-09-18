"""These are the tests that matter most: they prove the model can't smuggle an
unsupported claim past us, and can't talk the score down below the hard evidence.
"""
from backend.schemas import RiskLevel, Signal, Source, Tell, Verdict
from backend.verify import reconcile_verdict, verify_tells

MESSAGE = "Pay the ₹25 redelivery fee at indiapost-redelivery.top within 24 hours."

SIGNALS = [
    Signal(id="url.brand_in_subdomain", category="url", label="x", detail="y", severity=3),
    Signal(id="language.urgency", category="language", label="x", detail="y", severity=1),
]
SOURCES = [Source(id="src1", title="Reported scam domain", url="https://example.com", snippet="...")]


def test_valid_signal_tell_survives():
    tells = [Tell(title="Fake domain", explanation="…", evidence_type="signal",
                  evidence_ref="url.brand_in_subdomain")]
    kept, rejected = verify_tells(tells, SIGNALS, SOURCES, MESSAGE)
    assert len(kept) == 1 and rejected == []


def test_invented_signal_ref_is_dropped():
    tells = [Tell(title="Made up", explanation="…", evidence_type="signal",
                  evidence_ref="url.totally_invented")]
    kept, rejected = verify_tells(tells, SIGNALS, SOURCES, MESSAGE)
    assert kept == [] and len(rejected) == 1
    # The rejection is recorded with the offending claim and an explanation, so
    # the UI can show exactly what the model tried to slip through.
    assert rejected[0].title == "Made up"
    assert "signal" in rejected[0].reason


def test_invented_source_ref_is_dropped():
    tells = [Tell(title="Fake cite", explanation="…", evidence_type="source",
                  evidence_ref="src99")]
    kept, rejected = verify_tells(tells, SIGNALS, SOURCES, MESSAGE)
    assert len(rejected) == 1 and "source" in rejected[0].reason


def test_real_quote_survives_but_fabricated_quote_is_dropped():
    good = Tell(title="Urgency", explanation="…", evidence_type="quote", evidence_ref="quote",
                quote="within 24 hours")
    bad = Tell(title="Not in text", explanation="…", evidence_type="quote", evidence_ref="quote",
               quote="wire me ten thousand dollars")
    kept, rejected = verify_tells([good, bad], SIGNALS, SOURCES, MESSAGE)
    assert len(kept) == 1 and kept[0].quote == "within 24 hours"
    assert len(rejected) == 1 and rejected[0].title == "Not in text"


def test_score_cannot_fall_below_deterministic_floor():
    # Model tries to call a signal-heavy message "low / 10". Floor is 60.
    v = Verdict(risk_level=RiskLevel.low, score=10, headline="looks fine",
                tells=[], reasoning="…")
    fixed = reconcile_verdict(v, [], floor=60)
    assert fixed.score >= 60
    assert fixed.risk_level in (RiskLevel.high, RiskLevel.critical)


def test_score_is_clamped_to_100():
    v = Verdict(risk_level=RiskLevel.critical, score=250, headline="x", tells=[], reasoning="…")
    assert reconcile_verdict(v, [], floor=0).score == 100
