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
SOURCES = [
    Source(id="src1", title="Reported scam domain", url="https://example.com", snippet="...")
]


def test_valid_signal_tell_survives():
    tells = [
        Tell(
            title="Fake domain",
            explanation="…",
            evidence_type="signal",
            evidence_ref="url.brand_in_subdomain",
        )
    ]
    kept, rejected = verify_tells(tells, SIGNALS, SOURCES, MESSAGE)
    assert len(kept) == 1 and rejected == []


def test_invented_signal_ref_is_dropped():
    tells = [
        Tell(
            title="Made up",
            explanation="…",
            evidence_type="signal",
            evidence_ref="url.totally_invented",
        )
    ]
    kept, rejected = verify_tells(tells, SIGNALS, SOURCES, MESSAGE)
    assert kept == [] and len(rejected) == 1
    # The rejection is recorded with the offending claim and an explanation, so
    # the UI can show exactly what the model tried to slip through.
    assert rejected[0].title == "Made up"
    assert "signal" in rejected[0].reason


def test_invented_source_ref_is_dropped():
    tells = [Tell(title="Fake cite", explanation="…", evidence_type="source", evidence_ref="src99")]
    kept, rejected = verify_tells(tells, SIGNALS, SOURCES, MESSAGE)
    assert len(rejected) == 1 and "source" in rejected[0].reason


def test_real_quote_survives_but_fabricated_quote_is_dropped():
    good = Tell(
        title="Urgency",
        explanation="…",
        evidence_type="quote",
        evidence_ref="quote",
        quote="within 24 hours",
    )
    bad = Tell(
        title="Not in text",
        explanation="…",
        evidence_type="quote",
        evidence_ref="quote",
        quote="wire me ten thousand dollars",
    )
    kept, rejected = verify_tells([good, bad], SIGNALS, SOURCES, MESSAGE)
    assert len(kept) == 1 and kept[0].quote == "within 24 hours"
    assert len(rejected) == 1 and rejected[0].title == "Not in text"


def test_score_cannot_fall_below_deterministic_floor():
    # Model tries to call a signal-heavy message "low / 10". Floor is 60.
    v = Verdict(risk_level=RiskLevel.low, score=10, headline="looks fine", tells=[], reasoning="…")
    fixed = reconcile_verdict(v, [], floor=60)
    assert fixed.score >= 60
    assert fixed.risk_level in (RiskLevel.high, RiskLevel.critical)


def test_score_is_clamped_to_100():
    v = Verdict(risk_level=RiskLevel.critical, score=250, headline="x", tells=[], reasoning="…")
    assert reconcile_verdict(v, [], floor=0).score == 100


def test_unsupported_quote_cannot_survive():
    """A tell that quotes words the user never wrote is rejected, so the model can't
    put language into the victim's mouth to justify a verdict."""
    tell = Tell(
        title="Invented demand",
        explanation="…",
        evidence_type="quote",
        evidence_ref="quote",
        quote="send your Aadhaar number and OTP immediately",
    )
    kept, rejected = verify_tells([tell], SIGNALS, SOURCES, MESSAGE)
    assert kept == [] and len(rejected) == 1
    assert rejected[0].evidence_type == "quote"
    assert "message" in rejected[0].reason


def test_model_cannot_lower_verified_risk_floor():
    """When the model returns a score below the deterministic floor, the verdict is
    pulled up to the floor exactly and the band raised to match, so the model cannot
    talk the risk down below what the hard evidence already justifies."""
    v = Verdict(risk_level=RiskLevel.info, score=3, headline="looks fine", tells=[], reasoning="…")
    fixed = reconcile_verdict(v, [], floor=70)
    assert fixed.score == 70  # pulled up to the floor, not left at 3
    assert fixed.risk_level == RiskLevel.high  # band raised to match the clamped score


# ---- support checks: a valid pointer is not enough -------------------------------------

OTP_MESSAGE = "456123 is your OTP for login. Do not share it with anyone. - HDFC Bank"
COURIER = "India Post: pay the fee at https://indiapost-redelivery.top/track within 24 hours."
ON_TOPIC = Source(
    id="src1",
    title="Scam alert",
    url="https://example.org/a",
    snippet="Readers reported indiapost-redelivery.top as a fake India Post fee site this month.",
    about="indiapost-redelivery.top",
    mentions=["indiapost-redelivery.top"],
)
PATTERN_ONLY = Source(
    id="src2",
    title="Courier fee texts",
    url="https://example.org/b",
    snippet="Fake courier texts ask for a small redelivery fee and link to a copycat site.",
    about="pattern",
)


def _codes(tells, message=COURIER, sources=(ON_TOPIC, PATTERN_ONLY), signals=SIGNALS):
    _, rejected = verify_tells(list(tells), signals, list(sources), message)
    return [r.code for r in rejected]


def _quote(q):
    return Tell(title="t", explanation="e", evidence_type="quote", evidence_ref="quote", quote=q)


def _source(ref, support, title="Reported", explanation="seen in a report"):
    return Tell(
        title=title,
        explanation=explanation,
        evidence_type="source",
        evidence_ref=ref,
        support=support,
    )


def test_quote_used_only_in_the_negative_is_rejected():
    assert _codes([_quote("share it with anyone")], message=OTP_MESSAGE) == ["quote_negated"]


def test_condition_is_not_mistaken_for_negation():
    msg = "If you don't pay the fee today your account will be closed."
    assert _codes([_quote("pay the fee today")], message=msg) == []


def test_single_word_quote_is_rejected():
    assert _codes([_quote("fee")]) == ["quote_too_short"]


def test_quote_must_match_whole_words():
    assert _codes([_quote("ia post: pay")]) == ["quote_not_found"]


def test_source_tell_needs_an_excerpt_from_that_source():
    assert _codes([_source("src2", "")]) == ["no_excerpt"]
    assert _codes([_source("src2", "courier texts are always fake")]) == ["excerpt_not_in_source"]
    assert _codes([_source("src2", "ask for a small redelivery fee")]) == []


def test_named_entity_needs_a_source_that_mentions_it():
    claim = dict(title="Domain reported", explanation="indiapost-redelivery.top has been reported")
    assert _codes([_source("src2", "ask for a small redelivery fee", **claim)]) == [
        "source_off_topic"
    ]
    assert _codes([_source("src1", "reported indiapost-redelivery.top as a fake", **claim)]) == []


def test_this_domain_needs_an_on_topic_source():
    claim = dict(title="Flagged", explanation="this domain was flagged by other users")
    assert _codes([_source("src2", "link to a copycat site", **claim)]) == ["source_off_topic"]


def test_signal_cannot_back_outside_confirmation():
    tell = Tell(
        title="Government has confirmed this website is fraudulent",
        explanation="officially blacklisted",
        evidence_type="signal",
        evidence_ref="url.brand_in_subdomain",
    )
    assert _codes([tell]) == ["overreach"]


def test_every_rejection_carries_a_code_and_reason():
    tells = [_quote("fee"), _source("src9", "x y z w")]
    _, rejected = verify_tells(tells, SIGNALS, [ON_TOPIC], COURIER)
    assert [r.code for r in rejected] == ["quote_too_short", "unknown_source"]
    assert all(r.reason for r in rejected)
