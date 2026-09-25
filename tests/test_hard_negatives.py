"""Legitimate messages that use scam vocabulary.

The model can't argue the detector floor down, so every false signal here would become a
false alarm the user sees. These pin the matcher fixes (PSL-aware domains, whole-word
terms, protective-advice handling) so they can't quietly regress.
"""

import pytest

from backend.detectors import run_detectors, signal_score, signal_vocabulary
from backend.detectors.entities import extract_entities
from backend.detectors.language import analyze_language
from backend.detectors.urls import analyze_urls
from backend.samples import ADVERSARIAL, HARD_NEGATIVES, SAMPLES

FLAG_THRESHOLD = 35  # first score of the "medium" band


@pytest.mark.parametrize("sample", HARD_NEGATIVES, ids=lambda s: s.id)
def test_hard_negative_stays_below_flag_threshold(sample):
    _, signals = run_detectors(sample.text)
    assert signal_score(signals) < FLAG_THRESHOLD, [(s.id, s.evidence_text) for s in signals]


def _url_ids(text):
    return {s.id for s in analyze_urls(text, extract_entities(text))}


@pytest.mark.parametrize(
    "text",
    [
        "Visit https://sbi.co.in/web/personal-banking",
        "Log in at https://www.onlinesbi.sbi",
        "HDFC Bank statement ready at https://netbanking.hdfc.bank.in/statement",
        "Your Amazon order: https://www.amazon.co.uk/orders",
    ],
)
def test_genuine_domains_raise_no_link_signals(text):
    assert _url_ids(text) == set()


@pytest.mark.parametrize("host", ["firstpost.com", "straitstimes.com", "purchase.stripe.com"])
def test_brand_keyword_inside_an_ordinary_word_is_ignored(host):
    assert "url.brand_in_subdomain" not in _url_ids(f"Read more at https://{host}/story")


@pytest.mark.parametrize(
    "url", ["https://hdfc-bank.in/login", "https://sbi.bank.in.kyc-update.top/verify"]
)
def test_imitation_of_bank_in_is_flagged(url):
    assert "url.fake_bank_in" in _url_ids(f"Verify your account at {url}")


def test_short_brand_names_need_a_whole_label():
    assert "url.brand_in_subdomain" in _url_ids("Update KYC at https://sbi-kyc-update.xyz/login")
    assert "url.lookalike" not in _url_ids("Official portal: https://www.usa.gov")


def test_chat_shorthand_is_not_a_domain():
    e = extract_entities("saw ur message.pandy lol. i.ll call later")
    assert "message.pandy" not in e.domains
    assert "i.ll" not in e.domains


def _lang(text):
    return {s.id for s in analyze_language(text)}


def test_protective_advice_is_not_a_credential_request():
    assert "language.credentials" not in _lang(
        "We will never ask for your UPI PIN or CVV. Never share them with anyone."
    )


def test_a_real_credential_request_is_still_caught():
    assert "language.credentials" in _lang(
        "Sir, please share the OTP you just received to cancel the charge."
    )


@pytest.mark.parametrize(
    "text", ["Hi, Abhishek here", "Courtesy reminder", "I'm fine, reached home"]
)
def test_terms_match_whole_words(text):
    assert not ({"language.urgency", "language.threat"} & _lang(text))


def test_space_and_hyphen_match_alike():
    assert "language.recruitment_bait" in _lang("Earn with a part-time job from your phone")


def test_every_emitted_signal_is_in_the_vocabulary():
    vocab = set(signal_vocabulary())
    for s in SAMPLES + ADVERSARIAL + HARD_NEGATIVES:
        _, signals = run_detectors(s.text)
        assert {x.id for x in signals} <= vocab, s.id


@pytest.mark.parametrize("host", ["verifyapple.uk", "securepaypal.top", "myhdfcbank-kyc.top"])
def test_action_word_glued_to_a_brand_is_flagged(host):
    assert "url.brand_in_subdomain" in _url_ids(f"Confirm your account at http://{host}/login")
