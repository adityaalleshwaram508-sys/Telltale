from backend.detectors.language import analyze_language


def _ids(text):
    return {s.id for s in analyze_language(text)}


def test_credential_request_is_high_severity():
    sigs = analyze_language("Please share OTP to confirm")
    ids = {s.id for s in sigs}
    assert "language.credentials" in ids
    assert max(s.severity for s in sigs if s.id == "language.credentials") == 3


def test_threat_and_secrecy():
    ids = _ids("You will be arrested. Do not tell your family, stay on the call.")
    assert "language.threat" in ids
    assert "language.secrecy" in ids


def test_remote_access_tools():
    assert "language.remote_access" in _ids("Install AnyDesk so I can fix your account")


def test_benign_text_is_quiet():
    ids = _ids("Thanks for your order, it will arrive Thursday.")
    assert "language.credentials" not in ids
    assert "language.threat" not in ids
