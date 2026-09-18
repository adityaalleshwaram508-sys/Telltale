"""Exercises the full (model-on) pipeline branch with a stubbed Nemotron and
Tavily, so we cover the code that only runs when a key is present — evidence
binding, dropping unsupported tells, score reconciliation, and the curated
report-channel/archetype wiring.
"""
import pytest

import backend.pipeline as pipeline
from backend.config import get_settings
from backend.samples import get_sample
from backend.schemas import (
    ActionDraft, ActionStep, AnalysisResult, ArchetypeMatch, MessageContext,
    RiskLevel, Source, Tell, Verdict,
)


class StubLLM:
    """Returns canned, schema-correct objects for each step."""

    async def structured(self, schema, system, user, *, model=None, images=None, temperature=0.2):
        name = schema.__name__
        if name == "MessageContext":
            return MessageContext(language="English", channel="sms",
                                  claimed_sender="India Post", summary="Fake redelivery fee.",
                                  asked_to=["click a link", "pay a fee"])
        if name == "ArchetypeMatch":
            return ArchetypeMatch(archetype_id="delivery_package", name="Delivery / courier scam",
                                  confidence=0.9, rationale="classic courier-fee phish",
                                  matched_tells=["fee to release parcel"])
        if name == "Verdict":
            return Verdict(
                risk_level=RiskLevel.low,   # deliberately too low; floor must override
                score=5,
                headline="This is a fake India Post redelivery-fee scam.",
                reasoning="Everything points to a courier phish.",
                tells=[
                    Tell(title="Look-alike link", explanation="not India Post's domain",
                         evidence_type="signal", evidence_ref="url.suspicious_tld"),
                    Tell(title="Urgency", explanation="pressure to act fast",
                         evidence_type="quote", evidence_ref="quote", quote="within 24 hours"),
                    Tell(title="Reported online", explanation="matches a live report",
                         evidence_type="source", evidence_ref="src1"),
                    # these two must be dropped by verify:
                    Tell(title="Invented signal", explanation="nope",
                         evidence_type="signal", evidence_ref="url.does_not_exist"),
                    Tell(title="Fabricated quote", explanation="nope",
                         evidence_type="quote", evidence_ref="quote", quote="send me 10000 dollars"),
                ],
            )
        if name == "ActionDraft":
            return ActionDraft(
                do_now=[ActionStep(step="Don't pay.", why="It's a scam.")],
                do_not=["Don't click the link."],
                how_to_verify=["Check on indiapost.gov.in directly."],
                safe_reply="",
            )
        raise AssertionError(f"unexpected schema {name}")


async def _fake_research(entities, claimed_sender, region_hint):
    return [Source(id="src1", title="Reported courier scam domain",
                   url="https://example.com/report", snippet="users report this domain")], [], ["q"]


@pytest.fixture
def model_on(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "test-key")
    get_settings.cache_clear()
    monkeypatch.setattr(pipeline, "get_llm", lambda: StubLLM())
    monkeypatch.setattr(pipeline, "gather_evidence", _fake_research)
    yield
    get_settings.cache_clear()


async def test_full_pipeline_with_model(model_on):
    s = get_sample("delivery_sms")
    result = None
    async for item in pipeline.analyze(text=s.text, region_hint=s.region_hint):
        if isinstance(item, AnalysisResult):
            result = item

    assert result is not None
    # The two unsupported tells were dropped; three real ones survive.
    assert len(result.verdict.tells) == 3
    refs = {(t.evidence_type, t.evidence_ref) for t in result.verdict.tells}
    assert ("signal", "url.suspicious_tld") in refs
    assert ("source", "src1") in refs
    assert ("quote", "quote") in refs

    # Model said "low/5" but the deterministic floor forces a serious verdict.
    assert result.verdict.risk_level in (RiskLevel.medium, RiskLevel.high, RiskLevel.critical)
    assert result.verdict.score >= 35

    # Curated wiring came through.
    assert result.archetype.archetype_id == "delivery_package"
    assert result.archetype_how           # curated "how it works" text
    assert any(c.name.startswith("National Cyber Crime") for c in result.action_plan.report_to)
    assert any("rejected" in n.lower() for n in result.coverage_notes)

    # The evidence-check centerpiece: 5 proposed, 3 backed, 2 rejected, and the
    # two rejects are surfaced with a reason apiece.
    assert result.evidence_audit.proposed == 5
    assert result.evidence_audit.kept == 3
    assert result.evidence_audit.rejected == 2
    assert len(result.rejected_claims) == 2
    assert {c.title for c in result.rejected_claims} == {"Invented signal", "Fabricated quote"}
    assert all(c.reason for c in result.rejected_claims)
