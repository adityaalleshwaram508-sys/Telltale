"""End-to-end pipeline tests in deterministic mode (no API keys needed).

They assert the pieces wire together and that a strong scam never comes back as
"safe", and a clean control message never gets over-flagged.
"""
import pytest

from backend.pipeline import analyze
from backend.samples import get_sample
from backend.schemas import AnalysisResult


async def _run(sample_id):
    s = get_sample(sample_id)
    result = None
    async for item in analyze(text=s.text, region_hint=s.region_hint, input_kind="sample"):
        if isinstance(item, AnalysisResult):
            result = item
    return result


@pytest.mark.parametrize("sample_id", ["upi_refund", "delivery_sms", "digital_arrest"])
async def test_strong_scams_are_not_marked_safe(sample_id):
    r = await _run(sample_id)
    assert r is not None
    assert r.verdict.risk_level.value in ("medium", "high", "critical")
    assert r.verdict.score >= 35
    assert r.action_plan.report_to           # always tell people where to report


async def test_control_message_is_not_overflagged():
    r = await _run("legit_order")
    assert r.verdict.risk_level.value in ("info", "low")


async def test_result_shape_is_complete():
    r = await _run("delivery_sms")
    assert r.entities.domains                 # extracted the link
    assert r.disclaimer                       # always present
    # every tell must reference real evidence (verify layer already ran)
    sig_ids = {s.id for s in r.signals}
    src_ids = {s.id for s in r.sources}
    for t in r.verdict.tells:
        if t.evidence_type == "signal":
            assert t.evidence_ref in sig_ids
        elif t.evidence_type == "source":
            assert t.evidence_ref in src_ids
