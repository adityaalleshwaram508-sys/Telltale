"""The analysis pipeline.

An async generator that yields StepEvents as it goes (so the UI can narrate the
work) and finishes by emitting the assembled AnalysisResult. Each model step is
wrapped so a failure degrades to a deterministic fallback and a coverage note
rather than a 500 — the deterministic detectors alone are enough to give a
useful, honest answer if the model or the network is down.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator

from backend.config import get_settings
from backend.detectors import run_detectors, signal_score
from backend.knowledge import archetype, reporting_channels
from backend.llm import LLMError, get_llm
from backend.prompts import (
    action_system, action_user, classify_system, classify_user,
    context_system, context_user, verdict_system, verdict_user,
    vision_system, vision_user,
)
from backend.schemas import (
    ActionDraft, ActionPlan, AnalysisResult, ArchetypeMatch, Entities,
    EvidenceAudit, MessageContext, RejectedClaim, ReportingChannel, RiskLevel,
    Signal, Source, StepEvent, Tell, Transcription, Verdict,
)
from backend.tavily import gather_evidence
from backend.verify import reconcile_verdict, verify_archetype, verify_tells

DISCLAIMER = (
    "Telltale gives you evidence and a considered opinion — not a guarantee. "
    "Scammers adapt, and legitimate messages can look odd. When money or personal "
    "data is at stake, verify through an official channel you find yourself."
)


def _event(step: str, status: str, message: str, **data) -> StepEvent:
    return StepEvent(step=step, status=status, message=message, data=data or None)


def _infer_region(entities: Entities, text: str, hint: str | None) -> str | None:
    if hint:
        return hint.upper()
    if entities.upi_ids or re.search(r"₹|\b(?:rs\.?|inr)\b|\blakh|\bcrore", text, re.I):
        return "IN"
    return None


# --------------------------------------------------------------------------- #
#  Deterministic fallbacks (used when the model/network is unavailable)
# --------------------------------------------------------------------------- #
def _heuristic_context(text: str, entities: Entities) -> MessageContext:
    lower = text.lower()
    channel = "unknown"
    if entities.emails or "subject:" in lower:
        channel = "email"
    elif "whatsapp" in lower:
        channel = "whatsapp"
    elif entities.urls:
        channel = "sms"
    sender = entities.brands_mentioned[0] if entities.brands_mentioned else "unknown"
    return MessageContext(
        language="unknown", channel=channel, claimed_sender=sender,
        summary=text.strip()[:160], asked_to=[],
    )


def _heuristic_archetype(text: str, signals: list[Signal]) -> ArchetypeMatch:
    from backend.knowledge import archetypes
    lower = text.lower()
    best_id, best_score = "none", 0
    for a in archetypes().values():
        score = sum(1 for kw in a.aliases if kw in lower)
        if any(s.id == "payment.upi_collect" for s in signals) and a.id in ("marketplace", "otp_upi"):
            score += 1
        if score > best_score:
            best_id, best_score = a.id, score
    a = archetype(best_id) if best_id != "none" else None
    return ArchetypeMatch(
        archetype_id=best_id,
        name=a.name if a else "Unclassified",
        confidence=min(0.4 + 0.15 * best_score, 0.9) if a else 0.0,
        rationale="Matched by keyword overlap (model unavailable).",
        matched_tells=[],
    )


def _heuristic_verdict(signals: list[Signal], floor: int) -> tuple[Verdict, list[Tell]]:
    tells = [
        Tell(title=s.label, explanation=s.detail, evidence_type="signal",
             evidence_ref=s.id, quote="")
        for s in sorted(signals, key=lambda x: -x.severity)[:6]
    ]
    v = Verdict(risk_level=RiskLevel.info, score=floor,
                headline="Assessed from automated signals only (model unavailable).",
                tells=tells, reasoning="The reasoning model was unavailable, so this "
                "verdict reflects the deterministic detectors alone.")
    return reconcile_verdict(v, tells, floor), tells


def _heuristic_action(a_name: str) -> ActionDraft:
    return ActionDraft(
        do_now=[],
        do_not=["Don't click links, share codes, or pay anyone until you've verified independently."],
        how_to_verify=["Contact the organisation through its official app or website — never a "
                       "number or link from the message itself."],
        safe_reply="",
    )


# --------------------------------------------------------------------------- #
#  Main pipeline
# --------------------------------------------------------------------------- #
async def analyze(
    *, text: str | None = None, url: str | None = None,
    images: list[str] | None = None, region_hint: str | None = None,
    input_kind: str = "text",
) -> AsyncIterator[StepEvent | AnalysisResult]:
    settings = get_settings()
    llm = get_llm()
    coverage: list[str] = []

    # --- 1. Ingest ---------------------------------------------------------
    yield _event("ingest", "started", "Reading what you gave me…")
    if images:
        if settings.has_llm:
            try:
                tr = await llm.structured(Transcription, vision_system(), vision_user(),
                                          model=settings.vision_model, images=images)
                text = (tr.text or "").strip()
                yield _event("ingest", "done", "Read the text out of your screenshot.")
            except LLMError as e:
                coverage.append(f"Couldn't read the image with the vision model ({e}).")
                text = text or ""
                yield _event("ingest", "error", "Couldn't read the screenshot; continuing with any text you added.")
        else:
            coverage.append("Screenshot reading needs a model key; none configured.")
            text = text or ""
            yield _event("ingest", "skipped", "No model key — can't read the screenshot.")
    elif url:
        # We analyse the link itself and research its reputation; we don't fetch
        # the page (never render a suspect site to the user).
        text = url.strip()
        yield _event("ingest", "done", "Analysing the link (not opening it).")
    else:
        text = (text or "").strip()
        yield _event("ingest", "done", "Got it.")

    if not text:
        yield _event("ingest", "error", "There was nothing to analyse.")
        return

    # --- 2. Deterministic detectors ---------------------------------------
    yield _event("detect", "started", "Scanning for red flags…")
    entities, signals = run_detectors(text)
    floor = signal_score(signals)
    region = _infer_region(entities, text, region_hint)
    yield _event("detect", "done",
                 f"Found {len(signals)} concrete signal(s).",
                 signals=len(signals), entities=entities.model_dump())

    # --- 3. Context --------------------------------------------------------
    yield _event("context", "started", "Working out what it claims to be…")
    if settings.has_llm:
        try:
            # Lightweight extraction runs on the fast/cheap Nano model; the
            # reasoning-heavy steps below stay on Super.
            context = await llm.structured(MessageContext, context_system(), context_user(text),
                                           model=settings.fast_model)
            yield _event("context", "done", f"Looks like a {context.channel} from {context.claimed_sender}.",
                         context=context.model_dump())
        except LLMError as e:
            context = _heuristic_context(text, entities)
            coverage.append(f"Context read heuristically (model error: {e}).")
            yield _event("context", "error", "Model unavailable; read context heuristically.")
    else:
        context = _heuristic_context(text, entities)
        coverage.append("Running without a model key — deterministic mode only.")
        yield _event("context", "skipped", "No model key; using heuristics.")

    # --- 4. Archetype ------------------------------------------------------
    yield _event("classify", "started", "Matching it to known scam patterns…")
    if settings.has_llm:
        try:
            match = verify_archetype(
                await llm.structured(ArchetypeMatch, classify_system(), classify_user(text, context))
            )
        except LLMError as e:
            match = _heuristic_archetype(text, signals)
            coverage.append(f"Archetype matched heuristically (model error: {e}).")
    else:
        match = _heuristic_archetype(text, signals)
    arch = archetype(match.archetype_id)
    yield _event("classify", "done",
                 f"Closest pattern: {match.name}." if match.archetype_id != "none"
                 else "No single known pattern dominates.",
                 archetype=match.model_dump())

    # --- 5. Live research (Tavily) ----------------------------------------
    yield _event("research", "started", "Checking links and numbers against live reports…")
    sources, research_notes, queries = await gather_evidence(entities, context.claimed_sender, region)
    coverage.extend(research_notes)
    yield _event("research", "done",
                 f"{len(sources)} live source(s) found." if sources else "No live reports found.",
                 sources=[s.model_dump() for s in sources], queries=queries)

    # --- 6. Verdict --------------------------------------------------------
    # This is where the model proposes and the verifier disposes. Every tell the
    # model returns is checked against real evidence; the ones that don't hold up
    # are recorded (not just discarded) so the UI can show its working.
    yield _event("verdict", "started", "Weighing the evidence…")
    rejected_claims: list[RejectedClaim] = []
    if settings.has_llm:
        try:
            raw_verdict = await llm.structured(
                Verdict, verdict_system(),
                verdict_user(text, context, entities, signals, sources,
                             match.name, arch.how_it_works if arch else "Unknown pattern.", floor),
            )
            kept, rejected_claims = verify_tells(raw_verdict.tells, signals, sources, text)
            if rejected_claims:
                coverage.append(
                    f"Verifier rejected {len(rejected_claims)} model claim(s) the evidence "
                    "couldn't support."
                )
            verdict = reconcile_verdict(raw_verdict, kept, floor)
            evidence_audit = EvidenceAudit(
                proposed=len(raw_verdict.tells), kept=len(kept),
                rejected=len(rejected_claims),
            )
        except LLMError as e:
            verdict, kept = _heuristic_verdict(signals, floor)
            evidence_audit = EvidenceAudit(proposed=len(kept), kept=len(kept), rejected=0)
            coverage.append(f"Verdict from signals only (model error: {e}).")
    else:
        verdict, kept = _heuristic_verdict(signals, floor)
        evidence_audit = EvidenceAudit(proposed=len(kept), kept=len(kept), rejected=0)
    yield _event("verdict", "done", verdict.headline,
                 verdict=verdict.model_dump(),
                 evidence_audit=evidence_audit.model_dump(),
                 rejected_claims=[rc.model_dump() for rc in rejected_claims])

    # --- 7. Action plan ----------------------------------------------------
    yield _event("action", "started", "Writing your next steps…")
    if settings.has_llm:
        try:
            draft = await llm.structured(
                ActionDraft, action_system(),
                action_user(text, context, verdict.risk_level.value, match.name),
            )
        except LLMError as e:
            draft = _heuristic_action(match.name)
            coverage.append(f"Action steps are generic (model error: {e}).")
    else:
        draft = _heuristic_action(match.name)

    report_to = [ReportingChannel(**c) for c in reporting_channels(region)]
    action_plan = ActionPlan(
        do_now=draft.do_now, do_not=draft.do_not,
        how_to_verify=draft.how_to_verify, report_to=report_to,
        safe_reply=draft.safe_reply,
    )
    yield _event("action", "done", "Done.")

    # --- 8. Assemble -------------------------------------------------------
    result = AnalysisResult(
        input_kind=input_kind, extracted_text=text, context=context,
        entities=entities, signals=signals, sources=sources, archetype=match,
        archetype_how=arch.how_it_works if arch else "",
        archetype_refs=arch.refs if arch else [],
        verdict=verdict,
        evidence_audit=evidence_audit,
        rejected_claims=rejected_claims,
        action_plan=action_plan,
        coverage_notes=coverage, disclaimer=DISCLAIMER,
    )
    yield result
