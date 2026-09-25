"""The analysis pipeline: detectors, Nemotron steps, live research, verification.

Every model step has a deterministic fallback, so a model or network failure narrows an
answer instead of breaking it. Fallbacks are listed in coverage_notes and the run trace,
and a run that fell back is never cached.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

from backend.config import Settings, get_settings
from backend.detectors import run_detectors, signal_score
from backend.knowledge import archetype, archetypes, reporting_channels
from backend.llm import LLMError, get_llm
from backend.prompts import (
    action_system,
    action_user,
    classify_system,
    classify_user,
    context_system,
    context_user,
    verdict_system,
    verdict_user,
    vision_system,
    vision_user,
)
from backend.schemas import (
    ActionDraft,
    ActionPlan,
    AnalysisResult,
    ArchetypeMatch,
    Entities,
    EvidenceAudit,
    MessageContext,
    RejectedClaim,
    ReportingChannel,
    RiskLevel,
    Signal,
    Source,
    StepEvent,
    Tell,
    TraceEntry,
    Transcription,
    Verdict,
)
from backend.tavily import gather_evidence
from backend.verify import reconcile_verdict, verify_archetype, verify_tells

DISCLAIMER = (
    "Telltale gives you evidence and a considered opinion, not a guarantee. Scammers adapt, "
    "and legitimate messages can look odd. When money or personal data is at stake, verify "
    "through an official channel you find yourself."
)


@dataclass(frozen=True)
class Stage:
    model: str
    thinking: str | None
    max_tokens: int


def stages(s: Settings) -> dict[str, Stage]:
    """Which model runs each step and whether Nemotron reasons first.

    Nano reads the message; Super classifies, judges and writes the plan. Reasoning goes to
    the verdict, where weighing evidence benefits from it. The other steps are extraction
    and writing, where a reasoning trace costs latency and tokens without changing the output.
    """

    def budget(base: int, thinking: str) -> int:
        return base if thinking == "off" else base + 4000

    return {
        "vision": Stage(s.vision_model, None, 1500),
        "context": Stage(s.fast_model, s.thinking_context, budget(700, s.thinking_context)),
        "classify": Stage(s.reasoning_model, s.thinking_classify, budget(900, s.thinking_classify)),
        "verdict": Stage(s.reasoning_model, s.thinking_verdict, budget(2000, s.thinking_verdict)),
        "action": Stage(s.reasoning_model, s.thinking_action, budget(1500, s.thinking_action)),
        "second_opinion": Stage(
            s.escalation_model, s.thinking_escalation, budget(2000, s.thinking_escalation)
        ),
    }


def _event(step: str, status: str, message: str, **data) -> StepEvent:
    return StepEvent(step=step, status=status, message=message, data=data or None)


def _infer_region(entities: Entities, text: str, hint: str | None) -> str | None:
    if hint:
        return hint.upper()
    if entities.upi_ids or re.search(r"₹|\b(?:rs\.?|inr)\b|\blakh|\bcrore", text, re.I):
        return "IN"
    return None


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
        language="unknown",
        channel=channel,
        claimed_sender=sender,
        summary=text.strip()[:160],
        asked_to=[],
    )


def _heuristic_archetype(text: str, signals: list[Signal]) -> ArchetypeMatch:
    lower = text.lower()
    best_id, best_score = "none", 0
    upi_collect = any(s.id == "payment.upi_collect" for s in signals)
    for candidate in archetypes().values():
        score = sum(1 for keyword in candidate.aliases if keyword in lower)
        if upi_collect and candidate.id in ("marketplace", "otp_upi"):
            score += 1
        if score > best_score:
            best_id, best_score = candidate.id, score
    matched = archetype(best_id) if best_id != "none" else None
    return ArchetypeMatch(
        archetype_id=best_id,
        name=matched.name if matched else "Unclassified",
        confidence=min(0.4 + 0.15 * best_score, 0.9) if matched else 0.0,
        rationale="Matched by keyword overlap (model unavailable).",
        matched_tells=[],
    )


def _heuristic_verdict(signals: list[Signal], floor: int) -> tuple[Verdict, list[Tell]]:
    tells = [
        Tell(title=s.label, explanation=s.detail, evidence_type="signal", evidence_ref=s.id)
        for s in sorted(signals, key=lambda s: -s.severity)[:6]
    ]
    verdict = Verdict(
        risk_level=RiskLevel.info,
        score=floor,
        headline="Assessed from automated signals only (model unavailable).",
        tells=tells,
        reasoning="The reasoning model was unavailable, so this verdict reflects the detectors alone.",
    )
    return reconcile_verdict(verdict, tells, floor), tells


def _not_proven(entities: Entities) -> list[str]:
    """What the evidence can't establish, shown next to the verdict."""
    items = ["Whether this was really sent by the party it claims to be from."]
    if entities.domains or entities.urls:
        items.append("Who actually owns the linked domain, or whether it's the official site.")
    if entities.phones:
        items.append("Whether the phone number truly belongs to the claimed sender.")
    if entities.upi_ids or entities.crypto_addresses:
        items.append("Who really controls the account the money would end up in.")
    return items[:4]


def _heuristic_action() -> ActionDraft:
    return ActionDraft(
        do_now=[],
        do_not=[
            "Don't click links, share codes, or pay anyone until you've verified independently."
        ],
        how_to_verify=[
            "Contact the organisation through its official app or website, never a number or "
            "link from the message itself."
        ],
        safe_reply="",
    )


def _judge(
    raw: Verdict,
    signals: list[Signal],
    sources: list[Source],
    text: str,
    entities: Entities,
    floor: int,
) -> tuple[Verdict, list[RejectedClaim], EvidenceAudit]:
    kept, rejected = verify_tells(raw.tells, signals, sources, text, entities)
    audit = EvidenceAudit(proposed=len(raw.tells), kept=len(kept), rejected=len(rejected))
    return reconcile_verdict(raw, kept, floor), rejected, audit


def second_opinion_reason(verdict: Verdict, rejected: list[RejectedClaim]) -> str | None:
    """Why a verdict is worth a second, larger model, or None if it isn't."""
    if len(rejected) >= 2:
        return "the first pass proposed claims the evidence couldn't back"
    if 35 <= verdict.score < 60:
        return "the evidence pointed both ways (medium risk)"
    return None


async def analyze(
    *,
    text: str | None = None,
    url: str | None = None,
    images: list[str] | None = None,
    region_hint: str | None = None,
    input_kind: str = "text",
    allow_model: bool = True,
) -> AsyncIterator[StepEvent | AnalysisResult]:
    settings = get_settings()
    llm = get_llm()
    plan = stages(settings)
    model_on = settings.has_llm and allow_model
    coverage: list[str] = []
    trace: list[TraceEntry] = []
    degraded = settings.has_llm and not allow_model
    started = time.perf_counter()

    async def ask(schema, system: str, user: str, stage: str, images: list[str] | None = None):
        cfg = plan[stage]
        return await llm.structured(
            schema,
            system,
            user,
            stage=stage,
            model=cfg.model,
            images=images,
            thinking=cfg.thinking,
            max_tokens=cfg.max_tokens,
            trace=trace,
        )

    if settings.has_llm and not allow_model:
        coverage.append(
            "The public demo's model budget for today is used up, so this ran on the detectors "
            "and knowledge base only."
        )

    # Ingest ------------------------------------------------------------------------------
    yield _event("ingest", "started", "Reading what you gave me…")
    if images:
        if model_on:
            try:
                transcription = await ask(
                    Transcription, vision_system(), vision_user(), "vision", images
                )
                text = (transcription.text or "").strip()
                yield _event("ingest", "done", "Read the text out of your screenshot.")
            except LLMError as exc:
                degraded = True
                coverage.append(f"Couldn't read the image with the vision model ({exc}).")
                text = text or ""
                yield _event(
                    "ingest",
                    "error",
                    "Couldn't read the screenshot; continuing with any text you added.",
                )
        else:
            coverage.append(
                "Screenshot reading needs the model, which isn't available for this run."
            )
            text = text or ""
            yield _event("ingest", "skipped", "Model unavailable, so the screenshot can't be read.")
    elif url:
        text = url.strip()  # the link is analysed as text; it is never fetched or rendered
        yield _event("ingest", "done", "Analysing the link (not opening it).")
    else:
        text = (text or "").strip()
        yield _event("ingest", "done", "Got it.")

    if not text:
        yield _event("ingest", "error", "There was nothing to analyse.")
        return

    # Detectors ---------------------------------------------------------------------------
    yield _event("detect", "started", "Scanning for red flags…")
    entities, signals = run_detectors(text)
    floor = signal_score(signals)
    region = _infer_region(entities, text, region_hint)
    yield _event(
        "detect",
        "done",
        f"Found {len(signals)} concrete signal(s).",
        signals=len(signals),
        entities=entities.model_dump(),
    )

    # Context -----------------------------------------------------------------------------
    yield _event("context", "started", "Working out what it claims to be…")
    if model_on:
        try:
            context = await ask(MessageContext, context_system(), context_user(text), "context")
            yield _event(
                "context",
                "done",
                f"Looks like a {context.channel} from {context.claimed_sender}.",
                context=context.model_dump(),
            )
        except LLMError as exc:
            degraded = True
            context = _heuristic_context(text, entities)
            coverage.append(f"Context read heuristically (model error: {exc}).")
            yield _event("context", "error", "Model unavailable; read context heuristically.")
    else:
        context = _heuristic_context(text, entities)
        if not settings.has_llm:
            coverage.append("Running without a model key: deterministic mode only.")
        yield _event("context", "skipped", "Model unavailable; using heuristics.")

    # Archetype ---------------------------------------------------------------------------
    yield _event("classify", "started", "Matching it to known scam patterns…")
    if model_on:
        try:
            match = verify_archetype(
                await ask(
                    ArchetypeMatch, classify_system(), classify_user(text, context), "classify"
                )
            )
        except LLMError as exc:
            degraded = True
            match = _heuristic_archetype(text, signals)
            coverage.append(f"Archetype matched heuristically (model error: {exc}).")
    else:
        match = _heuristic_archetype(text, signals)
    arch = archetype(match.archetype_id)
    yield _event(
        "classify",
        "done",
        f"Closest pattern: {match.name}."
        if match.archetype_id != "none"
        else "No single known pattern dominates.",
        archetype=match.model_dump(),
    )

    # Live research -----------------------------------------------------------------------
    yield _event("research", "started", "Checking links and numbers against live reports…")
    research = await gather_evidence(entities, context.claimed_sender, region)
    sources = research.sources
    coverage.extend(research.notes)
    trace.extend(research.trace)
    degraded = degraded or research.failed
    yield _event(
        "research",
        "done",
        f"{len(sources)} live source(s) found." if sources else "No live reports found.",
        sources=[s.model_dump() for s in sources],
        queries=research.queries,
    )

    # Verdict -----------------------------------------------------------------------------
    yield _event("verdict", "started", "Weighing the evidence…")
    rejected_claims: list[RejectedClaim] = []
    if model_on:
        prompt = verdict_user(
            text,
            context,
            entities,
            signals,
            sources,
            match.name,
            arch.how_it_works if arch else "Unknown pattern.",
            floor,
        )
        try:
            raw = await ask(Verdict, verdict_system(), prompt, "verdict")
            verdict, rejected_claims, audit = _judge(raw, signals, sources, text, entities, floor)
            reason = settings.escalation_model and second_opinion_reason(verdict, rejected_claims)
            if reason:
                yield _event("verdict", "started", "Asking a larger model for a second opinion…")
                try:
                    raw = await ask(Verdict, verdict_system(), prompt, "second_opinion")
                    verdict, rejected_claims, audit = _judge(
                        raw, signals, sources, text, entities, floor
                    )
                    coverage.append(
                        f"Second opinion from {settings.escalation_model} because {reason}."
                    )
                except LLMError:
                    coverage.append(
                        "A second opinion was requested but unavailable; the first verdict stands."
                    )
            if rejected_claims:
                coverage.append(
                    f"The verifier rejected {len(rejected_claims)} model claim(s) the evidence couldn't support."
                )
        except LLMError as exc:
            degraded = True
            verdict, kept = _heuristic_verdict(signals, floor)
            audit = EvidenceAudit(proposed=len(kept), kept=len(kept), rejected=0)
            coverage.append(f"Verdict from signals only (model error: {exc}).")
    else:
        verdict, kept = _heuristic_verdict(signals, floor)
        audit = EvidenceAudit(proposed=len(kept), kept=len(kept), rejected=0)
    yield _event(
        "verdict",
        "done",
        verdict.headline,
        verdict=verdict.model_dump(),
        evidence_audit=audit.model_dump(),
        rejected_claims=[c.model_dump() for c in rejected_claims],
    )

    # Action plan -------------------------------------------------------------------------
    yield _event("action", "started", "Writing your next steps…")
    if model_on:
        try:
            draft = await ask(
                ActionDraft,
                action_system(),
                action_user(text, context, verdict.risk_level.value, match.name),
                "action",
            )
        except LLMError as exc:
            degraded = True
            draft = _heuristic_action()
            coverage.append(f"Action steps are generic (model error: {exc}).")
    else:
        draft = _heuristic_action()
    action_plan = ActionPlan(
        do_now=draft.do_now,
        do_not=draft.do_not,
        how_to_verify=draft.how_to_verify,
        report_to=[ReportingChannel(**c) for c in reporting_channels(region)],
        safe_reply=draft.safe_reply,
    )
    yield _event("action", "done", "Done.")

    yield AnalysisResult(
        input_kind=input_kind,
        extracted_text=text,
        context=context,
        entities=entities,
        signals=signals,
        sources=sources,
        archetype=match,
        archetype_how=arch.how_it_works if arch else "",
        archetype_refs=arch.refs if arch else [],
        verdict=verdict,
        evidence_audit=audit,
        rejected_claims=rejected_claims,
        not_proven=_not_proven(entities),
        action_plan=action_plan,
        coverage_notes=coverage,
        run_trace=trace,
        degraded=degraded,
        duration_ms=int((time.perf_counter() - started) * 1000),
        disclaimer=DISCLAIMER,
    )


# Repeat checks of the same text or link are served from memory for a while, which keeps
# answers consistent between runs and saves credits. Screenshots, and runs where a model or
# search step fell back, are never cached, so a transient outage isn't replayed.
_CACHE: OrderedDict[str, tuple[float, list[StepEvent | AnalysisResult]]] = OrderedDict()
_CACHE_MAX = 256


def _cache_key(text: str | None, url: str | None, region_hint: str | None, input_kind: str) -> str:
    value = "\x1f".join((input_kind, region_hint or "", url or "", (text or "").strip()))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def clear_cache() -> None:
    _CACHE.clear()


async def analyze_cached(
    *,
    text: str | None = None,
    url: str | None = None,
    images: list[str] | None = None,
    region_hint: str | None = None,
    input_kind: str = "text",
    take_model_budget: Callable[[], bool] = lambda: True,
) -> AsyncIterator[StepEvent | AnalysisResult]:
    """analyze() with the cache in front. The model budget is only drawn on a cache miss."""
    kwargs = dict(text=text, url=url, region_hint=region_hint, input_kind=input_kind)
    if images:
        async for item in analyze(images=images, allow_model=take_model_budget(), **kwargs):
            yield item
        return

    key = _cache_key(text, url, region_hint, input_kind)
    now = time.monotonic()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < get_settings().cache_ttl_s:
        _CACHE.move_to_end(key)
        for item in hit[1]:
            yield item
        return

    items: list[StepEvent | AnalysisResult] = []
    async for item in analyze(allow_model=take_model_budget(), **kwargs):
        items.append(item)
        yield item
    if items and isinstance(items[-1], AnalysisResult) and not items[-1].degraded:
        _CACHE[key] = (now, items)
        _CACHE.move_to_end(key)
        while len(_CACHE) > _CACHE_MAX:
            _CACHE.popitem(last=False)
