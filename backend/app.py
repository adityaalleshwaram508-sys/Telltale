"""FastAPI application: the analysis API and the static frontend."""

from __future__ import annotations

import base64
import json
import logging
import re
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.limits import DailyBudget, RateLimiter
from backend.pipeline import analyze_cached
from backend.samples import DEMO_ADVERSARIAL_IDS, DEMO_IDS, get_sample
from backend.schemas import AnalysisResult, AnalyzeRequest, StepEvent

logger = logging.getLogger("telltale")
settings = get_settings()

app = FastAPI(title="Telltale", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list or ["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp"}
RATE = RateLimiter(settings.rate_limit_per_ip, settings.rate_limit_window_s)
BUDGET = DailyBudget(settings.daily_model_budget)

_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


def _client_key(request: Request) -> str:
    # Render and most hosts put the caller first in X-Forwarded-For. The header can be
    # spoofed, which is acceptable for a cost guard but not for authentication.
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")


def _reject(status: int, message: str, **headers) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


def _check_rate(request: Request) -> JSONResponse | None:
    key = _client_key(request)
    if RATE.allow(key):
        return None
    wait = RATE.retry_after(key)
    return _reject(
        429,
        f"Too many checks from this connection. Try again in {wait} seconds.",
        **{"Retry-After": str(wait)},
    )


def _check_text(text: str | None) -> JSONResponse | None:
    if text and len(text) > settings.max_input_chars:
        return _reject(413, f"Messages up to {settings.max_input_chars} characters can be checked.")
    return None


def _region(hint: str | None) -> str | None:
    return hint.upper() if hint and re.fullmatch(r"[A-Za-z]{2}", hint) else None


async def _read_images(files: list[UploadFile]) -> list[str] | JSONResponse:
    files = [f for f in files or [] if f.filename]
    if len(files) > settings.max_images:
        return _reject(413, f"Up to {settings.max_images} screenshots per check.")
    data_urls = []
    for f in files:
        if f.content_type not in IMAGE_TYPES:
            return _reject(415, "Screenshots must be PNG, JPEG or WebP images.")
        raw = await f.read(settings.max_image_bytes + 1)
        if len(raw) > settings.max_image_bytes:
            return _reject(
                413, f"Each screenshot must be under {settings.max_image_bytes // 1_000_000} MB."
            )
        if raw:
            data_urls.append(f"data:{f.content_type};base64,{base64.b64encode(raw).decode()}")
    return data_urls


def _sample_card(sample) -> dict:
    return {
        "id": sample.id,
        "label": sample.label,
        "kind": sample.kind,
        "region_hint": sample.region_hint,
        "preview": sample.text[:120] + "…",
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": app.version,
        "capabilities": {
            "reasoning_model": settings.reasoning_model if settings.has_llm else None,
            "fast_model": settings.fast_model if settings.has_llm else None,
            "vision_model": settings.vision_model if settings.has_llm else None,
            "second_opinion_model": settings.escalation_model or None,
            "live_research": settings.has_tavily,
        },
        "note": None
        if settings.has_llm
        else "NEBIUS_API_KEY not set: deterministic (detectors-only) mode.",
    }


@app.get("/api/samples")
def list_samples():
    return [_sample_card(s) for s in map(get_sample, DEMO_IDS) if s]


@app.get("/api/adversarial")
def list_adversarial():
    return [_sample_card(s) for s in map(get_sample, DEMO_ADVERSARIAL_IDS) if s]


@app.get("/api/samples/{sample_id}")
def read_sample(sample_id: str):
    sample = get_sample(sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="No sample with that id.")
    return {**_sample_card(sample), "text": sample.text}


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@app.post("/api/analyze/stream")
async def analyze_stream(
    request: Request,
    text: str | None = Form(default=None),
    url: str | None = Form(default=None),
    region_hint: str | None = Form(default=None),
    images: list[UploadFile] = File(default=[]),
):
    if (problem := _check_text(text) or _check_text(url) or _check_rate(request)) is not None:
        return problem
    data_urls = await _read_images(images)
    if isinstance(data_urls, JSONResponse):
        return data_urls
    input_kind = "image" if data_urls else "url" if url else "text"

    async def gen():
        try:
            async for item in analyze_cached(
                text=text,
                url=url,
                images=data_urls or None,
                region_hint=_region(region_hint),
                input_kind=input_kind,
                take_model_budget=BUDGET.take,
            ):
                if isinstance(item, StepEvent):
                    yield _sse({"type": "step", **item.model_dump()})
                elif isinstance(item, AnalysisResult):
                    yield _sse({"type": "result", "result": item.model_dump()})
        except Exception:
            run_id = uuid.uuid4().hex[:8]
            logger.exception("analysis failed (run_id=%s)", run_id)
            yield _sse(
                {
                    "type": "step",
                    "step": "error",
                    "status": "error",
                    "message": f"Analysis failed. Please retry. Reference: {run_id}",
                    "data": None,
                }
            )

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_once(req: AnalyzeRequest, request: Request):
    """Run an analysis and return only the final result."""
    if not (req.text or req.url):
        raise HTTPException(status_code=422, detail="Provide text or url.")
    if (
        problem := _check_text(req.text) or _check_text(req.url) or _check_rate(request)
    ) is not None:
        return problem
    result = None
    async for item in analyze_cached(
        text=req.text,
        url=req.url,
        region_hint=_region(req.region_hint),
        input_kind="url" if req.url else "text",
        take_model_budget=BUDGET.take,
    ):
        if isinstance(item, AnalysisResult):
            result = item
    if result is None:
        raise HTTPException(status_code=422, detail="There was nothing to analyse.")
    return result


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
