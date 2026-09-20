"""FastAPI application and API routes."""

from __future__ import annotations

import base64
import json
import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.pipeline import analyze, analyze_cached
from backend.samples import DEMO_ADVERSARIAL_IDS, DEMO_IDS, get_sample
from backend.schemas import AnalysisResult, AnalyzeRequest, StepEvent


logger = logging.getLogger("telltale")

app = FastAPI(
    title="Telltale",
    version="0.1.0",
)

settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "capabilities": {
            "reasoning_model": (
                settings.reasoning_model
                if settings.has_llm
                else None
            ),
            "vision_model": (
                settings.vision_model
                if settings.has_llm
                else None
            ),
            "live_research": settings.has_tavily,
        },
        "note": (
            None
            if settings.has_llm
            else (
                "NEBIUS_API_KEY not set — running in "
                "deterministic (detectors-only) mode."
            )
        ),
    }


@app.get("/api/samples")
def list_samples():
    samples = [
        get_sample(sample_id)
        for sample_id in DEMO_IDS
    ]

    return [
        {
            "id": sample.id,
            "label": sample.label,
            "kind": sample.kind,
            "region_hint": sample.region_hint,
            "preview": sample.text[:120] + "…",
        }
        for sample in samples
        if sample
    ]


@app.get("/api/adversarial")
def list_adversarial():
    """Return adversarial examples used by the evaluation set."""

    samples = [
        get_sample(sample_id)
        for sample_id in DEMO_ADVERSARIAL_IDS
    ]

    return [
        {
            "id": sample.id,
            "label": sample.label,
            "kind": sample.kind,
            "region_hint": sample.region_hint,
            "preview": sample.text[:120] + "…",
        }
        for sample in samples
        if sample
    ]


@app.get("/api/samples/{sample_id}")
def read_sample(sample_id: str):
    sample = get_sample(sample_id)

    if not sample:
        return {"error": "not found"}

    return {
        "id": sample.id,
        "label": sample.label,
        "kind": sample.kind,
        "region_hint": sample.region_hint,
        "text": sample.text,
    }


async def _images_to_data_urls(
    files: list[UploadFile],
) -> list[str]:
    data_urls: list[str] = []

    for file in files or []:
        raw = await file.read()

        if not raw:
            continue

        mime = file.content_type or "image/png"

        data_urls.append(
            f"data:{mime};base64,"
            f"{base64.b64encode(raw).decode()}"
        )

    return data_urls


def _sse(payload: dict) -> str:
    return (
        f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
    )


@app.post("/api/analyze/stream")
async def analyze_stream(
    text: str | None = Form(default=None),
    url: str | None = Form(default=None),
    region_hint: str | None = Form(default=None),
    images: list[UploadFile] = File(default=[]),
):
    data_urls = await _images_to_data_urls(images)

    input_kind = (
        "image"
        if data_urls
        else "url"
        if url
        else "text"
    )

    async def gen():
        try:
            async for item in analyze_cached(
                text=text,
                url=url,
                images=data_urls or None,
                region_hint=region_hint,
                input_kind=input_kind,
            ):
                if isinstance(item, StepEvent):
                    yield _sse(
                        {
                            "type": "step",
                            **item.model_dump(),
                        }
                    )

                elif isinstance(item, AnalysisResult):
                    yield _sse(
                        {
                            "type": "result",
                            "result": item.model_dump(),
                        }
                    )

        except Exception:
            run_id = uuid.uuid4().hex[:8]

            logger.exception(
                "analysis failed (run_id=%s)",
                run_id,
            )

            yield _sse(
                {
                    "type": "step",
                    "step": "error",
                    "status": "error",
                    "message": (
                        "Analysis failed. Please retry. "
                        f"Reference: {run_id}"
                    ),
                    "data": None,
                }
            )

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post(
    "/api/analyze",
    response_model=AnalysisResult,
)
async def analyze_once(req: AnalyzeRequest):
    """Run analysis without streaming."""

    result: AnalysisResult | None = None

    async for item in analyze(
        text=req.text,
        url=req.url,
        region_hint=req.region_hint,
        input_kind="url" if req.url else "text",
    ):
        if isinstance(item, AnalysisResult):
            result = item

    return result


if FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(
            directory=str(FRONTEND_DIR),
            html=True,
        ),
        name="frontend",
    )
