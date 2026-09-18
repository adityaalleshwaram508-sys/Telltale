"""FastAPI surface for Telltale.

Endpoints:
  GET  /api/health              — config + which capabilities are live
  GET  /api/samples             — built-in example messages
  GET  /api/samples/{id}        — one example's text
  POST /api/analyze             — full analysis, single JSON response (text/url only)
  POST /api/analyze/stream      — same, but streamed step-by-step over SSE (supports screenshots)

The frontend is served as static files from /.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.pipeline import analyze
from backend.samples import DEMO_IDS, get_sample
from backend.schemas import AnalysisResult, AnalyzeRequest, StepEvent

app = FastAPI(title="Telltale", version="0.1.0")

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
            "reasoning_model": settings.reasoning_model if settings.has_llm else None,
            "vision_model": settings.vision_model if settings.has_llm else None,
            "live_research": settings.has_tavily,
        },
        "note": None if settings.has_llm else
        "NEBIUS_API_KEY not set — running in deterministic (detectors-only) mode.",
    }


@app.get("/api/samples")
def list_samples():
    samples = [get_sample(i) for i in DEMO_IDS]
    return [
        {"id": s.id, "label": s.label, "kind": s.kind,
         "region_hint": s.region_hint, "preview": s.text[:120] + "…"}
        for s in samples if s
    ]


@app.get("/api/samples/{sample_id}")
def read_sample(sample_id: str):
    s = get_sample(sample_id)
    if not s:
        return {"error": "not found"}
    return {"id": s.id, "label": s.label, "kind": s.kind,
            "region_hint": s.region_hint, "text": s.text}


async def _images_to_data_urls(files: list[UploadFile]) -> list[str]:
    out = []
    for f in files or []:
        raw = await f.read()
        if not raw:
            continue
        mime = f.content_type or "image/png"
        out.append(f"data:{mime};base64,{base64.b64encode(raw).decode()}")
    return out


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@app.post("/api/analyze/stream")
async def analyze_stream(
    text: str | None = Form(default=None),
    url: str | None = Form(default=None),
    region_hint: str | None = Form(default=None),
    images: list[UploadFile] = File(default=[]),
):
    data_urls = await _images_to_data_urls(images)
    input_kind = "image" if data_urls else ("url" if url else "text")

    async def gen():
        try:
            async for item in analyze(
                text=text, url=url, images=data_urls or None,
                region_hint=region_hint, input_kind=input_kind,
            ):
                if isinstance(item, StepEvent):
                    yield _sse({"type": "step", **item.model_dump()})
                elif isinstance(item, AnalysisResult):
                    yield _sse({"type": "result", "result": item.model_dump()})
        except Exception as e:  # last-resort guard so the stream always closes cleanly
            yield _sse({"type": "step", "step": "error", "status": "error",
                        "message": f"Analysis failed: {e}", "data": None})

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_once(req: AnalyzeRequest):
    """Non-streaming variant for scripts, tests, and the eval harness."""
    result: AnalysisResult | None = None
    async for item in analyze(
        text=req.text, url=req.url, region_hint=req.region_hint,
        input_kind="url" if req.url else "text",
    ):
        if isinstance(item, AnalysisResult):
            result = item
    return result


# Serve the frontend. Mounted last so it never shadows the API routes above.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
