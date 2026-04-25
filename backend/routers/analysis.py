"""POST /analyze and GET /sessions endpoints."""

from __future__ import annotations

import asyncio
import logging
import math
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Header,
    HTTPException,
    Request,
    UploadFile,
)

from backend.middleware.auth import verify_token
from backend.models.enums import ClassLabel
from backend.models.schemas import (
    AnalysisSummary,
    AnalyzeResponse,
    FlowResult,
    TopSourceIp,
)
from backend.services.feature_service import MODEL_FEATURES, FeatureService
from backend.services.ml_service import MLService
from backend.services.supabase_client import make_user_client
from backend.utils.pcap_validator import validate_pcap

logger = logging.getLogger(__name__)

router = APIRouter()

UPLOAD_CHUNK_BYTES = 1024 * 1024  # 1 MiB streaming chunks
INFERENCE_BATCH = 64  # flows per inference + DB insert batch


def _bearer_from_header(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return authorization.split(None, 1)[1].strip()


async def _stream_upload_to_temp(file: UploadFile) -> Path:
    """Persist the upload to a temp file without loading it fully into memory."""
    tmp = tempfile.NamedTemporaryFile(prefix="smhg_", suffix=".pcap", delete=False)
    tmp_path = Path(tmp.name)
    try:
        while True:
            chunk = await file.read(UPLOAD_CHUNK_BYTES)
            if not chunk:
                break
            tmp.write(chunk)
    finally:
        tmp.close()
    return tmp_path


def _normalize_features(df: pd.DataFrame) -> pd.DataFrame:
    """Lowercase/underscore columns and align to the 46 MODEL_FEATURES columns."""
    df = df.copy()
    df.columns = [c.lower().replace(" ", "_") for c in df.columns]
    for col in MODEL_FEATURES:
        if col not in df.columns:
            df[col] = 0
    df = df[MODEL_FEATURES].fillna(0)
    return df


def _build_streaming_flow_rows(
    batch: list[dict],
    predictions: list[dict],
    session_id: str,
    user_id: str,
) -> list[dict[str, Any]]:
    """Convert a batch of {features, identity} + predictions into flow_events insert payload."""
    rows: list[dict[str, Any]] = []
    for flow_dict, pred in zip(batch, predictions, strict=False):
        features = flow_dict["features"]
        identity = flow_dict["identity"]

        features_json = {
            k.lower().replace(" ", "_"): (v.item() if hasattr(v, "item") else v)
            for k, v in features.items()
        }

        rows.append({
            "id": str(uuid.uuid4()),
            "session_id": session_id,
            "user_id": user_id,
            "source_ip": identity.get("src_ip", "UNKNOWN"),
            "destination_ip": identity.get("dst_ip", "UNKNOWN"),
            "source_port": int(identity.get("src_port", 0) or 0),
            "destination_port": int(identity.get("dst_port", 0) or 0),
            "protocol_name": identity.get("protocol_name", "UNKNOWN"),
            "protocol_type": int(features_json.get("protocol_type", 0) or 0),
            "predicted_category": pred["predicted_category"].value,
            "confidence": pred["confidence"],
            "features_json": features_json,
        })
    return rows


async def _flush_batch(
    *,
    batch: list[dict],
    ml_service: MLService,
    supabase,
    session_id: str,
    user_id: str,
    totals: dict,
    protocol_counter: Counter,
    top_ip_counter: Counter,
) -> None:
    """Run inference on `batch`, insert flow_events, update running counters."""
    if not batch:
        return

    features_df = pd.DataFrame([f["features"] for f in batch])
    features_df = _normalize_features(features_df)
    predictions = ml_service.predict(features_df)

    flow_rows = _build_streaming_flow_rows(batch, predictions, session_id, user_id)

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None, lambda: supabase.table("flow_events").insert(flow_rows).execute()
    )

    for flow_dict, pred in zip(batch, predictions, strict=False):
        category = pred["predicted_category"]
        totals["total_flows"] += 1
        if category == ClassLabel.BENIGN:
            totals["benign"] += 1
        else:
            totals["threat_count"] += 1
            if category == ClassLabel.SPOOFING:
                totals["spoofing"] += 1
            elif category == ClassLabel.RECON:
                totals["recon"] += 1
            elif category == ClassLabel.BRUTE_FORCE:
                totals["brute_force"] += 1

        proto = flow_dict["identity"].get("protocol_name")
        if proto:
            protocol_counter[proto] += 1
        src_ip = flow_dict["identity"].get("src_ip")
        if src_ip and src_ip != "UNKNOWN":
            top_ip_counter[src_ip] += 1


async def _run_streaming_pipeline(
    *,
    ml_service: MLService,
    feature_service: FeatureService,
    tmp_path: Path,
    session_id: str,
    user_id: str,
    user_jwt: str,
) -> None:
    """Stream flows from the PCAP, infer in batches of INFERENCE_BATCH, write live."""
    supabase = make_user_client(user_jwt)

    buffer: list[dict] = []
    totals = {
        "total_flows": 0, "threat_count": 0,
        "benign": 0, "spoofing": 0, "recon": 0, "brute_force": 0,
    }
    protocol_counter: Counter[str] = Counter()
    top_ip_counter: Counter[str] = Counter()

    async def flush() -> None:
        nonlocal buffer
        await _flush_batch(
            batch=buffer, ml_service=ml_service, supabase=supabase,
            session_id=session_id, user_id=user_id, totals=totals,
            protocol_counter=protocol_counter, top_ip_counter=top_ip_counter,
        )
        buffer = []

    async for flow in feature_service.stream_flows(str(tmp_path)):
        buffer.append(flow)
        if len(buffer) >= INFERENCE_BATCH:
            await flush()

    # Flush any remaining flows in the buffer
    if buffer:
        await flush()

    summary = AnalysisSummary(
        total_flows=totals["total_flows"],
        benign_count=totals["benign"],
        spoofing_count=totals["spoofing"],
        recon_count=totals["recon"],
        brute_force_count=totals["brute_force"],
        protocol_counts=dict(protocol_counter),
        top_source_ips=[
            TopSourceIp(ip=ip, count=count)
            for ip, count in top_ip_counter.most_common(10)
        ],
    )

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: supabase.table("scan_sessions").update({
            "status": "completed",
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "total_flows": totals["total_flows"],
            "threat_count": totals["threat_count"],
            "summary_json": summary.model_dump(),
        }).eq("id", session_id).execute(),
    )


def _mark_session_error(user_jwt: str, session_id: str, detail: str) -> None:
    try:
        supabase = make_user_client(user_jwt)
        supabase.table("scan_sessions").update({
            "status": "error",
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "summary_json": {"error": detail},
        }).eq("id", session_id).execute()
    except Exception:
        logger.exception("Failed to mark session %s as error", session_id)


async def _background_pipeline(
    ml_service: MLService,
    feature_service: FeatureService,
    tmp_path: Path,
    session_id: str,
    user_id: str,
    user_jwt: str,
) -> None:
    try:
        await _run_streaming_pipeline(
            ml_service=ml_service,
            feature_service=feature_service,
            tmp_path=tmp_path,
            session_id=session_id,
            user_id=user_id,
            user_jwt=user_jwt,
        )
    except Exception as exc:
        logger.exception("Background analysis failed for session %s", session_id)
        _mark_session_error(user_jwt, session_id, str(exc))
    finally:
        tmp_path.unlink(missing_ok=True)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_pcap(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    claims: dict = Depends(verify_token),
) -> AnalyzeResponse:
    """Start a streaming PCAP analysis. Returns immediately with session_id.

    Flows and alerts arrive on the frontend via Supabase realtime as the
    background pipeline inserts them batch-by-batch.
    """
    t0 = time.time()
    user_id = claims["sub"]
    user_jwt = _bearer_from_header(authorization)

    ml_service: MLService = request.app.state.ml_service
    if not ml_service.is_loaded:
        raise HTTPException(status_code=503, detail="Model not ready")
    feature_service: FeatureService = request.app.state.feature_service

    tmp_path = await _stream_upload_to_temp(file)

    try:
        validate_pcap(tmp_path, file.filename or "upload.pcap")
    except HTTPException:
        tmp_path.unlink(missing_ok=True)
        raise

    file_size = tmp_path.stat().st_size
    supabase = make_user_client(user_jwt)
    session_insert = supabase.table("scan_sessions").insert({
        "user_id": user_id,
        "mode": "pcap",
        "status": "scanning",
        "pcap_file_name": file.filename,
        "pcap_file_size_bytes": file_size,
    }).execute()

    if not session_insert.data:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Failed to create scan session")

    session_id = session_insert.data[0]["id"]

    background_tasks.add_task(
        _background_pipeline,
        ml_service,
        feature_service,
        tmp_path,
        session_id,
        user_id,
        user_jwt,
    )

    return AnalyzeResponse(
        session_id=session_id,
        flows=[],
        summary=AnalysisSummary(
            total_flows=0, benign_count=0, spoofing_count=0,
            recon_count=0, brute_force_count=0,
            protocol_counts={}, top_source_ips=[],
        ),
        processing_time_ms=round((time.time() - t0) * 1000, 2),
    )


@router.get("/sessions")
async def list_sessions(
    page: int = 1,
    page_size: int = 20,
    authorization: str | None = Header(default=None),
    claims: dict = Depends(verify_token),
) -> dict[str, Any]:
    """Paginated list of the caller's scan sessions, newest first."""
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(status_code=400, detail="Invalid page or page_size")

    user_jwt = _bearer_from_header(authorization)
    supabase = make_user_client(user_jwt)
    offset = (page - 1) * page_size

    response = (
        supabase.table("scan_sessions")
        .select("*", count="exact")
        .order("created_at", desc=True)
        .range(offset, offset + page_size - 1)
        .execute()
    )

    total = response.count or 0
    total_pages = math.ceil(total / page_size) if total else 0

    return {
        "data": response.data,
        "meta": {
            "page": page,
            "per_page": page_size,
            "total": total,
            "total_pages": total_pages,
        },
    }


@router.get("/sessions/{session_id}/status")
async def session_status(
    session_id: str,
    authorization: str | None = Header(default=None),
    claims: dict = Depends(verify_token),
) -> dict[str, Any]:
    """Lightweight status for polling during BackgroundTasks processing."""
    user_jwt = _bearer_from_header(authorization)
    supabase = make_user_client(user_jwt)

    response = (
        supabase.table("scan_sessions")
        .select("id, status, total_flows, threat_count, started_at, ended_at, summary_json")
        .eq("id", session_id)
        .single()
        .execute()
    )

    if not response.data:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "session_id": response.data["id"],
        "status": response.data["status"],
        "total_flows": response.data["total_flows"],
        "threat_count": response.data["threat_count"],
        "started_at": response.data["started_at"],
        "ended_at": response.data["ended_at"],
        "summary_json": response.data.get("summary_json"),
    }
