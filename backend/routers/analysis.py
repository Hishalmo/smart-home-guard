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
from backend.models.enums import CATEGORY_SEVERITY, ClassLabel
from backend.models.schemas import (
    AnalysisSummary,
    AnalyzeResponse,
    FlowResult,
    TopSourceIp,
)
from backend.services.feature_service import FeatureService
from backend.services.ml_service import MLService
from backend.services.supabase_client import make_user_client
from backend.utils.pcap_validator import validate_pcap

logger = logging.getLogger(__name__)

router = APIRouter()

BACKGROUND_THRESHOLD_BYTES = 20 * 1024 * 1024  # 20 MB
UPLOAD_CHUNK_BYTES = 1024 * 1024  # 1 MiB streaming chunks
FLOW_INSERT_BATCH = 500


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


def _build_summary(
    flows: list[FlowResult], connectivity: pd.DataFrame
) -> AnalysisSummary:
    counts = Counter(f.predicted_category for f in flows)
    protocol_counts = Counter(f.protocol_name for f in flows if f.protocol_name)
    top_ips = Counter(
        ip for ip in connectivity["src_ip"].tolist() if ip and ip != "UNKNOWN"
    ).most_common(10)

    return AnalysisSummary(
        total_flows=len(flows),
        benign_count=counts.get(ClassLabel.BENIGN, 0),
        spoofing_count=counts.get(ClassLabel.SPOOFING, 0),
        recon_count=counts.get(ClassLabel.RECON, 0),
        brute_force_count=counts.get(ClassLabel.BRUTE_FORCE, 0),
        protocol_counts=dict(protocol_counts),
        top_source_ips=[TopSourceIp(ip=ip, count=count) for ip, count in top_ips],
    )


def _build_flow_rows(
    features_df: pd.DataFrame,
    identity_df: pd.DataFrame,
    predictions: list[dict],
) -> tuple[list[FlowResult], list[dict[str, Any]]]:
    """Return (pydantic FlowResult list, supabase insert payload list)."""
    flows: list[FlowResult] = []
    supabase_rows: list[dict[str, Any]] = []

    for i, pred in enumerate(predictions):
        feat_row = features_df.iloc[i]
        ident_row = identity_df.iloc[i]
        flow_id = str(uuid.uuid4())

        features_json = {
            col: (val.item() if hasattr(val, "item") else val)
            for col, val in feat_row.items()
        }

        flow = FlowResult(
            id=flow_id,
            source_ip=str(ident_row["src_ip"]),
            destination_ip=str(ident_row["dst_ip"]),
            source_port=int(ident_row["src_port"]),
            destination_port=int(ident_row["dst_port"]),
            protocol_name=str(ident_row["protocol_name"]),
            flow_duration=float(features_json.get("flow_duration", 0) or 0),
            rate=float(features_json.get("rate", 0) or 0),
            fin_flag_number=int(features_json.get("fin_flag_number", 0) or 0),
            syn_flag_number=int(features_json.get("syn_flag_number", 0) or 0),
            rst_flag_number=int(features_json.get("rst_flag_number", 0) or 0),
            psh_flag_number=int(features_json.get("psh_flag_number", 0) or 0),
            ack_flag_number=int(features_json.get("ack_flag_number", 0) or 0),
            urg_flag_number=int(features_json.get("urg_flag_number", 0) or 0),
            ece_flag_number=int(features_json.get("ece_flag_number", 0) or 0),
            cwr_flag_number=int(features_json.get("cwr_flag_number", 0) or 0),
            predicted_category=pred["predicted_category"],
            confidence=pred["confidence"],
            features=features_json,
        )
        flows.append(flow)

        supabase_rows.append({
            "id": flow_id,
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "protocol_name": flow.protocol_name,
            "protocol_type": int(features_json.get("protocol_type", 0) or 0),
            "predicted_category": flow.predicted_category.value,
            "confidence": flow.confidence,
            "features_json": features_json,
        })

    return flows, supabase_rows


def _build_alert_rows(
    flows: list[FlowResult], session_id: str, user_id: str
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for flow in flows:
        if flow.predicted_category == ClassLabel.BENIGN:
            continue
        severity = CATEGORY_SEVERITY[flow.predicted_category]
        message = (
            f"{flow.predicted_category.value} detected from "
            f"{flow.source_ip} → {flow.destination_ip} via {flow.protocol_name}"
        )
        alerts.append({
            "session_id": session_id,
            "user_id": user_id,
            "flow_id": flow.id,
            "severity": severity.value,
            "category": flow.predicted_category.value,
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "message": message,
        })
    return alerts


def _insert_flows_chunked(
    supabase, rows: list[dict[str, Any]], session_id: str, user_id: str
) -> None:
    for row in rows:
        row["session_id"] = session_id
        row["user_id"] = user_id
    for i in range(0, len(rows), FLOW_INSERT_BATCH):
        batch = rows[i : i + FLOW_INSERT_BATCH]
        supabase.table("flow_events").insert(batch).execute()


async def _run_pipeline(
    *,
    ml_service: MLService,
    feature_service: FeatureService,
    tmp_path: Path,
    session_id: str,
    user_id: str,
    user_jwt: str,
) -> tuple[list[FlowResult], AnalysisSummary]:
    """Feature extraction → inference → Supabase writes. Shared by sync + async paths."""
    features_df = await feature_service.extract_features(str(tmp_path))
    flow_count = len(features_df)
    identity_df = await feature_service.aggregate_connectivity_per_flow(
        str(tmp_path), flow_count=flow_count
    )
    connectivity_df = await feature_service.extract_connectivity_info(str(tmp_path))

    predictions = ml_service.predict(features_df)
    flows, flow_payload = _build_flow_rows(features_df, identity_df, predictions)
    alerts = _build_alert_rows(flows, session_id, user_id)
    summary = _build_summary(flows, connectivity_df)

    supabase = make_user_client(user_jwt)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None, _insert_flows_chunked, supabase, flow_payload, session_id, user_id
    )
    if alerts:
        await loop.run_in_executor(
            None, lambda: supabase.table("alerts").insert(alerts).execute()
        )

    supabase.table("scan_sessions").update({
        "status": "completed",
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "total_flows": len(flows),
        "threat_count": sum(
            1 for f in flows if f.predicted_category != ClassLabel.BENIGN
        ),
        "summary_json": summary.model_dump(),
    }).eq("id", session_id).execute()

    return flows, summary


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
        await _run_pipeline(
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
    """Analyze a PCAP file and persist flows + alerts for the caller."""
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

    if file_size > BACKGROUND_THRESHOLD_BYTES:
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
            processing_time_ms=0.0,
        )

    try:
        flows, summary = await _run_pipeline(
            ml_service=ml_service,
            feature_service=feature_service,
            tmp_path=tmp_path,
            session_id=session_id,
            user_id=user_id,
            user_jwt=user_jwt,
        )
    except HTTPException:
        _mark_session_error(user_jwt, session_id, "http error during analysis")
        raise
    except Exception as exc:
        logger.exception("Analysis pipeline failed for session %s", session_id)
        _mark_session_error(user_jwt, session_id, str(exc))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    return AnalyzeResponse(
        session_id=session_id,
        flows=flows,
        summary=summary,
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
        .select("id, status, total_flows, threat_count, started_at, ended_at")
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
    }
