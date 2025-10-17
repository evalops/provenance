"""Detector metadata endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends

from app.core.config import settings
from app.dependencies import get_detection_service
from app.schemas.detectors import DetectorCapabilitiesResponse
from app.services.detection import DetectionService

router = APIRouter(prefix=f"{settings.api_v1_prefix}/detectors", tags=["detectors"])


@router.get("/capabilities", response_model=DetectorCapabilitiesResponse)
def list_detector_capabilities(
    detection_service: DetectionService = Depends(get_detection_service),
) -> DetectorCapabilitiesResponse:
    capabilities = detection_service.list_capabilities()
    return DetectorCapabilitiesResponse(capabilities=capabilities, request_id=f"rq_{uuid.uuid4().hex}")
