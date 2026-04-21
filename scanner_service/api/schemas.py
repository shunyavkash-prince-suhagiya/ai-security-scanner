"""Pydantic request/response models."""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScanResponse(BaseModel):
    id: str
    status: str
    target_name: str
    created_at: datetime


class FindingResponse(BaseModel):
    finding_type: str
    risk_level: str
    risk_score: int
    file_path: str
    line_number: int
    detector: str
    value_preview: str


class ScanDetailResponse(ScanResponse):
    report_path: Optional[str] = None
    findings: List[FindingResponse] = []


class ReportSummary(BaseModel):
    scan_id: str
    target_name: str
    status: str
    created_at: datetime
