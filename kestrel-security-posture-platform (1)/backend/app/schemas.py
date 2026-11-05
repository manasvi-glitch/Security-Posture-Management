from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict

from app.models import (
    Role, AssetType, Criticality, Severity, Category, Exploitability, FindingStatus
)


# ---------- Auth / Users ----------

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    role: Role = Role.viewer


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    username: str
    email: EmailStr
    role: Role
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------- Assets ----------

class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType = AssetType.server
    ip_address: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality: Criticality = Criticality.medium
    internet_facing: bool = False


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[AssetType] = None
    ip_address: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[Criticality] = None
    internet_facing: Optional[bool] = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    asset_type: AssetType
    ip_address: Optional[str]
    owner: Optional[str]
    environment: Optional[str]
    criticality: Criticality
    internet_facing: bool
    created_at: datetime
    open_finding_count: int = 0


# ---------- Findings ----------

class FindingCreate(BaseModel):
    asset_id: str
    title: str
    description: Optional[str] = None
    severity: Severity
    category: Category
    exploitability: Exploitability = Exploitability.theoretical
    cve_id: Optional[str] = None
    source: str = "manual"
    external_id: Optional[str] = None
    due_date: Optional[datetime] = None


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[Severity] = None
    category: Optional[Category] = None
    exploitability: Optional[Exploitability] = None
    due_date: Optional[datetime] = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    asset_id: str
    source: str
    external_id: Optional[str]
    cve_id: Optional[str]
    title: str
    description: Optional[str]
    severity: Severity
    category: Category
    exploitability: Exploitability
    risk_score: float
    status: FindingStatus
    assigned_to: Optional[str]
    due_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]


class FindingDetailOut(FindingOut):
    events: List["RemediationEventOut"] = []


# ---------- Remediation ----------

class StatusChangeRequest(BaseModel):
    to_status: FindingStatus
    note: Optional[str] = None


class AssignRequest(BaseModel):
    user_id: str
    note: Optional[str] = None


class NoteRequest(BaseModel):
    note: str


class EvidenceRequest(BaseModel):
    evidence_url: str
    note: Optional[str] = None


class RemediationEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    action: str
    from_status: Optional[str]
    to_status: Optional[str]
    note: Optional[str]
    evidence_url: Optional[str]
    actor_id: Optional[str]
    created_at: datetime


FindingDetailOut.model_rebuild()


# ---------- Dashboard / Reporting ----------

class CategoryScore(BaseModel):
    category: Category
    score: float


class PostureScore(BaseModel):
    overall: float
    rating: str
    categories: List[CategoryScore]
    trend_30d: float


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    total: int


class AssetCounts(BaseModel):
    total: int
    high_risk: int
    internet_facing: int
    needs_attention: int


class RemediationCounts(BaseModel):
    open: int
    in_progress: int
    resolved_30d: int
    avg_days_to_fix: Optional[float]


class PipelineCounts(BaseModel):
    detected: int
    triaged: int
    assigned: int
    fix_in_progress: int
    remediated: int
    verification: int
    resolved_30d: int


class PriorityItem(BaseModel):
    rank: int
    finding_id: str
    title: str
    severity: Severity
    risk_score: float
    asset_name: str
    asset_id: str


class TrendPoint(BaseModel):
    label: str
    score: float


class DashboardSummary(BaseModel):
    posture: PostureScore
    findings: SeverityCounts
    assets: AssetCounts
    remediation: RemediationCounts
    pipeline: PipelineCounts
    top_priorities: List[PriorityItem]
    trend: List[TrendPoint]


# ---------- Import ----------

class ImportResult(BaseModel):
    assets_created: int
    findings_created: int
    findings_skipped: int
    errors: List[str] = []
