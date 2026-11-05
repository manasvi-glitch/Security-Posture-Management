"""
ORM models.

Entities: User, Asset, Finding, RemediationEvent, AuditLog.

Design notes
------------
- Finding.status is a state machine driven through the remediation router
  (see app/routers/remediation.py) rather than a free-text field a client
  can set arbitrarily, so transitions are always recorded as
  RemediationEvent rows for the audit trail.
- risk_score and category are computed/assigned server-side by
  app/risk_engine.py at creation/update time -- clients never set them
  directly. This keeps the scoring logic centralized and explainable.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Float, Boolean, ForeignKey, DateTime, Text, Enum, Integer
)
from sqlalchemy.orm import relationship

from app.database import Base


def gen_id() -> str:
    return uuid.uuid4().hex[:12]


class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class AssetType(str, enum.Enum):
    server = "server"
    workstation = "workstation"
    network_device = "network_device"
    application = "application"
    cloud_resource = "cloud_resource"


class Criticality(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Category(str, enum.Enum):
    authentication = "authentication"
    network = "network"
    configuration = "configuration"
    patch_management = "patch_management"
    access_control = "access_control"
    application = "application"


class Exploitability(str, enum.Enum):
    theoretical = "theoretical"        # no known public exploit
    poc = "poc"                        # proof-of-concept exists
    active = "active"                  # known to be actively exploited


class FindingStatus(str, enum.Enum):
    detected = "detected"
    triaged = "triaged"
    assigned = "assigned"
    fix_in_progress = "fix_in_progress"
    remediated = "remediated"
    verification = "verification"
    resolved = "resolved"
    reopened = "reopened"


# Valid forward transitions for the remediation workflow state machine.
ALLOWED_TRANSITIONS = {
    FindingStatus.detected: {FindingStatus.triaged},
    FindingStatus.triaged: {FindingStatus.assigned},
    FindingStatus.assigned: {FindingStatus.fix_in_progress},
    FindingStatus.fix_in_progress: {FindingStatus.remediated},
    FindingStatus.remediated: {FindingStatus.verification},
    FindingStatus.verification: {FindingStatus.resolved, FindingStatus.reopened},
    FindingStatus.resolved: {FindingStatus.reopened},
    FindingStatus.reopened: {FindingStatus.triaged},
}


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_id)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.analyst)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    assigned_findings = relationship("Finding", back_populates="assignee")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, nullable=False, index=True)
    asset_type = Column(Enum(AssetType), nullable=False, default=AssetType.server)
    ip_address = Column(String, nullable=True)
    owner = Column(String, nullable=True)
    environment = Column(String, nullable=True)  # e.g. production, staging, dev
    criticality = Column(Enum(Criticality), nullable=False, default=Criticality.medium)
    internet_facing = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")

    @property
    def open_finding_count(self) -> int:
        return sum(1 for f in self.findings if f.status != FindingStatus.resolved)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=False)

    source = Column(String, nullable=False, default="manual")  # e.g. "manual", "nessus_csv", "kestrel_scan"
    external_id = Column(String, nullable=True)  # id/plugin id from the source scanner
    cve_id = Column(String, nullable=True)

    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)

    severity = Column(Enum(Severity), nullable=False)
    category = Column(Enum(Category), nullable=False)
    exploitability = Column(Enum(Exploitability), nullable=False, default=Exploitability.theoretical)

    risk_score = Column(Float, nullable=False, default=0.0)
    status = Column(Enum(FindingStatus), nullable=False, default=FindingStatus.detected)

    assigned_to = Column(String, ForeignKey("users.id"), nullable=True)
    due_date = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    asset = relationship("Asset", back_populates="findings")
    assignee = relationship("User", back_populates="assigned_findings")
    events = relationship("RemediationEvent", back_populates="finding",
                           cascade="all, delete-orphan", order_by="RemediationEvent.created_at")


class RemediationEvent(Base):
    """An immutable log entry for anything that happens to a finding."""
    __tablename__ = "remediation_events"
    id = Column(String, primary_key=True, default=gen_id)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    actor_id = Column(String, ForeignKey("users.id"), nullable=True)

    action = Column(String, nullable=False)  # status_change | note | evidence | assignment
    from_status = Column(String, nullable=True)
    to_status = Column(String, nullable=True)
    note = Column(Text, nullable=True)
    evidence_url = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="events")
    actor = relationship("User")


class AuditLog(Base):
    """System-wide audit trail, separate from remediation-specific events."""
    __tablename__ = "audit_log"
    id = Column(String, primary_key=True, default=gen_id)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    username = Column(String, nullable=True)
    action = Column(String, nullable=False)
    entity_type = Column(String, nullable=True)
    entity_id = Column(String, nullable=True)
    detail = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
