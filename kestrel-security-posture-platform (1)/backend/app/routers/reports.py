import csv
import io
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, auth

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/findings.csv")
def export_findings_csv(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    """Basic reporting: exports the full findings register as CSV."""
    findings = db.query(models.Finding).order_by(models.Finding.risk_score.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "title", "asset", "severity", "category", "risk_score", "status",
        "exploitability", "cve_id", "source", "assigned_to", "created_at", "resolved_at",
    ])
    for f in findings:
        writer.writerow([
            f.id, f.title, f.asset.name if f.asset else "", f.severity.value, f.category.value,
            f.risk_score, f.status.value, f.exploitability.value, f.cve_id or "", f.source,
            f.assignee.username if f.assignee else "", f.created_at.isoformat(),
            f.resolved_at.isoformat() if f.resolved_at else "",
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings_report.csv"},
    )
