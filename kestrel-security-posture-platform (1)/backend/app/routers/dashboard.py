from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth
from app.risk_engine import (
    compute_category_scores, compute_overall_score, rating_for_score, compute_trend_30d
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=schemas.DashboardSummary)
def summary(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    findings = db.query(models.Finding).all()
    assets = db.query(models.Asset).all()

    # ---- Posture score ----
    category_scores = compute_category_scores(findings)
    overall = compute_overall_score(category_scores)
    trend = compute_trend_30d(db, overall)
    posture = schemas.PostureScore(
        overall=overall,
        rating=rating_for_score(overall),
        categories=[schemas.CategoryScore(category=c.category, score=c.score) for c in category_scores],
        trend_30d=trend,
    )

    # ---- Findings by severity (open only) ----
    open_findings = [f for f in findings if f.status != models.FindingStatus.resolved]
    sev_counts = {s: 0 for s in models.Severity}
    for f in open_findings:
        sev_counts[f.severity] += 1
    findings_out = schemas.SeverityCounts(
        critical=sev_counts[models.Severity.critical],
        high=sev_counts[models.Severity.high],
        medium=sev_counts[models.Severity.medium],
        low=sev_counts[models.Severity.low],
        total=len(open_findings),
    )

    # ---- Assets ----
    high_risk_ids = {f.asset_id for f in open_findings if f.severity in
                      (models.Severity.critical, models.Severity.high)}
    assets_out = schemas.AssetCounts(
        total=len(assets),
        high_risk=len(high_risk_ids),
        internet_facing=sum(1 for a in assets if a.internet_facing),
        needs_attention=sum(1 for a in assets if a.open_finding_count > 0),
    )

    # ---- Remediation ----
    cutoff = datetime.utcnow() - timedelta(days=30)
    resolved_30d = [f for f in findings if f.status == models.FindingStatus.resolved
                     and f.resolved_at and f.resolved_at >= cutoff]
    in_progress_statuses = {models.FindingStatus.assigned, models.FindingStatus.fix_in_progress}
    avg_days = None
    fix_times = [(f.resolved_at - f.created_at).total_seconds() / 86400 for f in resolved_30d if f.resolved_at]
    if fix_times:
        avg_days = round(sum(fix_times) / len(fix_times), 1)

    remediation_out = schemas.RemediationCounts(
        open=len(open_findings),
        in_progress=sum(1 for f in findings if f.status in in_progress_statuses),
        resolved_30d=len(resolved_30d),
        avg_days_to_fix=avg_days,
    )

    # ---- Pipeline (stage counts) ----
    def count_status(s):
        return sum(1 for f in findings if f.status == s)

    pipeline_out = schemas.PipelineCounts(
        detected=count_status(models.FindingStatus.detected),
        triaged=count_status(models.FindingStatus.triaged),
        assigned=count_status(models.FindingStatus.assigned),
        fix_in_progress=count_status(models.FindingStatus.fix_in_progress),
        remediated=count_status(models.FindingStatus.remediated),
        verification=count_status(models.FindingStatus.verification),
        resolved_30d=len(resolved_30d),
    )

    # ---- Top priorities ----
    ranked = sorted(open_findings, key=lambda f: f.risk_score, reverse=True)[:5]
    priorities = [
        schemas.PriorityItem(
            rank=i + 1,
            finding_id=f.id,
            title=f.title,
            severity=f.severity,
            risk_score=f.risk_score,
            asset_name=f.asset.name,
            asset_id=f.asset_id,
        )
        for i, f in enumerate(ranked)
    ]

    # ---- Trend (posture score over recent weeks, approximated) ----
    # For the MVP we don't persist historical snapshots; we synthesize a
    # short trend line by walking backwards and re-opening findings that
    # were resolved before each point in time. This is clearly documented
    # as an approximation -- a production version would persist a
    # PostureScoreHistory row on a schedule instead.
    trend_points = []
    labels = ["-25w", "-20w", "-15w", "-10w", "-5w", "now"]
    offsets = [175, 140, 105, 70, 35, 0]
    for label, days_ago in zip(labels, offsets):
        as_of = datetime.utcnow() - timedelta(days=days_ago)
        synthetic = []
        for f in findings:
            if f.status == models.FindingStatus.resolved and f.resolved_at and f.resolved_at > as_of:
                synthetic.append(models.Finding(category=f.category, risk_score=f.risk_score,
                                                 status=models.FindingStatus.detected))
            elif f.created_at and f.created_at <= as_of:
                synthetic.append(f)
        cats = compute_category_scores(synthetic)
        trend_points.append(schemas.TrendPoint(label=label, score=compute_overall_score(cats)))

    return schemas.DashboardSummary(
        posture=posture,
        findings=findings_out,
        assets=assets_out,
        remediation=remediation_out,
        pipeline=pipeline_out,
        top_priorities=priorities,
        trend=trend_points,
    )
