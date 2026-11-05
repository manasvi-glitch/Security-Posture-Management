"""
Risk Assessment Engine & Security Posture Calculation.

This is intentionally kept in one small, readable module because the spec
calls for the scoring methodology to be "transparent and explainable
rather than an arbitrary number" -- anyone should be able to read this
file top to bottom and reproduce a score by hand.

--------------------------------------------------------------------------
1. FINDING RISK SCORE
--------------------------------------------------------------------------
    risk_score = severity_weight * exposure_weight * criticality_weight
                 * exploitability_weight * 100

Every factor is normalized to 0-1, so risk_score lands in [0, 100].
This directly implements the conceptual model from the spec:

    Risk = Severity x Exposure x Asset Criticality x Exploitability

--------------------------------------------------------------------------
2. CATEGORY / OVERALL POSTURE SCORE
--------------------------------------------------------------------------
Each category starts at a perfect 100 and loses points for every OPEN
(not resolved) finding in that category, proportional to that finding's
risk_score. The deduction per finding is capped so that a single finding
can never single-handedly zero out a category, and the category floor is
0. The overall posture score is the average of the six category scores.

    category_score = 100 - sum(min(risk_score * 0.35, 22) for open findings)
    overall_score  = average(category_score for all 6 categories)

This keeps the score sensitive to both HOW BAD and HOW MANY open issues
exist per category, while remaining easy to explain to a non-technical
stakeholder ("each open critical finding costs you up to ~22 points in
its category").
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List, Dict

from app import models

# --- Weights (all normalized 0-1) -----------------------------------------

SEVERITY_WEIGHT = {
    models.Severity.critical: 1.0,
    models.Severity.high: 0.75,
    models.Severity.medium: 0.5,
    models.Severity.low: 0.25,
}

CRITICALITY_WEIGHT = {
    models.Criticality.critical: 1.0,
    models.Criticality.high: 0.8,
    models.Criticality.medium: 0.55,
    models.Criticality.low: 0.3,
}

EXPLOITABILITY_WEIGHT = {
    models.Exploitability.active: 1.0,
    models.Exploitability.poc: 0.7,
    models.Exploitability.theoretical: 0.4,
}

INTERNET_FACING_EXPOSURE = 1.0
INTERNAL_EXPOSURE = 0.45

DEDUCTION_PER_FINDING_CAP = 22.0
DEDUCTION_MULTIPLIER = 0.35

RATING_BANDS = [
    (90, "Excellent"),
    (75, "Good"),
    (60, "Fair"),
    (40, "Poor"),
    (0, "Critical"),
]


def compute_exposure_weight(asset: models.Asset) -> float:
    return INTERNET_FACING_EXPOSURE if asset.internet_facing else INTERNAL_EXPOSURE


def compute_risk_score(finding: models.Finding, asset: models.Asset) -> float:
    """Pure function: (finding, asset) -> risk score in [0, 100]."""
    s = SEVERITY_WEIGHT[finding.severity]
    e = compute_exposure_weight(asset)
    c = CRITICALITY_WEIGHT[asset.criticality]
    x = EXPLOITABILITY_WEIGHT[finding.exploitability]
    return round(s * e * c * x * 100, 2)


def rating_for_score(score: float) -> str:
    for threshold, label in RATING_BANDS:
        if score >= threshold:
            return label
    return "Critical"


@dataclass
class CategoryBreakdown:
    category: models.Category
    score: float


def compute_category_scores(findings: Iterable[models.Finding]) -> List[CategoryBreakdown]:
    scores: Dict[models.Category, float] = {c: 100.0 for c in models.Category}
    for f in findings:
        if f.status == models.FindingStatus.resolved:
            continue
        deduction = min(f.risk_score * DEDUCTION_MULTIPLIER, DEDUCTION_PER_FINDING_CAP)
        scores[f.category] = max(0.0, scores[f.category] - deduction)
    return [CategoryBreakdown(category=c, score=round(v, 1)) for c, v in scores.items()]


def compute_overall_score(category_scores: List[CategoryBreakdown]) -> float:
    if not category_scores:
        return 100.0
    return round(sum(c.score for c in category_scores) / len(category_scores), 1)


def compute_trend_30d(db_session, current_score: float) -> float:
    """
    Approximate a 30-day trend by comparing the current score to what the
    score would have been if findings resolved in the last 30 days were
    still open. This avoids needing a separate score-history table for
    the MVP while still answering "is posture improving or worsening?".
    """
    from app import models as m
    cutoff = datetime.utcnow() - timedelta(days=30)
    resolved_recently = (
        db_session.query(m.Finding)
        .filter(m.Finding.status == m.FindingStatus.resolved)
        .filter(m.Finding.resolved_at != None)  # noqa: E711
        .filter(m.Finding.resolved_at >= cutoff)
        .all()
    )
    if not resolved_recently:
        return 0.0

    all_findings = db_session.query(m.Finding).all()
    # Re-open the recently-resolved findings in memory only, to compute a
    # "before" score without mutating the database.
    reopened_ids = {f.id for f in resolved_recently}
    synthetic = []
    for f in all_findings:
        if f.id in reopened_ids:
            f_copy = models.Finding(
                category=f.category, risk_score=f.risk_score,
                status=models.FindingStatus.detected,  # pretend still open
            )
            synthetic.append(f_copy)
        else:
            synthetic.append(f)

    before_categories = compute_category_scores(synthetic)
    before_score = compute_overall_score(before_categories)
    return round(current_score - before_score, 1)
