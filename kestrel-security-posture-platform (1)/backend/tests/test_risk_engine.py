from app import models
from app.risk_engine import (
    compute_risk_score, compute_category_scores, compute_overall_score, rating_for_score
)


def make_asset(criticality=models.Criticality.medium, internet_facing=False):
    return models.Asset(name="a", criticality=criticality, internet_facing=internet_facing)


def make_finding(severity=models.Severity.medium, category=models.Category.network,
                  exploitability=models.Exploitability.theoretical, status=models.FindingStatus.detected):
    return models.Finding(severity=severity, category=category, exploitability=exploitability, status=status)


def test_critical_internet_facing_active_exploit_scores_maximum():
    asset = make_asset(models.Criticality.critical, internet_facing=True)
    finding = make_finding(models.Severity.critical, exploitability=models.Exploitability.active)
    score = compute_risk_score(finding, asset)
    assert score == 100.0  # 1.0 * 1.0 * 1.0 * 1.0 * 100


def test_low_severity_internal_theoretical_scores_low():
    asset = make_asset(models.Criticality.low, internet_facing=False)
    finding = make_finding(models.Severity.low, exploitability=models.Exploitability.theoretical)
    score = compute_risk_score(finding, asset)
    assert score < 10.0


def test_internet_facing_scores_higher_than_internal_otherwise_identical():
    internal_asset = make_asset(models.Criticality.high, internet_facing=False)
    external_asset = make_asset(models.Criticality.high, internet_facing=True)
    finding = make_finding(models.Severity.high, exploitability=models.Exploitability.poc)
    internal_score = compute_risk_score(finding, internal_asset)
    external_score = compute_risk_score(finding, external_asset)
    assert external_score > internal_score


def test_resolved_findings_do_not_affect_category_score():
    findings = [make_finding(models.Severity.critical, status=models.FindingStatus.resolved)]
    for f in findings:
        f.risk_score = 100.0
    scores = compute_category_scores(findings)
    network_score = next(s for s in scores if s.category == models.Category.network)
    assert network_score.score == 100.0  # untouched, since the finding is resolved


def test_open_critical_finding_deducts_points_from_its_category():
    f = make_finding(models.Severity.critical, category=models.Category.network,
                      status=models.FindingStatus.detected)
    f.risk_score = 100.0
    scores = compute_category_scores([f])
    network_score = next(s for s in scores if s.category == models.Category.network)
    assert network_score.score < 100.0
    other_category_score = next(s for s in scores if s.category == models.Category.access_control)
    assert other_category_score.score == 100.0  # unaffected categories stay perfect


def test_single_finding_cannot_zero_out_a_category():
    f = make_finding(models.Severity.critical, status=models.FindingStatus.detected)
    f.risk_score = 100.0
    scores = compute_category_scores([f])
    network_score = next(s for s in scores if s.category == models.Category.network)
    assert network_score.score > 0  # capped deduction, not wiped out by one finding


def test_overall_score_is_average_of_categories():
    scores = compute_category_scores([])  # no findings -> all categories perfect
    overall = compute_overall_score(scores)
    assert overall == 100.0


def test_rating_bands():
    assert rating_for_score(95) == "Excellent"
    assert rating_for_score(80) == "Good"
    assert rating_for_score(65) == "Fair"
    assert rating_for_score(45) == "Poor"
    assert rating_for_score(10) == "Critical"
