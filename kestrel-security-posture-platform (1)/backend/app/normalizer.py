"""
Data Ingestion Layer / Finding Parser & Normalizer.

Consumes findings from external security data sources and converts them
into the platform's internal Finding/Asset schema. This module is where
the "aggregates security findings from multiple sources" part of the
project lives -- the rest of the platform never has to know whether a
finding came from a CSV export, a JSON scan report, or a manual entry.

Supported formats (MVP scope: "one or two real scanner formats" per spec):
  - "kestrel_scan"  : a generic structured JSON format, representative of
                       what an nmap/vuln-scanner wrapper might emit.
  - "nessus_csv"     : a CSV with the common Nessus/OpenVAS export columns
                       (Plugin ID, CVE, Risk, Host, Name, Synopsis, Port).

Both normalizers return a list of dicts ready to be turned into Asset +
Finding rows by the /findings/import endpoint, plus a list of human
readable errors for rows that couldn't be parsed.
"""
import csv
import io
from typing import List, Dict, Any, Tuple

from app import models

SEVERITY_MAP = {
    "critical": models.Severity.critical,
    "high": models.Severity.high,
    "medium": models.Severity.medium,
    "moderate": models.Severity.medium,
    "low": models.Severity.low,
    "info": models.Severity.low,
    "informational": models.Severity.low,
    # Nessus/CVSS-style numeric risk factor fallback
    "4": models.Severity.critical,
    "3": models.Severity.high,
    "2": models.Severity.medium,
    "1": models.Severity.low,
    "0": models.Severity.low,
}

# Best-effort keyword categorization for scanners that don't already
# provide a category (most don't). Falls back to "configuration".
CATEGORY_KEYWORDS = [
    (("ssh", "rdp", "telnet", "firewall", "port", "exposed service", "open port"), models.Category.network),
    (("password", "auth", "login", "credential", "mfa", "2fa"), models.Category.authentication),
    (("patch", "update", "outdated", "eol", "end of life", "cve-"), models.Category.patch_management),
    (("privilege", "account", "permission", "access", "admin", "iam"), models.Category.access_control),
    (("xss", "sql injection", "csrf", "web app", "application"), models.Category.application),
]


def guess_category(text: str) -> models.Category:
    lowered = text.lower()
    for keywords, category in CATEGORY_KEYWORDS:
        if any(k in lowered for k in keywords):
            return category
    return models.Category.configuration


def guess_exploitability(text: str, cve_id: str = None) -> models.Exploitability:
    lowered = (text or "").lower()
    if "actively exploited" in lowered or "in the wild" in lowered:
        return models.Exploitability.active
    if "proof of concept" in lowered or "poc" in lowered or cve_id:
        return models.Exploitability.poc
    return models.Exploitability.theoretical


def normalize_kestrel_scan(raw: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Normalize the generic 'kestrel_scan' JSON format."""
    out, errors = [], []
    for i, row in enumerate(raw):
        try:
            host = row["host"]
            title = row["finding"]
            severity_raw = str(row.get("severity", "medium")).strip().lower()
            severity = SEVERITY_MAP.get(severity_raw, models.Severity.medium)
            description = row.get("description", "")
            category_hint = f"{title} {description}"
            out.append({
                "asset_name": host,
                "asset_ip": row.get("ip"),
                "internet_facing": bool(row.get("internet_facing", False)),
                "title": title,
                "description": description,
                "severity": severity,
                "category": guess_category(category_hint),
                "exploitability": guess_exploitability(category_hint, row.get("cve")),
                "cve_id": row.get("cve"),
                "external_id": row.get("id"),
                "source": "kestrel_scan",
            })
        except KeyError as e:
            errors.append(f"row {i}: missing required field {e}")
    return out, errors


def normalize_nessus_csv(csv_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Normalize a Nessus/OpenVAS-style CSV export."""
    out, errors = [], []
    reader = csv.DictReader(io.StringIO(csv_text))
    for i, row in enumerate(reader):
        try:
            host = row.get("Host") or row.get("host")
            title = row.get("Name") or row.get("name")
            if not host or not title:
                raise KeyError("Host/Name")
            severity_raw = str(row.get("Risk") or row.get("risk") or "medium").strip().lower()
            severity = SEVERITY_MAP.get(severity_raw, models.Severity.medium)
            description = row.get("Synopsis") or row.get("synopsis") or ""
            cve = row.get("CVE") or row.get("cve") or None
            category_hint = f"{title} {description}"
            out.append({
                "asset_name": host,
                "asset_ip": host,
                "internet_facing": False,
                "title": title,
                "description": description,
                "severity": severity,
                "category": guess_category(category_hint),
                "exploitability": guess_exploitability(category_hint, cve),
                "cve_id": cve,
                "external_id": row.get("Plugin ID") or row.get("plugin_id"),
                "source": "nessus_csv",
            })
        except KeyError as e:
            errors.append(f"row {i}: missing required column {e}")
    return out, errors
