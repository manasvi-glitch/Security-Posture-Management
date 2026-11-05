#!/usr/bin/env python3
"""Convert vulnerability-catalog CSV files into the platform's Nessus-style import CSV.

This creates DEMO findings and synthetic hosts: a vulnerability catalog does not
identify which machines in your environment are affected.

Supported inputs include CVE/CWE catalogs and the CISA KEV catalog. Headers are
matched case-insensitively after punctuation/spacing is removed. Comma, semicolon,
tab and pipe-delimited files are supported.

Example:
  python catalog_to_scan.py cisa_kev.csv scan_import.csv --since-year 2020 --min-severity HIGH --limit 80

Output columns match the backend importer:
  Plugin ID, CVE, Risk, Host, Protocol, Port, Name, Synopsis
"""
import argparse
import csv
import random
import re
import sys
from collections import defaultdict

ALIASES = {
    "cve": ["cveid", "cve", "cveidentifier", "cveids"],
    "vendor": ["vendorproject", "vendor", "vendorname"],
    "product": ["product", "productname"],
    "name": ["vulnerabilityname", "vulnerability", "name", "title", "finding"],
    "description": ["shortdescription", "description", "summary", "synopsis"],
    "ransomware": ["knownransomwarecampaignuse"],
    "severity": ["severity", "cvssseverity", "baseseverity", "risk"],
    "cwe": ["cweid", "cwes", "cwe"],
}

CVSS_ALIASES = [
    "cvssv4", "cvssv40", "cvssv31", "cvssv3", "cvssv2",
    "cvss", "cvssscore", "basescore", "cvssbasescore",
]
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CWE_GROUPS = {
    "web": ({79, 89, 352, 22, 434, 918, 94, 78, 611, 601, 502, 77, 917, 98, 74},
            ["portal", "web-app", "api-gateway", "cms"],
            "Web application weakness"),
    "auth": ({287, 306, 798, 522, 521, 862, 863, 269, 284, 295, 294, 640, 384},
             ["auth-gateway", "vpn-gateway", "iam-directory"],
             "Authentication and access weakness"),
    "memory": ({119, 120, 121, 122, 125, 416, 787, 190, 476, 400, 401, 134, 20},
               ["app-server", "db-server", "file-server", "edge-router"],
               "Memory-safety or input-handling flaw. Apply the vendor update"),
}
OTHER = ["srv"], "Software weakness. Apply the vendor update"


def norm(value):
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def read_catalog(path):
    """Read common CSV dialects and tolerate a UTF-8 BOM."""
    with open(path, "r", newline="", encoding="utf-8-sig") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(handle, dialect=dialect)
        if not reader.fieldnames:
            raise ValueError("The input file is empty or has no header row.")
        reader.fieldnames = [str(name or "").strip().lstrip("\ufeff") for name in reader.fieldnames]
        rows = list(reader)
        return reader.fieldnames, rows


def find_columns(fieldnames):
    by_norm = {norm(name): name for name in fieldnames}
    cols = {}
    for key, aliases in ALIASES.items():
        cols[key] = next((by_norm[a] for a in aliases if a in by_norm), None)
    cols["cvss_all"] = [by_norm[a] for a in CVSS_ALIASES if a in by_norm]
    return cols


def get(row, col):
    value = row.get(col) if col else ""
    return str(value or "").strip()


def best_score(row, cols):
    for col in cols["cvss_all"]:
        raw = get(row, col)
        if raw and raw.lower() not in ("none", "null", "nan", "n/a", "na"):
            match = re.search(r"(?<![0-9])(?:10(?:\.0)?|[0-9](?:\.\d+)?)(?![0-9])", raw)
            if match:
                try:
                    score = float(match.group())
                    if 0 <= score <= 10:
                        return score
                except ValueError:
                    pass
    return None


def risk_for(row, cols):
    score = best_score(row, cols)
    if score is not None:
        return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
    severity = get(row, cols["severity"]).strip().upper()
    severity = {"MODERATE": "MEDIUM", "INFORMATIONAL": "LOW", "INFO": "LOW"}.get(severity, severity)
    if severity in SEVERITY_RANK:
        return severity.title()
    if get(row, cols["ransomware"]).lower() == "known":
        return "Critical"
    return "High"


def cve_year(cve):
    match = re.search(r"CVE-(\d{4})-", cve or "", re.I)
    return int(match.group(1)) if match else None


def first_cwe(value):
    match = re.search(r"CWE-(\d+)", value or "", re.I)
    if match:
        return int(match.group(1))
    # Some catalogs store a bare CWE number.
    match = re.search(r"(?<!\d)(\d{1,5})(?!\d)", value or "")
    return int(match.group(1)) if match else None


def group_for(cwe_num):
    for name, (numbers, prefixes, hint) in CWE_GROUPS.items():
        if cwe_num in numbers:
            return name, prefixes, hint
    return "other", OTHER[0], OTHER[1]


def slug(value):
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "unknown"


def short_title(cve, description):
    sentence = re.split(r"(?<=[.!?])\s", description.strip(), maxsplit=1)[0] if description else ""
    sentence = sentence.rstrip(".")
    if len(sentence) > 110:
        sentence = sentence[:107].rsplit(" ", 1)[0] + "..."
    tag = cve.replace("CVE-", "CVE ", 1)
    return f"{sentence} [{tag}]" if sentence and cve else sentence or cve or "Catalog vulnerability"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="Source vulnerability catalog CSV")
    parser.add_argument("output", help="CSV file to create for platform import")
    parser.add_argument("--limit", type=int, default=60, help="Maximum findings to convert (default: 60)")
    parser.add_argument("--since-year", type=int, help="Only include CVEs from this year onward")
    parser.add_argument("--min-severity", choices=list(SEVERITY_RANK), type=str.upper,
                        help="Minimum severity: LOW, MEDIUM, HIGH or CRITICAL")
    parser.add_argument("--seed", type=int, default=7, help="Repeatable sampling seed (default: 7)")
    parser.add_argument("--hosts-per-group", type=int, default=3, help="Synthetic hosts per CWE group (default: 3)")
    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1")
    if args.hosts_per_group < 1:
        parser.error("--hosts-per-group must be at least 1")

    try:
        fieldnames, all_rows = read_catalog(args.input)
    except (OSError, UnicodeError, ValueError, csv.Error) as error:
        parser.error(f"could not read input CSV: {error}")

    cols = find_columns(fieldnames)
    if not cols["cve"] and not cols["name"]:
        parser.error("could not identify a CVE or vulnerability-name column. "
                     f"Available columns: {', '.join(fieldnames)}")

    rows = all_rows
    if args.since_year:
        rows = [row for row in rows if (cve_year(get(row, cols["cve"])) or 0) >= args.since_year]
    if args.min_severity:
        floor = SEVERITY_RANK[args.min_severity]
        rows = [row for row in rows if SEVERITY_RANK[risk_for(row, cols).upper()] >= floor]
    if not rows:
        parser.error(f"no rows remain after filtering (input contained {len(all_rows)} rows); "
                     "check --since-year and --min-severity")

    if len(rows) > args.limit:
        rows = random.Random(args.seed).sample(rows, args.limit)

    is_kev = bool(cols["ransomware"])
    product_hosts = {}
    group_counter = defaultdict(int)
    output_rows = []

    for index, row in enumerate(rows, start=1):
        cve = get(row, cols["cve"])
        description = get(row, cols["description"])
        name = get(row, cols["name"]) or short_title(cve, description)
        hint = ""

        product = get(row, cols["product"])
        vendor = get(row, cols["vendor"])
        if product or vendor:
            key = slug(" ".join(part for part in (vendor, product) if part))
            if key not in product_hosts:
                product_hosts[key] = f"{key}-01"
            host = product_hosts[key]
        else:
            cwe = first_cwe(get(row, cols["cwe"]))
            group, prefixes, hint = group_for(cwe)
            counter = group_counter[group]
            group_counter[group] += 1
            host = f"{prefixes[counter % len(prefixes)]}-{(counter // len(prefixes)) % args.hosts_per_group + 1:02d}"
            if cwe:
                hint = f"{hint} (CWE-{cwe})."
            else:
                hint = f"{hint}."

        synopsis_parts = [part for part in (description, hint) if part]
        if is_kev:
            synopsis_parts.append("Listed in the CISA Known Exploited Vulnerabilities catalog.")
        output_rows.append([
            10000 + index, cve, risk_for(row, cols), host, "tcp", 0,
            name, " ".join(synopsis_parts),
        ])

    try:
        with open(args.output, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Plugin ID", "CVE", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis"])
            writer.writerows(output_rows)
    except OSError as error:
        parser.error(f"could not write output CSV: {error}")

    host_count = len({row[3] for row in output_rows})
    print(f"Read {len(all_rows)} rows; wrote {len(output_rows)} findings across "
          f"{host_count} synthetic hosts to {args.output}")
    print("Output format: Nessus/OpenVAS CSV (compatible with Import & Export → Import CSV).")
    print("Note: hosts are synthetic demo data, not evidence that these vulnerabilities affect your assets.")


if __name__ == "__main__":
    main()
