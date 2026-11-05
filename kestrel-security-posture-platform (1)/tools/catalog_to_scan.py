#!/usr/bin/env python3
"""
Convert a vulnerability CATALOG csv into the Nessus-style CSV that the
platform's "Import CSV" page accepts.

Works with:
  * CVE & CWE datasets (columns like ID, CVE-ID, CVSS-V4, CVSS-V3, CVSS-V2,
    SEVERITY, DESCRIPTION, CWE-ID)
  * the CISA Known Exploited Vulnerabilities csv (cveID, vendorProject,
    product, vulnerabilityName, shortDescription, ...)

A catalog says which vulnerabilities EXIST, not which of your machines have
them, so this script invents the hosts. The output is demo data, not a scan.

Examples:
    python catalog_to_scan.py cve_cwe.csv scan_import.csv --since-year 2020 --min-severity HIGH --limit 80
    python catalog_to_scan.py known_exploited_vulnerabilities.csv scan_import.csv

Options:
    --limit N            rows to convert (default 60), sampled at random
    --since-year YYYY    only CVEs from this year on (recommended: 2020)
    --min-severity S     LOW | MEDIUM | HIGH | CRITICAL
    --seed N             make the random sample repeatable (default 7)
    --hosts-per-group N  size of the invented host pool (default 3)

Column names are matched ignoring case, hyphens, underscores and spaces,
so "CVE-ID", "cve_id" and "cveID" are all the same column.

Risk comes from, in order: the newest CVSS score present (v4, then v3, then
v2; the text "None" counts as missing) -> a severity column -> for CISA KEV
files, ransomware use "Known" = Critical, otherwise High.

Hosts: if the file has a product column, one host per product. Otherwise
each CVE goes to a host chosen from its CWE family (web apps, auth/VPN
gateways, memory-safety bugs on servers, everything else on generic servers).
"""
import argparse
import csv
import random
import re
import sys
from collections import defaultdict

# Aliases are compared after stripping everything but letters and digits.
ALIASES = {
    "cve": ["cveid", "cve"],
    "vendor": ["vendorproject", "vendor"],
    "product": ["product"],
    "name": ["vulnerabilityname", "name", "title"],
    "description": ["shortdescription", "description", "summary"],
    "ransomware": ["knownransomwarecampaignuse"],
    "cvss": ["cvssv4", "cvssv3", "cvssv31", "cvssv2", "cvss", "cvssscore", "basescore"],  # priority order
    "severity": ["severity", "cvssseverity"],
    "cwe": ["cweid", "cwes", "cwe"],
}

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
OTHER = (["srv"], "Software weakness. Apply the vendor update")


def norm(col):
    return re.sub(r"[^a-z0-9]", "", col.lower())


def find_columns(fieldnames):
    by_norm = {norm(c): c for c in fieldnames}
    cols = {}
    for key, aliases in ALIASES.items():
        cols[key] = next((by_norm[a] for a in aliases if a in by_norm), None)
    # all matching CVSS columns, newest generation first
    cols["cvss_all"] = [by_norm[a] for a in ALIASES["cvss"] if a in by_norm]
    return cols


def get(row, col):
    return (row.get(col) or "").strip() if col else ""


def best_score(row, cols):
    for col in cols["cvss_all"]:
        raw = get(row, col)
        if raw and raw.lower() not in ("none", "null", "nan", "n/a"):
            try:
                return float(raw)
            except ValueError:
                continue
    return None


def risk_for(row, cols):
    score = best_score(row, cols)
    if score is not None:
        return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
    sev = get(row, cols["severity"]).capitalize()
    if sev in ("Critical", "High", "Medium", "Low"):
        return sev
    if get(row, cols["ransomware"]).lower() == "known":
        return "Critical"
    return "High"


def cve_year(cve):
    m = re.match(r"CVE-(\d{4})-", cve, re.I)
    return int(m.group(1)) if m else None


def first_cwe(text):
    m = re.search(r"CWE-(\d+)", text or "", re.I)
    return int(m.group(1)) if m else None


def group_for(cwe_num):
    for name, (nums, prefixes, hint) in CWE_GROUPS.items():
        if cwe_num in nums:
            return name, prefixes, hint
    return "other", OTHER[0], OTHER[1]


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unknown"


def short_title(cve, desc):
    sentence = re.split(r"(?<=[.!?])\s", desc.strip(), maxsplit=1)[0] if desc else ""
    sentence = sentence.rstrip(".")
    if len(sentence) > 110:
        sentence = sentence[:107].rsplit(" ", 1)[0] + "..."
    # The importer treats the text "cve-" as a patching signal, so the ID is written
    # "CVE 2025-1001" in titles. The real ID still goes in the CVE column. Keeping
    # it in the title also keeps titles unique (the importer skips duplicate titles).
    tag = cve.replace("CVE-", "CVE ", 1)
    return f"{sentence} [{tag}]" if sentence else cve


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--since-year", type=int)
    ap.add_argument("--min-severity", choices=list(SEVERITY_RANK), type=str.upper)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hosts-per-group", type=int, default=3)
    args = ap.parse_args()

    with open(args.input, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        cols = find_columns(fieldnames)
        if not cols["cve"] and not cols["name"]:
            sys.exit(f"Couldn't find a CVE or name column. Columns in your file: {fieldnames}")
        all_rows = list(reader)

    rows = all_rows
    if args.since_year:
        rows = [r for r in rows if (cve_year(get(r, cols["cve"])) or 0) >= args.since_year]
    if args.min_severity:
        floor = SEVERITY_RANK[args.min_severity]
        rows = [r for r in rows if SEVERITY_RANK[risk_for(r, cols).upper()] >= floor]
    if not rows:
        sys.exit(f"No rows left after filtering (started with {len(all_rows)}). Loosen --since-year or --min-severity.")
    if len(rows) > args.limit:
        rows = random.Random(args.seed).sample(rows, args.limit)

    is_kev = bool(cols["ransomware"])
    has_product = bool(cols["product"])
    product_host = {}
    group_counter = defaultdict(int)
    out = []
    for i, row in enumerate(rows, start=1):
        cve = get(row, cols["cve"])
        desc = get(row, cols["description"])
        name = get(row, cols["name"]) or short_title(cve, desc)

        hint = ""
        if has_product and (get(row, cols["product"]) or get(row, cols["vendor"])):
            key = slug(get(row, cols["product"]) or get(row, cols["vendor"]))
            if key not in product_host:
                n = sum(1 for k in product_host if k == key) + 1
                product_host[key] = f"{key}-{n:02d}"
            host = product_host[key]
        else:
            cwe = first_cwe(get(row, cols["cwe"]))
            group, prefixes, hint = group_for(cwe)
            k = group_counter[group]
            group_counter[group] += 1
            host = f"{prefixes[k % len(prefixes)]}-{(k // len(prefixes)) % args.hosts_per_group + 1:02d}"
            if cwe:
                hint = f"{hint} (CWE-{cwe})."
            else:
                hint = f"{hint}."

        parts = [p for p in (desc, hint) if p]
        if is_kev:
            parts.append("Listed in the CISA Known Exploited Vulnerabilities catalog and actively exploited in the wild.")
        out.append([10000 + i, cve, risk_for(row, cols), host, "tcp", 0, name, " ".join(parts)])

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Plugin ID", "CVE", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis"])
        w.writerows(out)
    print(f"Read {len(all_rows)} rows, wrote {len(out)} findings across {len({r[3] for r in out})} hosts to {args.output}")


if __name__ == "__main__":
    main()
