import requests
import time
import json
import os
from pathlib import Path
from datetime import date, timedelta
from dotenv import load_dotenv
import pandas as pd

load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")
API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUT_DIR = Path("data/raw/nvd")
OUT_DIR.mkdir(parents=True, exist_ok=True)

YEARS = range(2016, 2027)
RESULTS_PER_PAGE = 2000
DELAY = 0.6

headers = {"apiKey": API_KEY}


def fetch_year(year):
    all_cves = []
    chunk_start = date(year, 1, 1)
    year_end = date(year, 12, 31)

    while chunk_start <= year_end:
        chunk_end = min(chunk_start + timedelta(days=89), year_end)
        start = chunk_start.strftime("%Y-%m-%dT00:00:00.000")
        end   = chunk_end.strftime("%Y-%m-%dT23:59:59.999")
        index = 0

        while True:
            params = {
                "pubStartDate": start,
                "pubEndDate":   end,
                "startIndex":   index,
                "resultsPerPage": RESULTS_PER_PAGE,
            }
            for attempt in range(5):
                try:
                    r = requests.get(BASE_URL, headers=headers, params=params, timeout=30)
                    r.raise_for_status()
                    data = r.json()
                    break
                except Exception as e:
                    print(f"  Intento {attempt+1} fallido: {e}")
                    time.sleep(5)
            else:
                print(f"  ERROR: {start} -> {end} index={index}")
                break

            vulns = data.get("vulnerabilities", [])
            all_cves.extend(vulns)
            total = data.get("totalResults", 0)
            print(f"  {start[:10]} -> {end[:10]}: {len(all_cves)} acumulados / {total} en chunk")

            if index + RESULTS_PER_PAGE >= total:
                break
            index += RESULTS_PER_PAGE
            time.sleep(DELAY)

        chunk_start = chunk_end + timedelta(days=1)

    return all_cves


def parse_cve(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id")

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), None
    )

    metrics = cve.get("metrics", {})
    cvss_score = cvss_severity = cvss_vector = cvss_version = None
    attack_vector = attack_complexity = privileges_required = None
    user_interaction = confidentiality = integrity = availability = None

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            cvss_version   = cvss_data.get("version")
            cvss_score     = cvss_data.get("baseScore")
            cvss_severity  = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            cvss_vector    = cvss_data.get("vectorString")
            attack_vector       = cvss_data.get("attackVector")
            attack_complexity   = cvss_data.get("attackComplexity")
            privileges_required = cvss_data.get("privilegesRequired")
            user_interaction    = cvss_data.get("userInteraction")
            confidentiality     = cvss_data.get("confidentialityImpact")
            integrity           = cvss_data.get("integrityImpact")
            availability        = cvss_data.get("availabilityImpact")
            break

    exploit_score = impact_score = None
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            exploit_score = m.get("exploitabilityScore")
            impact_score  = m.get("impactScore")
            break

    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])
    cwe = ";".join(set(cwes)) if cwes else None

    configs = cve.get("configurations", [])
    cpe_list = []
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe_list.append(match.get("criteria", ""))
    num_cpes = len(cpe_list)
    cpe_sample = cpe_list[0] if cpe_list else None

    refs = cve.get("references", [])

    return {
        "cve_id":                cve_id,
        "date_published_nvd":    cve.get("published"),
        "date_modified_nvd":     cve.get("lastModified"),
        "vuln_status":           cve.get("vulnStatus"),
        "description_nvd":       desc,
        "cvss_version_nvd":      cvss_version,
        "base_score_nvd":        cvss_score,
        "base_severity_nvd":     cvss_severity,
        "vector_string_nvd":     cvss_vector,
        "attack_vector":         attack_vector,
        "attack_complexity":     attack_complexity,
        "privileges_required":   privileges_required,
        "user_interaction":      user_interaction,
        "confidentiality_impact": confidentiality,
        "integrity_impact":      integrity,
        "availability_impact":   availability,
        "exploitability_score":  exploit_score,
        "impact_score":          impact_score,
        "cwe_nvd":               cwe,
        "num_cpes":              num_cpes,
        "cpe_sample":            cpe_sample,
        "references_count_nvd":  len(refs),
    }


# — MAIN —
all_rows = []
for year in YEARS:
    print(f"\nDescargando {year}...")
    raw = fetch_year(year)

    with open(OUT_DIR / f"nvd_{year}.json", "w") as f:
        json.dump(raw, f)

    rows = [parse_cve(item) for item in raw]
    all_rows.extend(rows)
    print(f"  {year}: {len(rows)} CVEs parseados")

df = pd.DataFrame(all_rows)
out_path = Path("data/processed/nvd_dataset.csv")
df.to_csv(out_path, index=False)
print(f"\nNVD dataset guardado: {out_path}")
print(df.shape)
print(df.isna().mean().sort_values(ascending=False).head(10))
