import json
from pathlib import Path
import pandas as pd

MITRE_DIR = Path("data/raw/mitre/mitre-cve-database/cve-data/mitre/cves")
OUT_DIR = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

rows = []

def get_description(cna):
    descs = cna.get("descriptions", [])
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value")
    return descs[0].get("value") if descs else None

def get_problem_type(cna):
    pts = cna.get("problemTypes", [])
    cwes = []
    for pt in pts:
        for d in pt.get("descriptions", []):
            if d.get("cweId"):
                cwes.append(d.get("cweId"))
            elif d.get("description"):
                cwes.append(d.get("description"))
    return ";".join(set(cwes)) if cwes else None

def get_cvss(cna):
    metrics = cna.get("metrics", [])
    for m in metrics:
        for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if key in m:
                cvss = m[key]
                return {
                    "cvss_version_mitre": key,
                    "base_score_mitre": cvss.get("baseScore"),
                    "base_severity_mitre": cvss.get("baseSeverity"),
                    "vector_string_mitre": cvss.get("vectorString"),
                }
    return {
        "cvss_version_mitre": None,
        "base_score_mitre": None,
        "base_severity_mitre": None,
        "vector_string_mitre": None,
    }

files = list(MITRE_DIR.rglob("CVE-*.json"))
print(f"Encontrados {len(files)} ficheros CVE")

for i, file in enumerate(files, start=1):
    try:
        with open(file, "r", encoding="utf-8") as f:
            data = json.load(f)

        meta = data.get("cveMetadata", {})
        cna = data.get("containers", {}).get("cna", {})

        cvss_data = get_cvss(cna)

        affected = cna.get("affected", [])
        vendors = []
        products = []

        for item in affected:
            vendor = item.get("vendor")
            product = item.get("product")
            if vendor:
                vendors.append(vendor)
            if product:
                products.append(product)

        row = {
            "cve_id": meta.get("cveId"),
            "state": meta.get("state"),
            "date_published": meta.get("datePublished"),
            "date_updated": meta.get("dateUpdated"),
            "assigner_short_name": meta.get("assignerShortName"),
            "title": cna.get("title"),
            "description": get_description(cna),
            "cwe": get_problem_type(cna),
            "vendors": ";".join(set(vendors)) if vendors else None,
            "products": ";".join(set(products)) if products else None,
            "num_affected_products": len(affected),
            "references_count": len(cna.get("references", [])),
            "has_metrics_mitre": bool(cna.get("metrics")),
            **cvss_data,
            "source_file": str(file),
        }

        rows.append(row)

        if i % 10000 == 0:
            print(f"Procesados {i}/{len(files)}")

    except Exception as e:
        print(f"Error en {file}: {e}")

df = pd.DataFrame(rows)

df.to_csv(OUT_DIR / "mitre_dataset.csv", index=False)

print("Dataset MITRE creado correctamente")
print(df.shape)
print(df.head())
print(df.isna().mean().sort_values(ascending=False).head(20))
