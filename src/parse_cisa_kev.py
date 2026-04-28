import json
import pandas as pd
from pathlib import Path

KEV_PATH = Path("data/raw/mitre/mitre-cve-database/cve-data/cisa-kev/known_exploited_vulnerabilities.json")
OUT_DIR = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

with open(KEV_PATH, encoding="utf-8") as f:
    data = json.load(f)

print(f"Total KEV: {data['count']}")
print(f"Versión catálogo: {data.get('catalogVersion')}")
print(f"Fecha: {data.get('dateReleased')}")

rows = []
for v in data["vulnerabilities"]:
    rows.append({
        "cve_id":                 v.get("cveID"),
        "kev_vendor":             v.get("vendorProject"),
        "kev_product":            v.get("product"),
        "kev_vulnerability_name": v.get("vulnerabilityName"),
        "kev_date_added":         v.get("dateAdded"),
        "kev_due_date":           v.get("dueDate"),
        "kev_ransomware":         v.get("knownRansomwareCampaignUse"),
        "kev_required_action":    v.get("requiredAction"),
        "kev_description":        v.get("shortDescription"),
        "kev_cwes":               ";".join(v.get("cwes", [])) if v.get("cwes") else None,
    })

df = pd.DataFrame(rows)
df["exploited_in_wild"] = True  # variable importante del modelo

out_path = OUT_DIR / "cisa_kev.csv"
df.to_csv(out_path, index=False)

print(f"\nCISA KEV guardado: {out_path}")
print(f"Shape: {df.shape}")
print(f"\nRansomware breakdown:")
print(df["kev_ransomware"].value_counts())
print(f"\nMuestra:")
print(df.head(3).to_string())
