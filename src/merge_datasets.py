import pandas as pd
from pathlib import Path

OUT_DIR = Path("data/processed")

print("Loading datasets...")
mitre = pd.read_csv(OUT_DIR / "mitre_dataset.csv")
nvd   = pd.read_csv(OUT_DIR / "nvd_dataset.csv")
kev   = pd.read_csv(OUT_DIR / "cisa_kev.csv")

print(f"MITRE: {mitre.shape}")
print(f"NVD:   {nvd.shape}")
print(f"KEV:   {kev.shape}")

# MERGE 1: NVD + MITRE
# Keep only MITRE columns that add new information (avoid duplicating NVD fields)
mitre_cols = [
    "cve_id", "state", "assigner_short_name", "title",
    "cwe", "vendors", "products", "num_affected_products",
    "references_count", "has_metrics_mitre",
    "cvss_version_mitre", "base_score_mitre",
    "base_severity_mitre", "vector_string_mitre"
]

df = nvd.merge(
    mitre[mitre_cols],
    on="cve_id",
    how="left"
)
print(f"\nAfter NVD+MITRE merge: {df.shape}")

# MERGE 2: + KEV
kev_cols = [
    "cve_id", "kev_vendor", "kev_product",
    "kev_date_added", "kev_ransomware",
    "kev_cwes", "exploited_in_wild"
]

df = df.merge(
    kev[kev_cols],
    on="cve_id",
    how="left"
)

# CVEs not in KEV -- exploited_in_wild = False
df["exploited_in_wild"] = df["exploited_in_wild"].fillna(False).astype(bool)

print(f"After +KEV merge: {df.shape}")
print(f"\nExploited in the wild: {df['exploited_in_wild'].sum()}")
print(f"Not exploited:         {(~df['exploited_in_wild']).sum()}")

# Consolidated CVSS
# NVD preferred, MITRE as fallback when NVD is missing
df["base_score_final"]    = df["base_score_nvd"].fillna(df["base_score_mitre"])
df["base_severity_final"] = df["base_severity_nvd"].fillna(df["base_severity_mitre"])
df["vector_string_final"] = df["vector_string_nvd"].fillna(df["vector_string_mitre"])
df["cwe_final"]           = df["cwe_nvd"].fillna(df["cwe"])

print(f"\nCVSS score available: {df['base_score_final'].notna().sum()} / {len(df)}")
print(f"CWE available:        {df['cwe_final'].notna().sum()} / {len(df)}")

# Publication year
df["year_published"] = pd.to_datetime(
    df["date_published_nvd"], errors="coerce"
).dt.year

# Save
out_path = OUT_DIR / "dataset_final.csv"
df.to_csv(out_path, index=False)

print(f"\nFinal dataset saved: {out_path}")
print(f"Final shape: {df.shape}")
print(f"Columns: {list(df.columns)}")
print(f"\nNaN per column (top 10):")
print(df.isna().mean().sort_values(ascending=False).head(10))
