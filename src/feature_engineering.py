"""
feature_engineering.py

Transforms dataset_final.csv into model_dataset.csv with clean,
numeric features ready for Random Forest and Logistic Regression.

Input:  data/processed/dataset_final.csv
Output: data/processed/model_dataset.csv

CRISP-DM Phase: Data Preparation
"""

import pandas as pd
import numpy as np
from datetime import datetime, timezone


INPUT_PATH  = "data/processed/dataset_final.csv"
OUTPUT_PATH = "data/processed/model_dataset.csv"

# Fixed reference date for reproducibility
REFERENCE_DATE = datetime(2025, 1, 1, tzinfo=timezone.utc)


def load_data(path):
    print(f"Loading dataset from {path} ...")
    df = pd.read_csv(path, low_memory=False)
    print(f"Shape: {df.shape}")
    return df


def encode_attack_vector(df):
    # Ordinal encoding: higher value = easier to reach = higher risk
    # CVSS v2 value ADJACENT_NETWORK is also mapped for compatibility
    mapping = {
        "NETWORK":          4,
        "ADJACENT_NETWORK": 3,
        "LOCAL":            2,
        "PHYSICAL":         1,
    }
    df["attack_vector_score"] = df["attack_vector"].map(mapping).fillna(0).astype(int)
    return df


def encode_attack_complexity(df):
    # LOW = easy to exploit (higher risk), HIGH = requires special conditions
    mapping = {"LOW": 2, "HIGH": 1}
    df["attack_complexity_score"] = df["attack_complexity"].map(mapping).fillna(0).astype(int)
    return df


def encode_privileges_required(df):
    # NONE = no account needed (highest risk)
    mapping = {"NONE": 3, "LOW": 2, "HIGH": 1}
    df["privileges_required_score"] = df["privileges_required"].map(mapping).fillna(0).astype(int)
    return df


def encode_user_interaction(df):
    # NONE = no user action needed (higher risk)
    mapping = {"NONE": 2, "REQUIRED": 1}
    df["user_interaction_score"] = df["user_interaction"].map(mapping).fillna(0).astype(int)
    return df


def encode_impact(df):
    # CVSS v2 values (COMPLETE, PARTIAL) are ignored and treated as unknown -> 0
    # Only CVSS v3 values (HIGH, LOW, NONE) are mapped
    impact_mapping = {"HIGH": 2, "LOW": 1, "NONE": 0}
    cols = {
        "confidentiality_impact": "confidentiality_score",
        "integrity_impact":       "integrity_score",
        "availability_impact":    "availability_score",
    }
    for source, target in cols.items():
        df[target] = df[source].map(impact_mapping).fillna(0).astype(int)
    return df


def add_binary_flags(df):
    df["is_network_based"]         = (df["attack_vector"] == "NETWORK").astype(int)
    df["is_low_complexity"]        = (df["attack_complexity"] == "LOW").astype(int)
    df["no_privileges_needed"]     = (df["privileges_required"] == "NONE").astype(int)
    df["no_user_interaction"]      = (df["user_interaction"] == "NONE").astype(int)
    df["high_conf_impact"]         = (df["confidentiality_impact"] == "HIGH").astype(int)
    df["high_integ_impact"]        = (df["integrity_impact"] == "HIGH").astype(int)
    df["high_avail_impact"]        = (df["availability_impact"] == "HIGH").astype(int)
    df["is_ransomware_associated"] = (
        df["kev_ransomware"].str.upper().eq("KNOWN").fillna(False).astype(int)
    )
    return df


def add_derived_features(df):
    df["date_published_nvd"] = pd.to_datetime(df["date_published_nvd"], errors="coerce", utc=True)
    df["days_since_published"] = (
        (REFERENCE_DATE - df["date_published_nvd"]).dt.days.fillna(-1).astype(int)
    )

    df["has_cwe"] = df["cwe_final"].notna().astype(int)

    df["total_references"] = (
        df["references_count_nvd"]
        .fillna(df["references_count"])
        .fillna(0)
        .astype(int)
    )

    # Sum of the three impact dimensions (range 0-6)
    df["total_impact_score"] = (
        df["confidentiality_score"] + df["integrity_score"] + df["availability_score"]
    )

    # Sum of access-related scores as a proxy for ease of exploitation (range 0-11)
    df["exploitability_proxy"] = (
        df["attack_vector_score"]
        + df["attack_complexity_score"]
        + df["privileges_required_score"]
        + df["user_interaction_score"]
    )

    return df


def select_features(df):
    feature_cols = [
        "base_score_final",
        "exploitability_score",
        "impact_score",
        "num_cpes",
        "total_references",
        "days_since_published",
        "year_published",
        "attack_vector_score",
        "attack_complexity_score",
        "privileges_required_score",
        "user_interaction_score",
        "confidentiality_score",
        "integrity_score",
        "availability_score",
        "is_network_based",
        "is_low_complexity",
        "no_privileges_needed",
        "no_user_interaction",
        "high_conf_impact",
        "high_integ_impact",
        "high_avail_impact",
        "is_ransomware_associated",
        "has_cwe",
        "total_impact_score",
        "exploitability_proxy",
        "exploited_in_wild",
    ]

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns after feature engineering: {missing}")

    return df[feature_cols].copy()


def impute_median(df):
    # Columns with NaN after feature engineering (CVEs pending NVD analysis)
    # Median is used instead of mean to avoid distortion from CVSS score outliers
    cols_to_impute = ["base_score_final", "exploitability_score", "impact_score"]
    for col in cols_to_impute:
        median_val = df[col].median()
        df[col] = df[col].fillna(median_val)
        print(f"  {col}: imputed {df[col].isna().sum()} nulls with median={median_val:.3f}")
    return df


def print_summary(df):
    print(f"\nRows:     {len(df):,}")
    print(f"Features: {len(df.columns) - 1}  (+ 1 target)")

    vc = df["exploited_in_wild"].value_counts()
    total = len(df)
    print("\nTarget distribution:")
    print(f"  Exploited:     {vc.get(True,  0):>7,}  ({vc.get(True,  0) / total * 100:.2f}%)")
    print(f"  Not exploited: {vc.get(False, 0):>7,}  ({vc.get(False, 0) / total * 100:.2f}%)")

    nulls = df.isnull().sum()
    nulls = nulls[nulls > 0]
    print("\nNull values per feature:")
    if nulls.empty:
        print("  None")
    else:
        print(nulls.to_string())

    print("\nFeature list:")
    for col in df.columns:
        print(f"  {col}")


df = load_data(INPUT_PATH)

print("Encoding CVSS categorical features ...")
df = encode_attack_vector(df)
df = encode_attack_complexity(df)
df = encode_privileges_required(df)
df = encode_user_interaction(df)
df = encode_impact(df)

print("Adding binary flags ...")
df = add_binary_flags(df)

print("Adding derived features ...")
df = add_derived_features(df)

print("Selecting final feature set ...")
model_df = select_features(df)

print("Imputing nulls with median ...")
model_df = impute_median(model_df)

print(f"Saving to {OUTPUT_PATH} ...")
model_df.to_csv(OUTPUT_PATH, index=False)

print_summary(model_df)