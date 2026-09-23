"""
STAGE 2 - CIC-IDS2017 preprocessing (leakage-safe).

Kya karta hai:
  1. Sab 8 CSV load + column names clean
  2. Web Attack label ka corrupted text fix
  3. RF classes mein consolidate karo (roadmap ke mutabiq)
  4. Bot/Infiltration/Heartbleed = zero-day holdout (RF/QPSO inhe kabhi nahi dekhते)
  5. inf -> NaN -> drop; bad-duration rows drop
  6. Constant columns hatao (FULL combined data par check karke)
  7. Duplicate rows hatao
  8. Train / Val / Test split (stratified, sirf yahi split baad ke sab steps use karenge)
  9. Sab kuch data/processed/ mein save

Run: python src\preprocessing.py
"""
import glob
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

RAW_DIR = "data/raw"
OUT_DIR = "data/processed"
SEED = 42

# Roadmap ke 6 RF classes
LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "WebAttack": "WebAttack",
}
# Ye teeno RF training mein kabhi shamil nahi honge -> zero-day test set
ZERO_DAY_LABELS = {"Bot", "Infiltration", "Heartbleed"}


def clean_label(raw: str) -> str:
    """Corrupted 'Web Attack ...' text fix + whitespace clean."""
    s = str(raw).strip()
    if s.startswith("Web Attack"):
        return "WebAttack"
    return s


def load_all(raw_dir):
    files = sorted(glob.glob(os.path.join(raw_dir, "*.csv")))
    assert files, f"{raw_dir} mein CSV nahi mili"
    frames = []
    for f in files:
        d = pd.read_csv(f, encoding="latin1", low_memory=False)
        d.columns = d.columns.str.strip()
        frames.append(d)
        print(f"  loaded {os.path.basename(f):55s} {d.shape}")
    df = pd.concat(frames, ignore_index=True)
    print(f"\nCombined shape: {df.shape}")
    return df


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print("[1] Loading + combining 8 CSV files...")
    df = load_all(RAW_DIR)

    print("\n[2] Fixing Web Attack labels + cleaning...")
    df["Label"] = df["Label"].apply(clean_label)

    # Known duplicate column
    if "Fwd Header Length.1" in df.columns:
        df = df.drop(columns=["Fwd Header Length.1"])
        print("  Dropped duplicate column: Fwd Header Length.1")

    print("\n[3] Splitting off zero-day holdout (Bot, Infiltration, Heartbleed)...")
    is_zeroday = df["Label"].isin(ZERO_DAY_LABELS)
    zero_day_df = df[is_zeroday].copy()
    df = df[~is_zeroday].copy()
    print(f"  Zero-day holdout: {zero_day_df.shape[0]:,} rows")
    print(f"  Remaining for RF/QPSO: {df.shape[0]:,} rows")

    print("\n[4] Mapping labels to consolidated classes...")
    df["Label"] = df["Label"].map(LABEL_MAP)
    unmapped = df["Label"].isna().sum()
    if unmapped:
        print(f"  !! WARNING: {unmapped} rows ka label map nahi hua, drop kar rahe hain")
        df = df.dropna(subset=["Label"])
    print(df["Label"].value_counts().to_string())

    feat_cols = [c for c in df.columns if c != "Label"]

    print("\n[5] Handling inf / NaN...")
    for d in (df, zero_day_df):
        d[feat_cols] = d[feat_cols].apply(pd.to_numeric, errors="coerce")
    n_before = len(df)
    df[feat_cols] = df[feat_cols].replace([np.inf, -np.inf], np.nan)
    n_nan_rows = df[feat_cols].isna().any(axis=1).sum()
    df = df.dropna(subset=feat_cols)
    print(f"  Dropped {n_nan_rows:,} rows with NaN/inf ({n_nan_rows/n_before:.3%})")

    print("\n[6] Dropping rows with negative Duration/IAT (data-quality bugs)...")
    bad_time_cols = [c for c in feat_cols if ("Duration" in c or "IAT" in c)
                      and "Init_Win" not in c]
    n_before = len(df)
    neg_mask = (df[bad_time_cols] < 0).any(axis=1)
    df = df[~neg_mask]
    print(f"  Dropped {neg_mask.sum():,} rows ({neg_mask.sum()/n_before:.3%})")

    print("\n[7] Dropping constant columns (checked on FULL combined data)...")
    const_cols = [c for c in feat_cols if df[c].nunique(dropna=True) <= 1]
    print(f"  Constant columns found: {const_cols}")
    df = df.drop(columns=const_cols)
    zero_day_df = zero_day_df.drop(columns=[c for c in const_cols
                                             if c in zero_day_df.columns])
    feat_cols = [c for c in feat_cols if c not in const_cols]

    print("\n[8] Dropping duplicate rows...")
    n_before = len(df)
    df = df.drop_duplicates()
    print(f"  Dropped {n_before - len(df):,} duplicates "
          f"({(n_before - len(df))/n_before:.2%})")

    df[feat_cols] = df[feat_cols].astype(np.float32)
    zero_day_df[feat_cols] = zero_day_df[feat_cols].astype(np.float32)

    print(f"\nFinal cleaned shape: {df.shape}")
    print(df["Label"].value_counts().to_string())

    print("\n[9] Train / Val / Test split (70 / 15 / 15, stratified)...")
    train_df, temp_df = train_test_split(
        df, test_size=0.30, stratify=df["Label"], random_state=SEED)
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, stratify=temp_df["Label"], random_state=SEED)

    print(f"  train: {train_df.shape} | val: {val_df.shape} | test: {test_df.shape}")

    train_df.to_pickle(f"{OUT_DIR}/train.pkl")
    val_df.to_pickle(f"{OUT_DIR}/val.pkl")
    test_df.to_pickle(f"{OUT_DIR}/test.pkl")
    zero_day_df.to_pickle(f"{OUT_DIR}/zero_day_holdout.pkl")
    with open(f"{OUT_DIR}/feature_columns.txt", "w") as f:
        f.write("\n".join(feat_cols))

    print(f"\nSaved to {OUT_DIR}/: train.pkl, val.pkl, test.pkl, "
          f"zero_day_holdout.pkl, feature_columns.txt")
    print(f"Total usable features: {len(feat_cols)}")


if __name__ == "__main__":
    main()