"""
STAGE 7 (FINAL) - Isolation Forest training, ALL 69 features par (QPSO 15 nahi).

Decision: ablation test (tune_isolation_forest.py) ne dikhaya ke IF ko ALL 69
features par train karna zero-day detection ke liye behtar hai, kyunke
QPSO ke 15 features sirf RF classification ke liye optimize hue the.

Run: python src\\train_isolation_forest.py
"""
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

TRAIN_PKL    = "data/processed/train.pkl"
VAL_PKL      = "data/processed/val.pkl"
ZERODAY_PKL  = "data/processed/zero_day_holdout.pkl"
FEAT_TXT     = "data/processed/feature_columns.txt"   # <- ab QPSO json nahi, ALL features
MODEL_OUT    = "models/iso_forest.pkl"
SEED = 42

BENIGN_PERCENTILE = 5.0    # <- ablation se decide hua


def main():
    print("[1] Loading data + ALL feature columns...")
    train_df = pd.read_pickle(TRAIN_PKL)
    val_df   = pd.read_pickle(VAL_PKL)
    zday_df  = pd.read_pickle(ZERODAY_PKL)
    with open(FEAT_TXT) as f:
        sel = [l.strip() for l in f if l.strip()]
    print(f"  Using {len(sel)} features (ALL, not QPSO subset)")

    train_benign = train_df[train_df["Label"] == "BENIGN"]
    print(f"  BENIGN rows for training: {len(train_benign):,}")

    X_train = train_benign[sel].values

    print("\n[2] Training IsolationForest (BENIGN-only, ALL features)...")
    iso = IsolationForest(
        n_estimators=200, contamination="auto",
        n_jobs=-1, random_state=SEED)
    iso.fit(X_train)

    print("\n[3] Setting threshold from validation BENIGN traffic...")
    val_benign = val_df[val_df["Label"] == "BENIGN"]
    scores_benign_val = iso.decision_function(val_benign[sel].values)
    threshold = np.percentile(scores_benign_val, BENIGN_PERCENTILE)
    print(f"  Threshold: {threshold:.4f} (percentile={BENIGN_PERCENTILE})")
    false_alarm_rate = (scores_benign_val < threshold).mean()
    print(f"  False-alarm rate on BENIGN val: {false_alarm_rate:.2%}")

    print("\n[4] Testing separation on KNOWN ATTACKS (val set)...")
    val_attacks = val_df[val_df["Label"] != "BENIGN"]
    for label, g in val_attacks.groupby("Label"):
        scores = iso.decision_function(g[sel].values)
        flagged = (scores < threshold).mean()
        print(f"  {label:12s} n={len(g):6,} | flagged-as-anomaly: {flagged:.2%}")

    print("\n[5] Testing separation on ZERO-DAY holdout...")
    for label, g in zday_df.groupby("Label"):
        scores = iso.decision_function(g[sel].values)
        flagged = (scores < threshold).mean()
        print(f"  {label:12s} n={len(g):6,} | flagged-as-anomaly: {flagged:.2%}")

    joblib.dump({"model": iso, "features": sel, "threshold": float(threshold)},
                MODEL_OUT)
    print(f"\nSaved -> {MODEL_OUT} ({len(sel)} features, threshold={threshold:.4f})")


if __name__ == "__main__":
    main()