"""
zero_day_sim.csv (v3) - features ko TRAINING MAXIMUM se bhi bahar dhakelte hain.

IF axis-aligned splits use karta hai, isliye ye combination-based
anomalies (v1: shuffle, v2: shuffle+scale) ko kamzor pakadta hai, lekin
per-feature out-of-range values ko bohot achi tarah pakadta hai.
Ye IF ki ek documented limitation/characteristic hai.

Run: python src\\generate_zero_day_sim.py
"""
import joblib
import numpy as np
import pandas as pd

TRAIN_PKL = "data/processed/train.pkl"
TEST_PKL  = "data/processed/test.pkl"
IF_PATH   = "models/iso_forest.pkl"
OUT_CSV   = "outputs/zero_day_sim.csv"
N_SIM = 200
FRAC_EXTREME = 0.3                     # 30% features ko extreme banao
EXTREME_FACTORS = [3.0, 5.0, 8.0]      # training max ka 3x-8x
SEED = 42


def main():
    rng = np.random.default_rng(SEED)

    print("[1] Loading train.pkl (per-feature max ke liye) + "
          "test.pkl (base rows) + IF model...")
    train_df = pd.read_pickle(TRAIN_PKL)
    test_df = pd.read_pickle(TEST_PKL)
    if_bundle = joblib.load(IF_PATH)
    iso, if_feats, threshold = (if_bundle["model"], if_bundle["features"],
                                 if_bundle["threshold"])

    train_benign = train_df[train_df["Label"] == "BENIGN"][if_feats]
    feat_max = train_benign.max().astype(np.float64)

    test_benign = (test_df[test_df["Label"] == "BENIGN"][if_feats]
                   .reset_index(drop=True).astype(np.float64))
    print(f"  BENIGN base pool: {len(test_benign):,} rows, {len(if_feats)} features")

    print(f"\n[2] Generating {N_SIM} synthetic flows "
          f"({FRAC_EXTREME:.0%} features pushed beyond training max)...")
    base_idx = rng.choice(len(test_benign), size=N_SIM, replace=True)
    synthetic = test_benign.iloc[base_idx].reset_index(drop=True).copy()

    n_extreme = int(len(if_feats) * FRAC_EXTREME)
    for row_i in range(N_SIM):
        cols_extreme = rng.choice(if_feats, size=n_extreme, replace=False)
        for col in cols_extreme:
            factor = rng.choice(EXTREME_FACTORS)
            base_val = max(feat_max[col], 1.0)   # max=0 wale columns ke liye fallback
            synthetic.loc[row_i, col] = base_val * factor

    synthetic["Label"] = "ZeroDaySim"

    print("\n[3] Testing with Isolation Forest...")
    scores = iso.decision_function(synthetic[if_feats].values)
    flagged = (scores < threshold).mean()
    print(f"  Flagged-as-anomaly: {flagged:.2%} (threshold={threshold:.4f})")
    print(f"  Score range: min={scores.min():.4f}, "
          f"mean={scores.mean():.4f}, max={scores.max():.4f}")

    synthetic.to_csv(OUT_CSV, index=False)
    print(f"\nSaved -> {OUT_CSV} ({N_SIM} rows)")


if __name__ == "__main__":
    main()