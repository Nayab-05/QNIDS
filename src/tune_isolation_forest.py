"""
STAGE 7b - Isolation Forest ablation: alag feature-sets aur thresholds try karo,
taake pata chale zero-day detection kis setting mein sab se behtar hota hai.

Run: python src\\tune_isolation_forest.py
"""
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

TRAIN_PKL   = "data/processed/train.pkl"
VAL_PKL     = "data/processed/val.pkl"
ZERODAY_PKL = "data/processed/zero_day_holdout.pkl"
FEAT_JSON   = "outputs/selected_features.json"
FEAT_TXT    = "data/processed/feature_columns.txt"
SEED = 42

PERCENTILES = [1.0, 5.0, 10.0]


def evaluate(iso, sel, val_df, zday_df, percentile):
    val_benign = val_df[val_df["Label"] == "BENIGN"]
    scores_benign = iso.decision_function(val_benign[sel].values)
    threshold = np.percentile(scores_benign, percentile)
    false_alarm = (scores_benign < threshold).mean()

    attack_rates = {}
    for label, g in val_df[val_df["Label"] != "BENIGN"].groupby("Label"):
        scores = iso.decision_function(g[sel].values)
        attack_rates[label] = (scores < threshold).mean()

    zday_rates = {}
    for label, g in zday_df.groupby("Label"):
        scores = iso.decision_function(g[sel].values)
        zday_rates[label] = (scores < threshold).mean()

    return threshold, false_alarm, attack_rates, zday_rates


def main():
    print("[1] Loading data...")
    train_df = pd.read_pickle(TRAIN_PKL)
    val_df   = pd.read_pickle(VAL_PKL)
    zday_df  = pd.read_pickle(ZERODAY_PKL)

    with open(FEAT_JSON) as f:
        qpso_features = json.load(f)["selected_features"]
    with open(FEAT_TXT) as f:
        all_features = [l.strip() for l in f if l.strip()]

    feature_sets = {
        "QPSO_15": qpso_features,
        "ALL_69": all_features,
    }

    train_benign = train_df[train_df["Label"] == "BENIGN"]

    results = []
    for fname, feats in feature_sets.items():
        print(f"\n[2] Training IsolationForest on feature set: {fname} "
              f"({len(feats)} features)...")
        iso = IsolationForest(
            n_estimators=150, contamination="auto",
            n_jobs=-1, random_state=SEED)
        iso.fit(train_benign[feats].values)

        for p in PERCENTILES:
            threshold, false_alarm, attack_rates, zday_rates = evaluate(
                iso, feats, val_df, zday_df, p)
            avg_zday = np.mean(list(zday_rates.values()))
            print(f"  [{fname} | percentile={p}] false_alarm={false_alarm:.2%} "
                  f"| avg_zero-day_flagged={avg_zday:.2%}")
            results.append({
                "feature_set": fname, "percentile": p,
                "threshold": threshold, "false_alarm": false_alarm,
                "attack_rates": attack_rates, "zday_rates": zday_rates,
            })

    print("\n" + "=" * 80)
    print("FULL COMPARISON TABLE")
    print("=" * 80)
    for r in results:
        print(f"\n-- {r['feature_set']} | percentile={r['percentile']} "
              f"| threshold={r['threshold']:.4f} | "
              f"false_alarm={r['false_alarm']:.2%} --")
        print("  Known attacks flagged:")
        for k, v in r["attack_rates"].items():
            print(f"    {k:12s} {v:.2%}")
        print("  Zero-day flagged:")
        for k, v in r["zday_rates"].items():
            print(f"    {k:12s} {v:.2%}")

    with open("outputs/if_ablation_results.json", "w") as f:
        json.dump(results, f, indent=2, default=float)
    print("\nSaved -> outputs/if_ablation_results.json")


if __name__ == "__main__":
    main()