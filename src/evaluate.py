"""
Full Evaluation - RF + Isolation Forest, TEST set (test.pkl) par.
Ye numbers FYP report mein final results ke tor par use hone hain,
kyunke test.pkl kabhi kisi decision (threshold, hyperparameter) ke liye
use nahi hua - ye asli unbiased performance hai.

Run: python src\\evaluate.py
"""
import json

import joblib
import matplotlib
matplotlib.use("Agg")   # GUI window na khole, seedha file save kare
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, f1_score

TEST_PKL    = "data/processed/test.pkl"
ZERODAY_PKL = "data/processed/zero_day_holdout.pkl"
RF_PATH     = "models/rf_model.pkl"
IF_PATH     = "models/iso_forest.pkl"
OUT_DIR     = "results"


def main():
    print("[1] Loading TEST set (kabhi chhua nahi gaya) + models...")
    test_df = pd.read_pickle(TEST_PKL)
    zday_df = pd.read_pickle(ZERODAY_PKL)
    rf_bundle = joblib.load(RF_PATH)
    if_bundle = joblib.load(IF_PATH)
    rf, rf_feats = rf_bundle["model"], rf_bundle["features"]
    iso, if_feats, threshold = (if_bundle["model"], if_bundle["features"],
                                 if_bundle["threshold"])
    print(f"  Test set: {test_df.shape}")

    # ---------- RF evaluation ----------
    print("\n[2] Random Forest evaluation (TEST set)...")
    X_test, y_test = test_df[rf_feats].values, test_df["Label"].values
    y_pred = rf.predict(X_test)

    report_str = classification_report(y_test, y_pred, digits=4)
    print(report_str)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    print(f"Macro-F1 (TEST): {macro_f1:.4f}")

    report_dict = classification_report(y_test, y_pred, digits=4, output_dict=True)
    pd.DataFrame(report_dict).T.to_csv(f"{OUT_DIR}/rf_test_classification_report.csv")

    # ---------- Confusion matrix ----------
    print("\n[3] Confusion matrix banate hain...")
    labels = sorted(set(y_test))
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)

    fig, ax = plt.subplots(figsize=(9, 7))
    sns.heatmap(cm_norm, annot=True, fmt=".2%", cmap="Blues",
                xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("RF Confusion Matrix (row-normalized) - TEST set")
    plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/confusion_matrix.png", dpi=150)
    plt.close()
    print(f"  Saved -> {OUT_DIR}/confusion_matrix.png")

    # ---------- Isolation Forest evaluation ----------
    print("\n[4] Isolation Forest evaluation (TEST set)...")
    test_benign = test_df[test_df["Label"] == "BENIGN"]
    scores_benign = iso.decision_function(test_benign[if_feats].values)
    false_alarm = (scores_benign < threshold).mean()
    print(f"  False-alarm rate on TEST BENIGN: {false_alarm:.2%}")

    if_results = {"false_alarm_rate": float(false_alarm), "known_attacks": {},
                  "zero_day": {}}

    print("\n  Known attacks flagged-as-anomaly (TEST):")
    for label, g in test_df[test_df["Label"] != "BENIGN"].groupby("Label"):
        scores = iso.decision_function(g[if_feats].values)
        flagged = (scores < threshold).mean()
        if_results["known_attacks"][label] = float(flagged)
        print(f"    {label:12s} n={len(g):6,} | {flagged:.2%}")

    print("\n  Zero-day holdout flagged-as-anomaly:")
    for label, g in zday_df.groupby("Label"):
        scores = iso.decision_function(g[if_feats].values)
        flagged = (scores < threshold).mean()
        if_results["zero_day"][label] = float(flagged)
        print(f"    {label:12s} n={len(g):6,} | {flagged:.2%}")

    # ---------- Save everything ----------
    summary = {
        "rf_macro_f1_test": float(macro_f1),
        "rf_accuracy_test": float(report_dict["accuracy"]),
        "if_results": if_results,
        "test_set_size": len(test_df),
    }
    with open(f"{OUT_DIR}/final_evaluation_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {OUT_DIR}/final_evaluation_summary.json")
    print(f"Saved -> {OUT_DIR}/rf_test_classification_report.csv")


if __name__ == "__main__":
    main()