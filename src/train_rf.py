"""
STAGE 6 - Random Forest training (QPSO-selected 15 features par).

Kya karta hai:
  1. train.pkl + val.pkl load karo
  2. selected_features.json se 15 features lo
  3. RF train karo poore train.pkl par (QPSO wale chhote sample par nahi)
  4. val.pkl par evaluate karo, model save karo

Run: python src\\train_rf.py
"""
import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score

TRAIN_PKL = "data/processed/train.pkl"
VAL_PKL   = "data/processed/val.pkl"
FEAT_JSON = "outputs/selected_features.json"
MODEL_OUT = "models/rf_model.pkl"
SEED = 42


def main():
    print("[1] Loading data + selected features...")
    train_df = pd.read_pickle(TRAIN_PKL)
    val_df   = pd.read_pickle(VAL_PKL)
    with open(FEAT_JSON) as f:
        sel = json.load(f)["selected_features"]
    print(f"  Using {len(sel)} features: {sel}")

    X_train, y_train = train_df[sel].values, train_df["Label"].values
    X_val, y_val     = val_df[sel].values, val_df["Label"].values

    print(f"\n[2] Training RandomForest on {X_train.shape[0]:,} rows...")
    t0 = time.time()
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=20, n_jobs=-1,
        class_weight="balanced", random_state=SEED)
    clf.fit(X_train, y_train)
    print(f"  Trained in {time.time()-t0:.1f}s")

    print("\n[3] Evaluating on validation set...")
    y_pred = clf.predict(X_val)
    print(classification_report(y_val, y_pred, digits=4))
    macro_f1 = f1_score(y_val, y_pred, average="macro")
    print(f"Macro-F1 (validation): {macro_f1:.4f}")

    print("\n[4] Feature importances:")
    for name, imp in sorted(zip(sel, clf.feature_importances_),
                             key=lambda x: -x[1]):
        print(f"  {imp:.4f}  {name}")

    joblib.dump({"model": clf, "features": sel}, MODEL_OUT)
    print(f"\nSaved -> {MODEL_OUT}")


if __name__ == "__main__":
    main()