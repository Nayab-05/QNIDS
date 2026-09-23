"""
STAGE 3-4 - QPSO Feature Selection.

Kya karta hai:
  1. data/processed/train.pkl load karo
  2. Chhota BALANCED sample banao (QPSO speed ke liye; final RF baad mein
     poore train.pkl par train hoga, sirf feature-choosing yahan sample par hoti hai)
  3. QPSO chalao -> 15-25 best features dhoondo
  4. Result save karo: outputs/selected_features.json

Run: python src\\qpso_feature_selection.py
"""
import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

# ---------------- CONFIG ----------------
TRAIN_PKL     = "data/processed/train.pkl"
OUT_DIR       = "outputs"
MIN_FEAT, MAX_FEAT = 15, 25
N_PARTICLES   = 20
N_ITER        = 30
ALPHA_MAX, ALPHA_MIN = 1.0, 0.5
LAMBDA        = 0.05          # feature-count penalty
PER_CLASS_CAP = 6000          # QPSO sample: har class se max itni rows
SEED          = 42
# -----------------------------------------


class QPSOFeatureSelector:
    """Quantum-inspired PSO, feature-selection ke liye."""

    def __init__(self, n_features, fitness_fn, min_feat, max_feat,
                 n_particles, n_iter, alpha_max, alpha_min, seed):
        self.D = n_features
        self.fitness_fn = fitness_fn
        self.min_feat, self.max_feat = min_feat, max_feat
        self.N, self.T = n_particles, n_iter
        self.a_max, self.a_min = alpha_max, alpha_min
        self.rng = np.random.default_rng(seed)
        self.cache = {}
        self.history = []

        # >>> FIX: threshold ab 0.5 nahi, dynamically calculate karo <
        # Taake random particle ka average selected-count 15-25 ke BEECH mein aaye,
        # 25 par hamesha clip na ho. target_mid features chahiye out of D total.
        target_mid = (min_feat + max_feat) / 2
        self.threshold = 1.0 - (target_mid / n_features)
        print(f"  [QPSO] selection threshold set to {self.threshold:.3f} "
              f"(target ~{target_mid:.0f} features out of {n_features})")

    def decode(self, x):
        """[0,1]^D vector -> feature indices (15-25 ke beech)."""
        k = int((x > self.threshold).sum())
        k = max(self.min_feat, min(self.max_feat, k))
        idx = np.argsort(-x)[:k]
        return tuple(sorted(idx.tolist()))

    def evaluate(self, x):
        idx = self.decode(x)
        if idx not in self.cache:
            self.cache[idx] = self.fitness_fn(np.array(idx))
        return self.cache[idx], idx

    def run(self):
        rng = self.rng
        X = rng.random((self.N, self.D))
        pbest = X.copy()
        pfit = np.full(self.N, -np.inf)
        gbest, gfit, gidx = None, -np.inf, None

        for i in range(self.N):
            pfit[i], idx = self.evaluate(X[i])
            if pfit[i] > gfit:
                gfit, gbest, gidx = pfit[i], X[i].copy(), idx

        for t in range(self.T):
            t0 = time.time()
            alpha = self.a_max - (self.a_max - self.a_min) * t / max(1, self.T - 1)
            mbest = pbest.mean(axis=0)

            for i in range(self.N):
                phi = rng.random(self.D)
                p = phi * pbest[i] + (1 - phi) * gbest
                u = np.clip(rng.random(self.D), 1e-12, 1.0)
                sign = np.where(rng.random(self.D) < 0.5, -1.0, 1.0)
                X[i] = p + sign * alpha * np.abs(mbest - X[i]) * np.log(1.0 / u)
            X = np.clip(X, 0.0, 1.0)

            for i in range(self.N):
                f, idx = self.evaluate(X[i])
                if f > pfit[i]:
                    pfit[i], pbest[i] = f, X[i].copy()
                    if f > gfit:
                        gfit, gbest, gidx = f, X[i].copy(), idx

            self.history.append(float(gfit))
            print(f"  iter {t+1:02d}/{self.T} | best fitness={gfit:.4f} "
                  f"| #features={len(gidx)} | alpha={alpha:.2f} "
                  f"| {time.time()-t0:.1f}s")

        return list(gidx), gfit


def balanced_sample(df, cap, seed):
    parts = [g.sample(min(len(g), cap), random_state=seed)
             for _, g in df.groupby("Label")]
    return pd.concat(parts).sample(frac=1, random_state=seed)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print("[1] Loading train.pkl...")
    df = pd.read_pickle(TRAIN_PKL)
    feat_cols = [c for c in df.columns if c != "Label"]
    print(f"  Full train shape: {df.shape}")

    print("\n[2] Building balanced sample for QPSO speed...")
    sub = balanced_sample(df, PER_CLASS_CAP, SEED)
    print(f"  Sample shape: {sub.shape}")
    print(sub["Label"].value_counts().to_string())

    X_all = sub[feat_cols].values
    y_all = sub["Label"].values
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_all, y_all, test_size=0.3, stratify=y_all, random_state=SEED)

    def make_rf():
        return RandomForestClassifier(
            n_estimators=20, max_depth=12, n_jobs=-1,
            class_weight="balanced", random_state=SEED)

    def fitness(idx):
        clf = make_rf().fit(X_tr[:, idx], y_tr)
        f1 = f1_score(y_val, clf.predict(X_val[:, idx]), average="macro")
        penalty = LAMBDA * len(idx) / len(feat_cols)
        return f1 - penalty

    print(f"\n[3] Running QPSO ({N_PARTICLES} particles x {N_ITER} iterations)...")
    qpso = QPSOFeatureSelector(
        n_features=len(feat_cols), fitness_fn=fitness,
        min_feat=MIN_FEAT, max_feat=MAX_FEAT,
        n_particles=N_PARTICLES, n_iter=N_ITER,
        alpha_max=ALPHA_MAX, alpha_min=ALPHA_MIN, seed=SEED)
    best_idx, best_fit = qpso.run()
    selected = [feat_cols[i] for i in best_idx]

    print("\n[4] Comparing: ALL features vs QPSO-selected features...")
    f_all = f1_score(y_val, make_rf().fit(X_tr, y_tr).predict(X_val), average="macro")
    f_sel = f1_score(y_val,
                      make_rf().fit(X_tr[:, best_idx], y_tr).predict(X_val[:, best_idx]),
                      average="macro")
    print(f"  Macro-F1 with ALL {len(feat_cols)} features : {f_all:.4f}")
    print(f"  Macro-F1 with QPSO {len(selected)} features : {f_sel:.4f}")

    print(f"\nSELECTED {len(selected)} FEATURES (is exact order mein Anita ko bhejni hai):")
    for i, c in enumerate(selected, 1):
        print(f"  {i:2d}. {c}")

    result = {
        "selected_features": selected,
        "n_selected": len(selected),
        "n_total_features": len(feat_cols),
        "all_feature_columns": feat_cols,
        "macro_f1_all_features": float(f_all),
        "macro_f1_selected": float(f_sel),
        "best_fitness": float(best_fit),
        "convergence_history": qpso.history,
        "config": dict(n_particles=N_PARTICLES, n_iter=N_ITER,
                        lam=LAMBDA, per_class_cap=PER_CLASS_CAP, seed=SEED),
    }
    with open(f"{OUT_DIR}/selected_features.json", "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved -> {OUT_DIR}/selected_features.json")


if __name__ == "__main__":
    main()