"""
Anita ke CSVSimulator demo ke liye 2 files banata hai:
  1. outputs/benign_sample.csv   - sirf BENIGN traffic
  2. outputs/attacks_sample.csv  - known attacks (DoS, DDoS, PortScan, etc)

test.pkl se sample liya hai (train.pkl se NAHI) - kyunke test.pkl
kabhi kisi training/tuning decision ke liye use nahi hua, isliye demo
ke liye zyada "clean" evidence hai.

Run: python src\\generate_demo_csvs.py
"""
import pandas as pd

TEST_PKL = "data/processed/test.pkl"
OUT_BENIGN  = "outputs/benign_sample.csv"
OUT_ATTACKS = "outputs/attacks_sample.csv"

N_BENIGN = 300          # kitni BENIGN rows chahiye
N_PER_ATTACK = 100      # har attack class se kitni rows chahiye
SEED = 42


def main():
    print("[1] Loading test.pkl...")
    df = pd.read_pickle(TEST_PKL)
    print(f"  Total test rows: {len(df):,}")
    print(df["Label"].value_counts().to_string())

    print(f"\n[2] Sampling {N_BENIGN} BENIGN rows...")
    benign = df[df["Label"] == "BENIGN"].sample(
        n=min(N_BENIGN, (df["Label"] == "BENIGN").sum()), random_state=SEED)
    benign.to_csv(OUT_BENIGN, index=False)
    print(f"  Saved -> {OUT_BENIGN} ({len(benign)} rows)")

    print(f"\n[3] Sampling up to {N_PER_ATTACK} rows per attack class...")
    attack_df = df[df["Label"] != "BENIGN"]
    parts = []
    for label, g in attack_df.groupby("Label"):
        n = min(N_PER_ATTACK, len(g))
        parts.append(g.sample(n=n, random_state=SEED))
        print(f"  {label:12s} {n} rows")
    attacks = pd.concat(parts).sample(frac=1, random_state=SEED)  # shuffle
    attacks.to_csv(OUT_ATTACKS, index=False)
    print(f"\n  Saved -> {OUT_ATTACKS} ({len(attacks)} rows)")


if __name__ == "__main__":
    main()