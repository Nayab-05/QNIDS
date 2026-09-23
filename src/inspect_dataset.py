"""
STAGE 1 - CIC-IDS2017 dataset inspection (READ-ONLY).

Usage:
    python src\inspect_dataset.py data\raw                  # poora folder
    python src\inspect_dataset.py data\raw\<one_file>.csv   # sirf ek file

Ye script sirf report print karti hai. Koi data change ya save nahi hota.
"""
import glob
import os
import sys

import numpy as np
import pandas as pd

pd.set_option("display.width", 200)
pd.set_option("display.max_rows", 200)


def find_csvs(path):
    if os.path.isdir(path):
        return sorted(glob.glob(os.path.join(path, "*.csv")))
    return [path] if os.path.isfile(path) else []


def find_label_col(cols):
    """Label column dhoondo: strip + lowercase karke 'label' match."""
    hits = [c for c in cols if str(c).strip().lower() == "label"]
    return hits[0] if hits else None


def inspect_file(path):
    print("\n" + "=" * 90)
    print("FILE:", os.path.basename(path))
    print("=" * 90)

    # latin1: kuch labels mein non-UTF8 character hota hai (e.g. Web Attack)
    df = pd.read_csv(path, encoding="latin1", low_memory=False)
    n_rows, n_cols = df.shape
    print(f"Shape: {n_rows:,} rows x {n_cols} columns "
          f"| RAM: {df.memory_usage(deep=True).sum() / 1e6:.0f} MB")

    # --- Columns (repr() se leading/trailing spaces nazar aayenge) ---
    print("\n[1] COLUMN NAMES (repr, spaces visible):")
    for i, c in enumerate(df.columns):
        print(f"  {i:2d}: {c!r}")
    n_space = sum(1 for c in df.columns if c != str(c).strip())
    print(f"  -> {n_space} column names mein leading/trailing space hai")

    # --- Label column ---
    label_col = find_label_col(df.columns)
    print(f"\n[2] LABEL COLUMN: {label_col!r}")
    if label_col is None:
        print("  !! 'Label' column nahi mila. Upar ki list dekho.")
    else:
        vc = df[label_col].value_counts(dropna=False)
        print(f"  {len(vc)} unique labels:")
        for k, v in vc.items():
            print(f"  {k!r:45s} {v:>10,}  {v / n_rows:7.2%}")

    # --- Dtypes ---
    print("\n[3] DTYPES:")
    print(df.dtypes.value_counts().to_string())
    # >>> FIX (pandas 3): 'object' ki jagah numeric check use karo <
    obj_cols = [c for c in df.columns
                if c != label_col and not pd.api.types.is_numeric_dtype(df[c])]
    print(f"  Non-numeric columns (Label ke ilawa): {obj_cols if obj_cols else 'none'}")

    numeric = df.select_dtypes(include=[np.number])

    # --- NaN ---
    print("\n[4] NaN:")
    nan_per_col = df.isna().sum()
    nan_cols = nan_per_col[nan_per_col > 0]
    print(f"  Rows with >=1 NaN: {int(df.isna().any(axis=1).sum()):,}")
    print(nan_cols.to_string() if len(nan_cols) else "  No NaN found")

    # --- Infinity ---
    print("\n[5] INFINITY (+inf / -inf):")
    inf_mask = np.isinf(numeric)
    inf_per_col = inf_mask.sum()
    inf_cols = inf_per_col[inf_per_col > 0]
    print(f"  Rows with >=1 inf: {int(inf_mask.any(axis=1).sum()):,}")
    print(inf_cols.to_string() if len(inf_cols) else "  No inf found")
    del inf_mask

    # --- Extra checks jo preprocessing decisions ke liye chahiye ---
    print("\n[6] CONSTANT columns (<=1 unique value):")
    const = [c for c in numeric.columns if numeric[c].nunique(dropna=True) <= 1]
    print(" ", const if const else "none")

    print("\n[7] Columns with NEGATIVE values (count):")
    neg = (numeric < 0).sum()
    neg = neg[neg > 0]
    print(neg.to_string() if len(neg) else "  none")

    # --- Duplicates ---
    print("\n[8] DUPLICATE ROWS (is file ke andar, Label samet):")
    dups = int(df.duplicated().sum())
    print(f"  {dups:,} ({dups / n_rows:.2%})")

    # global duplicate check ke liye row hashes (memory-efficient)
    hashes = pd.util.hash_pandas_object(df, index=False).to_numpy()
    stripped_cols = [str(c).strip() for c in df.columns]
    label_counts = (df[label_col].astype(str).str.strip().value_counts()
                    if label_col else None)
    return stripped_cols, label_counts, hashes, n_rows


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    files = find_csvs(sys.argv[1])
    if not files:
        print(f"ERROR: '{sys.argv[1]}' mein koi CSV nahi mili.")
        sys.exit(1)
    print(f"{len(files)} CSV file(s) mili.")

    all_cols, all_hashes, total_rows = {}, [], 0
    total_labels = pd.Series(dtype="int64")
    for f in files:
        cols, lc, h, n = inspect_file(f)
        all_cols[os.path.basename(f)] = cols
        all_hashes.append(h)
        total_rows += n
        if lc is not None:
            total_labels = total_labels.add(lc, fill_value=0)

    # --- Cross-file summary ---
    print("\n" + "=" * 90)
    print("CROSS-FILE SUMMARY")
    print("=" * 90)
    ref_name, ref_cols = next(iter(all_cols.items()))
    same = True
    for name, cols in all_cols.items():
        if cols != ref_cols:
            same = False
            print(f"  !! Columns alag hain: {name} vs {ref_name}")
            print("     only here :", sorted(set(cols) - set(ref_cols)))
            print("     only in ref:", sorted(set(ref_cols) - set(cols)))
    if same:
        print("  Sab files mein column names (strip ke baad) same hain.")

    print(f"\n  Total rows (sab files): {total_rows:,}")
    if len(total_labels):
        print("\n  TOTAL LABEL DISTRIBUTION (strip ke baad):")
        for k, v in total_labels.sort_values(ascending=False).items():
            print(f"  {k!r:45s} {int(v):>10,}  {v / total_rows:7.2%}")

    if len(all_hashes) > 1:
        h = np.concatenate(all_hashes)
        g_dups = len(h) - len(np.unique(h))
        print(f"\n  GLOBAL duplicate rows (files ke beech mila kar): {g_dups:,} "
              f"({g_dups / len(h):.2%})")


if __name__ == "__main__":
    main()