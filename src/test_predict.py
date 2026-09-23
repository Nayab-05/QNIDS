"""
STAGE 3 (roadmap) - predict.py ke 5 unit tests.

Test cases:
  1. Normal (BENIGN) flow
  2. DoS flow
  3. DDoS flow
  4. PortScan flow
  5. Malformed/empty input (crash nahi hona chahiye)

Run: python src\\test_predict.py
"""
import sys

import pandas as pd

sys.path.insert(0, "src")
import predict

VAL_PKL = "data/processed/val.pkl"


def row_to_dict(row, feature_cols):
    return {c: float(row[c]) for c in feature_cols}


def run_case(name, features_dict, expect_in_decision=None):
    print(f"\n--- Test: {name} ---")
    try:
        result = predict.predict(features_dict)
        print(f"  Result: {result}")
        ok = True
        if expect_in_decision is not None:
            ok = expect_in_decision in result["decision"]
        status = "PASS" if ok else "FAIL (expected decision containing "\
                                    f"'{expect_in_decision}')"
        print(f"  Status: {status}")
        return ok
    except Exception as e:
        print(f"  CRASHED: {type(e).__name__}: {e}")
        print("  Status: FAIL (predict() should never crash)")
        return False


def main():
    print("[1] Loading model + validation data...")
    predict.load_model()
    val_df = pd.read_pickle(VAL_PKL)
    feature_cols = [c for c in val_df.columns if c != "Label"]

    results = []

    # Test 1: Normal
    row = val_df[val_df["Label"] == "BENIGN"].iloc[0]
    results.append(run_case("Normal (BENIGN) flow",
                             row_to_dict(row, feature_cols),
                             expect_in_decision="Normal"))

    # Test 2: DoS
    row = val_df[val_df["Label"] == "DoS"].iloc[0]
    results.append(run_case("DoS flow",
                             row_to_dict(row, feature_cols),
                             expect_in_decision="DoS"))

    # Test 3: DDoS
    row = val_df[val_df["Label"] == "DDoS"].iloc[0]
    results.append(run_case("DDoS flow",
                             row_to_dict(row, feature_cols),
                             expect_in_decision="DDoS"))

    # Test 4: PortScan
    row = val_df[val_df["Label"] == "PortScan"].iloc[0]
    results.append(run_case("PortScan flow",
                             row_to_dict(row, feature_cols),
                             expect_in_decision="PortScan"))

    # Test 5: Malformed / empty input -> crash NAHI hona chahiye
    print("\n--- Test: Malformed/empty input ---")
    try:
        result = predict.predict({})
        crashed = False
        print(f"  Result: {result}")
        has_missing = len(result["missing_features"]) > 0
        print(f"  missing_features reported: {has_missing}")
        status = "PASS" if has_missing else "FAIL (missing_features khali nahi honi chahiye)"
        print(f"  Status: {status}")
        results.append(has_missing)
    except Exception as e:
        print(f"  CRASHED: {type(e).__name__}: {e}")
        print("  Status: FAIL (empty dict se crash NAHI hona chahiye)")
        results.append(False)

    print("\n" + "=" * 50)
    print(f"SUMMARY: {sum(results)}/{len(results)} tests passed")
    print("=" * 50)


if __name__ == "__main__":
    main()