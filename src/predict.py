"""
STAGE 8 - predict.py: RF (Layer 1) + Isolation Forest (Layer 2) combine karta hai.

Anita ka GUI isay is tarah use karega:
    import predict
    predict.load_model()
    result = predict.predict(features_dict)   # features_dict = CICFlowTracker ka output

Contract (roadmap ke mutabiq):
    predict() ek dict return karta hai:
        {
          "decision": "Normal" | "Known Attack — [ClassName]" | "Suspicious / Zero-day",
          "label": RF ki predicted class (e.g. "DoS", "BENIGN"),
          "rf_confidence": float 0-1,
          "if_score": float (zyada = zyada normal, kam/negative = zyada anomalous),
          "missing_features": list (agar koi feature missing thi)
        }
"""
import joblib
import numpy as np

RF_PATH = "models/rf_model.pkl"
IF_PATH = "models/iso_forest.pkl"

# Roadmap ke thresholds (validation data se justify: RF ka macro-F1 0.996 hai,
# is liye high threshold rakhna safe hai)
RF_NORMAL_CONF_THRESHOLD = 0.85
RF_ATTACK_CONF_THRESHOLD = 0.70

_state = {"rf": None, "rf_features": None, "iso": None,
          "if_features": None, "if_threshold": None, "loaded": False}


def load_model():
    """Models sirf EK BAAR load karo (startup par), har predict() call par nahi."""
    rf_bundle = joblib.load(RF_PATH)
    if_bundle = joblib.load(IF_PATH)

    _state["rf"] = rf_bundle["model"]
    _state["rf_features"] = rf_bundle["features"]
    _state["iso"] = if_bundle["model"]
    _state["if_features"] = if_bundle["features"]
    _state["if_threshold"] = if_bundle["threshold"]
    _state["loaded"] = True

    print(f"[predict.py] Models loaded: RF uses {len(_state['rf_features'])} "
          f"features, IF uses {len(_state['if_features'])} features.")


def _extract(features_dict, required):
    """Dict se features ko SAHI ORDER mein nikalo. Missing ho to batao, crash mat karo."""
    missing = [f for f in required if f not in features_dict]
    row = [features_dict.get(f, 0.0) for f in required]  # missing = 0.0 (safe default)
    return np.array(row, dtype=np.float64).reshape(1, -1), missing


def predict(features_dict):
    if not _state["loaded"]:
        load_model()

    all_missing = set()

    # --- Layer 1: Random Forest ---
    X_rf, missing_rf = _extract(features_dict, _state["rf_features"])
    all_missing.update(missing_rf)
    rf_pred = _state["rf"].predict(X_rf)[0]
    rf_proba = _state["rf"].predict_proba(X_rf)[0]
    rf_confidence = float(np.max(rf_proba))

    # --- Layer 2: Isolation Forest ---
    X_if, missing_if = _extract(features_dict, _state["if_features"])
    all_missing.update(missing_if)
    if_score = float(_state["iso"].decision_function(X_if)[0])
    is_anomaly = if_score < _state["if_threshold"]

    # --- Decision logic (roadmap ke mutabiq) ---
    if rf_pred == "BENIGN" and rf_confidence >= RF_NORMAL_CONF_THRESHOLD and not is_anomaly:
        decision = "Normal"
    elif rf_pred != "BENIGN" and rf_confidence >= RF_ATTACK_CONF_THRESHOLD:
        decision = f"Known Attack - {rf_pred}"
    elif is_anomaly:
        decision = "Suspicious / Zero-day"
    else:
        decision = "Normal"

    return {
        "decision": decision,
        "label": str(rf_pred),
        "rf_confidence": round(rf_confidence, 4),
        "if_score": round(if_score, 4),
        "missing_features": sorted(all_missing),
    }


if __name__ == "__main__":
    # Chhota self-test: sab features 0 (kaafi hoga load-check ke liye)
    print("[predict.py] Self-test chal raha hai...")
    load_model()
    dummy = {f: 0.0 for f in _state["if_features"]}
    result = predict(dummy)
    print("Result:", result)
    print("\nAgar 'decision', 'label', 'rf_confidence', 'if_score' sab aaye")
    print("bina crash hue, to predict.py sahi kaam kar raha hai.")