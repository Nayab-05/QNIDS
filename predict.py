"""
predict.py — QNIDS Dual-Layer Prediction Interface
====================================================
Integrates Partner A's RF + Isolation Forest models
with Anita's GUI via QNIDSPredictor wrapper.
"""

import os
import joblib
import numpy as np
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# ── Absolute model paths (works from any working directory)
_BASE = os.path.dirname(os.path.abspath(__file__))
RF_PATH = os.path.join(_BASE, "models", "rf_model.pkl")
IF_PATH = os.path.join(_BASE, "models", "iso_forest.pkl")

# ── RF thresholds (Partner A's values)
RF_NORMAL_CONF_THRESHOLD = 0.85
RF_ATTACK_CONF_THRESHOLD = 0.70

# ── Internal state
_state = {
    "rf":           None,
    "rf_features":  None,
    "iso":          None,
    "if_features":  None,
    "if_threshold": None,
    "loaded":       False,
}


def load_models():
    """
    Load RF and Isolation Forest models from disk.
    Called once at startup — not on every prediction.
    """
    if _state["loaded"]:
        return

    if not os.path.exists(RF_PATH):
        print(f"[predict] WARNING: RF model not found at {RF_PATH}")
        print("[predict] Running in MOCK mode.")
        return

    try:
        rf_bundle = joblib.load(RF_PATH)
        if_bundle = joblib.load(IF_PATH)

        _state["rf"]           = rf_bundle["model"]
        _state["rf_features"]  = rf_bundle["features"]
        _state["iso"]          = if_bundle["model"]
        _state["if_features"]  = if_bundle["features"]
        _state["if_threshold"] = if_bundle["threshold"]
        _state["loaded"]       = True

        print(f"[predict] RF loaded — {len(_state['rf_features'])} features")
        print(f"[predict] IF loaded — {len(_state['if_features'])} features")
        print(f"[predict] IF threshold — {_state['if_threshold']:.4f}")

    except Exception as e:
        print(f"[predict] Model load error: {e}")
        print("[predict] Falling back to MOCK mode.")


# Alias for Partner A's naming convention
load_model = load_models


def _extract(features_dict: dict, required: list):
    """Extract features in correct order. Missing = 0.0."""
    missing = [f for f in required if f not in features_dict]
    row     = [features_dict.get(f, 0.0) for f in required]
    return np.array(row, dtype=np.float64).reshape(1, -1), missing


def predict(features_dict: dict) -> dict:
    """
    Run dual-layer prediction on one network flow.

    Parameters
    ----------
    features_dict : dict
        CICFlowTracker output — feature_name → float value.

    Returns
    -------
    dict with keys:
        decision        : "Normal" | "Known Attack - <class>" | "Suspicious / Zero-day"
        label           : RF predicted class string
        rf_confidence   : float 0.0 – 1.0
        if_score        : float (lower/negative = more anomalous)
        missing_features: list of missing feature names
    """
    if not _state["loaded"]:
        return _mock_predict()

    try:
        all_missing = set()

        # Layer 1 — Random Forest
        X_rf, miss_rf = _extract(features_dict, _state["rf_features"])
        all_missing.update(miss_rf)
        rf_pred       = _state["rf"].predict(X_rf)[0]
        rf_proba      = _state["rf"].predict_proba(X_rf)[0]
        rf_confidence = float(np.max(rf_proba))

        # Layer 2 — Isolation Forest
        X_if, miss_if = _extract(features_dict, _state["if_features"])
        all_missing.update(miss_if)
        if_score  = float(_state["iso"].decision_function(X_if)[0])
        is_anomaly = if_score < _state["if_threshold"]

        # Decision logic
        if (rf_pred == "BENIGN"
                and rf_confidence >= RF_NORMAL_CONF_THRESHOLD
                and not is_anomaly):
            decision = "Normal"
        elif rf_pred != "BENIGN" and rf_confidence >= RF_ATTACK_CONF_THRESHOLD:
            decision = f"Known Attack - {rf_pred}"
        elif is_anomaly:
            decision = "Suspicious / Zero-day"
        else:
            decision = "Normal"

        return {
            "decision":         decision,
            "label":            str(rf_pred),
            "rf_confidence":    round(rf_confidence, 4),
            "if_score":         round(if_score, 4),
            "missing_features": sorted(all_missing),
        }

    except Exception as e:
        print(f"[predict] Prediction error: {e}")
        return _mock_predict()


def _mock_predict() -> dict:
    """Fallback mock when models are not loaded."""
    import random
    labels    = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack"]
    label     = random.choices(labels, weights=[70, 6, 6, 6, 6, 6])[0]
    rf_conf   = round(random.uniform(0.72, 0.99), 4)
    if_score  = round(random.uniform(-0.45, 0.15), 4)
    is_anomaly = if_score < -0.20

    if label == "BENIGN" and rf_conf >= 0.85 and not is_anomaly:
        decision = "Normal"
    elif label != "BENIGN" and rf_conf >= 0.70:
        decision = f"Known Attack - {label}"
    else:
        decision = "Suspicious / Zero-day"

    return {
        "decision":         decision,
        "label":            label,
        "rf_confidence":    rf_conf,
        "if_score":         if_score,
        "missing_features": [],
    }


# ══════════════════════════════════════════════════════
# QNIDSPredictor — CSV Simulator wrapper
# ══════════════════════════════════════════════════════
class QNIDSPredictor:
    """
    Wrapper for CSVSimulator compatibility.
    predict_row(pandas_row) → (display_name, verdict, color, confidence, if_score)
    """

    GREEN  = "#10b981"
    RED    = "#ef4444"
    ORANGE = "#f59e0b"

    # Map decision string → GUI display name
    DISPLAY_MAP = {
        "Normal":              "Normal Traffic",
        "Suspicious / Zero-day": "Suspicious / Zero-day",
    }

    def __init__(self):
        self.is_loaded = True
        load_models()

    def predict_row(self, row) -> tuple:
        row_dict = row.to_dict() if hasattr(row, "to_dict") else dict(row)

        # Map NSL-KDD / CIC-IDS2017 column names to CICFlowTracker keys
        flow_dict = {
    "Flow Duration":                    float(row_dict.get("Flow Duration",      row_dict.get("flow_duration",     row_dict.get("duration", 0)))),
    "Total Fwd Packets":                float(row_dict.get("Total Fwd Packets",  row_dict.get("total_fwd_packets", row_dict.get("count", 1)))),
    "Total Backward Packets":           float(row_dict.get("Total Backward Packets", row_dict.get("total_bwd_packets", 1))),
    "Total Length of Fwd Packets":      float(row_dict.get("Total Length of Fwd Packets", row_dict.get("total_length_fwd_packets", row_dict.get("src_bytes", 0)))),
    "Total Length of Bwd Packets":      float(row_dict.get("Total Length of Bwd Packets", row_dict.get("total_length_bwd_packets", row_dict.get("dst_bytes", 0)))),
    "Fwd Packet Length Max":            float(row_dict.get("Fwd Packet Length Max",  row_dict.get("fwd_packet_length_max",  0))),
    "Fwd Packet Length Min":            float(row_dict.get("Fwd Packet Length Min",  row_dict.get("fwd_packet_length_min",  0))),
    "Fwd Packet Length Mean":           float(row_dict.get("Fwd Packet Length Mean", row_dict.get("fwd_packet_length_mean", 0))),
    "Fwd Packet Length Std":            float(row_dict.get("Fwd Packet Length Std",  row_dict.get("fwd_packet_length_std",  0))),
    "Bwd Packet Length Max":            float(row_dict.get("Bwd Packet Length Max",  row_dict.get("bwd_packet_length_max",  0))),
    "Bwd Packet Length Min":            float(row_dict.get("Bwd Packet Length Min",  row_dict.get("bwd_packet_length_min",  0))),
    "Bwd Packet Length Mean":           float(row_dict.get("Bwd Packet Length Mean", row_dict.get("bwd_packet_length_mean", 0))),
    "Bwd Packet Length Std":            float(row_dict.get("Bwd Packet Length Std",  row_dict.get("bwd_packet_length_std",  0))),
    "Flow Bytes/s":                     float(row_dict.get("Flow Bytes/s",        row_dict.get("flow_bytes_per_sec", 0))),
    "Flow Packets/s":                   float(row_dict.get("Flow Packets/s",      row_dict.get("flow_packets_per_sec", 0))),
    "Flow IAT Mean":                    float(row_dict.get("Flow IAT Mean",       row_dict.get("flow_iat_mean", 0))),
    "Flow IAT Std":                     float(row_dict.get("Flow IAT Std",        row_dict.get("flow_iat_std", 0))),
    "Flow IAT Max":                     float(row_dict.get("Flow IAT Max",        row_dict.get("flow_iat_max", 0))),
    "Flow IAT Min":                     float(row_dict.get("Flow IAT Min",        row_dict.get("flow_iat_min", 0))),
    "Fwd IAT Total":                    float(row_dict.get("Fwd IAT Total",       row_dict.get("fwd_iat_total", 0))),
    "Fwd IAT Mean":                     float(row_dict.get("Fwd IAT Mean",        row_dict.get("fwd_iat_mean", 0))),
    "Fwd IAT Std":                      float(row_dict.get("Fwd IAT Std",         row_dict.get("fwd_iat_std", 0))),
    "Fwd IAT Max":                      float(row_dict.get("Fwd IAT Max",         row_dict.get("fwd_iat_max", 0))),
    "Fwd IAT Min":                      float(row_dict.get("Fwd IAT Min",         row_dict.get("fwd_iat_min", 0))),
    "Bwd IAT Total":                    float(row_dict.get("Bwd IAT Total",       row_dict.get("bwd_iat_total", 0))),
    "Bwd IAT Mean":                     float(row_dict.get("Bwd IAT Mean",        row_dict.get("bwd_iat_mean", 0))),
    "Bwd IAT Std":                      float(row_dict.get("Bwd IAT Std",         row_dict.get("bwd_iat_std", 0))),
    "Bwd IAT Max":                      float(row_dict.get("Bwd IAT Max",         row_dict.get("bwd_iat_max", 0))),
    "Bwd IAT Min":                      float(row_dict.get("Bwd IAT Min",         row_dict.get("bwd_iat_min", 0))),
    "Fwd PSH Flags":                    float(row_dict.get("Fwd PSH Flags",       row_dict.get("fwd_psh_flags", 0))),
    "Fwd URG Flags":                    float(row_dict.get("Fwd URG Flags",       row_dict.get("fwd_urg_flags", 0))),
    "Fwd Header Length":                float(row_dict.get("Fwd Header Length",   row_dict.get("fwd_header_length", 0))),
    "Bwd Header Length":                float(row_dict.get("Bwd Header Length",   row_dict.get("bwd_header_length", 0))),
    "Fwd Packets/s":                    float(row_dict.get("Fwd Packets/s",       row_dict.get("fwd_packets_per_sec", 0))),
    "Bwd Packets/s":                    float(row_dict.get("Bwd Packets/s",       row_dict.get("bwd_packets_per_sec", 0))),
    "Min Packet Length":                float(row_dict.get("Min Packet Length",   row_dict.get("min_packet_length", 0))),
    "Max Packet Length":                float(row_dict.get("Max Packet Length",   row_dict.get("max_packet_length", 0))),
    "Packet Length Mean":               float(row_dict.get("Packet Length Mean",  row_dict.get("packet_length_mean", 0))),
    "Packet Length Std":                float(row_dict.get("Packet Length Std",   row_dict.get("packet_length_std", 0))),
    "Packet Length Variance":           float(row_dict.get("Packet Length Variance", row_dict.get("packet_length_variance", 0))),
    "FIN Flag Count":                   float(row_dict.get("FIN Flag Count",      row_dict.get("fin_flag_count", 0))),
    "SYN Flag Count":                   float(row_dict.get("SYN Flag Count",      row_dict.get("syn_flag_count", 0))),
    "RST Flag Count":                   float(row_dict.get("RST Flag Count",      row_dict.get("rst_flag_count", 0))),
    "PSH Flag Count":                   float(row_dict.get("PSH Flag Count",      row_dict.get("psh_flag_count", 0))),
    "ACK Flag Count":                   float(row_dict.get("ACK Flag Count",      row_dict.get("ack_flag_count", 0))),
    "URG Flag Count":                   float(row_dict.get("URG Flag Count",      row_dict.get("urg_flag_count", 0))),
    "CWE Flag Count":                   float(row_dict.get("CWE Flag Count",      row_dict.get("cwe_flag_count", 0))),
    "ECE Flag Count":                   float(row_dict.get("ECE Flag Count",      row_dict.get("ece_flag_count", 0))),
    "Down/Up Ratio":                    float(row_dict.get("Down/Up Ratio",       row_dict.get("down_up_ratio", 0))),
    "Average Packet Size":              float(row_dict.get("Average Packet Size", row_dict.get("average_packet_size", 0))),
    "Avg Fwd Segment Size":             float(row_dict.get("Avg Fwd Segment Size", row_dict.get("avg_fwd_segment_size", 0))),
    "Avg Bwd Segment Size":             float(row_dict.get("Avg Bwd Segment Size", row_dict.get("avg_bwd_segment_size", 0))),
    "Subflow Fwd Packets":              float(row_dict.get("Subflow Fwd Packets", row_dict.get("subflow_fwd_packets", 0))),
    "Subflow Fwd Bytes":                float(row_dict.get("Subflow Fwd Bytes",   row_dict.get("subflow_fwd_bytes", 0))),
    "Subflow Bwd Packets":              float(row_dict.get("Subflow Bwd Packets", row_dict.get("subflow_bwd_packets", 0))),
    "Subflow Bwd Bytes":                float(row_dict.get("Subflow Bwd Bytes",   row_dict.get("subflow_bwd_bytes", 0))),
    "Init_Win_bytes_forward":           float(row_dict.get("Init_Win_bytes_forward",  row_dict.get("init_fwd_win_bytes", 65535))),
    "Init_Win_bytes_backward":          float(row_dict.get("Init_Win_bytes_backward", row_dict.get("init_bwd_win_bytes", 65535))),
    "act_data_pkt_fwd":                 float(row_dict.get("act_data_pkt_fwd",    row_dict.get("act_data_pkt_fwd", 0))),
    "min_seg_size_forward":             float(row_dict.get("min_seg_size_forward", row_dict.get("min_seg_size_forward", 0))),
    "Active Mean":                      float(row_dict.get("Active Mean",  row_dict.get("active_mean", 0))),
    "Active Std":                       float(row_dict.get("Active Std",   row_dict.get("active_std", 0))),
    "Active Max":                       float(row_dict.get("Active Max",   row_dict.get("active_max", 0))),
    "Active Min":                       float(row_dict.get("Active Min",   row_dict.get("active_min", 0))),
    "Idle Mean":                        float(row_dict.get("Idle Mean",    row_dict.get("idle_mean", 0))),
    "Idle Std":                         float(row_dict.get("Idle Std",     row_dict.get("idle_std", 0))),
    "Idle Max":                         float(row_dict.get("Idle Max",     row_dict.get("idle_max", 0))),
    "Idle Min":                         float(row_dict.get("Idle Min",     row_dict.get("idle_min", 0))),
    "Destination Port":                 float(row_dict.get("Destination Port", row_dict.get("destination_port", 0))),
}
      # Classify with dual-layer model
        result = predict(flow_dict)

        decision = result.get("decision", "Suspicious / Zero-day")
        rf_label = result.get("label", "UNKNOWN")
        conf     = int(result.get("rf_confidence", 0) * 100)
        if_score_val = result.get("if_score", 0.0)

       # Map Partner A's decision strings to GUI verdict
        if decision == "Normal":
           verdict = "NORMAL"
           color   = "#10b981"
           label   = "Normal Traffic"
        elif decision.startswith("Known Attack"):
           verdict = "ATTACK"
           color   = "#ef4444"
           label   = decision.replace("Known Attack - ", "") + " Attack"
        else:
           verdict = "UNKNOWN"
           color   = "#f59e0b"
           label   = "Suspicious / Zero-day"

        return label, verdict, color, conf, if_score_val

    def load_unsw_model(self):
        print("[QNIDSPredictor] load_unsw_model: not implemented.")

    def load_nslkdd_model(self):
        print("[QNIDSPredictor] load_nslkdd_model: not implemented.")