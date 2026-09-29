import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from feature_extractor import FeatureExtractor
from predict import QNIDSPredictor
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

extractor = FeatureExtractor()
predictor = QNIDSPredictor()

print("=" * 55)
print("  Real Traffic Classification Test")
print("=" * 55)
print("Browser mein koi website kholo")
print("Ctrl+C se rokna\n")

count = 0

def process(pkt):
    global count

    features = extractor.process_packet(pkt)
    if features is None:
        return

    # ── Sirf TCP complete connections classify karo
    protocol = features.get('_protocol', '')
    duration = features.get('duration', 0)
    src_bytes = features.get('src_bytes', 0)

    # UDP/ICMP aur zero duration skip karo
    if protocol != 'TCP':
        return
    if duration <= 0:
        return
    # Bohat chhoti connections bhi skip karo
    if src_bytes < 100:
        return

    try:
        row = pd.Series(features)
        attack_type, verdict, color, conf = \
            predictor.predict_row(row)

        src = features.get('_src', '?')
        svc = features.get('_service_name', '?')
        dur = features.get('duration', 0)
        byt = features.get('src_bytes', 0)

        # Low confidence = Normal treat karo
        if conf < 70:
            verdict     = '🟢 NORMAL'
            attack_type = 'Normal Traffic'

        count += 1
        print(
            f"[{count}] "
            f"{datetime.now().strftime('%H:%M:%S')} | "
            f"{src:<16} | "
            f"{svc:<10} | "
            f"Dur:{dur:.3f}s | "
            f"Bytes:{byt} | "
            f"{verdict} | "
            f"{conf}%"
        )

    except Exception as e:
        print(f"Error: {e}")

try:
    sniff(
        prn=process,
        filter="tcp",  # Sirf TCP
        store=False
    )
except KeyboardInterrupt:
    print(f"\nTotal classified: {count}")