import pandas as pd
import threading
import time
import random
from datetime import datetime
from predict import QNIDSPredictor

# NSL-KDD column names
NSLKDD_COLUMNS = [
    'duration','protocol_type','service','flag',
    'src_bytes','dst_bytes','land','wrong_fragment',
    'urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate',
    'dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty'
]

FAKE_IPS = [
    '192.168.1.105', '192.168.1.10',
    '10.0.0.5',      '172.16.0.8',
    '203.0.113.42',  '10.10.0.25',
    '192.168.0.100', '172.31.0.15',
]


class CSVSimulator:

    def __init__(self, callback=None):
        self.callback    = callback
        self.is_running  = False
        self.is_paused   = False
        self._thread     = None
        self.df          = None
        self.current_row = 0
        self.speed       = 0.5

        # Real predictor load karo
        print("Predictor initializing...")
        self.predictor   = QNIDSPredictor()

        if self.predictor.is_loaded:
            print("Real model connected!")
        else:
            print("Fallback mode — label se direct")

    def load_csv(self, filepath):
        try:
            with open(filepath, 'r') as f:
                first_line = f.readline().strip()

            has_header = not first_line[0].isdigit()

            if has_header:
                self.df = pd.read_csv(filepath)
                self.df.columns = self.df.columns.str.strip()
                print(f"[simulator] CIC-IDS2017 CSV loaded: {len(self.df)} rows")
                print(f"[simulator] Columns: {list(self.df.columns[:5])}...")
            else:
                self.df = pd.read_csv(
                    filepath,
                    header=None,
                    names=NSLKDD_COLUMNS
                )
                print(f"[simulator] NSL-KDD CSV loaded: {len(self.df)} rows")

            self.current_row = 0
            return True

        except Exception as e:
            print(f"[simulator] CSV load error: {e}")
            return False
    def start(self):
        if self.df is None:
            print("CSV not loaded")
            return
        if self.is_running:
            self.stop()
            time.sleep(0.3)
        self.is_running = True
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True
        )
        self._thread.start()
        print("Simulation started")

    def stop(self):
        self.is_running  = False
        self.current_row = 0

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False

    def set_speed(self, seconds):
        self.speed = seconds

    def _loop(self):
        while self.is_running:
            if self.is_paused:
                time.sleep(0.1)
                continue

            if self.current_row >= len(self.df):
                self.current_row = 0
                print("Dataset complete — restarting...")

            try:
                row = self.df.iloc[self.current_row]
                self.current_row += 1

                # Real model se predict karo
                attack_type, verdict, color, confidence, if_score = \
                     self.predictor.predict_row(row)

                ip = random.choice(FAKE_IPS)
                ts = datetime.now().strftime("%H:%M:%S")

                if self.callback:
                    self.callback(
                        ts, ip,
                        attack_type,
                        verdict,
                        color,
                        confidence,
                        if_score
                   )

            except Exception as e:
                print(f"Row error: {e}")

            time.sleep(self.speed)