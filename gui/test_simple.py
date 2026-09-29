import sys
import matplotlib
matplotlib.use('Agg')

print("Step 1: matplotlib OK")

from PyQt5.QtWidgets import QApplication
app = QApplication(sys.argv)
print("Step 2: QApplication OK")

from chart_widget import AttackPieChart
print("Step 3: chart_widget OK")

from loading_screen import LoadingScreen
print("Step 4: loading_screen OK")

from alert_system import UnknownThreatPopup
print("Step 5: alert_system OK")

from export_manager import ExportManager
print("Step 6: export_manager OK")

from capture_to_gui import PacketCapture
print("Step 7: capture_to_gui OK")

from csv_simulator import CSVSimulator
print("Step 8: csv_simulator OK")

from predict import QNIDSPredictor
print("Step 9: predict OK")

print("\nSab imports theek hain!")
print("Main window import karte hain...")

from main_window import QNIDSMainWindow
print("Step 10: main_window import OK")

window = QNIDSMainWindow()
print("Step 11: window create OK")

window.show()
print("Step 12: window show OK")

sys.exit(app.exec_())