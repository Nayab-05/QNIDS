import sys
import matplotlib
matplotlib.use('Agg')
from PyQt5.QtWidgets import QApplication, QWidget
app = QApplication(sys.argv)
w = QWidget()
w.show()
print("Chart import OK")
sys.exit(app.exec_())