from PyQt5.QtWidgets import QSplashScreen, QLabel
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QColor, QFont, QPainter


class LoadingScreen(QSplashScreen):

    def __init__(self):
        pixmap = QPixmap(500, 300)
        pixmap.fill(QColor('#0a0f1a'))
        
        # Painter create karo aur immediately finish karo
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        # Border
        painter.setPen(QColor('#00d4ff'))
        painter.drawRect(1, 1, 498, 298)

        # Title
        painter.setFont(QFont('Arial', 32, QFont.Bold))
        painter.setPen(QColor('#00d4ff'))
        painter.drawText(0, 80, 500, 60,
            Qt.AlignCenter, "QNIDS")

        # Subtitle
        painter.setFont(QFont('Arial', 10))
        painter.setPen(QColor('#64748b'))
        painter.drawText(0, 150, 500, 30,
            Qt.AlignCenter,
            "Quantum-Inspired Network "
            "Intrusion Detection System")

        # Loading
        painter.setFont(QFont('Arial', 9))
        painter.setPen(QColor('#3b82f6'))
        painter.drawText(0, 220, 500, 30,
            Qt.AlignCenter,
            "Loading models and initializing...")

        # Version
        painter.setFont(QFont('Arial', 8))
        painter.setPen(QColor('#1e3048'))
        painter.drawText(0, 275, 500, 20,
            Qt.AlignCenter,
            "v1.0  |  Final Year Project  |  BSCS 2021-2025")

        # ── Painter ZAROOR end karo pixmap pass karne se pehle
        painter.end()

        super().__init__(pixmap)
        self.setWindowFlag(Qt.WindowStaysOnTopHint)