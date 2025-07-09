from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPushButton, QFileDialog, QMessageBox
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import hashlib
import random
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime

class ForensicPage(QWidget):
    def __init__(self):
        super().__init__()
        self.events = []
        self.setup_ui()
        self.load_events()

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("Analyse Forensic - Timeline post-incident")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)

        # Timeline QListWidget
        self.timeline = QListWidget()
        self.timeline.setMinimumHeight(400)
        layout.addWidget(self.timeline)

        # Boutons export
        btns_layout = QHBoxLayout()
        self.export_pdf_btn = QPushButton("Exporter en PDF")
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        btns_layout.addWidget(self.export_pdf_btn)
        self.export_csv_btn = QPushButton("Exporter en CSV")
        self.export_csv_btn.clicked.connect(self.export_csv)
        btns_layout.addWidget(self.export_csv_btn)
        btns_layout.addStretch()
        layout.addLayout(btns_layout)

        self.setLayout(layout)

    def load_events(self):
        # Simulation de 50 événements forensic
        self.events = []
        for i in range(50):
            equip = f"PC-{random.randint(1,10)}"
            user = random.choice(["alice", "bob", "carol", "dave", "eve"])
            action = random.choice([
                "Connexion SSH",
                "Suppression de fichier",
                "Modification de config",
                "Accès admin",
                "Téléchargement suspect",
                "Exécution script",
                "Changement mot de passe"
            ])
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Hash sur la concaténation des infos
            hash_input = f"{equip}|{user}|{action}|{timestamp}".encode()
            hash_md5 = hashlib.md5(hash_input).hexdigest()
            hash_sha256 = hashlib.sha256(hash_input).hexdigest()
            self.events.append({
                'equipement': equip,
                'utilisateur': user,
                'action': action,
                'timestamp': timestamp,
                'hash_md5': hash_md5,
                'hash_sha256': hash_sha256
            })
        self.update_timeline()

    def update_timeline(self):
        self.timeline.clear()
        for event in self.events:
            text = f"[{event['timestamp']}]  {event['equipement']}  |  {event['utilisateur']}  |  {event['action']}\nMD5: {event['hash_md5']}  |  SHA256: {event['hash_sha256'][:12]}..."
            item = QListWidgetItem(text)
            self.timeline.addItem(item)

    def export_csv(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Exporter en CSV", "forensic_timeline.csv", "Fichiers CSV (*.csv)")
        if not filename:
            return
        try:
            df = pd.DataFrame(self.events)
            df.to_csv(filename, index=False, encoding='utf-8')
            QMessageBox.information(self, "Export CSV", f"Export CSV réussi : {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur export CSV : {e}")

    def export_pdf(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Exporter en PDF", "forensic_timeline.pdf", "Fichiers PDF (*.pdf)")
        if not filename:
            return
        try:
            c = canvas.Canvas(filename, pagesize=A4)
            width, height = A4
            c.setFont("Helvetica", 10)
            y = height - 40
            c.drawString(40, y, "Rapport Forensic - Timeline post-incident")
            y -= 30
            for event in self.events:
                line = f"[{event['timestamp']}]  {event['equipement']} | {event['utilisateur']} | {event['action']}"
                hashline = f"MD5: {event['hash_md5']}  |  SHA256: {event['hash_sha256']}"
                c.drawString(40, y, line)
                y -= 15
                c.drawString(60, y, hashline)
                y -= 20
                if y < 60:
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    y = height - 40
            c.save()
            QMessageBox.information(self, "Export PDF", f"Export PDF réussi : {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur export PDF : {e}") 