from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QComboBox, QLineEdit, QPushButton, QFileDialog
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor
import qtawesome as qta
import pandas as pd
from monitoring.services.wazuh_service import WazuhService

PALETTE = {
    'main_bg': '#F5F6FA',
    'header': '#39396A',
    'header_text': '#FFD94A',
    'table_header': '#39396A',
    'table_header_text': '#FFD94A',
    'row_alt': '#F8F9FA',
    'row_bg': '#FFFFFF',
    'status_normal': '#27ae60',
    'status_suspect': '#F7B55E',
    'status_critique': '#e74c3c',
    'status_text': '#fff',
    'btn_gradient': 'qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FFD94A, stop:1 #D96B8A)',
    'btn_text': '#39396A',
    'accent': '#FFD94A',
    'font': 'Roboto, Segoe UI, Arial, sans-serif',
}

class UserActivityPage(QWidget):
    def __init__(self):
        super().__init__()
        self.wazuh_service = WazuhService()
        self.events = []
        self.setup_ui()
        self.refresh_data()
        self.setup_timer()

    def setup_ui(self):
        self.setStyleSheet(f"font-family: {PALETTE['font']}; background: {PALETTE['main_bg']};")
        layout = QVBoxLayout()
        # Titre principal
        title = QLabel("Activité Utilisateur - Timeline Sécurité")
        title.setFont(QFont("Roboto", 22, QFont.Bold))
        title.setStyleSheet(f"color: {PALETTE['header']}; margin: 10px 0 0 10px;")
        layout.addWidget(title)
        # Sous-titre
        subtitle = QLabel("Logs Wazuh, analyse ML, détection d'anomalies et export")
        subtitle.setFont(QFont("Roboto", 13, QFont.Normal))
        subtitle.setStyleSheet(f"color: {PALETTE['header']}; margin-left: 12px; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        # Indicateur de connexion
        self.connection_status = QLabel("Connexion Wazuh: Vérification...")
        self.connection_status.setStyleSheet(f"color: {PALETTE['status_critique']}; font-weight: bold; margin-left: 12px;")
        layout.addWidget(self.connection_status)
        # Filtres et recherche
        controls_layout = QHBoxLayout()
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Tous", "Connexion", "Programme", "Fichier", "Réseau"])
        self.type_combo.setStyleSheet(f"background: {PALETTE['row_alt']}; border-radius: 6px; padding: 4px 8px;")
        self.type_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Type:"))
        controls_layout.addWidget(self.type_combo)
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["Tous", "Normal", "Suspect", "Critique"])
        self.risk_combo.setStyleSheet(f"background: {PALETTE['row_alt']}; border-radius: 6px; padding: 4px 8px;")
        self.risk_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Risque:"))
        controls_layout.addWidget(self.risk_combo)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Recherche utilisateur ou action...")
        self.search_edit.setStyleSheet(f"background: {PALETTE['row_alt']}; border-radius: 6px; padding: 4px 8px;")
        self.search_edit.textChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.search_edit)
        export_btn = QPushButton(qta.icon('fa5s.file-csv', color=PALETTE['btn_text']), "Exporter CSV")
        export_btn.clicked.connect(self.export_csv)
        export_btn.setStyleSheet(f'''
            QPushButton {{
                background: {PALETTE['btn_gradient']};
                color: {PALETTE['btn_text']};
                border: none;
                border-radius: 8px;
                padding: 8px 18px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: {PALETTE['accent']};
                color: {PALETTE['header']};
            }}
        ''')
        controls_layout.addWidget(export_btn)
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        # Tableau stylé
        group = QGroupBox("Logs d'activité utilisateur")
        group.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                border: 2px solid {PALETTE['table_header']};
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background: {PALETTE['row_bg']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: {PALETTE['table_header']};
                font-size: 15px;
            }}
        """)
        table_layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Date/Heure", "Utilisateur", "Type", "Message", "Agent", "Risque", "Score ML"
        ])
        header = self.table.horizontalHeader()
        if header:
            header.setStyleSheet(f"background: {PALETTE['table_header']}; color: {PALETTE['table_header_text']}; font-weight: bold; font-size: 14px; border-radius: 8px;")
            header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            for i in range(1, 7):
                header.setSectionResizeMode(i, QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                gridline-color: {PALETTE['row_alt']};
                background-color: {PALETTE['row_bg']};
                alternate-background-color: {PALETTE['row_alt']};
                border-radius: 8px;
            }}
            QHeaderView::section {{
                background-color: {PALETTE['table_header']};
                color: {PALETTE['table_header_text']};
                padding: 8px;
                border: 1px solid {PALETTE['table_header']};
                font-weight: bold;
                font-size: 14px;
            }}
        """)
        table_layout.addWidget(self.table)
        group.setLayout(table_layout)
        layout.addWidget(group)
        self.setLayout(layout)

    def setup_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(30000)

    def refresh_data(self):
        try:
            if not self.wazuh_service.test_connection():
                self.connection_status.setText("Connexion Wazuh: DÉCONNECTÉ")
                self.connection_status.setStyleSheet(f"color: {PALETTE['status_critique']}; font-weight: bold; margin-left: 12px;")
                self.events = self.simulate_events()
            else:
                self.connection_status.setText("Connexion Wazuh: CONNECTÉ")
                self.connection_status.setStyleSheet(f"color: {PALETTE['status_normal']}; font-weight: bold; margin-left: 12px;")
                self.events = self.wazuh_service.get_user_activity()
            self.update_table()
        except Exception as e:
            self.connection_status.setText("Connexion Wazuh: ERREUR")
            self.connection_status.setStyleSheet(f"color: {PALETTE['status_critique']}; font-weight: bold; margin-left: 12px;")
            self.events = self.simulate_events()
            self.update_table()

    def simulate_events(self):
        import random
        from datetime import datetime, timedelta
        users = ["alice", "bob", "carol", "dave", "eve"]
        types = ["Connexion", "Programme", "Fichier", "Réseau"]
        risks = ["Normal", "Suspect", "Critique"]
        events = []
        now = datetime.now()
        for i in range(50):
            dt = now - timedelta(minutes=i*3)
            events.append({
                'timestamp': dt.strftime("%Y-%m-%d %H:%M:%S"),
                'user': random.choice(users),
                'type': random.choice(types),
                'message': random.choice([
                    "Connexion SSH", "Suppression de fichier", "Exécution script", "Accès admin", "Changement mot de passe"
                ]),
                'agent': f"PC-{random.randint(1,10)}",
                'risk': random.choices(risks, weights=[0.7, 0.2, 0.1])[0],
                'score': round(random.uniform(0, 1), 2)
            })
        return events

    def update_table(self):
        self.table.setRowCount(len(self.events))
        for row, event in enumerate(self.events):
            self.table.setItem(row, 0, QTableWidgetItem(event['timestamp']))
            self.table.setItem(row, 1, QTableWidgetItem(event['user']))
            self.table.setItem(row, 2, QTableWidgetItem(event['type']))
            self.table.setItem(row, 3, QTableWidgetItem(event['message']))
            self.table.setItem(row, 4, QTableWidgetItem(event['agent']))
            risk_item = QTableWidgetItem(event['risk'])
            if event['risk'] == "Critique":
                risk_item.setBackground(QColor(PALETTE['status_critique']))
                risk_item.setForeground(QColor(PALETTE['status_text']))
            elif event['risk'] == "Suspect":
                risk_item.setBackground(QColor(PALETTE['status_suspect']))
                risk_item.setForeground(QColor(PALETTE['status_text']))
            else:
                risk_item.setBackground(QColor(PALETTE['status_normal']))
                risk_item.setForeground(QColor(PALETTE['status_text']))
            self.table.setItem(row, 5, risk_item)
            score_item = QTableWidgetItem(str(event['score']))
            self.table.setItem(row, 6, score_item)

    def apply_filters(self):
        type_filter = self.type_combo.currentText()
        risk_filter = self.risk_combo.currentText()
        search_text = self.search_edit.text().lower()
        for row, event in enumerate(self.events):
            type_match = (type_filter == "Tous" or event['type'] == type_filter)
            risk_match = (risk_filter == "Tous" or event['risk'] == risk_filter)
            search_match = (search_text == "" or search_text in event['user'].lower() or search_text in event['message'].lower())
            self.table.setRowHidden(row, not (type_match and risk_match and search_match))

    def export_csv(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Exporter en CSV", "user_activity.csv", "CSV Files (*.csv)")
        if not filename:
            return
        try:
            df = pd.DataFrame(self.events)
            df.to_csv(filename, index=False, encoding='utf-8')
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.information(self, "Export réussi", f"Données exportées vers {filename}")
        except Exception as e:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Erreur d'export", f"Erreur lors de l'export: {str(e)}") 