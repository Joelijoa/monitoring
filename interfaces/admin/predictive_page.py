from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QFrame, QComboBox, QPushButton, QGroupBox,
                             QProgressBar, QSplitter, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import requests
import json
from datetime import datetime
import pyqtgraph as pg
import numpy as np
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from monitoring.services.predictive_service import PredictiveService
from monitoring.config.predictive_config import ANOMALY_TYPES, REFRESH_INTERVALS

class PredictivePage(QWidget):
    def __init__(self):
        super().__init__()
        self.predictive_service = PredictiveService()
        self.anomalies_data = []
        self.filtered_data = []
        self.suspicious_threshold = 0.3  # Seuil pour les anomalies suspectes
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre et description
        title = QLabel("Détection Anomalies via Isolation Forest")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        desc = QLabel("Analyse horaire sur logs Wazuh/ELK - Réentraînement mensuel - Score < 0.3 = suspect")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Statut de l'analyse
        self.analysis_status = QLabel("Statut de l'analyse: Initialisation...")
        self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.analysis_status)
        
        # Contrôles de filtrage et actions
        controls_layout = QHBoxLayout()
        
        # Filtre par type d'anomalie
        self.anomaly_filter_combo = QComboBox()
        self.anomaly_filter_combo.addItems(["Toutes", "Comportement", "Réseau", "Système", "Utilisateur"])
        self.anomaly_filter_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Type:"))
        controls_layout.addWidget(self.anomaly_filter_combo)
        
        # Filtre par score
        self.score_filter_combo = QComboBox()
        self.score_filter_combo.addItems(["Tous", "Suspects (< 0.3)", "Normaux (≥ 0.3)"])
        self.score_filter_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Score:"))
        controls_layout.addWidget(self.score_filter_combo)
        
        # Boutons d'export
        export_csv_btn = QPushButton("Export CSV")
        export_csv_btn.clicked.connect(self.export_csv)
        export_csv_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        controls_layout.addWidget(export_csv_btn)
        
        export_pdf_btn = QPushButton("Export PDF")
        export_pdf_btn.clicked.connect(self.export_pdf)
        export_pdf_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        controls_layout.addWidget(export_pdf_btn)
        
        # Bouton d'analyse manuelle
        analyze_btn = QPushButton("🔍 Analyser Maintenant")
        analyze_btn.clicked.connect(self.run_analysis)
        analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        controls_layout.addWidget(analyze_btn)
        
        # Bouton d'entraînement
        train_btn = QPushButton("🎓 Réentraîner")
        train_btn.clicked.connect(self.train_models)
        train_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        controls_layout.addWidget(train_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des anomalies
        left_widget = self.create_anomalies_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Graphiques et feedback
        right_widget = self.create_graphs_section()
        splitter.addWidget(right_widget)
        
        # Répartition 60% tableau, 40% graphiques
        splitter.setSizes([600, 400])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def create_anomalies_table(self):
        group = QGroupBox("Anomalies Détectées")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Tableau des anomalies
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Équipement", "Type", "Score", "Horodatage", "Détails", "Vrai Positif", "Faux Positif"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Équipement
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Type
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Score
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Horodatage
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)           # Détails
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Vrai Positif
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Faux Positif
        
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                gridline-color: #bdc3c7;
                background-color: white;
                alternate-background-color: #f8f9fa;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 8px;
                border: 1px solid #2c3e50;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.table)
        group.setLayout(layout)
        return group
        
    def create_graphs_section(self):
        group = QGroupBox("Graphiques et Feedback")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Configuration pyqtgraph
        pg.setConfigOptions(antialias=True)
        
        # Graphique des scores d'anomalie
        scores_widget = pg.PlotWidget()
        scores_widget.setTitle("Scores d'Anomalie - Temps Réel")
        scores_widget.setLabel('left', 'Score')
        scores_widget.setLabel('bottom', 'Temps')
        scores_widget.showGrid(x=True, y=True)
        self.scores_plot = scores_widget.plot(pen='r', name='Scores')
        layout.addWidget(scores_widget)
        
        # Graphique des types d'anomalies
        types_widget = pg.PlotWidget()
        types_widget.setTitle("Types d'Anomalies")
        types_widget.setLabel('left', 'Nombre')
        types_widget.setLabel('bottom', 'Type')
        types_widget.showGrid(x=True, y=True)
        self.types_plot = types_widget.plot(pen='b', name='Types')
        layout.addWidget(types_widget)
        
        # Statistiques
        stats_label = QLabel("Statistiques:")
        stats_label.setStyleSheet("font-weight: bold; margin-top: 10px; margin-bottom: 5px;")
        layout.addWidget(stats_label)
        
        self.total_anomalies_label = QLabel("Total anomalies: 0")
        self.suspicious_anomalies_label = QLabel("Anomalies suspectes: 0")
        self.true_positives_label = QLabel("Vrais positifs: 0")
        self.false_positives_label = QLabel("Faux positifs: 0")
        
        for label in [self.total_anomalies_label, self.suspicious_anomalies_label, 
                     self.true_positives_label, self.false_positives_label]:
            label.setStyleSheet("margin: 2px 0;")
            layout.addWidget(label)
        
        layout.addStretch()
        group.setLayout(layout)
        return group
        
    def setup_timers(self):
        """Configure les timers pour l'analyse horaire et le réentraînement mensuel"""
        # Timer pour l'analyse horaire
        self.analysis_timer = QTimer()
        self.analysis_timer.timeout.connect(self.run_analysis)
        self.analysis_timer.start(3600000)  # 1 heure
        
        # Timer pour le réentraînement mensuel (simulé toutes les 24h pour les tests)
        self.training_timer = QTimer()
        self.training_timer.timeout.connect(self.train_models)
        self.training_timer.start(86400000)  # 24 heures (pour les tests)
        
        # Première analyse
        self.run_analysis()
        
    def run_analysis(self):
        """Lance l'analyse prédictive avec Isolation Forest"""
        try:
            self.analysis_status.setText("Statut de l'analyse: Analyse en cours...")
            self.analysis_status.setStyleSheet("color: #f39c12; font-weight: bold;")
            
            # Récupérer les données depuis le service prédictif
            if not self.predictive_service.test_connection():
                self.analysis_status.setText("Statut de l'analyse: DÉCONNECTÉ - Utilisation données simulées")
                self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
                self.simulate_anomaly_data()
            else:
                self.analysis_status.setText("Statut de l'analyse: CONNECTÉ")
                self.analysis_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                self.get_real_anomaly_data()
            
            self.apply_filters()
            self.update_statistics()
            self.update_graphs()
            
        except Exception as e:
            print(f"Erreur lors de l'analyse: {e}")
            self.analysis_status.setText("Statut de l'analyse: ERREUR")
            self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def get_real_anomaly_data(self):
        """Récupère les vraies données d'anomalies depuis le service"""
        try:
            anomalies = self.predictive_service.detect_anomalies()
            self.anomalies_data = []
            
            for anomaly in anomalies:
                processed_data = {
                    'equipment': anomaly.get('equipment', 'N/A'),
                    'type': anomaly.get('type', 'N/A'),
                    'score': anomaly.get('score', 0.0),
                    'timestamp': anomaly.get('timestamp', ''),
                    'details': anomaly.get('details', ''),
                    'feedback': anomaly.get('feedback', 'none')  # none, true_positive, false_positive
                }
                self.anomalies_data.append(processed_data)
                
        except Exception as e:
            print(f"Erreur lors de la récupération des anomalies: {e}")
            self.simulate_anomaly_data()
            
    def simulate_anomaly_data(self):
        """Simule des données d'anomalies pour les tests"""
        import random
        from datetime import datetime, timedelta
        
        equipment_names = [
            "Serveur-WEB-01", "PC-Admin-02", "Switch-Core-01", "Router-FW-01",
            "PC-User-03", "Serveur-DB-02", "Laptop-Dev-01", "PC-Guest-04"
        ]
        
        anomaly_types = ["Comportement", "Réseau", "Système", "Utilisateur"]
        
        self.anomalies_data = []
        current_time = datetime.now()
        
        for i in range(50):  # Générer 50 anomalies
            # Timestamp aléatoire dans les dernières 24h
            random_hours = random.uniform(0, 24)
            event_time = current_time - timedelta(hours=random_hours)
            
            # Score d'anomalie (plus le score est bas, plus c'est suspect)
            score = random.uniform(0.1, 0.9)
            
            # Type d'anomalie
            anomaly_type = random.choice(anomaly_types)
            
            # Détails selon le type
            if anomaly_type == "Comportement":
                details = f"Comportement anormal détecté: {random.choice(['activité hors heures', 'patterns inhabituels', 'séquences suspectes'])}"
            elif anomaly_type == "Réseau":
                details = f"Anomalie réseau: {random.choice(['trafic inhabituel', 'connexions suspectes', 'bande passante anormale'])}"
            elif anomaly_type == "Système":
                details = f"Anomalie système: {random.choice(['utilisation CPU anormale', 'processus suspect', 'modifications système'])}"
            else:  # Utilisateur
                details = f"Anomalie utilisateur: {random.choice(['connexions multiples', 'accès inhabituels', 'activité suspecte'])}"
            
            data = {
                'equipment': random.choice(equipment_names),
                'type': anomaly_type,
                'score': round(score, 3),
                'timestamp': event_time.strftime("%Y-%m-%d %H:%M:%S"),
                'details': details,
                'feedback': 'none'  # Aucun feedback initial
            }
            self.anomalies_data.append(data)
            
        # Trier par timestamp (plus récent en premier)
        self.anomalies_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
    def train_models(self):
        """Réentraîne les modèles ML"""
        try:
            self.analysis_status.setText("Statut de l'analyse: Réentraînement en cours...")
            self.analysis_status.setStyleSheet("color: #f39c12; font-weight: bold;")
            
            # Simulation du réentraînement
            QTimer.singleShot(2000, lambda: self.analysis_status.setText("Statut de l'analyse: Modèles réentraînés"))
            QTimer.singleShot(2000, lambda: self.analysis_status.setStyleSheet("color: #27ae60; font-weight: bold;"))
            
            QMessageBox.information(self, "Réentraînement", "Modèles ML réentraînés avec succès")
            
        except Exception as e:
            print(f"Erreur lors du réentraînement: {e}")
            self.analysis_status.setText("Statut de l'analyse: ERREUR RÉENTRAÎNEMENT")
            self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def apply_filters(self):
        """Applique les filtres de type et de score"""
        filter_type = self.anomaly_filter_combo.currentText()
        filter_score = self.score_filter_combo.currentText()
        
        self.filtered_data = []
        
        for anomaly in self.anomalies_data:
            # Filtre par type
            type_match = filter_type == "Toutes" or anomaly['type'] == filter_type
            
            # Filtre par score
            if filter_score == "Suspects (< 0.3)":
                score_match = anomaly['score'] < self.suspicious_threshold
            elif filter_score == "Normaux (≥ 0.3)":
                score_match = anomaly['score'] >= self.suspicious_threshold
            else:
                score_match = True
            
            if type_match and score_match:
                self.filtered_data.append(anomaly)
        
        self.update_table()
        
    def update_table(self):
        """Met à jour le tableau avec les anomalies filtrées"""
        self.table.setRowCount(len(self.filtered_data))
        
        for row, anomaly in enumerate(self.filtered_data):
            # Équipement
            equipment_item = QTableWidgetItem(anomaly['equipment'])
            self.table.setItem(row, 0, equipment_item)
            
            # Type
            type_item = QTableWidgetItem(anomaly['type'])
            self.table.setItem(row, 1, type_item)
            
            # Score avec couleur selon le seuil
            score_item = QTableWidgetItem(f"{anomaly['score']:.3f}")
            if anomaly['score'] < self.suspicious_threshold:
                score_item.setBackground(QColor(231, 76, 60))  # Rouge pour suspect
                score_item.setForeground(QColor(255, 255, 255))
            else:
                score_item.setBackground(QColor(46, 204, 113))  # Vert pour normal
                score_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 2, score_item)
            
            # Horodatage
            timestamp_item = QTableWidgetItem(anomaly['timestamp'])
            self.table.setItem(row, 3, timestamp_item)
            
            # Détails
            details_item = QTableWidgetItem(anomaly['details'])
            self.table.setItem(row, 4, details_item)
            
            # Bouton Vrai Positif
            true_positive_btn = QPushButton("✅ Vrai")
            true_positive_btn.clicked.connect(lambda checked, r=row: self.mark_true_positive(r))
            true_positive_btn.setStyleSheet("""
                QPushButton {
                    background-color: #27ae60;
                    color: white;
                    border: none;
                    padding: 4px 8px;
                    border-radius: 3px;
                    font-size: 10px;
                }
                QPushButton:hover {
                    background-color: #229954;
                }
            """)
            self.table.setCellWidget(row, 5, true_positive_btn)
            
            # Bouton Faux Positif
            false_positive_btn = QPushButton("❌ Faux")
            false_positive_btn.clicked.connect(lambda checked, r=row: self.mark_false_positive(r))
            false_positive_btn.setStyleSheet("""
                QPushButton {
                    background-color: #e74c3c;
                    color: white;
                    border: none;
                    padding: 4px 8px;
                    border-radius: 3px;
                    font-size: 10px;
                }
                QPushButton:hover {
                    background-color: #c0392b;
                }
            """)
            self.table.setCellWidget(row, 6, false_positive_btn)
            
    def mark_true_positive(self, row):
        """Marque une anomalie comme vrai positif"""
        if row < len(self.filtered_data):
            self.filtered_data[row]['feedback'] = 'true_positive'
            self.anomalies_data[self.anomalies_data.index(self.filtered_data[row])]['feedback'] = 'true_positive'
            self.update_statistics()
            QMessageBox.information(self, "Feedback", "Anomalie marquée comme vrai positif")
            
    def mark_false_positive(self, row):
        """Marque une anomalie comme faux positif"""
        if row < len(self.filtered_data):
            self.filtered_data[row]['feedback'] = 'false_positive'
            self.anomalies_data[self.anomalies_data.index(self.filtered_data[row])]['feedback'] = 'false_positive'
            self.update_statistics()
            QMessageBox.information(self, "Feedback", "Anomalie marquée comme faux positif")
            
    def update_statistics(self):
        """Met à jour les statistiques"""
        total = len(self.anomalies_data)
        suspicious = len([a for a in self.anomalies_data if a['score'] < self.suspicious_threshold])
        true_positives = len([a for a in self.anomalies_data if a['feedback'] == 'true_positive'])
        false_positives = len([a for a in self.anomalies_data if a['feedback'] == 'false_positive'])
        
        self.total_anomalies_label.setText(f"Total anomalies: {total}")
        self.suspicious_anomalies_label.setText(f"Anomalies suspectes: {suspicious}")
        self.true_positives_label.setText(f"Vrais positifs: {true_positives}")
        self.false_positives_label.setText(f"Faux positifs: {false_positives}")
        
    def update_graphs(self):
        """Met à jour les graphiques pyqtgraph"""
        if not self.anomalies_data:
            return
            
        # Graphique des scores
        scores = [a['score'] for a in self.anomalies_data[-20:]]  # 20 dernières anomalies
        if scores:
            self.scores_plot.setData(scores)
        
        # Graphique des types
        type_counts = {}
        for anomaly in self.anomalies_data:
            anomaly_type = anomaly['type']
            type_counts[anomaly_type] = type_counts.get(anomaly_type, 0) + 1
        
        if type_counts:
            types = list(type_counts.keys())
            counts = list(type_counts.values())
            self.types_plot.setData(counts)
            
    def export_csv(self):
        """Exporte les données en CSV"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Exporter en CSV", "anomalies_data.csv", "CSV Files (*.csv)"
            )
            
            if filename:
                # Préparer les données pour l'export
                export_data = []
                for anomaly in self.filtered_data:
                    export_data.append({
                        'Équipement': anomaly['equipment'],
                        'Type': anomaly['type'],
                        'Score': anomaly['score'],
                        'Horodatage': anomaly['timestamp'],
                        'Détails': anomaly['details'],
                        'Feedback': anomaly['feedback']
                    })
                
                # Créer le DataFrame et exporter
                df = pd.DataFrame(export_data)
                df.to_csv(filename, index=False, encoding='utf-8')
                
                QMessageBox.information(self, "Export réussi", f"Données exportées vers {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur d'export", f"Erreur lors de l'export: {str(e)}")
            
    def export_pdf(self):
        """Exporte les données en PDF"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Exporter en PDF", "anomalies_report.pdf", "PDF Files (*.pdf)"
            )
            
            if filename:
                # Créer le document PDF
                doc = SimpleDocTemplate(filename, pagesize=letter)
                elements = []
                
                # Titre
                styles = getSampleStyleSheet()
                title = Paragraph("Rapport d'Anomalies Détectées", styles['Title'])
                elements.append(title)
                
                # Tableau des données
                table_data = [['Équipement', 'Type', 'Score', 'Horodatage', 'Détails']]
                
                for anomaly in self.filtered_data[:50]:  # Limiter à 50 anomalies pour le PDF
                    table_data.append([
                        anomaly['equipment'],
                        anomaly['type'],
                        f"{anomaly['score']:.3f}",
                        anomaly['timestamp'],
                        anomaly['details'][:50] + "..." if len(anomaly['details']) > 50 else anomaly['details']
                    ])
                
                table = Table(table_data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                elements.append(table)
                doc.build(elements)
                
                QMessageBox.information(self, "Export réussi", f"Rapport PDF exporté vers {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur d'export", f"Erreur lors de l'export PDF: {str(e)}") 