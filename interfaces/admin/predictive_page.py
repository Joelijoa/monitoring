from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QFrame, QComboBox, QPushButton, QGroupBox,
                             QProgressBar, QSplitter)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import requests
import json
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from monitoring.services.predictive_service import PredictiveService
from monitoring.config.predictive_config import ANOMALY_TYPES, REFRESH_INTERVALS

class PredictivePage(QWidget):
    def __init__(self):
        super().__init__()
        self.predictive_service = PredictiveService()
        self.anomalies_data = []
        self.filtered_data = []
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre
        title = QLabel("Analyse Prédictive")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Détection de comportements anormaux via IA - Analyse des logs Wazuh/ELK toutes les heures")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Statut de l'analyse
        self.analysis_status = QLabel("Statut de l'analyse: Initialisation...")
        self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.analysis_status)
        
        # Contrôles de filtrage
        filter_layout = QHBoxLayout()
        
        # Filtre par type d'anomalie
        filter_label = QLabel("Filtrer par type :")
        filter_label.setStyleSheet("font-weight: bold; margin-right: 10px;")
        filter_layout.addWidget(filter_label)
        
        self.anomaly_filter_combo = QComboBox()
        self.anomaly_filter_combo.addItem("Toutes les anomalies", "all")
        for anomaly_key, anomaly_info in ANOMALY_TYPES.items():
            self.anomaly_filter_combo.addItem(
                f"{anomaly_info['icon']} {anomaly_info['name']}", 
                anomaly_key
            )
        self.anomaly_filter_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.anomaly_filter_combo)
        
        # Filtre par sévérité
        severity_label = QLabel("Sévérité :")
        severity_label.setStyleSheet("font-weight: bold; margin-left: 20px; margin-right: 10px;")
        filter_layout.addWidget(severity_label)
        
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("Toutes", "all")
        self.severity_combo.addItem("Critique", "critical")
        self.severity_combo.addItem("Avertissement", "warning")
        self.severity_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.severity_combo)
        
        # Bouton d'analyse manuelle
        analyze_btn = QPushButton("🔍 Analyser Maintenant")
        analyze_btn.clicked.connect(self.run_analysis)
        analyze_btn.setStyleSheet("""
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
        filter_layout.addWidget(analyze_btn)
        
        # Bouton d'entraînement
        train_btn = QPushButton("🎓 Entraîner Modèles")
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
        filter_layout.addWidget(train_btn)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des anomalies
        left_widget = self.create_anomalies_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Statistiques et graphiques
        right_widget = self.create_statistics_section()
        splitter.addWidget(right_widget)
        
        # Répartition 70% tableau, 30% statistiques
        splitter.setSizes([700, 300])
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
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Équipement", "Type d'Anomalie", "Probabilité", "Date/Heure", 
            "Détails", "Sévérité"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Équipement
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Type
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Probabilité
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Date
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)           # Détails
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Sévérité
        
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
        
    def create_statistics_section(self):
        group = QGroupBox("Statistiques et Analyse")
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
        
        # Statistiques générales
        stats_group = QGroupBox("Résumé")
        stats_layout = QVBoxLayout()
        
        self.total_anomalies_label = QLabel("Total anomalies: 0")
        self.critical_anomalies_label = QLabel("Anomalies critiques: 0")
        self.warning_anomalies_label = QLabel("Anomalies avertissement: 0")
        self.model_confidence_label = QLabel("Confiance modèle: 0%")
        
        for label in [self.total_anomalies_label, self.critical_anomalies_label, 
                     self.warning_anomalies_label, self.model_confidence_label]:
            label.setStyleSheet("font-size: 12px; margin: 5px;")
            stats_layout.addWidget(label)
            
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Graphique des types d'anomalies
        self.anomalies_figure = Figure(figsize=(4, 3))
        self.anomalies_canvas = FigureCanvas(self.anomalies_figure)
        self.anomalies_ax = self.anomalies_figure.add_subplot(111)
        self.anomalies_ax.set_title("Types d'Anomalies")
        
        layout.addWidget(self.anomalies_canvas)
        
        # Graphique de sévérité
        self.severity_figure = Figure(figsize=(4, 3))
        self.severity_canvas = FigureCanvas(self.severity_figure)
        self.severity_ax = self.severity_figure.add_subplot(111)
        self.severity_ax.set_title("Répartition par Sévérité")
        
        layout.addWidget(self.severity_canvas)
        
        group.setLayout(layout)
        return group
        
    def setup_timers(self):
        """Configure les timers pour l'analyse automatique"""
        # Timer pour l'analyse d'anomalies (toutes les heures)
        self.analysis_timer = QTimer()
        self.analysis_timer.timeout.connect(self.run_analysis)
        self.analysis_timer.start(REFRESH_INTERVALS['anomaly_detection'] * 1000)
        
        # Timer pour l'entraînement des modèles (quotidien)
        self.training_timer = QTimer()
        self.training_timer.timeout.connect(self.train_models)
        self.training_timer.start(REFRESH_INTERVALS['model_training'] * 1000)
        
        # Première analyse
        self.run_analysis()
        
    def run_analysis(self):
        """Lance l'analyse d'anomalies"""
        try:
            self.analysis_status.setText("Statut de l'analyse: Analyse en cours...")
            self.analysis_status.setStyleSheet("color: #f39c12; font-weight: bold;")
            
            # Exécuter l'analyse
            self.anomalies_data = self.predictive_service.analyze_anomalies()
            
            # Mettre à jour l'affichage
            self.apply_filters()
            self.update_statistics()
            self.update_charts()
            
            # Mettre à jour le statut
            if self.anomalies_data:
                self.analysis_status.setText(f"Statut de l'analyse: {len(self.anomalies_data)} anomalies détectées")
                self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            else:
                self.analysis_status.setText("Statut de l'analyse: Aucune anomalie détectée")
                self.analysis_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                
        except Exception as e:
            print(f"Erreur lors de l'analyse: {e}")
            self.analysis_status.setText("Statut de l'analyse: Erreur lors de l'analyse")
            self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def train_models(self):
        """Entraîne les modèles ML"""
        try:
            self.analysis_status.setText("Statut de l'analyse: Entraînement des modèles...")
            self.analysis_status.setStyleSheet("color: #f39c12; font-weight: bold;")
            
            # Entraîner les modèles
            self.predictive_service.train_models()
            
            self.analysis_status.setText("Statut de l'analyse: Modèles entraînés avec succès")
            self.analysis_status.setStyleSheet("color: #27ae60; font-weight: bold;")
            
        except Exception as e:
            print(f"Erreur lors de l'entraînement: {e}")
            self.analysis_status.setText("Statut de l'analyse: Erreur lors de l'entraînement")
            self.analysis_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def apply_filters(self):
        """Applique les filtres sélectionnés"""
        self.filtered_data = self.anomalies_data.copy()
        
        # Filtre par type d'anomalie
        anomaly_filter = self.anomaly_filter_combo.currentData()
        if anomaly_filter != "all":
            self.filtered_data = [anomaly for anomaly in self.filtered_data 
                                if anomaly['anomaly_type'] == anomaly_filter]
        
        # Filtre par sévérité
        severity_filter = self.severity_combo.currentText().lower()
        if severity_filter != "toutes":
            self.filtered_data = [anomaly for anomaly in self.filtered_data 
                                if anomaly['severity'] == severity_filter]
        
        self.update_table()
        
    def update_table(self):
        """Met à jour le tableau avec les anomalies filtrées"""
        self.table.setRowCount(len(self.filtered_data))
        
        for row, anomaly in enumerate(self.filtered_data):
            # Équipement
            equipment_item = QTableWidgetItem(anomaly['equipment'])
            equipment_item.setFont(QFont("Arial", 10, QFont.Bold))
            self.table.setItem(row, 0, equipment_item)
            
            # Type d'anomalie
            anomaly_type = ANOMALY_TYPES.get(anomaly['anomaly_type'], {})
            type_item = QTableWidgetItem(f"{anomaly['icon']} {anomaly_type.get('name', anomaly['anomaly_type'])}")
            self.table.setItem(row, 1, type_item)
            
            # Probabilité
            prob_item = QTableWidgetItem(f"{anomaly['probability']:.2%}")
            if anomaly['probability'] > 0.9:
                prob_item.setBackground(QColor(231, 76, 60))
                prob_item.setForeground(QColor(255, 255, 255))
            elif anomaly['probability'] > 0.7:
                prob_item.setBackground(QColor(243, 156, 18))
                prob_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 2, prob_item)
            
            # Date/Heure
            datetime_item = QTableWidgetItem(anomaly['timestamp'])
            self.table.setItem(row, 3, datetime_item)
            
            # Détails
            details_item = QTableWidgetItem(anomaly['details'])
            self.table.setItem(row, 4, details_item)
            
            # Sévérité
            severity_item = QTableWidgetItem(anomaly['severity'].upper())
            if anomaly['severity'] == 'critical':
                severity_item.setBackground(QColor(231, 76, 60))
                severity_item.setForeground(QColor(255, 255, 255))
            elif anomaly['severity'] == 'warning':
                severity_item.setBackground(QColor(243, 156, 18))
                severity_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 5, severity_item)
            
    def update_statistics(self):
        """Met à jour les statistiques"""
        stats = self.predictive_service.get_anomaly_statistics()
        
        self.total_anomalies_label.setText(f"Total anomalies: {stats['total_anomalies']}")
        self.critical_anomalies_label.setText(f"Anomalies critiques: {stats['critical_anomalies']}")
        self.warning_anomalies_label.setText(f"Anomalies avertissement: {stats['warning_anomalies']}")
        
        # Calculer la confiance du modèle (simulée)
        if stats['total_anomalies'] > 0:
            confidence = min(95, 70 + (stats['total_anomalies'] * 2))
        else:
            confidence = 70
        self.model_confidence_label.setText(f"Confiance modèle: {confidence}%")
        
    def update_charts(self):
        """Met à jour les graphiques"""
        stats = self.predictive_service.get_anomaly_statistics()
        
        # Graphique des types d'anomalies
        self.anomalies_ax.clear()
        anomaly_types = stats.get('anomaly_types', {})
        
        if anomaly_types:
            labels = []
            values = []
            colors = []
            
            for anomaly_type, count in anomaly_types.items():
                anomaly_info = ANOMALY_TYPES.get(anomaly_type, {})
                labels.append(f"{anomaly_info.get('icon', '')} {anomaly_info.get('name', anomaly_type)}")
                values.append(count)
                
                # Couleur selon la sévérité
                if anomaly_info.get('severity') == 'critical':
                    colors.append('#e74c3c')
                else:
                    colors.append('#f39c12')
            
            if labels and values:
                bars = self.anomalies_ax.bar(labels, values, color=colors)
                self.anomalies_ax.set_title("Types d'Anomalies")
                self.anomalies_ax.set_ylabel("Nombre d'anomalies")
                
                # Rotation des labels pour la lisibilité
                self.anomalies_ax.tick_params(axis='x', rotation=45)
                
                # Ajouter les valeurs sur les barres
                for bar, value in zip(bars, values):
                    self.anomalies_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                        str(value), ha='center', va='bottom')
                
                self.anomalies_canvas.draw()
        
        # Graphique de sévérité
        self.severity_ax.clear()
        critical_count = stats.get('critical_anomalies', 0)
        warning_count = stats.get('warning_anomalies', 0)
        
        if critical_count > 0 or warning_count > 0:
            labels = ['Critique', 'Avertissement']
            values = [critical_count, warning_count]
            colors = ['#e74c3c', '#f39c12']
            
            bars = self.severity_ax.bar(labels, values, color=colors)
            self.severity_ax.set_title("Répartition par Sévérité")
            self.severity_ax.set_ylabel("Nombre d'anomalies")
            
            # Ajouter les valeurs sur les barres
            for bar, value in zip(bars, values):
                if value > 0:
                    self.severity_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                        str(value), ha='center', va='bottom')
            
            self.severity_canvas.draw() 