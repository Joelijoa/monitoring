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
from monitoring.services.wazuh_service import WazuhService
from monitoring.config.wazuh_config import FILTER_OPTIONS, REFRESH_INTERVALS, EVENT_TYPES

class UserActivityPage(QWidget):
    def __init__(self):
        super().__init__()
        self.wazuh_service = WazuhService()
        self.user_activity_data = []
        self.filtered_data = []
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre
        title = QLabel("Activité Utilisateur")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Affiche toutes les actions enregistrées par les utilisateurs et le système")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Indicateur de connexion
        self.connection_status = QLabel("État de la connexion: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Contrôles de filtrage
        filter_layout = QHBoxLayout()
        
        # Filtre par type d'événement
        filter_label = QLabel("Filtrer par :")
        filter_label.setStyleSheet("font-weight: bold; margin-right: 10px;")
        filter_layout.addWidget(filter_label)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("Tous les événements", "all")
        self.filter_combo.addItem("Connexions/Déconnexions", "login")
        self.filter_combo.addItem("Exécution de programmes", "program_execution")
        self.filter_combo.addItem("Accès aux fichiers", "file_access")
        self.filter_combo.addItem("Accès réseau", "network_access")
        self.filter_combo.addItem("Événements système", "system_event")
        self.filter_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.filter_combo)
        
        # Filtre par niveau de risque
        risk_label = QLabel("Niveau de risque :")
        risk_label.setStyleSheet("font-weight: bold; margin-left: 20px; margin-right: 10px;")
        filter_layout.addWidget(risk_label)
        
        self.risk_combo = QComboBox()
        self.risk_combo.addItem("Tous", "all")
        self.risk_combo.addItem("Normal", "normal")
        self.risk_combo.addItem("Suspect", "suspicious")
        self.risk_combo.addItem("Critique", "critical")
        self.risk_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.risk_combo)
        
        # Bouton de rafraîchissement
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.refresh_data)
        refresh_btn.setStyleSheet("""
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
        filter_layout.addWidget(refresh_btn)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des événements
        left_widget = self.create_events_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Statistiques et graphiques
        right_widget = self.create_statistics_section()
        splitter.addWidget(right_widget)
        
        # Répartition 70% tableau, 30% statistiques
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def create_events_table(self):
        group = QGroupBox("Événements Utilisateur")
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
        
        # Tableau des événements
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Date/Heure", "Utilisateur", "Type", "Message", "Agent", 
            "Sévérité", "Score Suspicion", "Niveau Risque"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Date
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Utilisateur
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Type
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)           # Message
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Agent
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Sévérité
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Score
            header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # Risque
        
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
        
        self.total_events_label = QLabel("Total événements: 0")
        self.suspicious_events_label = QLabel("Événements suspects: 0")
        self.critical_events_label = QLabel("Événements critiques: 0")
        self.active_users_label = QLabel("Utilisateurs actifs: 0")
        
        for label in [self.total_events_label, self.suspicious_events_label, 
                     self.critical_events_label, self.active_users_label]:
            label.setStyleSheet("font-size: 12px; margin: 5px;")
            stats_layout.addWidget(label)
            
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Graphique des types d'événements
        self.events_figure = Figure(figsize=(4, 3))
        self.events_canvas = FigureCanvas(self.events_figure)
        self.events_ax = self.events_figure.add_subplot(111)
        self.events_ax.set_title("Types d'Événements")
        
        layout.addWidget(self.events_canvas)
        
        # Graphique des niveaux de risque
        self.risk_figure = Figure(figsize=(4, 3))
        self.risk_canvas = FigureCanvas(self.risk_figure)
        self.risk_ax = self.risk_figure.add_subplot(111)
        self.risk_ax.set_title("Niveaux de Risque")
        
        layout.addWidget(self.risk_canvas)
        
        group.setLayout(layout)
        return group
        
    def setup_timer(self):
        """Configure le timer pour rafraîchir les données"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(REFRESH_INTERVALS['user_activity'] * 1000)  # Conversion en millisecondes
        self.refresh_data()  # Première récupération
        
    def refresh_data(self):
        """Récupère les données depuis l'API Wazuh et met à jour l'affichage"""
        try:
            # Test de connexion
            if not self.wazuh_service.test_connection():
                self.connection_status.setText("État de la connexion: DÉCONNECTÉ")
                self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
                # Utiliser les données simulées en cas de déconnexion
                self.simulate_wazuh_data()
            else:
                self.connection_status.setText("État de la connexion: CONNECTÉ")
                self.connection_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                # Récupérer les vraies données
                self.get_real_wazuh_data()
                
            self.apply_filters()
            self.update_statistics()
            self.update_charts()
        except Exception as e:
            print(f"Erreur lors de la récupération des données: {e}")
            self.connection_status.setText("État de la connexion: ERREUR")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def get_real_wazuh_data(self):
        """Récupère les vraies données depuis l'API Wazuh"""
        try:
            self.user_activity_data = self.wazuh_service.get_all_user_activity()
        except Exception as e:
            print(f"Erreur lors de la récupération des données Wazuh: {e}")
            # Fallback vers les données simulées
            self.simulate_wazuh_data()
            
    def simulate_wazuh_data(self):
        """Simule les données de l'API Wazuh pour la démonstration"""
        import random
        
        users = ["admin", "user1", "user2", "john.doe", "jane.smith", "tech_support"]
        agents = ["SRV-WEB-01", "SRV-DB-01", "PC-USER-01", "PC-USER-02", "LAPTOP-01"]
        event_types = list(EVENT_TYPES.keys())
        
        self.user_activity_data = []
        current_time = datetime.now()
        
        for i in range(50):  # Générer 50 événements simulés
            # Timestamp aléatoire dans les dernières 24h
            timestamp = current_time.timestamp() - random.uniform(0, 86400)
            
            user = random.choice(users)
            event_type = random.choice(event_types)
            agent = random.choice(agents)
            severity = random.randint(0, 15)
            
            # Messages selon le type d'événement
            messages = {
                'login': f"Connexion utilisateur {user} sur {agent}",
                'program_execution': f"Programme {random.choice(['chrome.exe', 'notepad.exe', 'cmd.exe'])} exécuté par {user}",
                'file_access': f"Accès au fichier {random.choice(['document.txt', 'config.ini', 'data.csv'])} par {user}",
                'network_access': f"Connexion réseau suspecte depuis {agent} par {user}",
                'system_event': f"Événement système sur {agent}"
            }
            
            message = messages.get(event_type, f"Événement {event_type} par {user}")
            
            # Scores simulés
            suspicious_score = random.uniform(0, 1)
            anomaly_score = random.uniform(-0.5, 0.5)
            
            # Niveau de risque basé sur les scores
            if suspicious_score > 0.8 or abs(anomaly_score) > 0.4:
                risk_level = "critical"
            elif suspicious_score > 0.5:
                risk_level = "suspicious"
            else:
                risk_level = "normal"
                
            event_data = {
                'id': f"evt_{i}",
                'timestamp': timestamp,
                'user': user,
                'event_type': event_type,
                'message': message,
                'agent': agent,
                'severity': severity,
                'suspicious_score': suspicious_score,
                'anomaly_score': anomaly_score,
                'risk_level': risk_level,
                'datetime': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.user_activity_data.append(event_data)
            
        # Tri par timestamp (plus récent en premier)
        self.user_activity_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
    def apply_filters(self):
        """Applique les filtres sélectionnés"""
        self.filtered_data = self.user_activity_data.copy()
        
        # Filtre par type d'événement
        event_filter = self.filter_combo.currentData()
        if event_filter != "all":
            self.filtered_data = [event for event in self.filtered_data 
                                if event['event_type'] == event_filter]
        
        # Filtre par niveau de risque
        risk_filter = self.risk_combo.currentText().lower()
        if risk_filter != "tous":
            self.filtered_data = [event for event in self.filtered_data 
                                if event['risk_level'] == risk_filter]
        
        self.update_table()
        
    def update_table(self):
        """Met à jour le tableau avec les données filtrées"""
        self.table.setRowCount(len(self.filtered_data))
        
        for row, event in enumerate(self.filtered_data):
            # Date/Heure
            datetime_item = QTableWidgetItem(event['datetime'])
            self.table.setItem(row, 0, datetime_item)
            
            # Utilisateur
            user_item = QTableWidgetItem(event['user'])
            user_item.setFont(QFont("Arial", 10, QFont.Bold))
            self.table.setItem(row, 1, user_item)
            
            # Type d'événement
            event_type = EVENT_TYPES.get(event['event_type'], {}).get('name', event['event_type'])
            type_item = QTableWidgetItem(f"{EVENT_TYPES.get(event['event_type'], {}).get('icon', '')} {event_type}")
            self.table.setItem(row, 2, type_item)
            
            # Message
            message_item = QTableWidgetItem(event['message'])
            self.table.setItem(row, 3, message_item)
            
            # Agent
            agent_item = QTableWidgetItem(event['agent'])
            self.table.setItem(row, 4, agent_item)
            
            # Sévérité
            severity_item = QTableWidgetItem(str(event['severity']))
            if event['severity'] >= 10:
                severity_item.setBackground(QColor(231, 76, 60))
                severity_item.setForeground(QColor(255, 255, 255))
            elif event['severity'] >= 5:
                severity_item.setBackground(QColor(243, 156, 18))
                severity_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 5, severity_item)
            
            # Score de suspicion
            score_item = QTableWidgetItem(f"{event['suspicious_score']:.2f}")
            if event['suspicious_score'] > 0.8:
                score_item.setBackground(QColor(231, 76, 60))
                score_item.setForeground(QColor(255, 255, 255))
            elif event['suspicious_score'] > 0.5:
                score_item.setBackground(QColor(243, 156, 18))
                score_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 6, score_item)
            
            # Niveau de risque
            risk_item = QTableWidgetItem(event['risk_level'].upper())
            if event['risk_level'] == 'critical':
                risk_item.setBackground(QColor(231, 76, 60))
                risk_item.setForeground(QColor(255, 255, 255))
            elif event['risk_level'] == 'suspicious':
                risk_item.setBackground(QColor(243, 156, 18))
                risk_item.setForeground(QColor(255, 255, 255))
            else:
                risk_item.setBackground(QColor(46, 204, 113))
                risk_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 7, risk_item)
            
    def update_statistics(self):
        """Met à jour les statistiques"""
        total_events = len(self.user_activity_data)
        suspicious_events = len([e for e in self.user_activity_data if e['risk_level'] == 'suspicious'])
        critical_events = len([e for e in self.user_activity_data if e['risk_level'] == 'critical'])
        active_users = len(set(e['user'] for e in self.user_activity_data))
        
        self.total_events_label.setText(f"Total événements: {total_events}")
        self.suspicious_events_label.setText(f"Événements suspects: {suspicious_events}")
        self.critical_events_label.setText(f"Événements critiques: {critical_events}")
        self.active_users_label.setText(f"Utilisateurs actifs: {active_users}")
        
    def update_charts(self):
        """Met à jour les graphiques"""
        # Graphique des types d'événements
        self.events_ax.clear()
        event_counts = {}
        for event in self.user_activity_data:
            event_type = event['event_type']
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        if event_counts:
            labels = [EVENT_TYPES.get(et, {}).get('name', et) for et in event_counts.keys()]
            # Filtrer les valeurs None
            labels = [label for label in labels if label is not None]
            values = list(event_counts.values())
            colors = ['#3498db', '#e74c3c', '#f39c12', '#27ae60', '#9b59b6']
            
            if labels and values:
                self.events_ax.pie(values, labels=labels, colors=colors[:len(values)], autopct='%1.1f%%')
                self.events_ax.set_title("Types d'Événements")
                self.events_canvas.draw()
        
        # Graphique des niveaux de risque
        self.risk_ax.clear()
        risk_counts = {}
        for event in self.user_activity_data:
            risk_level = event['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        if risk_counts:
            labels = list(risk_counts.keys())
            values = list(risk_counts.values())
            colors = ['#27ae60', '#f39c12', '#e74c3c']  # Normal, Suspect, Critique
            
            bars = self.risk_ax.bar(labels, values, color=colors[:len(values)])
            self.risk_ax.set_title("Niveaux de Risque")
            self.risk_ax.set_ylabel("Nombre d'événements")
            
            # Ajouter les valeurs sur les barres
            for bar, value in zip(bars, values):
                self.risk_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                str(value), ha='center', va='bottom')
            
            self.risk_canvas.draw() 