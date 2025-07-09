from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QFrame, QSplitter, QProgressBar, QGroupBox,
                             QComboBox, QLineEdit, QPushButton, QSlider,
                             QHBoxLayout, QVBoxLayout, QFileDialog)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import requests
import json
from datetime import datetime
import pyqtgraph as pg
import numpy as np
import pandas as pd
from monitoring.services.netxms_service import NetXMSService
from monitoring.config.netxms_config import REFRESH_INTERVALS

class SurveillancePage(QWidget):
    def __init__(self):
        super().__init__()
        self.netxms_service = NetXMSService()
        self.equipments_data = []
        self.historical_data = {}  # Pour stocker les données historiques
        self.cpu_threshold = 90  # Seuil CPU par défaut
        self.ram_threshold = 85  # Seuil RAM par défaut
        self.disk_threshold = 90  # Seuil disque par défaut
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre et description
        title = QLabel("Supervision Temps Réel")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        desc = QLabel("Métriques (CPU, RAM, disque, réseau, uptime) via NetXMS (API REST, 30s)")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Indicateur de connexion
        self.connection_status = QLabel("État de la connexion: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Contrôles de filtrage et recherche
        controls_layout = QHBoxLayout()
        
        # Filtre par type d'équipement
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Tous", "Serveurs", "PC", "Réseau", "Autres"])
        self.filter_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Filtre:"))
        controls_layout.addWidget(self.filter_combo)
        
        # Recherche
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Rechercher un équipement...")
        self.search_edit.textChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Recherche:"))
        controls_layout.addWidget(self.search_edit)
        
        # Bouton export CSV
        export_btn = QPushButton("Exporter CSV")
        export_btn.clicked.connect(self.export_csv)
        export_btn.setStyleSheet("""
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
        controls_layout.addWidget(export_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Configuration des seuils
        thresholds_layout = QHBoxLayout()
        thresholds_layout.addWidget(QLabel("Seuils d'alerte:"))
        
        # Seuil CPU
        thresholds_layout.addWidget(QLabel("CPU >"))
        self.cpu_slider = QSlider(Qt.Orientation.Horizontal)
        self.cpu_slider.setRange(50, 100)
        self.cpu_slider.setValue(self.cpu_threshold)
        self.cpu_slider.valueChanged.connect(self.update_cpu_threshold)
        thresholds_layout.addWidget(self.cpu_slider)
        self.cpu_threshold_label = QLabel(f"{self.cpu_threshold}%")
        thresholds_layout.addWidget(self.cpu_threshold_label)
        
        # Seuil RAM
        thresholds_layout.addWidget(QLabel("RAM >"))
        self.ram_slider = QSlider(Qt.Orientation.Horizontal)
        self.ram_slider.setRange(50, 100)
        self.ram_slider.setValue(self.ram_threshold)
        self.ram_slider.valueChanged.connect(self.update_ram_threshold)
        thresholds_layout.addWidget(self.ram_slider)
        self.ram_threshold_label = QLabel(f"{self.ram_threshold}%")
        thresholds_layout.addWidget(self.ram_threshold_label)
        
        # Seuil Disque
        thresholds_layout.addWidget(QLabel("Disque >"))
        self.disk_slider = QSlider(Qt.Orientation.Horizontal)
        self.disk_slider.setRange(50, 100)
        self.disk_slider.setValue(self.disk_threshold)
        self.disk_slider.valueChanged.connect(self.update_disk_threshold)
        thresholds_layout.addWidget(self.disk_slider)
        self.disk_threshold_label = QLabel(f"{self.disk_threshold}%")
        thresholds_layout.addWidget(self.disk_threshold_label)
        
        layout.addLayout(thresholds_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des équipements
        left_widget = self.create_equipment_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Graphiques pyqtgraph
        right_widget = self.create_charts_section()
        splitter.addWidget(right_widget)
        
        # Répartition 60% tableau, 40% graphiques
        splitter.setSizes([600, 400])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def create_equipment_table(self):
        group = QGroupBox("État des Équipements")
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
        
        # Tableau des équipements
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Équipement", "État", "CPU (%)", "RAM (%)", "Disque (%)", 
            "Réseau (Mbps)", "Uptime"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Nom équipement
            for i in range(1, 7):
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        
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
        
    def create_charts_section(self):
        group = QGroupBox("Graphiques Temps Réel")
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
        
        # Graphique CPU
        cpu_widget = pg.PlotWidget()
        cpu_widget.setTitle("Utilisation CPU - Temps Réel")
        cpu_widget.setLabel('left', 'CPU (%)')
        cpu_widget.setLabel('bottom', 'Temps')
        cpu_widget.showGrid(x=True, y=True)
        self.cpu_plot = cpu_widget.plot(pen='r', name='CPU')
        layout.addWidget(cpu_widget)
        
        # Graphique RAM
        ram_widget = pg.PlotWidget()
        ram_widget.setTitle("Utilisation RAM - Temps Réel")
        ram_widget.setLabel('left', 'RAM (%)')
        ram_widget.setLabel('bottom', 'Temps')
        ram_widget.showGrid(x=True, y=True)
        self.ram_plot = ram_widget.plot(pen='b', name='RAM')
        layout.addWidget(ram_widget)
        
        group.setLayout(layout)
        return group
        
    def setup_timer(self):
        """Configure le timer pour rafraîchir les données toutes les 30 secondes"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(30000)  # 30 secondes
        self.refresh_data()  # Première récupération
        
    def refresh_data(self):
        """Récupère les données depuis l'API NetXMS et met à jour l'affichage"""
        try:
            # Test de connexion
            if not self.netxms_service.test_connection():
                self.connection_status.setText("État de la connexion: DÉCONNECTÉ")
                self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
                # Utiliser les données simulées en cas de déconnexion
                self.simulate_netxms_data()
            else:
                self.connection_status.setText("État de la connexion: CONNECTÉ")
                self.connection_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                # Récupérer les vraies données
                self.get_real_netxms_data()
                
            self.update_table()
            self.update_charts()
        except Exception as e:
            print(f"Erreur lors de la récupération des données: {e}")
            self.connection_status.setText("État de la connexion: ERREUR")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def get_real_netxms_data(self):
        """Récupère les vraies données depuis l'API NetXMS"""
        try:
            equipment_data = self.netxms_service.get_all_equipment_data()
            self.equipments_data = []
            
            for equipment in equipment_data:
                # Extraction des métriques
                metrics = equipment.get('metrics', {})
                cpu = metrics.get('cpu_utilization', {}).get('value', 0)
                ram = metrics.get('memory_utilization', {}).get('value', 0)
                disk = metrics.get('disk_utilization', {}).get('value', 0)
                network = metrics.get('network_traffic', {}).get('value', 0)
                
                processed_data = {
                    'name': equipment['name'],
                    'status': equipment.get('status', 'Inconnu'),
                    'cpu': cpu,
                    'ram': ram,
                    'disk': disk,
                    'network': network,
                    'uptime': equipment.get('uptime', 'N/A'),
                    'type': equipment.get('type', 'Autres')
                }
                self.equipments_data.append(processed_data)
                
        except Exception as e:
            print(f"Erreur lors de la récupération des données NetXMS: {e}")
            self.simulate_netxms_data()
            
    def simulate_netxms_data(self):
        """Simule des données d'équipements pour les tests"""
        import random
        from datetime import datetime, timedelta
        
        equipment_names = [
            "Serveur-WEB-01", "Serveur-DB-02", "PC-Admin-03", "Switch-Core-01",
            "Router-FW-01", "PC-User-04", "Serveur-Backup-01", "PC-Dev-05"
        ]
        
        self.equipments_data = []
        current_time = datetime.now()
        
        for i, name in enumerate(equipment_names):
            # Génération de données réalistes
            cpu = random.uniform(20, 95)
            ram = random.uniform(30, 90)
            disk = random.uniform(40, 85)
            network = random.uniform(10, 100)
            
            # Uptime aléatoire
            uptime_days = random.randint(1, 30)
            uptime_hours = random.randint(0, 23)
            uptime = f"{uptime_days}j {uptime_hours}h"
            
            equipment_type = "Serveurs" if "Serveur" in name else "PC" if "PC" in name else "Réseau"
            
            data = {
                'name': name,
                'status': 'En ligne' if random.random() > 0.1 else 'Hors ligne',
                'cpu': round(cpu, 1),
                'ram': round(ram, 1),
                'disk': round(disk, 1),
                'network': round(network, 1),
                'uptime': uptime,
                'type': equipment_type,
                'timestamp': current_time
            }
            self.equipments_data.append(data)
            
        # Stocker les données historiques pour les graphiques
        for data in self.equipments_data:
            name = data['name']
            if name not in self.historical_data:
                self.historical_data[name] = {'cpu': [], 'ram': [], 'timestamps': []}
            
            self.historical_data[name]['cpu'].append(data['cpu'])
            self.historical_data[name]['ram'].append(data['ram'])
            self.historical_data[name]['timestamps'].append(current_time)
            
            # Garder seulement les 20 dernières valeurs
            if len(self.historical_data[name]['cpu']) > 20:
                self.historical_data[name]['cpu'].pop(0)
                self.historical_data[name]['ram'].pop(0)
                self.historical_data[name]['timestamps'].pop(0)
                
    def update_table(self):
        """Met à jour le tableau avec les données actuelles"""
        self.table.setRowCount(len(self.equipments_data))
        
        for row, data in enumerate(self.equipments_data):
            # Nom de l'équipement
            name_item = QTableWidgetItem(data['name'])
            self.table.setItem(row, 0, name_item)
            
            # État avec couleur
            status_item = QTableWidgetItem(data['status'])
            if data['status'] == 'En ligne':
                status_item.setBackground(QColor(144, 238, 144))  # Vert clair
            else:
                status_item.setBackground(QColor(255, 182, 193))  # Rouge clair
            self.table.setItem(row, 1, status_item)
            
            # CPU avec alerte visuelle
            cpu_item = QTableWidgetItem(f"{data['cpu']}%")
            if data['cpu'] > self.cpu_threshold:
                cpu_item.setBackground(QColor(255, 0, 0))  # Rouge
                cpu_item.setForeground(QColor(255, 255, 255))  # Texte blanc
            self.table.setItem(row, 2, cpu_item)
            
            # RAM avec alerte visuelle
            ram_item = QTableWidgetItem(f"{data['ram']}%")
            if data['ram'] > self.ram_threshold:
                ram_item.setBackground(QColor(255, 0, 0))  # Rouge
                ram_item.setForeground(QColor(255, 255, 255))  # Texte blanc
            self.table.setItem(row, 3, ram_item)
            
            # Disque avec alerte visuelle
            disk_item = QTableWidgetItem(f"{data['disk']}%")
            if data['disk'] > self.disk_threshold:
                disk_item.setBackground(QColor(255, 0, 0))  # Rouge
                disk_item.setForeground(QColor(255, 255, 255))  # Texte blanc
            self.table.setItem(row, 4, disk_item)
            
            # Réseau
            network_item = QTableWidgetItem(f"{data['network']:.1f}")
            self.table.setItem(row, 5, network_item)
            
            # Uptime
            uptime_item = QTableWidgetItem(data['uptime'])
            self.table.setItem(row, 6, uptime_item)
            
    def update_charts(self):
        """Met à jour les graphiques pyqtgraph"""
        if not self.equipments_data:
            return
            
        # Prendre le premier équipement pour l'exemple
        first_equipment = self.equipments_data[0]['name']
        if first_equipment in self.historical_data:
            data = self.historical_data[first_equipment]
            
            # Mise à jour du graphique CPU
            if data['cpu']:
                self.cpu_plot.setData(data['cpu'])
            
            # Mise à jour du graphique RAM
            if data['ram']:
                self.ram_plot.setData(data['ram'])
                
    def apply_filters(self):
        """Applique les filtres de recherche et de type"""
        search_text = self.search_edit.text().lower()
        filter_type = self.filter_combo.currentText()
        
        for row in range(self.table.rowCount()):
            name_item = self.table.item(row, 0)
            if name_item:
                name = name_item.text().lower()
                equipment_data = next((d for d in self.equipments_data if d['name'].lower() == name), None)
                
                # Filtre par type
                type_match = filter_type == "Tous" or (equipment_data and equipment_data['type'] == filter_type)
                
                # Filtre par recherche
                search_match = search_text == "" or search_text in name
                
                # Afficher/masquer la ligne
                self.table.setRowHidden(row, not (type_match and search_match))
                
    def update_cpu_threshold(self, value):
        """Met à jour le seuil CPU"""
        self.cpu_threshold = value
        self.cpu_threshold_label.setText(f"{value}%")
        self.update_table()
        
    def update_ram_threshold(self, value):
        """Met à jour le seuil RAM"""
        self.ram_threshold = value
        self.ram_threshold_label.setText(f"{value}%")
        self.update_table()
        
    def update_disk_threshold(self, value):
        """Met à jour le seuil disque"""
        self.disk_threshold = value
        self.disk_threshold_label.setText(f"{value}%")
        self.update_table()
        
    def export_csv(self):
        """Exporte les données du tableau en CSV"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Exporter en CSV", "surveillance_data.csv", "CSV Files (*.csv)"
            )
            
            if filename:
                # Préparer les données pour l'export
                export_data = []
                for row in range(self.table.rowCount()):
                    if not self.table.isRowHidden(row):
                        row_data = []
                        for col in range(self.table.columnCount()):
                            item = self.table.item(row, col)
                            row_data.append(item.text() if item else "")
                        export_data.append(row_data)
                
                # Créer le DataFrame et exporter
                df = pd.DataFrame(export_data)
                df.columns = [
                    "Équipement", "État", "CPU (%)", "RAM (%)", "Disque (%)", 
                    "Réseau (Mbps)", "Uptime"
                ]
                df.to_csv(filename, index=False, encoding='utf-8')
                
                # Message de confirmation
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.information(self, "Export réussi", f"Données exportées vers {filename}")
                
        except Exception as e:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Erreur d'export", f"Erreur lors de l'export: {str(e)}") 