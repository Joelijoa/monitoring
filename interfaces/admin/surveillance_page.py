from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QFrame, QSplitter, QProgressBar, QGroupBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import requests
import json
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from monitoring.services.netxms_service import NetXMSService
from monitoring.config.netxms_config import REFRESH_INTERVALS

class SurveillancePage(QWidget):
    def __init__(self):
        super().__init__()
        self.netxms_service = NetXMSService()
        self.equipments_data = []
        self.historical_data = {}  # Pour stocker les données historiques
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre
        title = QLabel("Surveillance en Temps Réel")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Supervision en temps réel de tous les équipements de l'entreprise")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Indicateur de connexion
        self.connection_status = QLabel("État de la connexion: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des équipements
        left_widget = self.create_equipment_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Graphiques
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
        group = QGroupBox("Tendances et Graphiques")
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
        
        # Graphique CPU
        self.cpu_figure = Figure(figsize=(6, 3))
        self.cpu_canvas = FigureCanvas(self.cpu_figure)
        self.cpu_ax = self.cpu_figure.add_subplot(111)
        self.cpu_ax.set_title("Utilisation CPU - Tendances")
        self.cpu_ax.set_ylabel("CPU (%)")
        self.cpu_ax.grid(True, alpha=0.3)
        
        # Graphique RAM
        self.ram_figure = Figure(figsize=(6, 3))
        self.ram_canvas = FigureCanvas(self.ram_figure)
        self.ram_ax = self.ram_figure.add_subplot(111)
        self.ram_ax.set_title("Utilisation RAM - Tendances")
        self.ram_ax.set_ylabel("RAM (%)")
        self.ram_ax.grid(True, alpha=0.3)
        
        layout.addWidget(self.cpu_canvas)
        layout.addWidget(self.ram_canvas)
        
        group.setLayout(layout)
        return group
        
    def setup_timer(self):
        """Configure le timer pour rafraîchir les données toutes les 30 secondes"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(REFRESH_INTERVALS['real_time'] * 1000)  # Conversion en millisecondes
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
                    'status': equipment['status'],
                    'cpu': cpu,
                    'ram': ram,
                    'disk': disk,
                    'network': network,
                    'uptime': equipment['uptime_hours'],
                    'timestamp': datetime.now()
                }
                
                self.equipments_data.append(processed_data)
                
                # Stockage des données historiques
                if equipment['name'] not in self.historical_data:
                    self.historical_data[equipment['name']] = {'cpu': [], 'ram': [], 'timestamps': []}
                
                self.historical_data[equipment['name']]['cpu'].append(cpu)
                self.historical_data[equipment['name']]['ram'].append(ram)
                self.historical_data[equipment['name']]['timestamps'].append(datetime.now())
                
                # Garder seulement les 20 dernières valeurs
                if len(self.historical_data[equipment['name']]['cpu']) > 20:
                    self.historical_data[equipment['name']]['cpu'] = self.historical_data[equipment['name']]['cpu'][-20:]
                    self.historical_data[equipment['name']]['ram'] = self.historical_data[equipment['name']]['ram'][-20:]
                    self.historical_data[equipment['name']]['timestamps'] = self.historical_data[equipment['name']]['timestamps'][-20:]
                    
        except Exception as e:
            print(f"Erreur lors de la récupération des données NetXMS: {e}")
            # Fallback vers les données simulées
            self.simulate_netxms_data()
            
    def simulate_netxms_data(self):
        """Simule les données de l'API NetXMS pour la démonstration"""
        import random
        
        equipments = [
            "Serveur Web 1", "Serveur Web 2", "Serveur Base de Données", 
            "Routeur Principal", "Switch Core", "Firewall", "Serveur Mail"
        ]
        
        self.equipments_data = []
        current_time = datetime.now()
        
        for i, equipment in enumerate(equipments):
            # Simulation de données réalistes
            cpu = random.uniform(20, 85)
            ram = random.uniform(30, 90)
            disk = random.uniform(40, 95)
            network = random.uniform(50, 200)
            uptime_hours = random.uniform(24, 720)  # 1 jour à 30 jours
            
            # État basé sur les métriques
            if cpu > 80 or ram > 85 or disk > 90:
                status = "CRITIQUE"
            elif cpu > 60 or ram > 70 or disk > 80:
                status = "ATTENTION"
            else:
                status = "NORMAL"
                
            equipment_data = {
                'name': equipment,
                'status': status,
                'cpu': cpu,
                'ram': ram,
                'disk': disk,
                'network': network,
                'uptime': uptime_hours,
                'timestamp': current_time
            }
            
            self.equipments_data.append(equipment_data)
            
            # Stockage des données historiques pour les graphiques
            if equipment not in self.historical_data:
                self.historical_data[equipment] = {'cpu': [], 'ram': [], 'timestamps': []}
            
            self.historical_data[equipment]['cpu'].append(cpu)
            self.historical_data[equipment]['ram'].append(ram)
            self.historical_data[equipment]['timestamps'].append(current_time)
            
            # Garder seulement les 20 dernières valeurs
            if len(self.historical_data[equipment]['cpu']) > 20:
                self.historical_data[equipment]['cpu'] = self.historical_data[equipment]['cpu'][-20:]
                self.historical_data[equipment]['ram'] = self.historical_data[equipment]['ram'][-20:]
                self.historical_data[equipment]['timestamps'] = self.historical_data[equipment]['timestamps'][-20:]
                
    def update_table(self):
        """Met à jour le tableau avec les nouvelles données"""
        self.table.setRowCount(len(self.equipments_data))
        
        for row, equipment in enumerate(self.equipments_data):
            # Nom de l'équipement
            name_item = QTableWidgetItem(equipment['name'])
            name_item.setFont(QFont("Arial", 10, QFont.Bold))
            self.table.setItem(row, 0, name_item)
            
            # État
            status_item = QTableWidgetItem(equipment['status'])
            if equipment['status'] == "CRITIQUE":
                status_item.setBackground(QColor(231, 76, 60))  # Rouge
                status_item.setForeground(QColor(255, 255, 255))
            elif equipment['status'] == "ATTENTION":
                status_item.setBackground(QColor(243, 156, 18))  # Orange
                status_item.setForeground(QColor(255, 255, 255))
            else:
                status_item.setBackground(QColor(46, 204, 113))  # Vert
                status_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 1, status_item)
            
            # CPU avec barre de progression
            cpu_item = QTableWidgetItem(f"{equipment['cpu']:.1f}%")
            self.table.setItem(row, 2, cpu_item)
            
            # RAM
            ram_item = QTableWidgetItem(f"{equipment['ram']:.1f}%")
            self.table.setItem(row, 3, ram_item)
            
            # Disque
            disk_item = QTableWidgetItem(f"{equipment['disk']:.1f}%")
            self.table.setItem(row, 4, disk_item)
            
            # Réseau
            network_item = QTableWidgetItem(f"{equipment['network']:.1f}")
            self.table.setItem(row, 5, network_item)
            
            # Uptime
            uptime_days = equipment['uptime'] / 24
            uptime_item = QTableWidgetItem(f"{uptime_days:.1f} jours")
            self.table.setItem(row, 6, uptime_item)
            
    def update_charts(self):
        """Met à jour les graphiques avec les données historiques"""
        # Graphique CPU
        self.cpu_ax.clear()
        for equipment in self.equipments_data[:3]:  # Afficher seulement les 3 premiers
            if equipment['name'] in self.historical_data:
                data = self.historical_data[equipment['name']]
                if len(data['cpu']) > 1:
                    self.cpu_ax.plot(range(len(data['cpu'])), data['cpu'], 
                                   label=equipment['name'], marker='o')
        
        self.cpu_ax.set_title("Utilisation CPU - Tendances")
        self.cpu_ax.set_ylabel("CPU (%)")
        self.cpu_ax.legend()
        self.cpu_ax.grid(True, alpha=0.3)
        self.cpu_canvas.draw()
        
        # Graphique RAM
        self.ram_ax.clear()
        for equipment in self.equipments_data[:3]:  # Afficher seulement les 3 premiers
            if equipment['name'] in self.historical_data:
                data = self.historical_data[equipment['name']]
                if len(data['ram']) > 1:
                    self.ram_ax.plot(range(len(data['ram'])), data['ram'], 
                                   label=equipment['name'], marker='s')
        
        self.ram_ax.set_title("Utilisation RAM - Tendances")
        self.ram_ax.set_ylabel("RAM (%)")
        self.ram_ax.legend()
        self.ram_ax.grid(True, alpha=0.3)
        self.ram_canvas.draw() 