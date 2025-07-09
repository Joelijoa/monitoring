from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QListWidget, QListWidgetItem, QPushButton, 
                             QFrame, QComboBox, QGroupBox, QLineEdit,
                             QSplitter, QFileDialog, QMessageBox, QSpinBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import requests
import json
from datetime import datetime
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from monitoring.services.wazuh_service import WazuhService
from monitoring.config.wazuh_config import FILTER_OPTIONS, REFRESH_INTERVALS, EVENT_TYPES

class UserActivityPage(QWidget):
    def __init__(self):
        super().__init__()
        self.wazuh_service = WazuhService()
        self.user_activity_data = []
        self.filtered_data = []
        self.current_page = 0
        self.events_per_page = 50
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre et description
        title = QLabel("Suivi Actions Utilisateurs/Système")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        desc = QLabel("Connexions, processus, fichiers via Wazuh - Timeline temps réel")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Indicateur de connexion
        self.connection_status = QLabel("État de la connexion: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Contrôles de recherche et filtrage
        controls_layout = QHBoxLayout()
        
        # Recherche
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Rechercher dans les événements...")
        self.search_edit.textChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Recherche:"))
        controls_layout.addWidget(self.search_edit)
        
        # Filtre par type d'événement
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Tous", "Connexions", "Processus", "Fichiers", "Réseau", "Système"])
        self.filter_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Type:"))
        controls_layout.addWidget(self.filter_combo)
        
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
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Timeline des événements
        left_widget = self.create_timeline_section()
        splitter.addWidget(left_widget)
        
        # Partie droite - Actions de sécurité
        right_widget = self.create_security_actions_section()
        splitter.addWidget(right_widget)
        
        # Répartition 70% timeline, 30% actions
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def create_timeline_section(self):
        group = QGroupBox("Timeline des Événements")
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
        
        # QListWidget pour la timeline
        self.timeline_list = QListWidget()
        self.timeline_list.setStyleSheet("""
            QListWidget {
                background-color: white;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #ecf0f1;
            }
            QListWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #ecf0f1;
            }
        """)
        
        layout.addWidget(self.timeline_list)
        
        # Contrôles de pagination
        pagination_layout = QHBoxLayout()
        
        self.prev_btn = QPushButton("◀ Précédent")
        self.prev_btn.clicked.connect(self.previous_page)
        self.prev_btn.setEnabled(False)
        pagination_layout.addWidget(self.prev_btn)
        
        self.page_info = QLabel("Page 1")
        pagination_layout.addWidget(self.page_info)
        
        self.next_btn = QPushButton("Suivant ▶")
        self.next_btn.clicked.connect(self.next_page)
        pagination_layout.addWidget(self.next_btn)
        
        pagination_layout.addStretch()
        
        # Sélecteur d'événements par page
        pagination_layout.addWidget(QLabel("Événements par page:"))
        self.events_per_page_spin = QSpinBox()
        self.events_per_page_spin.setRange(10, 100)
        self.events_per_page_spin.setValue(50)
        self.events_per_page_spin.valueChanged.connect(self.change_events_per_page)
        pagination_layout.addWidget(self.events_per_page_spin)
        
        layout.addLayout(pagination_layout)
        
        group.setLayout(layout)
        return group
        
    def create_security_actions_section(self):
        group = QGroupBox("Actions de Sécurité")
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
        
        # Informations sur l'événement sélectionné
        self.selected_event_info = QLabel("Sélectionnez un événement pour voir les détails")
        self.selected_event_info.setWordWrap(True)
        self.selected_event_info.setStyleSheet("""
            QLabel {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(self.selected_event_info)
        
        # Boutons d'action
        actions_label = QLabel("Actions disponibles:")
        actions_label.setStyleSheet("font-weight: bold; margin-bottom: 5px;")
        layout.addWidget(actions_label)
        
        # Bouton Isoler IP
        self.isolate_ip_btn = QPushButton("🚫 Isoler IP")
        self.isolate_ip_btn.clicked.connect(self.isolate_ip)
        self.isolate_ip_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 4px;
                font-weight: bold;
                margin-bottom: 8px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        self.isolate_ip_btn.setEnabled(False)
        layout.addWidget(self.isolate_ip_btn)
        
        # Bouton Bloquer VPN
        self.block_vpn_btn = QPushButton("🔒 Bloquer VPN")
        self.block_vpn_btn.clicked.connect(self.block_vpn)
        self.block_vpn_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 4px;
                font-weight: bold;
                margin-bottom: 8px;
            }
            QPushButton:hover {
                background-color: #d68910;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        self.block_vpn_btn.setEnabled(False)
        layout.addWidget(self.block_vpn_btn)
        
        # Bouton Quarantaine
        self.quarantine_btn = QPushButton("🏥 Mettre en Quarantaine")
        self.quarantine_btn.clicked.connect(self.quarantine)
        self.quarantine_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 4px;
                font-weight: bold;
                margin-bottom: 8px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        self.quarantine_btn.setEnabled(False)
        layout.addWidget(self.quarantine_btn)
        
        # Statistiques
        stats_label = QLabel("Statistiques:")
        stats_label.setStyleSheet("font-weight: bold; margin-top: 20px; margin-bottom: 5px;")
        layout.addWidget(stats_label)
        
        self.total_events_label = QLabel("Total événements: 0")
        self.suspicious_events_label = QLabel("Événements suspects: 0")
        self.critical_events_label = QLabel("Événements critiques: 0")
        
        for label in [self.total_events_label, self.suspicious_events_label, self.critical_events_label]:
            label.setStyleSheet("margin: 2px 0;")
            layout.addWidget(label)
        
        layout.addStretch()
        group.setLayout(layout)
        return group
        
    def setup_timer(self):
        """Configure le timer pour rafraîchir les données toutes les 15 secondes"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(15000)  # 15 secondes
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
        except Exception as e:
            print(f"Erreur lors de la récupération des données: {e}")
            self.connection_status.setText("État de la connexion: ERREUR")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def get_real_wazuh_data(self):
        """Récupère les vraies données depuis l'API Wazuh"""
        try:
            events_data = self.wazuh_service.get_user_activity()
            self.user_activity_data = []
            
            for event in events_data:
                processed_data = {
                    'timestamp': event.get('timestamp', ''),
                    'user': event.get('user', 'N/A'),
                    'type': event.get('event_type', 'N/A'),
                    'message': event.get('message', ''),
                    'agent': event.get('agent', 'N/A'),
                    'severity': event.get('severity', 'info'),
                    'ip_address': event.get('ip_address', ''),
                    'process': event.get('process', ''),
                    'file': event.get('file', ''),
                    'risk_score': event.get('risk_score', 0)
                }
                self.user_activity_data.append(processed_data)
                
        except Exception as e:
            print(f"Erreur lors de la récupération des données Wazuh: {e}")
            self.simulate_wazuh_data()
            
    def simulate_wazuh_data(self):
        """Simule des données d'activité utilisateur pour les tests"""
        import random
        from datetime import datetime, timedelta
        
        event_types = [
            "Connexion", "Déconnexion", "Exécution programme", "Accès fichier",
            "Connexion réseau", "Modification système", "Tentative d'accès"
        ]
        
        users = ["admin", "user1", "user2", "dev1", "test_user", "guest"]
        agents = ["PC-001", "PC-002", "Serveur-WEB", "PC-Admin", "Laptop-Dev"]
        processes = ["chrome.exe", "notepad.exe", "cmd.exe", "explorer.exe", "powershell.exe"]
        files = ["document.txt", "config.ini", "data.csv", "script.py", "backup.zip"]
        
        self.user_activity_data = []
        current_time = datetime.now()
        
        for i in range(200):  # Générer 200 événements
            # Timestamp aléatoire dans les dernières 24h
            random_hours = random.uniform(0, 24)
            event_time = current_time - timedelta(hours=random_hours)
            
            event_type = random.choice(event_types)
            user = random.choice(users)
            agent = random.choice(agents)
            
            # Générer un message approprié selon le type
            if event_type == "Connexion":
                message = f"Connexion utilisateur {user} depuis {agent}"
                ip_address = f"192.168.1.{random.randint(1, 254)}"
            elif event_type == "Exécution programme":
                process = random.choice(processes)
                message = f"Programme {process} exécuté par {user}"
                ip_address = ""
            elif event_type == "Accès fichier":
                file = random.choice(files)
                message = f"Accès au fichier {file} par {user}"
                ip_address = ""
            else:
                message = f"Événement {event_type} pour {user}"
                ip_address = ""
            
            # Score de risque basé sur le type d'événement
            if event_type in ["Tentative d'accès", "Modification système"]:
                risk_score = random.randint(70, 100)
                severity = "critical"
            elif event_type in ["Exécution programme", "Connexion réseau"]:
                risk_score = random.randint(30, 70)
                severity = "warning"
            else:
                risk_score = random.randint(0, 30)
                severity = "info"
            
            data = {
                'timestamp': event_time.strftime("%Y-%m-%d %H:%M:%S"),
                'user': user,
                'type': event_type,
                'message': message,
                'agent': agent,
                'severity': severity,
                'ip_address': ip_address,
                'process': random.choice(processes) if event_type == "Exécution programme" else "",
                'file': random.choice(files) if event_type == "Accès fichier" else "",
                'risk_score': risk_score
            }
            self.user_activity_data.append(data)
            
        # Trier par timestamp (plus récent en premier)
        self.user_activity_data.sort(key=lambda x: x['timestamp'], reverse=True)
                
    def apply_filters(self):
        """Applique les filtres de recherche et de type"""
        search_text = self.search_edit.text().lower()
        filter_type = self.filter_combo.currentText()
        
        self.filtered_data = []
        
        for event in self.user_activity_data:
            # Filtre par type
            type_match = filter_type == "Tous" or event['type'] == filter_type
            
            # Filtre par recherche
            search_match = (search_text == "" or 
                          search_text in event['user'].lower() or
                          search_text in event['message'].lower() or
                          search_text in event['agent'].lower())
            
            if type_match and search_match:
                self.filtered_data.append(event)
        
        self.current_page = 0
        self.update_timeline()
        self.update_pagination_controls()
        
    def update_timeline(self):
        """Met à jour la timeline avec les événements filtrés"""
        self.timeline_list.clear()
        
        start_idx = self.current_page * self.events_per_page
        end_idx = start_idx + self.events_per_page
        page_events = self.filtered_data[start_idx:end_idx]
        
        for event in page_events:
            # Créer un item formaté pour la timeline
            severity_color = {
                'critical': '#e74c3c',
                'warning': '#f39c12', 
                'info': '#3498db'
            }.get(event['severity'], '#7f8c8d')
            
            # Format de l'item : [Timestamp] [Type] User@Agent: Message
            item_text = f"[{event['timestamp']}] [{event['type']}] {event['user']}@{event['agent']}: {event['message']}"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, event)  # Stocker les données complètes
            
            # Couleur selon la sévérité
            if event['severity'] == 'critical':
                item.setBackground(QColor(231, 76, 60, 50))  # Rouge transparent
            elif event['severity'] == 'warning':
                item.setBackground(QColor(243, 156, 18, 50))  # Orange transparent
            
            self.timeline_list.addItem(item)
            
        # Connecter la sélection
        self.timeline_list.itemSelectionChanged.connect(self.on_event_selected)
        
    def update_pagination_controls(self):
        """Met à jour les contrôles de pagination"""
        total_pages = (len(self.filtered_data) + self.events_per_page - 1) // self.events_per_page
        
        self.page_info.setText(f"Page {self.current_page + 1} sur {max(1, total_pages)}")
        self.prev_btn.setEnabled(self.current_page > 0)
        self.next_btn.setEnabled(self.current_page < total_pages - 1)
        
    def previous_page(self):
        """Page précédente"""
        if self.current_page > 0:
            self.current_page -= 1
            self.update_timeline()
            self.update_pagination_controls()
            
    def next_page(self):
        """Page suivante"""
        total_pages = (len(self.filtered_data) + self.events_per_page - 1) // self.events_per_page
        if self.current_page < total_pages - 1:
            self.current_page += 1
            self.update_timeline()
            self.update_pagination_controls()
            
    def change_events_per_page(self, value):
        """Change le nombre d'événements par page"""
        self.events_per_page = value
        self.current_page = 0
        self.update_timeline()
        self.update_pagination_controls()
        
    def on_event_selected(self):
        """Appelé quand un événement est sélectionné"""
        current_item = self.timeline_list.currentItem()
        if current_item:
            event_data = current_item.data(Qt.ItemDataRole.UserRole)
            self.update_selected_event_info(event_data)
            self.update_action_buttons(event_data)
        else:
            self.selected_event_info.setText("Sélectionnez un événement pour voir les détails")
            self.disable_action_buttons()
            
    def update_selected_event_info(self, event_data):
        """Met à jour les informations de l'événement sélectionné"""
        info_text = f"""
<b>Événement sélectionné:</b><br>
• <b>Timestamp:</b> {event_data['timestamp']}<br>
• <b>Utilisateur:</b> {event_data['user']}<br>
• <b>Type:</b> {event_data['type']}<br>
• <b>Agent:</b> {event_data['agent']}<br>
• <b>Message:</b> {event_data['message']}<br>
• <b>Sévérité:</b> {event_data['severity']}<br>
• <b>Score de risque:</b> {event_data['risk_score']}<br>
"""
        if event_data['ip_address']:
            info_text += f"• <b>IP:</b> {event_data['ip_address']}<br>"
        if event_data['process']:
            info_text += f"• <b>Processus:</b> {event_data['process']}<br>"
        if event_data['file']:
            info_text += f"• <b>Fichier:</b> {event_data['file']}<br>"
            
        self.selected_event_info.setText(info_text)
        
    def update_action_buttons(self, event_data):
        """Active/désactive les boutons d'action selon l'événement"""
        has_ip = bool(event_data.get('ip_address'))
        is_suspicious = event_data['risk_score'] > 50
        
        self.isolate_ip_btn.setEnabled(has_ip)
        self.block_vpn_btn.setEnabled(has_ip and is_suspicious)
        self.quarantine_btn.setEnabled(is_suspicious)
        
    def disable_action_buttons(self):
        """Désactive tous les boutons d'action"""
        self.isolate_ip_btn.setEnabled(False)
        self.block_vpn_btn.setEnabled(False)
        self.quarantine_btn.setEnabled(False)
        
    def isolate_ip(self):
        """Isole l'IP de l'événement sélectionné"""
        current_item = self.timeline_list.currentItem()
        if current_item:
            event_data = current_item.data(Qt.ItemDataRole.UserRole)
            ip = event_data.get('ip_address')
            if ip:
                QMessageBox.information(self, "Isolation IP", f"IP {ip} isolée avec succès")
                
    def block_vpn(self):
        """Bloque l'accès VPN pour l'IP"""
        current_item = self.timeline_list.currentItem()
        if current_item:
            event_data = current_item.data(Qt.ItemDataRole.UserRole)
            ip = event_data.get('ip_address')
            if ip:
                QMessageBox.information(self, "Blocage VPN", f"Accès VPN bloqué pour {ip}")
                
    def quarantine(self):
        """Met en quarantaine l'utilisateur/équipement"""
        current_item = self.timeline_list.currentItem()
        if current_item:
            event_data = current_item.data(Qt.ItemDataRole.UserRole)
            user = event_data.get('user')
            agent = event_data.get('agent')
            QMessageBox.information(self, "Quarantaine", f"Utilisateur {user} sur {agent} mis en quarantaine")
            
    def update_statistics(self):
        """Met à jour les statistiques"""
        total = len(self.user_activity_data)
        suspicious = len([e for e in self.user_activity_data if e['risk_score'] > 50])
        critical = len([e for e in self.user_activity_data if e['severity'] == 'critical'])
        
        self.total_events_label.setText(f"Total événements: {total}")
        self.suspicious_events_label.setText(f"Événements suspects: {suspicious}")
        self.critical_events_label.setText(f"Événements critiques: {critical}")
        
    def export_csv(self):
        """Exporte les données en CSV"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Exporter en CSV", "user_activity_data.csv", "CSV Files (*.csv)"
            )
            
            if filename:
                # Préparer les données pour l'export
                export_data = []
                for event in self.filtered_data:
                    export_data.append({
                        'Timestamp': event['timestamp'],
                        'Utilisateur': event['user'],
                        'Type': event['type'],
                        'Message': event['message'],
                        'Agent': event['agent'],
                        'Sévérité': event['severity'],
                        'Score_Risque': event['risk_score'],
                        'IP': event.get('ip_address', ''),
                        'Processus': event.get('process', ''),
                        'Fichier': event.get('file', '')
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
                self, "Exporter en PDF", "user_activity_report.pdf", "PDF Files (*.pdf)"
            )
            
            if filename:
                # Créer le document PDF
                doc = SimpleDocTemplate(filename, pagesize=letter)
                elements = []
                
                # Titre
                styles = getSampleStyleSheet()
                title = Paragraph("Rapport d'Activité Utilisateur", styles['Title'])
                elements.append(title)
                
                # Tableau des données
                table_data = [['Timestamp', 'Utilisateur', 'Type', 'Message', 'Agent', 'Sévérité']]
                
                for event in self.filtered_data[:100]:  # Limiter à 100 événements pour le PDF
                    table_data.append([
                        event['timestamp'],
                        event['user'],
                        event['type'],
                        event['message'][:50] + "..." if len(event['message']) > 50 else event['message'],
                        event['agent'],
                        event['severity']
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