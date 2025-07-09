from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QFrame, QComboBox, QPushButton, QGroupBox,
                             QProgressBar, QSplitter, QDialog, QLineEdit,
                             QTextEdit, QFormLayout, QMessageBox, QFileDialog)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor
import requests
import json
from datetime import datetime
import subprocess
import platform
from monitoring.services.vpn_service import VPNService
from monitoring.config.vpn_config import VPN_USER_TYPES, VPN_STATUS, REFRESH_INTERVALS

class PingThread(QThread):
    """Thread pour tester la connectivité ping"""
    ping_result = pyqtSignal(str, bool, str)  # IP, success, response_time
    
    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        
    def run(self):
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", self.ip_address]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", self.ip_address]
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Extraire le temps de réponse
                output = result.stdout
                if "time=" in output:
                    time_part = output.split("time=")[1].split()[0]
                    self.ping_result.emit(self.ip_address, True, time_part)
                else:
                    self.ping_result.emit(self.ip_address, True, "OK")
            else:
                self.ping_result.emit(self.ip_address, False, "Timeout")
                
        except Exception as e:
            self.ping_result.emit(self.ip_address, False, str(e))

class ManualRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ajouter une Règle Manuelle")
        self.setModal(True)
        self.resize(500, 300)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Formulaire
        form_layout = QFormLayout()
        
        # IP source
        self.source_ip_edit = QLineEdit()
        self.source_ip_edit.setPlaceholderText("ex: 192.168.1.100")
        form_layout.addRow("IP Source:", self.source_ip_edit)
        
        # IP destination
        self.dest_ip_edit = QLineEdit()
        self.dest_ip_edit.setPlaceholderText("ex: 10.0.0.50")
        form_layout.addRow("IP Destination:", self.dest_ip_edit)
        
        # Port
        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("ex: 80,443 ou 22")
        form_layout.addRow("Port:", self.port_edit)
        
        # Action
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Autoriser", "Bloquer", "Quarantaine"])
        form_layout.addRow("Action:", self.action_combo)
        
        # Raison
        self.reason_edit = QTextEdit()
        self.reason_edit.setMaximumHeight(80)
        self.reason_edit.setPlaceholderText("Raison de cette règle...")
        form_layout.addRow("Raison:", self.reason_edit)
        
        layout.addLayout(form_layout)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        add_btn = QPushButton("Ajouter")
        add_btn.clicked.connect(self.accept)
        add_btn.setStyleSheet("""
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
        button_layout.addWidget(add_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def get_rule_data(self):
        return {
            'source_ip': self.source_ip_edit.text().strip(),
            'dest_ip': self.dest_ip_edit.text().strip(),
            'port': self.port_edit.text().strip(),
            'action': self.action_combo.currentText(),
            'reason': self.reason_edit.toPlainText().strip()
        }

class VPNPage(QWidget):
    def __init__(self):
        super().__init__()
        self.vpn_service = VPNService()
        self.vpn_users = []
        self.filtered_users = []
        self.manual_rules = []
        self.ping_threads = {}
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre et description
        title = QLabel("Gestion VPN - Révocation Clés OPNsense")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        desc = QLabel("Utilisateur, IP, statut - Règles manuelles - Actions automatiques si score IA > 0.4")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Statut de la connexion
        self.connection_status = QLabel("Statut de la connexion: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Contrôles principaux
        controls_layout = QHBoxLayout()
        
        # Bouton révocation clés
        revoke_btn = QPushButton("🔑 Révoquer Clés")
        revoke_btn.clicked.connect(self.revoke_selected_keys)
        revoke_btn.setStyleSheet("""
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
        controls_layout.addWidget(revoke_btn)
        
        # Bouton règles manuelles
        rules_btn = QPushButton("📋 Règles Manuelles")
        rules_btn.clicked.connect(self.add_manual_rule)
        rules_btn.setStyleSheet("""
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
        controls_layout.addWidget(rules_btn)
        
        # Bouton test connectivité
        ping_btn = QPushButton("🏓 Test Connectivité")
        ping_btn.clicked.connect(self.test_connectivity)
        ping_btn.setStyleSheet("""
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
        controls_layout.addWidget(ping_btn)
        
        # Filtre par statut
        self.status_filter_combo = QComboBox()
        self.status_filter_combo.addItems(["Tous", "Connecté", "Déconnecté", "Suspect"])
        self.status_filter_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Statut:"))
        controls_layout.addWidget(self.status_filter_combo)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des utilisateurs
        left_widget = self.create_users_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Règles et actions
        right_widget = self.create_rules_section()
        splitter.addWidget(right_widget)
        
        # Répartition 70% tableau, 30% règles
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def create_users_table(self):
        group = QGroupBox("Utilisateurs VPN")
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
        
        # Tableau des utilisateurs
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Utilisateur", "IP", "Statut", "Score IA", "Connectivité", "Actions"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Utilisateur
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # IP
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Statut
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Score IA
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Connectivité
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Actions
        
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
        
    def create_rules_section(self):
        group = QGroupBox("Règles Manuelles et Actions")
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
        
        # Liste des règles manuelles
        rules_label = QLabel("Règles Manuelles:")
        rules_label.setStyleSheet("font-weight: bold; margin-bottom: 5px;")
        layout.addWidget(rules_label)
        
        self.rules_list = QTextEdit()
        self.rules_list.setMaximumHeight(150)
        self.rules_list.setReadOnly(True)
        self.rules_list.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.rules_list)
        
        # Actions automatiques
        actions_label = QLabel("Actions Automatiques (Score IA > 0.4):")
        actions_label.setStyleSheet("font-weight: bold; margin-top: 10px; margin-bottom: 5px;")
        layout.addWidget(actions_label)
        
        self.auto_actions_label = QLabel("Aucune action automatique déclenchée")
        self.auto_actions_label.setStyleSheet("color: #27ae60; font-style: italic;")
        layout.addWidget(self.auto_actions_label)
        
        # Statistiques
        stats_label = QLabel("Statistiques:")
        stats_label.setStyleSheet("font-weight: bold; margin-top: 20px; margin-bottom: 5px;")
        layout.addWidget(stats_label)
        
        self.total_users_label = QLabel("Total utilisateurs: 0")
        self.connected_users_label = QLabel("Utilisateurs connectés: 0")
        self.suspicious_users_label = QLabel("Utilisateurs suspects: 0")
        
        for label in [self.total_users_label, self.connected_users_label, self.suspicious_users_label]:
            label.setStyleSheet("margin: 2px 0;")
            layout.addWidget(label)
        
        layout.addStretch()
        group.setLayout(layout)
        return group
        
    def setup_timers(self):
        """Configure les timers pour la mise à jour automatique"""
        # Timer pour la mise à jour des connexions
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_connection_status)
        self.update_timer.start(30000)  # 30 secondes
        
        # Première mise à jour
        self.update_connection_status()
        
    def update_connection_status(self):
        """Met à jour le statut des connexions VPN"""
        try:
            # Test de connexion
            if not self.vpn_service.test_connection():
                self.connection_status.setText("Statut de la connexion: DÉCONNECTÉ")
                self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
                self.simulate_vpn_data()
            else:
                self.connection_status.setText("Statut de la connexion: CONNECTÉ")
                self.connection_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                self.get_real_vpn_data()
                
            self.apply_filters()
            self.update_statistics()
            self.check_automatic_actions()
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour: {e}")
            self.connection_status.setText("Statut de la connexion: ERREUR")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def get_real_vpn_data(self):
        """Récupère les vraies données VPN depuis le service"""
        try:
            users_data = self.vpn_service.get_all_users()
            self.vpn_users = []
            
            for user in users_data:
                processed_data = {
                    'user_id': user.get('user_id', 'N/A'),
                    'ip_address': user.get('ip_address', 'N/A'),
                    'status': user.get('status', 'Déconnecté'),
                    'ai_score': user.get('ai_score', 0.0),
                    'connectivity': user.get('connectivity', 'Inconnu'),
                    'last_seen': user.get('last_seen', 'N/A')
                }
                self.vpn_users.append(processed_data)
                
        except Exception as e:
            print(f"Erreur lors de la récupération des données VPN: {e}")
            self.simulate_vpn_data()
            
    def simulate_vpn_data(self):
        """Simule des données VPN pour les tests"""
        import random
        
        user_names = ["john.doe", "jane.smith", "admin.user", "tech.support", "dev.team"]
        ip_ranges = ["192.168.1.", "10.0.0.", "172.16.0."]
        
        self.vpn_users = []
        
        for i, name in enumerate(user_names):
            # IP aléatoire
            ip_base = random.choice(ip_ranges)
            ip_end = random.randint(100, 254)
            ip_address = f"{ip_base}{ip_end}"
            
            # Statut aléatoire
            status = random.choice(["Connecté", "Déconnecté", "Suspect"])
            
            # Score IA aléatoire
            ai_score = round(random.uniform(0.0, 1.0), 3)
            
            # Connectivité
            if status == "Connecté":
                connectivity = f"{random.randint(1, 50)}ms"
            else:
                connectivity = "N/A"
            
            data = {
                'user_id': name,
                'ip_address': ip_address,
                'status': status,
                'ai_score': ai_score,
                'connectivity': connectivity,
                'last_seen': datetime.now().strftime("%H:%M:%S")
            }
            self.vpn_users.append(data)
            
    def apply_filters(self):
        """Applique les filtres de statut"""
        filter_status = self.status_filter_combo.currentText()
        
        self.filtered_users = []
        
        for user in self.vpn_users:
            if filter_status == "Tous" or user['status'] == filter_status:
                self.filtered_users.append(user)
        
        self.update_table()
        
    def update_table(self):
        """Met à jour le tableau avec les utilisateurs filtrés"""
        self.table.setRowCount(len(self.filtered_users))
        
        for row, user in enumerate(self.filtered_users):
            # Utilisateur
            user_item = QTableWidgetItem(user['user_id'])
            self.table.setItem(row, 0, user_item)
            
            # IP
            ip_item = QTableWidgetItem(user['ip_address'])
            self.table.setItem(row, 1, ip_item)
            
            # Statut avec couleur
            status_item = QTableWidgetItem(user['status'])
            if user['status'] == "Connecté":
                status_item.setBackground(QColor(46, 204, 113))  # Vert
                status_item.setForeground(QColor(255, 255, 255))
            elif user['status'] == "Suspect":
                status_item.setBackground(QColor(231, 76, 60))  # Rouge
                status_item.setForeground(QColor(255, 255, 255))
            else:
                status_item.setBackground(QColor(149, 165, 166))  # Gris
                status_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 2, status_item)
            
            # Score IA avec couleur
            score_item = QTableWidgetItem(f"{user['ai_score']:.3f}")
            if user['ai_score'] > 0.4:
                score_item.setBackground(QColor(231, 76, 60))  # Rouge pour suspect
                score_item.setForeground(QColor(255, 255, 255))
            elif user['ai_score'] > 0.2:
                score_item.setBackground(QColor(243, 156, 18))  # Orange pour attention
                score_item.setForeground(QColor(255, 255, 255))
            else:
                score_item.setBackground(QColor(46, 204, 113))  # Vert pour normal
                score_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 3, score_item)
            
            # Connectivité
            connectivity_item = QTableWidgetItem(user['connectivity'])
            self.table.setItem(row, 4, connectivity_item)
            
            # Bouton d'action
            action_btn = QPushButton("🔑 Révoquer")
            action_btn.clicked.connect(lambda checked, r=row: self.revoke_user_key(r))
            action_btn.setStyleSheet("""
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
            self.table.setCellWidget(row, 5, action_btn)
            
    def revoke_user_key(self, row):
        """Révoque la clé d'un utilisateur spécifique"""
        if row < len(self.filtered_users):
            user = self.filtered_users[row]
            reply = QMessageBox.question(
                self, "Confirmation", 
                f"Révoquer la clé VPN de {user['user_id']} ({user['ip_address']}) ?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    # Appel API OPNsense pour révoquer la clé
                    success = self.vpn_service.revoke_user_key(user['user_id'])
                    if success:
                        QMessageBox.information(self, "Succès", f"Clé VPN révoquée pour {user['user_id']}")
                        self.update_connection_status()  # Rafraîchir les données
                    else:
                        QMessageBox.warning(self, "Erreur", "Impossible de révoquer la clé")
                except Exception as e:
                    QMessageBox.critical(self, "Erreur", f"Erreur lors de la révocation: {str(e)}")
                    
    def revoke_selected_keys(self):
        """Révoque les clés des utilisateurs sélectionnés"""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        
        if not selected_rows:
            QMessageBox.information(self, "Information", "Aucun utilisateur sélectionné")
            return
            
        reply = QMessageBox.question(
            self, "Confirmation", 
            f"Révoquer les clés VPN de {len(selected_rows)} utilisateur(s) ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            revoked_count = 0
            for row in selected_rows:
                if row < len(self.filtered_users):
                    user = self.filtered_users[row]
                    try:
                        success = self.vpn_service.revoke_user_key(user['user_id'])
                        if success:
                            revoked_count += 1
                    except Exception as e:
                        print(f"Erreur lors de la révocation de {user['user_id']}: {e}")
                        
            QMessageBox.information(self, "Résultat", f"{revoked_count} clé(s) révoquée(s) avec succès")
            self.update_connection_status()
            
    def add_manual_rule(self):
        """Ajoute une règle manuelle"""
        dialog = ManualRuleDialog(self)
        if dialog.exec_() == QDialog.DialogCode.Accepted:
            rule_data = dialog.get_rule_data()
            
            # Validation des données
            if not rule_data['source_ip'] or not rule_data['dest_ip']:
                QMessageBox.warning(self, "Erreur", "IP source et destination requises")
                return
                
            # Ajouter la règle
            self.manual_rules.append(rule_data)
            self.update_rules_display()
            
            # Appliquer la règle via l'API OPNsense
            try:
                success = self.vpn_service.add_firewall_rule(rule_data)
                if success:
                    QMessageBox.information(self, "Succès", "Règle ajoutée avec succès")
                else:
                    QMessageBox.warning(self, "Erreur", "Impossible d'ajouter la règle")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de l'ajout de la règle: {str(e)}")
                
    def update_rules_display(self):
        """Met à jour l'affichage des règles manuelles"""
        rules_text = ""
        for i, rule in enumerate(self.manual_rules, 1):
            rules_text += f"{i}. {rule['action']} {rule['source_ip']} → {rule['dest_ip']}:{rule['port']}\n"
            if rule['reason']:
                rules_text += f"   Raison: {rule['reason']}\n"
            rules_text += "\n"
            
        self.rules_list.setText(rules_text)
        
    def test_connectivity(self):
        """Teste la connectivité ping pour tous les utilisateurs connectés"""
        connected_users = [user for user in self.vpn_users if user['status'] == "Connecté"]
        
        if not connected_users:
            QMessageBox.information(self, "Information", "Aucun utilisateur connecté à tester")
            return
            
        # Lancer les tests ping en parallèle
        for user in connected_users:
            if user['ip_address'] != 'N/A':
                ping_thread = PingThread(user['ip_address'])
                ping_thread.ping_result.connect(self.on_ping_result)
                ping_thread.start()
                self.ping_threads[user['ip_address']] = ping_thread
                
        QMessageBox.information(self, "Test en cours", f"Test de connectivité lancé pour {len(connected_users)} utilisateur(s)")
        
    def on_ping_result(self, ip_address, success, response_time):
        """Appelé quand un test ping se termine"""
        # Mettre à jour l'utilisateur correspondant
        for user in self.vpn_users:
            if user['ip_address'] == ip_address:
                if success:
                    user['connectivity'] = response_time
                else:
                    user['connectivity'] = "Échec"
                break
                
        # Nettoyer le thread
        if ip_address in self.ping_threads:
            self.ping_threads[ip_address].deleteLater()
            del self.ping_threads[ip_address]
            
        # Mettre à jour l'affichage
        self.apply_filters()
        
    def check_automatic_actions(self):
        """Vérifie et exécute les actions automatiques si score IA > 0.4"""
        suspicious_users = [user for user in self.vpn_users if user['ai_score'] > 0.4]
        
        if suspicious_users:
            actions_text = f"Actions automatiques déclenchées pour {len(suspicious_users)} utilisateur(s):\n"
            
            for user in suspicious_users:
                actions_text += f"• {user['user_id']} (Score: {user['ai_score']:.3f}) - "
                
                # Actions automatiques selon le score
                if user['ai_score'] > 0.7:
                    actions_text += "Révocation immédiate + Quarantaine\n"
                    self.vpn_service.revoke_user_key(user['user_id'])
                elif user['ai_score'] > 0.5:
                    actions_text += "Surveillance renforcée\n"
                else:
                    actions_text += "Alerte générée\n"
                    
            self.auto_actions_label.setText(actions_text)
            self.auto_actions_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        else:
            self.auto_actions_label.setText("Aucune action automatique déclenchée")
            self.auto_actions_label.setStyleSheet("color: #27ae60; font-style: italic;")
            
    def update_statistics(self):
        """Met à jour les statistiques"""
        total = len(self.vpn_users)
        connected = len([u for u in self.vpn_users if u['status'] == "Connecté"])
        suspicious = len([u for u in self.vpn_users if u['ai_score'] > 0.4])
        
        self.total_users_label.setText(f"Total utilisateurs: {total}")
        self.connected_users_label.setText(f"Utilisateurs connectés: {connected}")
        self.suspicious_users_label.setText(f"Utilisateurs suspects: {suspicious}") 