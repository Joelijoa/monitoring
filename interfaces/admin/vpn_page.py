from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QFrame, QComboBox, QPushButton, QGroupBox,
                             QProgressBar, QSplitter, QDialog, QLineEdit,
                             QTextEdit, QFormLayout, QMessageBox, QFileDialog)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor
import requests
import json
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from monitoring.services.vpn_service import VPNService
from monitoring.config.vpn_config import VPN_USER_TYPES, VPN_STATUS, REFRESH_INTERVALS

class CreateUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Créer un nouvel utilisateur VPN")
        self.setModal(True)
        self.resize(400, 300)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Formulaire
        form_layout = QFormLayout()
        
        # ID utilisateur
        self.user_id_edit = QLineEdit()
        self.user_id_edit.setPlaceholderText("ex: john.doe")
        form_layout.addRow("ID Utilisateur:", self.user_id_edit)
        
        # Nom complet
        self.user_name_edit = QLineEdit()
        self.user_name_edit.setPlaceholderText("ex: John Doe")
        form_layout.addRow("Nom Complet:", self.user_name_edit)
        
        # Type d'utilisateur
        self.user_type_combo = QComboBox()
        for user_type, config in VPN_USER_TYPES.items():
            self.user_type_combo.addItem(
                f"{config['icon']} {config['name']} - {config['description']}", 
                user_type
            )
        form_layout.addRow("Type d'Utilisateur:", self.user_type_combo)
        
        # Description
        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(80)
        self.description_edit.setPlaceholderText("Description optionnelle...")
        form_layout.addRow("Description:", self.description_edit)
        
        layout.addLayout(form_layout)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        create_btn = QPushButton("Créer")
        create_btn.clicked.connect(self.accept)
        create_btn.setStyleSheet("""
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
        button_layout.addWidget(create_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def get_user_data(self):
        return {
            'user_id': self.user_id_edit.text().strip(),
            'user_name': self.user_name_edit.text().strip(),
            'user_type': self.user_type_combo.currentData(),
            'description': self.description_edit.toPlainText().strip()
        }

class RevokeDialog(QDialog):
    def __init__(self, user_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Révoquer l'utilisateur VPN")
        self.setModal(True)
        self.resize(400, 200)
        self.user_name = user_name
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Message de confirmation
        message = QLabel(f"Êtes-vous sûr de vouloir révoquer l'accès VPN de {self.user_name} ?")
        message.setStyleSheet("font-size: 14px; margin: 20px;")
        layout.addWidget(message)
        
        # Raison de révocation
        reason_label = QLabel("Raison de la révocation (optionnel):")
        layout.addWidget(reason_label)
        
        self.reason_edit = QTextEdit()
        self.reason_edit.setMaximumHeight(80)
        self.reason_edit.setPlaceholderText("Ex: Incident de sécurité, départ de l'entreprise...")
        layout.addWidget(self.reason_edit)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        revoke_btn = QPushButton("Révoquer")
        revoke_btn.clicked.connect(self.accept)
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
        button_layout.addWidget(revoke_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def get_reason(self):
        return self.reason_edit.toPlainText().strip()

class VPNPage(QWidget):
    def __init__(self):
        super().__init__()
        self.vpn_service = VPNService()
        self.vpn_users = []
        self.filtered_users = []
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre
        title = QLabel("Gestion VPN - WireGuard")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Gestion des connexions VPN des agents et techniciens via OPNsense/WireGuard")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Statut de la connexion
        self.connection_status = QLabel("Statut de la connexion: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Contrôles de gestion
        control_layout = QHBoxLayout()
        
        # Bouton créer utilisateur
        create_btn = QPushButton("➕ Créer Utilisateur")
        create_btn.clicked.connect(self.create_user)
        create_btn.setStyleSheet("""
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
        control_layout.addWidget(create_btn)
        
        # Bouton synchroniser
        sync_btn = QPushButton("🔄 Synchroniser")
        sync_btn.clicked.connect(self.sync_connections)
        sync_btn.setStyleSheet("""
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
        control_layout.addWidget(sync_btn)
        
        # Filtres
        filter_label = QLabel("Filtrer par statut :")
        filter_label.setStyleSheet("font-weight: bold; margin-left: 20px; margin-right: 10px;")
        control_layout.addWidget(filter_label)
        
        self.status_filter_combo = QComboBox()
        self.status_filter_combo.addItem("Tous les statuts", "all")
        for status_key, status_info in VPN_STATUS.items():
            self.status_filter_combo.addItem(
                f"{status_info['icon']} {status_info['name']}", 
                status_key
            )
        self.status_filter_combo.currentTextChanged.connect(self.apply_filters)
        control_layout.addWidget(self.status_filter_combo)
        
        # Filtre par type
        type_label = QLabel("Type :")
        type_label.setStyleSheet("font-weight: bold; margin-left: 20px; margin-right: 10px;")
        control_layout.addWidget(type_label)
        
        self.type_filter_combo = QComboBox()
        self.type_filter_combo.addItem("Tous les types", "all")
        for user_type, config in VPN_USER_TYPES.items():
            self.type_filter_combo.addItem(
                f"{config['icon']} {config['name']}", 
                user_type
            )
        self.type_filter_combo.currentTextChanged.connect(self.apply_filters)
        control_layout.addWidget(self.type_filter_combo)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des utilisateurs VPN
        left_widget = self.create_users_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Statistiques et actions
        right_widget = self.create_actions_section()
        splitter.addWidget(right_widget)
        
        # Répartition 70% tableau, 30% actions
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
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "ID", "Nom", "Type", "IP", "Statut", "Dernière Connexion", 
            "Connexions", "Actions"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # ID
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Nom
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Type
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # IP
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Statut
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Dernière Connexion
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Connexions
            header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # Actions
        
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
        
    def create_actions_section(self):
        group = QGroupBox("Actions et Statistiques")
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
        
        self.total_users_label = QLabel("Total utilisateurs: 0")
        self.active_users_label = QLabel("Utilisateurs actifs: 0")
        self.revoked_users_label = QLabel("Utilisateurs révoqués: 0")
        self.expired_users_label = QLabel("Utilisateurs expirés: 0")
        
        for label in [self.total_users_label, self.active_users_label, 
                     self.revoked_users_label, self.expired_users_label]:
            label.setStyleSheet("font-size: 12px; margin: 5px;")
            stats_layout.addWidget(label)
            
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Actions rapides
        actions_group = QGroupBox("Actions Rapides")
        actions_layout = QVBoxLayout()
        
        # Bouton vérifier expirations
        check_expired_btn = QPushButton("⏰ Vérifier Expirations")
        check_expired_btn.clicked.connect(self.check_expired_users)
        check_expired_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        actions_layout.addWidget(check_expired_btn)
        
        # Bouton exporter configurations
        export_btn = QPushButton("📁 Exporter Configurations")
        export_btn.clicked.connect(self.export_configurations)
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
        """)
        actions_layout.addWidget(export_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Graphique des types d'utilisateurs
        self.users_figure = Figure(figsize=(4, 3))
        self.users_canvas = FigureCanvas(self.users_figure)
        self.users_ax = self.users_figure.add_subplot(111)
        self.users_ax.set_title("Répartition par Type")
        
        layout.addWidget(self.users_canvas)
        
        group.setLayout(layout)
        return group
        
    def setup_timers(self):
        """Configure les timers pour la mise à jour automatique"""
        # Timer pour le statut des connexions (30 secondes)
        self.connection_timer = QTimer()
        self.connection_timer.timeout.connect(self.update_connection_status)
        self.connection_timer.start(REFRESH_INTERVALS['connection_status'] * 1000)
        
        # Timer pour la synchronisation avec OPNsense (5 minutes)
        self.sync_timer = QTimer()
        self.sync_timer.timeout.connect(self.sync_connections)
        self.sync_timer.start(REFRESH_INTERVALS['peer_sync'] * 1000)
        
        # Timer pour vérifier les expirations (1 heure)
        self.expiration_timer = QTimer()
        self.expiration_timer.timeout.connect(self.check_expired_users)
        self.expiration_timer.start(REFRESH_INTERVALS['expiration_check'] * 1000)
        
        # Première mise à jour
        self.load_vpn_users()
        
    def load_vpn_users(self):
        """Charge la liste des utilisateurs VPN"""
        try:
            self.connection_status.setText("Statut de la connexion: Chargement...")
            self.connection_status.setStyleSheet("color: #f39c12; font-weight: bold;")
            
            # Charger les utilisateurs depuis la base de données
            self.vpn_users = self.vpn_service.get_all_vpn_users()
            
            # Appliquer les filtres
            self.apply_filters()
            
            # Mettre à jour les statistiques
            self.update_statistics()
            self.update_charts()
            
            # Mettre à jour le statut
            if self.vpn_users:
                self.connection_status.setText(f"Statut de la connexion: {len(self.vpn_users)} utilisateurs chargés")
                self.connection_status.setStyleSheet("color: #27ae60; font-weight: bold;")
            else:
                self.connection_status.setText("Statut de la connexion: Aucun utilisateur trouvé")
                self.connection_status.setStyleSheet("color: #95a5a6; font-weight: bold;")
                
        except Exception as e:
            print(f"Erreur lors du chargement des utilisateurs VPN: {e}")
            self.connection_status.setText("Statut de la connexion: Erreur de chargement")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def create_user(self):
        """Ouvre le dialogue de création d'utilisateur"""
        dialog = CreateUserDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            user_data = dialog.get_user_data()
            
            # Valider les données
            if not user_data['user_id'] or not user_data['user_name']:
                QMessageBox.warning(self, "Erreur", "L'ID utilisateur et le nom sont obligatoires")
                return
                
            try:
                # Créer l'utilisateur VPN
                new_user = self.vpn_service.create_vpn_user(
                    user_data['user_id'],
                    user_data['user_name'],
                    user_data['user_type'],
                    user_data['description']
                )
                
                if new_user:
                    QMessageBox.information(self, "Succès", f"Utilisateur VPN {user_data['user_name']} créé avec succès")
                    self.load_vpn_users()
                else:
                    QMessageBox.warning(self, "Erreur", "Impossible de créer l'utilisateur VPN")
                    
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la création: {str(e)}")
                
    def revoke_user(self, vpn_id: int, user_name: str):
        """Révoque un utilisateur VPN"""
        dialog = RevokeDialog(user_name, self)
        if dialog.exec_() == QDialog.Accepted:
            reason = dialog.get_reason()
            
            try:
                success = self.vpn_service.revoke_vpn_user(vpn_id, reason)
                
                if success:
                    QMessageBox.information(self, "Succès", f"Utilisateur VPN {user_name} révoqué avec succès")
                    self.load_vpn_users()
                else:
                    QMessageBox.warning(self, "Erreur", "Impossible de révoquer l'utilisateur VPN")
                    
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la révocation: {str(e)}")
                
    def sync_connections(self):
        """Synchronise les connexions avec OPNsense"""
        try:
            self.connection_status.setText("Statut de la connexion: Synchronisation...")
            self.connection_status.setStyleSheet("color: #f39c12; font-weight: bold;")
            
            # Mettre à jour le statut des connexions
            self.vpn_service.update_connection_status()
            
            # Recharger les utilisateurs
            self.load_vpn_users()
            
            self.connection_status.setText("Statut de la connexion: Synchronisation terminée")
            self.connection_status.setStyleSheet("color: #27ae60; font-weight: bold;")
            
        except Exception as e:
            print(f"Erreur lors de la synchronisation: {e}")
            self.connection_status.setText("Statut de la connexion: Erreur de synchronisation")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def check_expired_users(self):
        """Vérifie et marque les utilisateurs expirés"""
        try:
            self.vpn_service.check_expired_users()
            self.load_vpn_users()
            
        except Exception as e:
            print(f"Erreur lors de la vérification des expirations: {e}")
            
    def export_configurations(self):
        """Exporte les configurations WireGuard"""
        try:
            # Demander le répertoire de destination
            directory = QFileDialog.getExistingDirectory(self, "Sélectionner le répertoire d'export")
            if not directory:
                return
                
            exported_count = 0
            
            for user in self.vpn_users:
                if user['status'] == 'active':
                    config = self.vpn_service.generate_config_file(user['id'])
                    if config:
                        filename = f"{user['user_id']}_wireguard.conf"
                        filepath = f"{directory}/{filename}"
                        
                        with open(filepath, 'w') as f:
                            f.write(config)
                        exported_count += 1
                        
            if exported_count > 0:
                QMessageBox.information(self, "Succès", f"{exported_count} configurations exportées dans {directory}")
            else:
                QMessageBox.warning(self, "Aucune configuration", "Aucune configuration active à exporter")
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'export: {str(e)}")
            
    def apply_filters(self):
        """Applique les filtres sélectionnés"""
        self.filtered_users = self.vpn_users.copy()
        
        # Filtre par statut
        status_filter = self.status_filter_combo.currentData()
        if status_filter != "all":
            self.filtered_users = [user for user in self.filtered_users 
                                 if user['status'] == status_filter]
        
        # Filtre par type
        type_filter = self.type_filter_combo.currentData()
        if type_filter != "all":
            self.filtered_users = [user for user in self.filtered_users 
                                 if user['user_type'] == type_filter]
        
        self.update_table()
        
    def update_table(self):
        """Met à jour le tableau avec les utilisateurs filtrés"""
        self.table.setRowCount(len(self.filtered_users))
        
        for row, user in enumerate(self.filtered_users):
            # ID
            id_item = QTableWidgetItem(user['user_id'])
            id_item.setFont(QFont("Arial", 10, QFont.Bold))
            self.table.setItem(row, 0, id_item)
            
            # Nom
            name_item = QTableWidgetItem(user['user_name'])
            self.table.setItem(row, 1, name_item)
            
            # Type
            user_type = VPN_USER_TYPES.get(user['user_type'], {})
            type_item = QTableWidgetItem(f"{user_type.get('icon', '')} {user_type.get('name', user['user_type'])}")
            self.table.setItem(row, 2, type_item)
            
            # IP
            ip_item = QTableWidgetItem(user['ip_address'])
            self.table.setItem(row, 3, ip_item)
            
            # Statut
            status_info = VPN_STATUS.get(user['status'], {})
            status_item = QTableWidgetItem(f"{status_info.get('icon', '')} {status_info.get('name', user['status'])}")
            status_item.setForeground(QColor(status_info.get('color', '#000000')))
            self.table.setItem(row, 4, status_item)
            
            # Dernière connexion
            last_conn = user.get('last_connection', '')
            if last_conn:
                last_conn_item = QTableWidgetItem(last_conn)
            else:
                last_conn_item = QTableWidgetItem("Jamais")
            self.table.setItem(row, 5, last_conn_item)
            
            # Nombre de connexions
            conn_count_item = QTableWidgetItem(str(user.get('connection_count', 0)))
            self.table.setItem(row, 6, conn_count_item)
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(2, 2, 2, 2)
            
            # Bouton révoquer
            if user['status'] == 'active':
                revoke_btn = QPushButton("🚫")
                revoke_btn.setToolTip("Révoquer l'accès")
                revoke_btn.setFixedSize(30, 25)
                revoke_btn.clicked.connect(lambda checked, u=user: self.revoke_user(u['id'], u['user_name']))
                revoke_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #e74c3c;
                        color: white;
                        border: none;
                        border-radius: 3px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #c0392b;
                    }
                """)
                actions_layout.addWidget(revoke_btn)
            
            actions_layout.addStretch()
            actions_widget.setLayout(actions_layout)
            self.table.setCellWidget(row, 7, actions_widget)
            
    def update_statistics(self):
        """Met à jour les statistiques"""
        stats = self.vpn_service.get_vpn_statistics()
        
        self.total_users_label.setText(f"Total utilisateurs: {stats.get('total_users', 0)}")
        self.active_users_label.setText(f"Utilisateurs actifs: {stats.get('active_users', 0)}")
        self.revoked_users_label.setText(f"Utilisateurs révoqués: {stats.get('revoked_users', 0)}")
        self.expired_users_label.setText(f"Utilisateurs expirés: {stats.get('expired_users', 0)}")
        
    def update_charts(self):
        """Met à jour les graphiques"""
        stats = self.vpn_service.get_vpn_statistics()
        
        # Graphique des types d'utilisateurs
        self.users_ax.clear()
        users_by_type = stats.get('users_by_type', {})
        
        if users_by_type:
            labels = []
            values = []
            colors = []
            
            for user_type, count in users_by_type.items():
                user_config = VPN_USER_TYPES.get(user_type, {})
                labels.append(f"{user_config.get('icon', '')} {user_config.get('name', user_type)}")
                values.append(count)
                colors.append('#3498db')  # Couleur uniforme pour les types
            
            if labels and values:
                bars = self.users_ax.bar(labels, values, color=colors)
                self.users_ax.set_title("Répartition par Type d'Utilisateur")
                self.users_ax.set_ylabel("Nombre d'utilisateurs")
                
                # Rotation des labels pour la lisibilité
                self.users_ax.tick_params(axis='x', rotation=45)
                
                # Ajouter les valeurs sur les barres
                for bar, value in zip(bars, values):
                    self.users_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                    str(value), ha='center', va='bottom')
                
                self.users_canvas.draw()
                
    def update_connection_status(self):
        """Met à jour le statut des connexions"""
        try:
            # Mettre à jour le statut des connexions
            self.vpn_service.update_connection_status()
            
            # Recharger les utilisateurs si nécessaire
            if hasattr(self, 'vpn_users'):
                self.load_vpn_users()
                
        except Exception as e:
            print(f"Erreur lors de la mise à jour du statut des connexions: {e}") 