from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QPushButton, QSplitter, QDateTimeEdit, QLineEdit, QMessageBox, QDialog, QFormLayout, QComboBox, QTextEdit, QProgressBar, QFrame)
from PyQt5.QtCore import Qt, QTimer, QDateTime, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor
from monitoring.services.backup_service import BackupService
from datetime import datetime, timedelta
import json

class RestoreDialog(QDialog):
    def __init__(self, job_name: str, parent=None):
        super().__init__(parent)
        self.job_name = job_name
        self.setWindowTitle(f"Restauration - {job_name}")
        self.setModal(True)
        self.resize(500, 300)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Informations du job
        info_label = QLabel(f"Restauration du job: {self.job_name}")
        info_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(info_label)
        
        # Formulaire
        form_layout = QFormLayout()
        
        # Chemin de restauration
        self.restore_path_edit = QLineEdit()
        self.restore_path_edit.setPlaceholderText("/chemin/vers/restauration")
        form_layout.addRow("Chemin de restauration:", self.restore_path_edit)
        
        # Type de restauration
        self.restore_type_combo = QComboBox()
        self.restore_type_combo.addItems(["Complète", "Partielle", "Fichiers spécifiques"])
        form_layout.addRow("Type de restauration:", self.restore_type_combo)
        
        # Options avancées
        self.overwrite_checkbox = QComboBox()
        self.overwrite_checkbox.addItems(["Oui", "Non", "Demander"])
        form_layout.addRow("Écraser les fichiers:", self.overwrite_checkbox)
        
        layout.addLayout(form_layout)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        restore_btn = QPushButton("Lancer la restauration")
        restore_btn.clicked.connect(self.accept)
        restore_btn.setStyleSheet("""
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
        button_layout.addWidget(restore_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def get_restore_data(self):
        return {
            'restore_path': self.restore_path_edit.text().strip(),
            'restore_type': self.restore_type_combo.currentText(),
            'overwrite': self.overwrite_checkbox.currentText()
        }

class AddBackupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Planifier une sauvegarde Bacula")
        self.setModal(True)
        self.resize(500, 350)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Formulaire
        form_layout = QFormLayout()
        
        # Nom du job
        self.job_name_edit = QLineEdit()
        self.job_name_edit.setPlaceholderText("ex: Backup_System_Quotidien")
        form_layout.addRow("Nom du job:", self.job_name_edit)
        
        # Horaire de planification
        self.schedule_edit = QDateTimeEdit(QDateTime.currentDateTime())
        self.schedule_edit.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.schedule_edit.setCalendarPopup(True)
        form_layout.addRow("Horaire de planification:", self.schedule_edit)
        
        # Type de sauvegarde
        self.backup_type_combo = QComboBox()
        self.backup_type_combo.addItems(["Complète", "Incrémentale", "Différentielle"])
        form_layout.addRow("Type de sauvegarde:", self.backup_type_combo)
        
        # Client/serveur
        self.client_edit = QLineEdit()
        self.client_edit.setPlaceholderText("ex: bacula-fd")
        self.client_edit.setText("bacula-fd")
        form_layout.addRow("Client:", self.client_edit)
        
        # FileSet
        self.fileset_edit = QLineEdit()
        self.fileset_edit.setPlaceholderText("ex: Full Set")
        self.fileset_edit.setText("Full Set")
        form_layout.addRow("FileSet:", self.fileset_edit)
        
        # Chemin de restauration (optionnel)
        self.restore_path_edit = QLineEdit()
        self.restore_path_edit.setPlaceholderText("Chemin de restauration (optionnel)")
        form_layout.addRow("Chemin restauration:", self.restore_path_edit)
        
        layout.addLayout(form_layout)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        add_btn = QPushButton("Planifier")
        add_btn.clicked.connect(self.accept)
        add_btn.setStyleSheet("""
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
        button_layout.addWidget(add_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def get_data(self):
        return {
            'job_name': self.job_name_edit.text().strip(),
            'schedule_time': self.schedule_edit.dateTime().toString("HH:mm"),
            'backup_type': self.backup_type_combo.currentText(),
            'client': self.client_edit.text().strip(),
            'fileset': self.fileset_edit.text().strip(),
            'restore_path': self.restore_path_edit.text().strip()
        }

class BackupPage(QWidget):
    def __init__(self):
        super().__init__()
        self.backup_service = BackupService()
        self.jobs = []
        self.filtered_jobs = []
        self.selected_job_id = None
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre et description
        title = QLabel("Gestion des Sauvegardes Bacula")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        desc = QLabel("Planification, suivi et restauration des sauvegardes Bacula. Alertes Wazuh en cas d'échec.")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Statut de la connexion
        self.connection_status = QLabel("Statut de la connexion: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Contrôles principaux
        controls_layout = QHBoxLayout()
        
        # Bouton planifier
        add_btn = QPushButton("➕ Planifier une sauvegarde")
        add_btn.clicked.connect(self.add_backup_job)
        add_btn.setStyleSheet("""
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
        controls_layout.addWidget(add_btn)
        
        # Bouton rafraîchir
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.load_jobs)
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
        controls_layout.addWidget(refresh_btn)
        
        # Filtre par statut
        self.status_filter_combo = QComboBox()
        self.status_filter_combo.addItems(["Tous", "Success", "Failed", "Running", "Scheduled"])
        self.status_filter_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Statut:"))
        controls_layout.addWidget(self.status_filter_combo)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des jobs
        left_widget = self.create_jobs_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Historique et actions
        right_widget = self.create_details_section()
        splitter.addWidget(right_widget)
        
        # Répartition 70% tableau, 30% détails
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def create_jobs_table(self):
        group = QGroupBox("Jobs de Sauvegarde Bacula")
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
        
        # Tableau des jobs
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "ID", "Nom du job", "Horaire", "Statut", "Dernière exécution", "Résultat", "Restaurer", "Actions"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # ID
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Nom
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Horaire
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Statut
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Dernière exécution
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Résultat
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Restaurer
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
        
        self.table.cellClicked.connect(self.on_table_cell_clicked)
        layout.addWidget(self.table)
        
        group.setLayout(layout)
        return group
        
    def create_details_section(self):
        group = QGroupBox("Détails et Historique")
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
        
        # Informations du job sélectionné
        self.job_info_label = QLabel("Sélectionnez un job pour voir les détails")
        self.job_info_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(self.job_info_label)
        
        # Historique du job
        history_label = QLabel("Historique du Job:")
        history_label.setStyleSheet("font-weight: bold; margin-top: 10px; margin-bottom: 5px;")
        layout.addWidget(history_label)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(3)
        self.history_table.setHorizontalHeaderLabels(["Date", "Résultat", "Log (début)"])
        
        header = self.history_table.horizontalHeader()
        if header:
            for i in range(3):
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #bdc3c7;
                background-color: white;
                alternate-background-color: #f8f9fa;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.history_table)
        
        # Actions rapides
        actions_label = QLabel("Actions Rapides:")
        actions_label.setStyleSheet("font-weight: bold; margin-top: 10px; margin-bottom: 5px;")
        layout.addWidget(actions_label)
        
        actions_layout = QHBoxLayout()
        
        self.run_btn = QPushButton("▶ Lancer")
        self.run_btn.clicked.connect(self.run_selected_job)
        self.run_btn.setEnabled(False)
        self.run_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        actions_layout.addWidget(self.run_btn)
        
        self.restore_btn = QPushButton("🔄 Restaurer")
        self.restore_btn.clicked.connect(self.restore_selected_job)
        self.restore_btn.setEnabled(False)
        self.restore_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        actions_layout.addWidget(self.restore_btn)
        
        layout.addLayout(actions_layout)
        
        # Statistiques
        stats_label = QLabel("Statistiques:")
        stats_label.setStyleSheet("font-weight: bold; margin-top: 15px; margin-bottom: 5px;")
        layout.addWidget(stats_label)
        
        self.total_jobs_label = QLabel("Total jobs: 0")
        self.successful_jobs_label = QLabel("Jobs réussis: 0")
        self.failed_jobs_label = QLabel("Jobs échoués: 0")
        self.success_rate_label = QLabel("Taux de succès: 0%")
        
        for label in [self.total_jobs_label, self.successful_jobs_label, self.failed_jobs_label, self.success_rate_label]:
            label.setStyleSheet("margin: 2px 0; font-size: 11px;")
            layout.addWidget(label)
        
        layout.addStretch()
        group.setLayout(layout)
        return group
        
    def setup_timers(self):
        """Configure les timers pour la mise à jour automatique"""
        # Timer pour la mise à jour des jobs
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_connection_status)
        self.update_timer.start(60000)  # 60 secondes
        
        # Première mise à jour
        self.update_connection_status()
        
    def update_connection_status(self):
        """Met à jour le statut de la connexion et les données"""
        try:
            # Test de connexion
            if not self.backup_service.test_connection():
                self.connection_status.setText("Statut de la connexion: DÉCONNECTÉ (Mode simulation)")
                self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            else:
                self.connection_status.setText("Statut de la connexion: CONNECTÉ")
                self.connection_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                
            self.load_jobs()
            self.update_statistics()
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour: {e}")
            self.connection_status.setText("Statut de la connexion: ERREUR")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def load_jobs(self):
        """Charge la liste des jobs"""
        try:
            self.jobs = self.backup_service.list_jobs()
            self.apply_filters()
        except Exception as e:
            print(f"Erreur lors du chargement des jobs: {e}")
            self.jobs = []
            
    def apply_filters(self):
        """Applique les filtres de statut"""
        filter_status = self.status_filter_combo.currentText()
        
        self.filtered_jobs = []
        
        for job in self.jobs:
            if filter_status == "Tous" or job['status'].lower() == filter_status.lower():
                self.filtered_jobs.append(job)
        
        self.update_table()
        
    def update_table(self):
        """Met à jour le tableau avec les jobs filtrés"""
        self.table.setRowCount(len(self.filtered_jobs))
        
        for row, job in enumerate(self.filtered_jobs):
            # ID
            id_item = QTableWidgetItem(job['id'])
            self.table.setItem(row, 0, id_item)
            
            # Nom du job
            name_item = QTableWidgetItem(job['job_name'])
            name_item.setFont(QFont("Arial", 10, QFont.Bold))
            self.table.setItem(row, 1, name_item)
            
            # Horaire
            self.table.setItem(row, 2, QTableWidgetItem(job.get('schedule_time', '02:00')))
            
            # Statut avec couleur
            status = job.get('status', 'unknown')
            status_item = QTableWidgetItem(status)
            if status == 'success':
                status_item.setBackground(QColor(46, 204, 113))  # Vert
                status_item.setForeground(QColor(255, 255, 255))
            elif status == 'failed':
                status_item.setBackground(QColor(231, 76, 60))  # Rouge
                status_item.setForeground(QColor(255, 255, 255))
            elif status == 'running':
                status_item.setBackground(QColor(52, 152, 219))  # Bleu
                status_item.setForeground(QColor(255, 255, 255))
            else:
                status_item.setBackground(QColor(149, 165, 166))  # Gris
                status_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 3, status_item)
            
            # Dernière exécution
            self.table.setItem(row, 4, QTableWidgetItem(str(job.get('start_time', ''))))
            
            # Résultat
            result_item = QTableWidgetItem(str(job.get('last_result', '')))
            if 'error' in str(job.get('last_result', '')).lower():
                result_item.setBackground(QColor(231, 76, 60))
                result_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 5, result_item)
            
            # Bouton restaurer
            restore_btn = QPushButton("🔄")
            restore_btn.clicked.connect(lambda checked, j=job: self.restore_job(j))
            restore_btn.setStyleSheet("""
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
            self.table.setCellWidget(row, 6, restore_btn)
            
            # Bouton lancer
            run_btn = QPushButton("▶")
            run_btn.clicked.connect(lambda checked, j=job: self.run_job(j))
            run_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    padding: 4px 8px;
                    border-radius: 3px;
                    font-size: 10px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
            self.table.setCellWidget(row, 7, run_btn)
            
    def on_table_cell_clicked(self, row, column):
        """Appelé quand une cellule du tableau est cliquée"""
        if row < 0 or row >= len(self.filtered_jobs):
            return
            
        job = self.filtered_jobs[row]
        self.selected_job_id = job['id']
        
        # Mettre à jour les informations du job
        self.job_info_label.setText(f"Job: {job['job_name']} (ID: {job['id']})")
        
        # Charger l'historique
        self.load_job_history(job['id'])
        
        # Activer les boutons d'action
        self.run_btn.setEnabled(True)
        self.restore_btn.setEnabled(True)
        
    def load_job_history(self, job_id: str):
        """Charge l'historique d'un job"""
        try:
            history = self.backup_service.list_history(job_id)
            self.history_table.setRowCount(len(history))
            
            for i, entry in enumerate(history):
                self.history_table.setItem(i, 0, QTableWidgetItem(str(entry.get('run_time', ''))))
                
                result_item = QTableWidgetItem(str(entry.get('result', '')))
                if entry.get('result') == 'failed':
                    result_item.setBackground(QColor(231, 76, 60))
                    result_item.setForeground(QColor(255, 255, 255))
                self.history_table.setItem(i, 1, result_item)
                
                log_preview = (entry.get('log', '') or '')[:80].replace('\n', ' ')
                self.history_table.setItem(i, 2, QTableWidgetItem(log_preview))
                
        except Exception as e:
            print(f"Erreur lors du chargement de l'historique: {e}")
            self.history_table.setRowCount(0)
            
    def add_backup_job(self):
        """Ajoute un nouveau job de sauvegarde"""
        dialog = AddBackupDialog(self)
        if dialog.exec_() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            
            if not data['job_name']:
                QMessageBox.warning(self, "Erreur", "Le nom du job est obligatoire.")
                return
                
            try:
                success = self.backup_service.add_job(
                    data['job_name'], 
                    data['schedule_time'], 
                    data['restore_path']
                )
                
                if success:
                    QMessageBox.information(self, "Succès", f"Job {data['job_name']} planifié avec succès.")
                    self.load_jobs()
                else:
                    QMessageBox.critical(self, "Erreur", "Erreur lors de la planification du job.")
                    
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la planification: {str(e)}")
                
    def run_job(self, job):
        """Lance un job de sauvegarde"""
        reply = QMessageBox.question(
            self, "Confirmation", 
            f"Lancer la sauvegarde {job['job_name']} ?",
            QMessageBox.StandardButtons.Yes | QMessageBox.StandardButtons.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                success = self.backup_service.run_backup(job['id'])
                if success:
                    QMessageBox.information(self, "Succès", f"Sauvegarde {job['job_name']} lancée avec succès.")
                else:
                    QMessageBox.critical(self, "Erreur", f"Erreur lors du lancement de {job['job_name']}.")
                self.load_jobs()
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors du lancement: {str(e)}")
                
    def run_selected_job(self):
        """Lance le job sélectionné"""
        if self.selected_job_id:
            job = next((j for j in self.filtered_jobs if j['id'] == self.selected_job_id), None)
            if job:
                self.run_job(job)
                
    def restore_job(self, job):
        """Lance une restauration"""
        dialog = RestoreDialog(job['job_name'], self)
        if dialog.exec_() == QDialog.DialogCode.Accepted:
            restore_data = dialog.get_restore_data()
            
            try:
                success = self.backup_service.run_restore(job['id'], restore_data['restore_path'])
                if success:
                    QMessageBox.information(self, "Succès", f"Restauration {job['job_name']} lancée avec succès.")
                else:
                    QMessageBox.critical(self, "Erreur", f"Erreur lors de la restauration {job['job_name']}.")
                self.load_jobs()
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la restauration: {str(e)}")
                
    def restore_selected_job(self):
        """Restaure le job sélectionné"""
        if self.selected_job_id:
            job = next((j for j in self.filtered_jobs if j['id'] == self.selected_job_id), None)
            if job:
                self.restore_job(job)
                
    def update_statistics(self):
        """Met à jour les statistiques"""
        try:
            stats = self.backup_service.get_backup_statistics()
            
            self.total_jobs_label.setText(f"Total jobs: {stats['total_jobs']}")
            self.successful_jobs_label.setText(f"Jobs réussis: {stats['successful_jobs']}")
            self.failed_jobs_label.setText(f"Jobs échoués: {stats['failed_jobs']}")
            self.success_rate_label.setText(f"Taux de succès: {stats['success_rate']:.1f}%")
            
        except Exception as e:
            print(f"Erreur lors du calcul des statistiques: {e}")
            self.total_jobs_label.setText("Total jobs: 0")
            self.successful_jobs_label.setText("Jobs réussis: 0")
            self.failed_jobs_label.setText("Jobs échoués: 0")
            self.success_rate_label.setText("Taux de succès: 0%") 