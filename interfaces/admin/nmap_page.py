from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QPushButton, QSplitter, QLineEdit, QMessageBox, QDialog, QFormLayout, QComboBox, QSlider, QProgressBar, QFrame, QFileDialog, QTextEdit)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor
from monitoring.services.nmap_service import NmapService
from monitoring.config.nmap_config import SCAN_TYPES, COMMON_PORTS
from datetime import datetime, timedelta
import json

class ScanThread(QThread):
    """Thread pour exécuter les scans Nmap en arrière-plan"""
    scan_progress = pyqtSignal(str)  # Progression du scan
    scan_completed = pyqtSignal(dict)  # Résultats du scan
    scan_error = pyqtSignal(str)  # Erreur du scan
    
    def __init__(self, nmap_service, target, scan_type, ports=None):
        super().__init__()
        self.nmap_service = nmap_service
        self.target = target
        self.scan_type = scan_type
        self.ports = ports
        
    def run(self):
        try:
            self.scan_progress.emit("Démarrage du scan...")
            
            # Exécution du scan
            result = self.nmap_service.scan_network(self.target, self.scan_type, self.ports)
            
            if result['status'] == 'completed':
                self.scan_completed.emit(result)
            else:
                self.scan_error.emit(result.get('error', 'Erreur inconnue'))
                
        except Exception as e:
            self.scan_error.emit(str(e))

class NewScanDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nouveau Scan Nmap")
        self.setModal(True)
        self.resize(500, 400)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Formulaire
        form_layout = QFormLayout()
        
        # Cible du scan
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("ex: 192.168.1.0/24 ou 10.0.0.1-10.0.0.100")
        form_layout.addRow("Cible:", self.target_edit)
        
        # Type de scan
        self.scan_type_combo = QComboBox()
        for scan_id, scan_info in SCAN_TYPES.items():
            self.scan_type_combo.addItem(scan_info['name'], scan_id)
        form_layout.addRow("Type de scan:", self.scan_type_combo)
        
        # Ports spécifiques
        self.ports_combo = QComboBox()
        self.ports_combo.addItem("Ports par défaut", "")
        for port_name, port_range in COMMON_PORTS.items():
            self.ports_combo.addItem(f"{port_name.title()} ({port_range})", port_range)
        self.ports_combo.addItem("Personnalisé", "custom")
        form_layout.addRow("Ports:", self.ports_combo)
        
        # Ports personnalisés
        self.custom_ports_edit = QLineEdit()
        self.custom_ports_edit.setPlaceholderText("ex: 80,443,8080 ou 1-1000")
        self.custom_ports_edit.setEnabled(False)
        form_layout.addRow("Ports personnalisés:", self.custom_ports_edit)
        
        # Connexion des événements
        self.ports_combo.currentTextChanged.connect(self.on_ports_changed)
        
        layout.addLayout(form_layout)
        
        # Informations sur le scan
        info_label = QLabel("Informations sur le scan:")
        info_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(info_label)
        
        self.scan_info_label = QLabel("Sélectionnez un type de scan pour voir les détails")
        self.scan_info_label.setStyleSheet("color: #7f8c8d; font-style: italic;")
        layout.addWidget(self.scan_info_label)
        
        # Connexion pour mettre à jour les informations
        self.scan_type_combo.currentTextChanged.connect(self.update_scan_info)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        scan_btn = QPushButton("Lancer le scan")
        scan_btn.clicked.connect(self.accept)
        scan_btn.setStyleSheet("""
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
        button_layout.addWidget(scan_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # Initialiser les informations
        self.update_scan_info()
        
    def on_ports_changed(self, text):
        """Appelé quand le type de ports change"""
        if "Personnalisé" in text:
            self.custom_ports_edit.setEnabled(True)
        else:
            self.custom_ports_edit.setEnabled(False)
            self.custom_ports_edit.clear()
            
    def update_scan_info(self):
        """Met à jour les informations sur le scan sélectionné"""
        scan_id = self.scan_type_combo.currentData()
        if scan_id in SCAN_TYPES:
            scan_info = SCAN_TYPES[scan_id]
            info_text = f"<b>{scan_info['name']}</b><br>"
            info_text += f"Description: {scan_info['description']}<br>"
            info_text += f"Durée estimée: {scan_info['duration']}<br>"
            info_text += f"Arguments: {scan_info['arguments']}"
            self.scan_info_label.setText(info_text)
            
    def get_scan_data(self):
        """Retourne les données du scan"""
        ports = self.ports_combo.currentData()
        if ports == "custom":
            ports = self.custom_ports_edit.text().strip()
            
        return {
            'target': self.target_edit.text().strip(),
            'scan_type': self.scan_type_combo.currentData(),
            'ports': ports if ports else None
        }

class NmapPage(QWidget):
    def __init__(self):
        super().__init__()
        self.nmap_service = NmapService()
        self.scan_results = []
        self.filtered_results = []
        self.scan_thread = None
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Titre et description
        title = QLabel("Scans Réseau Nmap - Résultats")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)
        
        desc = QLabel("Scans réseau avec python-nmap : ports, services, vulnérabilités via NSE. Export CSV disponible.")
        desc.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # Statut de la connexion
        self.connection_status = QLabel("Statut de Nmap: Vérification...")
        self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
        layout.addWidget(self.connection_status)
        
        # Contrôles principaux
        controls_layout = QHBoxLayout()
        
        # Bouton nouveau scan
        new_scan_btn = QPushButton("🔍 Nouveau Scan")
        new_scan_btn.clicked.connect(self.new_scan)
        new_scan_btn.setStyleSheet("""
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
        controls_layout.addWidget(new_scan_btn)
        
        # Bouton export CSV
        export_btn = QPushButton("📊 Export CSV")
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
        
        # Bouton rafraîchir
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.load_results)
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
        
        # Filtre par hôte
        self.host_filter_edit = QLineEdit()
        self.host_filter_edit.setPlaceholderText("Filtrer par hôte...")
        self.host_filter_edit.textChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Hôte:"))
        controls_layout.addWidget(self.host_filter_edit)
        
        # Filtre par service
        self.service_filter_combo = QComboBox()
        self.service_filter_combo.addItems(["Tous les services", "HTTP", "SSH", "FTP", "SMTP", "DNS"])
        self.service_filter_combo.currentTextChanged.connect(self.apply_filters)
        controls_layout.addWidget(QLabel("Service:"))
        controls_layout.addWidget(self.service_filter_combo)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Contrôles de scan périodique
        periodic_layout = QHBoxLayout()
        
        periodic_label = QLabel("Scan périodique (24h):")
        periodic_layout.addWidget(periodic_label)
        
        self.periodic_slider = QSlider(Qt.Orientation.Horizontal)
        self.periodic_slider.setMinimum(1)
        self.periodic_slider.setMaximum(168)  # 1 semaine
        self.periodic_slider.setValue(24)
        self.periodic_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.periodic_slider.setTickInterval(24)
        periodic_layout.addWidget(self.periodic_slider)
        
        self.periodic_value_label = QLabel("24h")
        self.periodic_slider.valueChanged.connect(self.update_periodic_label)
        periodic_layout.addWidget(self.periodic_value_label)
        
        self.periodic_target_edit = QLineEdit()
        self.periodic_target_edit.setPlaceholderText("Cible pour scan périodique")
        periodic_layout.addWidget(self.periodic_target_edit)
        
        self.schedule_btn = QPushButton("📅 Planifier")
        self.schedule_btn.clicked.connect(self.schedule_periodic_scan)
        self.schedule_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        periodic_layout.addWidget(self.schedule_btn)
        
        layout.addLayout(periodic_layout)
        
        # Barre de progression pour les scans
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        layout.addWidget(self.scan_progress)
        
        # Splitter pour diviser l'écran
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Partie gauche - Tableau des résultats
        left_widget = self.create_results_table()
        splitter.addWidget(left_widget)
        
        # Partie droite - Détails et vulnérabilités
        right_widget = self.create_details_section()
        splitter.addWidget(right_widget)
        
        # Répartition 70% tableau, 30% détails
        splitter.setSizes([700, 300])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def create_results_table(self):
        group = QGroupBox("Résultats des Scans Nmap")
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
        
        # Tableau des résultats
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Équipement", "Port", "Service", "Version", "Vulnérabilités", "Horodatage", "Actions"
        ])
        
        # Configuration du tableau
        header = self.table.horizontalHeader()
        if header:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Équipement
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Port
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Service
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Version
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Vulnérabilités
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Horodatage
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Actions
        
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
        group = QGroupBox("Détails et Vulnérabilités")
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
        
        # Informations de l'hôte sélectionné
        self.host_info_label = QLabel("Sélectionnez un résultat pour voir les détails")
        self.host_info_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(self.host_info_label)
        
        # Vulnérabilités
        vuln_label = QLabel("Vulnérabilités détectées:")
        vuln_label.setStyleSheet("font-weight: bold; margin-top: 10px; margin-bottom: 5px;")
        layout.addWidget(vuln_label)
        
        self.vuln_text = QTextEdit()
        self.vuln_text.setMaximumHeight(150)
        self.vuln_text.setReadOnly(True)
        self.vuln_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.vuln_text)
        
        # Statistiques
        stats_label = QLabel("Statistiques:")
        stats_label.setStyleSheet("font-weight: bold; margin-top: 15px; margin-bottom: 5px;")
        layout.addWidget(stats_label)
        
        self.total_scans_label = QLabel("Total scans: 0")
        self.total_hosts_label = QLabel("Total hôtes: 0")
        self.total_ports_label = QLabel("Total ports: 0")
        self.critical_vulns_label = QLabel("Vulnérabilités critiques: 0")
        
        for label in [self.total_scans_label, self.total_hosts_label, self.total_ports_label, self.critical_vulns_label]:
            label.setStyleSheet("margin: 2px 0; font-size: 11px;")
            layout.addWidget(label)
        
        layout.addStretch()
        group.setLayout(layout)
        return group
        
    def setup_timers(self):
        """Configure les timers pour la mise à jour automatique"""
        # Timer pour la mise à jour des résultats
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_connection_status)
        self.update_timer.start(30000)  # 30 secondes
        
        # Première mise à jour
        self.update_connection_status()
        
    def update_connection_status(self):
        """Met à jour le statut de la connexion et les données"""
        try:
            # Test de connexion
            if not self.nmap_service.test_connection():
                self.connection_status.setText("Statut de Nmap: DÉCONNECTÉ (Mode simulation)")
                self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            else:
                self.connection_status.setText("Statut de Nmap: CONNECTÉ")
                self.connection_status.setStyleSheet("color: #27ae60; font-weight: bold;")
                
            self.load_results()
            self.update_statistics()
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour: {e}")
            self.connection_status.setText("Statut de Nmap: ERREUR")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold;")
            
    def load_results(self):
        """Charge les résultats de scan"""
        try:
            self.scan_results = self.nmap_service.get_all_results()
            self.apply_filters()
        except Exception as e:
            print(f"Erreur lors du chargement des résultats: {e}")
            self.scan_results = []
            
    def apply_filters(self):
        """Applique les filtres sur les résultats"""
        host_filter = self.host_filter_edit.text().lower()
        service_filter = self.service_filter_combo.currentText()
        
        self.filtered_results = []
        
        for result in self.scan_results:
            host = result['host']
            
            # Filtre par hôte
            if host_filter and host_filter not in host.lower():
                continue
                
            # Filtre par service
            if service_filter != "Tous les services":
                has_service = False
                for port_info in result['ports']:
                    if service_filter.lower() in port_info['service'].lower():
                        has_service = True
                        break
                if not has_service:
                    continue
                    
            self.filtered_results.append(result)
        
        self.update_table()
        
    def update_table(self):
        """Met à jour le tableau avec les résultats filtrés"""
        # Compter le nombre total d'entrées (hôtes × ports)
        total_entries = sum(len(result['ports']) for result in self.filtered_results)
        
        self.table.setRowCount(total_entries)
        row = 0
        
        for result in self.filtered_results:
            host = result['host']
            hostname = result['hostname']
            os_info = result['os']
            timestamp = result['timestamp']
            
            for port_info in result['ports']:
                # Équipement (hôte + OS)
                equipment_text = f"{host}"
                if hostname:
                    equipment_text += f" ({hostname})"
                if os_info != "Unknown":
                    equipment_text += f" - {os_info}"
                    
                equipment_item = QTableWidgetItem(equipment_text)
                equipment_item.setFont(QFont("Arial", 10, QFont.Bold))
                self.table.setItem(row, 0, equipment_item)
                
                # Port
                port_item = QTableWidgetItem(str(port_info['port']))
                self.table.setItem(row, 1, port_item)
                
                # Service
                service_item = QTableWidgetItem(port_info['service'])
                self.table.setItem(row, 2, service_item)
                
                # Version
                version_text = port_info['version']
                if port_info['product']:
                    version_text += f" ({port_info['product']})"
                version_item = QTableWidgetItem(version_text)
                self.table.setItem(row, 3, version_item)
                
                # Vulnérabilités
                vuln_count = len(port_info['vulnerabilities'])
                if vuln_count > 0:
                    critical_count = sum(1 for v in port_info['vulnerabilities'] if v['severity'] == 'critical')
                    vuln_text = f"{vuln_count} vuln(s)"
                    if critical_count > 0:
                        vuln_text += f" ({critical_count} critiques)"
                    vuln_item = QTableWidgetItem(vuln_text)
                    vuln_item.setBackground(QColor(231, 76, 60))  # Rouge pour vulnérabilités
                    vuln_item.setForeground(QColor(255, 255, 255))
                else:
                    vuln_item = QTableWidgetItem("Aucune")
                    vuln_item.setBackground(QColor(46, 204, 113))  # Vert pour sécurisé
                    vuln_item.setForeground(QColor(255, 255, 255))
                self.table.setItem(row, 4, vuln_item)
                
                # Horodatage
                timestamp_item = QTableWidgetItem(timestamp[:19].replace('T', ' '))
                self.table.setItem(row, 5, timestamp_item)
                
                # Bouton d'action
                details_btn = QPushButton("🔍")
                details_btn.clicked.connect(lambda checked, r=result, p=port_info: self.show_details(r, p))
                details_btn.setStyleSheet("""
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
                self.table.setCellWidget(row, 6, details_btn)
                
                row += 1
                
    def on_table_cell_clicked(self, row, column):
        """Appelé quand une cellule du tableau est cliquée"""
        if row < 0 or row >= self.table.rowCount():
            return
            
        # Trouver le résultat correspondant
        current_row = 0
        for result in self.filtered_results:
            for port_info in result['ports']:
                if current_row == row:
                    self.show_details(result, port_info)
                    return
                current_row += 1
                
    def show_details(self, result, port_info):
        """Affiche les détails d'un résultat"""
        host = result['host']
        hostname = result['hostname']
        os_info = result['os']
        
        # Mettre à jour les informations de l'hôte
        host_text = f"Hôte: {host}"
        if hostname:
            host_text += f" ({hostname})"
        if os_info != "Unknown":
            host_text += f" - OS: {os_info}"
        self.host_info_label.setText(host_text)
        
        # Afficher les vulnérabilités
        vuln_text = ""
        
        # Vulnérabilités du port
        if port_info['vulnerabilities']:
            vuln_text += f"=== Vulnérabilités du port {port_info['port']} ===\n"
            for vuln in port_info['vulnerabilities']:
                vuln_text += f"Script: {vuln['script']}\n"
                vuln_text += f"Sévérité: {vuln['severity']}\n"
                if vuln['cve']:
                    vuln_text += f"CVE: {', '.join(vuln['cve'])}\n"
                vuln_text += f"Sortie: {vuln['output'][:200]}...\n\n"
                
        # Vulnérabilités de l'hôte
        if result['vulnerabilities']:
            vuln_text += f"=== Vulnérabilités de l'hôte ===\n"
            for vuln in result['vulnerabilities']:
                vuln_text += f"Script: {vuln['script']}\n"
                vuln_text += f"Sévérité: {vuln['severity']}\n"
                if vuln['cve']:
                    vuln_text += f"CVE: {', '.join(vuln['cve'])}\n"
                vuln_text += f"Sortie: {vuln['output'][:200]}...\n\n"
                
        if not vuln_text:
            vuln_text = "Aucune vulnérabilité détectée"
            
        self.vuln_text.setText(vuln_text)
        
    def new_scan(self):
        """Lance un nouveau scan"""
        dialog = NewScanDialog(self)
        if dialog.exec_() == QDialog.DialogCode.Accepted:
            scan_data = dialog.get_scan_data()
            
            if not scan_data['target']:
                QMessageBox.warning(self, "Erreur", "La cible du scan est obligatoire.")
                return
                
            # Lancer le scan dans un thread séparé
            self.scan_thread = ScanThread(
                self.nmap_service,
                scan_data['target'],
                scan_data['scan_type'],
                scan_data['ports']
            )
            
            self.scan_thread.scan_progress.connect(self.on_scan_progress)
            self.scan_thread.scan_completed.connect(self.on_scan_completed)
            self.scan_thread.scan_error.connect(self.on_scan_error)
            
            self.scan_thread.start()
            
            # Afficher la barre de progression
            self.scan_progress.setVisible(True)
            self.scan_progress.setRange(0, 0)  # Indéterminée
            
    def on_scan_progress(self, message):
        """Appelé pendant la progression du scan"""
        self.scan_progress.setFormat(message)
        
    def on_scan_completed(self, result):
        """Appelé quand le scan est terminé"""
        self.scan_progress.setVisible(False)
        
        QMessageBox.information(
            self, "Scan terminé", 
            f"Scan terminé avec succès!\n"
            f"Hôtes trouvés: {result['hosts_found']}\n"
            f"Durée: {result['duration']:.2f} secondes"
        )
        
        self.load_results()
        
    def on_scan_error(self, error):
        """Appelé en cas d'erreur du scan"""
        self.scan_progress.setVisible(False)
        QMessageBox.critical(self, "Erreur de scan", f"Erreur lors du scan: {error}")
        
    def export_csv(self):
        """Exporte les résultats en CSV"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Exporter en CSV", 
                f"nmap_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "Fichiers CSV (*.csv)"
            )
            
            if filename:
                exported_file = self.nmap_service.export_to_csv(filename)
                if exported_file:
                    QMessageBox.information(self, "Export réussi", f"Résultats exportés vers {exported_file}")
                else:
                    QMessageBox.critical(self, "Erreur d'export", "Erreur lors de l'export CSV")
                    
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'export: {str(e)}")
            
    def update_periodic_label(self, value):
        """Met à jour le label de l'intervalle périodique"""
        if value == 1:
            self.periodic_value_label.setText("1h")
        elif value == 24:
            self.periodic_value_label.setText("24h")
        elif value == 168:
            self.periodic_value_label.setText("1 semaine")
        else:
            self.periodic_value_label.setText(f"{value}h")
            
    def schedule_periodic_scan(self):
        """Planifie un scan périodique"""
        target = self.periodic_target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Erreur", "Veuillez spécifier une cible pour le scan périodique.")
            return
            
        interval_hours = self.periodic_slider.value()
        
        try:
            success = self.nmap_service.schedule_periodic_scan(target, interval_hours)
            if success:
                QMessageBox.information(
                    self, "Scan planifié", 
                    f"Scan périodique planifié pour {target} toutes les {interval_hours} heures."
                )
            else:
                QMessageBox.critical(self, "Erreur", "Erreur lors de la planification du scan.")
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la planification: {str(e)}")
            
    def update_statistics(self):
        """Met à jour les statistiques"""
        try:
            stats = self.nmap_service.get_statistics()
            
            self.total_scans_label.setText(f"Total scans: {stats['total_scans']}")
            self.total_hosts_label.setText(f"Total hôtes: {stats['total_hosts']}")
            self.total_ports_label.setText(f"Total ports: {stats['total_ports']}")
            self.critical_vulns_label.setText(f"Vulnérabilités critiques: {stats['vulnerabilities']['critical']}")
            
        except Exception as e:
            print(f"Erreur lors du calcul des statistiques: {e}")
            self.total_scans_label.setText("Total scans: 0")
            self.total_hosts_label.setText("Total hôtes: 0")
            self.total_ports_label.setText("Total ports: 0")
            self.critical_vulns_label.setText("Vulnérabilités critiques: 0") 