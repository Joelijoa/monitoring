from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QComboBox, QMessageBox, QGroupBox, QDialog, QLineEdit, QFormLayout
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor
from monitoring.services.nmap_service import NmapService
import random

class AddEquipementDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ajouter un équipement")
        self.setModal(True)
        self.resize(350, 180)
        layout = QFormLayout()
        self.nom_edit = QLineEdit()
        self.ip_edit = QLineEdit()
        self.os_edit = QLineEdit()
        layout.addRow("Nom :", self.nom_edit)
        layout.addRow("IP :", self.ip_edit)
        layout.addRow("OS :", self.os_edit)
        btns = QHBoxLayout()
        ok_btn = QPushButton("Ajouter")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(ok_btn)
        btns.addWidget(cancel_btn)
        layout.addRow(btns)
        self.setLayout(layout)
    def get_data(self):
        return {
            'nom': self.nom_edit.text().strip(),
            'ip': self.ip_edit.text().strip(),
            'os': self.os_edit.text().strip(),
            'statut': "Non installé"
        }

class GestionEquipementsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.nmap_service = NmapService()
        self.equipements = []
        self.setup_ui()
        self.scan_nmap_initial()

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("Gestion des Équipements")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin: 10px;")
        layout.addWidget(title)

        # Zone de sélection du type d'installation
        install_type_group = QGroupBox("Type d'installation de l'agent")
        install_type_layout = QHBoxLayout()
        self.install_type_combo = QComboBox()
        self.install_type_combo.addItems(["Linux (paramiko)", "Windows (WMI/PowerShell)"])
        install_type_layout.addWidget(QLabel("Choisir le type :"))
        install_type_layout.addWidget(self.install_type_combo)
        install_type_group.setLayout(install_type_layout)
        layout.addWidget(install_type_group)

        # Ligne de boutons (ajout, suppression, scan)
        btns_layout = QHBoxLayout()
        self.add_btn = QPushButton("➕ Ajouter un équipement")
        self.add_btn.clicked.connect(self.ajouter_equipement)
        btns_layout.addWidget(self.add_btn)
        self.delete_btn = QPushButton("🗑️ Supprimer l'équipement sélectionné")
        self.delete_btn.clicked.connect(self.supprimer_equipement)
        btns_layout.addWidget(self.delete_btn)
        self.scan_btn = QPushButton("🔍 Scan Nmap initial")
        self.scan_btn.clicked.connect(self.scan_nmap_initial)
        btns_layout.addWidget(self.scan_btn)
        btns_layout.addStretch()
        layout.addLayout(btns_layout)

        # Tableau des équipements
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Nom", "IP", "OS", "Statut agent"])
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

        # Bouton installer agent
        self.install_btn = QPushButton("Installer l'agent sur l'équipement sélectionné")
        self.install_btn.clicked.connect(self.installer_agent)
        layout.addWidget(self.install_btn)

        self.setLayout(layout)

    def ajouter_equipement(self):
        dialog = AddEquipementDialog(self)
        if dialog.exec_() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            if not data['nom'] or not data['ip'] or not data['os']:
                QMessageBox.warning(self, "Champs requis", "Tous les champs sont obligatoires.")
                return
            self.equipements.append(data)
            self.update_table()

    def supprimer_equipement(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Sélection requise", "Veuillez sélectionner un équipement à supprimer.")
            return
        equip = self.equipements[row]
        reply = QMessageBox.question(self, "Confirmation", f"Supprimer l'équipement {equip['nom']} ({equip['ip']}) ?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            del self.equipements[row]
            self.update_table()

    def scan_nmap_initial(self):
        # Utilise le service Nmap pour remplir la table (simulation si besoin)
        self.equipements = []
        nmap_results = self.nmap_service.scan_network(target="192.168.1.0/24", scan_type="basic")
        for result in nmap_results.get('results', []):
            nom = result.get('hostname') or result.get('host')
            ip = result.get('host')
            os = result.get('os', 'Inconnu')
            # Statut agent toujours "Non installé" après scan
            statut = "Non installé"
            self.equipements.append({
                'nom': nom,
                'ip': ip,
                'os': os,
                'statut': statut
            })
        self.update_table()

    def update_table(self):
        self.table.setRowCount(len(self.equipements))
        for row, equip in enumerate(self.equipements):
            self.table.setItem(row, 0, QTableWidgetItem(equip['nom']))
            self.table.setItem(row, 1, QTableWidgetItem(equip['ip']))
            self.table.setItem(row, 2, QTableWidgetItem(equip['os']))
            statut_item = QTableWidgetItem(equip['statut'])
            if equip['statut'] == "Installé":
                statut_item.setBackground(QColor(46, 204, 113))
                statut_item.setForeground(QColor(255, 255, 255))
            else:
                statut_item.setBackground(QColor(231, 76, 60))
                statut_item.setForeground(QColor(255, 255, 255))
            self.table.setItem(row, 3, statut_item)

    def installer_agent(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Sélection requise", "Veuillez sélectionner un équipement dans la liste.")
            return
        equip = self.equipements[row]
        install_type = self.install_type_combo.currentText()
        if equip['statut'] == "Installé":
            QMessageBox.information(self, "Déjà installé", f"L'agent est déjà installé sur {equip['nom']}.")
            return
        # Appel de la bonne méthode selon le type
        if install_type.startswith("Linux"):
            self.installer_agent_linux(equip)
        else:
            self.installer_agent_windows(equip)
        self.update_table()

    def installer_agent_linux(self, equip):
        # Ici tu mettras le vrai code paramiko
        # --- Simulation ---
        equip['statut'] = "Installé"
        QMessageBox.information(self, "Installation réussie", f"Agent installé sur {equip['nom']} (Linux/paramiko).")

    def installer_agent_windows(self, equip):
        # Ici tu mettras le vrai code WMI/PowerShell
        # --- Simulation ---
        equip['statut'] = "Installé"
        QMessageBox.information(self, "Installation réussie", f"Agent installé sur {equip['nom']} (Windows/WMI/PowerShell).") 