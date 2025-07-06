from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QStackedWidget, QFrame, QMenu
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from monitoring.interfaces.admin.surveillance_page import SurveillancePage
from monitoring.interfaces.admin.user_activity_page import UserActivityPage
from monitoring.interfaces.admin.predictive_page import PredictivePage
from monitoring.interfaces.admin.vpn_page import VPNPage

class AdminDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dashboard Administrateur")
        self.resize(1000, 650)

        # --------- Sidebar verticale ---------
        sidebar = QFrame()
        sidebar.setStyleSheet("background-color: #273c75;")
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 30, 0, 0)
        sidebar_layout.setSpacing(20)

        # Boutons de la sidebar
        self.buttons = []
        sections = [
            "Surveillance", "Activité Utilisateur", "Analyse Prédictive",
            "VPN", "Sauvegardes", "Résultats Nmap", "Gestion des Équipements"
        ]
        for section in sections:
            btn = QPushButton(section)
            btn.setStyleSheet("""
                QPushButton {
                    color: white; background: none; border: none;
                    font-size: 15px; padding: 15px; text-align: left;
                }
                QPushButton:hover {
                    background-color: #40739e;
                }
            """)
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            sidebar_layout.addWidget(btn)
            self.buttons.append(btn)
        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)

        # --------- Zone de contenu (QStackedWidget) ---------
        self.stack = QStackedWidget()
        self.pages = []
        
        # Page de surveillance spéciale
        surveillance_page = SurveillancePage()
        self.stack.addWidget(surveillance_page)
        self.pages.append(surveillance_page)
        
        # Page d'activité utilisateur spéciale
        user_activity_page = UserActivityPage()
        self.stack.addWidget(user_activity_page)
        self.pages.append(user_activity_page)
        
        # Page d'analyse prédictive spéciale
        predictive_page = PredictivePage()
        self.stack.addWidget(predictive_page)
        self.pages.append(predictive_page)
        
        # Page VPN spéciale
        vpn_page = VPNPage()
        self.stack.addWidget(vpn_page)
        self.pages.append(vpn_page)
        
        # Autres pages
        for section in sections[4:]:  # Skip les 4 premières sections car déjà ajoutées
            page = QWidget()
            layout = QVBoxLayout()
            layout.addWidget(QLabel(f"Contenu de la section : {section}"))
            page.setLayout(layout)
            self.stack.addWidget(page)
            self.pages.append(page)

        # Connexion des boutons à l'affichage des pages
        for i, btn in enumerate(self.buttons):
            btn.clicked.connect(lambda checked, idx=i: self.stack.setCurrentIndex(idx))

        # --------- Profil utilisateur en haut à droite ---------
        profile_button = QPushButton("Admin ▼")
        profile_menu = QMenu()
        profile_menu.addAction("Profil")
        profile_menu.addAction("Paramètres")
        profile_menu.addAction("Déconnexion")
        profile_button.setMenu(profile_menu)
        profile_button.setFixedWidth(120)
        profile_button.setStyleSheet("""
            QPushButton {
                background-color: #f5f6fa;
                border: none;
                font-weight: bold;
                font-size: 15px;
            }
            QPushButton::menu-indicator { image: none; }
        """)

        header_layout = QHBoxLayout()
        header_layout.addStretch()
        header_layout.addWidget(profile_button)
        header_layout.setAlignment(profile_button, Qt.AlignmentFlag.AlignRight)

        # --------- Layout principal ---------
        content_layout = QVBoxLayout()
        content_layout.addLayout(header_layout)
        content_layout.addWidget(self.stack)

        main_layout = QHBoxLayout()
        main_layout.addWidget(sidebar)
        main_layout.addLayout(content_layout)
        self.setLayout(main_layout) 