from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QStackedWidget, QFrame, QMenu, QSizePolicy
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QCursor, QPixmap, QFont
from monitoring.interfaces.admin.surveillance_page import SurveillancePage
from monitoring.interfaces.admin.user_activity_page import UserActivityPage
from monitoring.interfaces.admin.predictive_page import PredictivePage
from monitoring.interfaces.admin.vpn_page import VPNPage
from monitoring.interfaces.admin.backup_page import BackupPage
from monitoring.interfaces.admin.nmap_page import NmapPage
from monitoring.interfaces.admin.gestion_equipements_page import GestionEquipementsPage
from monitoring.interfaces.admin.forensic_page import ForensicPage
import qtawesome as qta

# Palette couleurs
PALETTE = {
    'sidebar_bg': '#39396A',
    'sidebar_active': '#FFD94A',
    'sidebar_hover': '#F7B55E',
    'sidebar_text': '#F5F6FA',
    'main_bg': '#F5F6FA',
    'header_bg': '#39396A',
    'header_text': '#FFD94A',
    'btn_gradient': 'qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FFD94A, stop:1 #D96B8A)',
    'btn_text': '#39396A',
    'active_icon': '#FFD94A',
    'inactive_icon': '#F5F6FA',
}

ICON_NAMES = [
    'fa5s.tachometer-alt',    # Surveillance
    'fa5s.user-friends',      # Activité Utilisateur
    'fa5s.chart-line',        # Analyse Prédictive
    'fa5s.key',               # VPN
    'fa5s.hdd',               # Sauvegardes
    'fa5s.network-wired',     # Nmap
    'fa5s.desktop',           # Gestion équipements
    'fa5s.search',            # Forensic
]

class AdminDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dashboard Administrateur")
        self.resize(1200, 750)
        self.setStyleSheet(f"font-family: 'Roboto', 'Segoe UI', Arial, sans-serif; background: {PALETTE['main_bg']};")

        # --------- Sidebar moderne ---------
        sidebar = QFrame()
        sidebar.setStyleSheet(f"background-color: {PALETTE['sidebar_bg']}; border: none;")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(10)

        # Logo en haut
        logo = QLabel()
        logo_pix = QPixmap('ressources/logo.png')
        if not logo_pix.isNull():
            logo.setPixmap(logo_pix.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        logo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sidebar_layout.addSpacing(18)
        sidebar_layout.addWidget(logo)
        sidebar_layout.addSpacing(10)

        # Boutons de la sidebar avec icônes
        self.buttons = []
        self.sections = [
            "Surveillance", "Activité Utilisateur", "Analyse Prédictive",
            "VPN", "Sauvegardes", "Résultats Nmap", "Gestion des Équipements", "Analyse Forensic"
        ]
        for i, section in enumerate(self.sections):
            btn = QPushButton(section)
            btn.setIcon(qta.icon(ICON_NAMES[i], color=PALETTE['inactive_icon']))
            btn.setIconSize(QSize(22, 22))
            btn.setCursor(QCursor(Qt.PointingHandCursor))
            btn.setStyleSheet(f'''
                QPushButton {{
                    color: {PALETTE['sidebar_text']};
                    background: none;
                    border: none;
                    font-size: 16px;
                    padding: 14px 18px;
                    text-align: left;
                    border-radius: 8px;
                    margin: 2px 10px;
                }}
                QPushButton:hover {{
                    background: {PALETTE['sidebar_hover']};
                    color: {PALETTE['sidebar_bg']};
                }}
            ''')
            sidebar_layout.addWidget(btn)
            self.buttons.append(btn)
        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)

        # --------- Zone de contenu (QStackedWidget) ---------
        self.stack = QStackedWidget()
        self.pages = []
        self.stack.addWidget(SurveillancePage())
        self.stack.addWidget(UserActivityPage())
        self.stack.addWidget(PredictivePage())
        self.stack.addWidget(VPNPage())
        self.stack.addWidget(BackupPage())
        self.stack.addWidget(NmapPage())
        self.stack.addWidget(GestionEquipementsPage())
        self.stack.addWidget(ForensicPage())

        # Connexion des boutons à l'affichage des pages + surbrillance
        for i, btn in enumerate(self.buttons):
            btn.clicked.connect(lambda checked, idx=i: self.set_active_page(idx))
        self.set_active_page(0)

        # --------- Profil utilisateur en haut à droite ---------
        profile_button = QPushButton(qta.icon('fa5s.user-circle', color=PALETTE['sidebar_bg']), "  Admin")
        profile_menu = QMenu()
        profile_menu.addAction(qta.icon('fa5s.user-cog'), "Profil")
        profile_menu.addAction(qta.icon('fa5s.cog'), "Paramètres")
        profile_menu.addAction(qta.icon('fa5s.sign-out-alt'), "Déconnexion")
        profile_button.setMenu(profile_menu)
        profile_button.setFixedWidth(150)
        profile_button.setStyleSheet(f'''
            QPushButton {{
                background: {PALETTE['header_bg']};
                color: {PALETTE['header_text']};
                border: none;
                font-weight: bold;
                font-size: 16px;
                border-radius: 8px;
                padding: 8px 18px;
            }}
            QPushButton::menu-indicator {{ image: none; }}
        ''')

        header_layout = QHBoxLayout()
        header_layout.addStretch()
        header_layout.addWidget(profile_button)
        header_layout.setAlignment(profile_button, Qt.AlignRight)
        header_layout.setContentsMargins(0, 10, 20, 0)

        # --------- Layout principal ---------
        content_layout = QVBoxLayout()
        content_layout.addLayout(header_layout)
        content_layout.addWidget(self.stack)
        content_layout.setContentsMargins(0, 0, 0, 0)

        main_layout = QHBoxLayout()
        main_layout.addWidget(sidebar)
        main_layout.addLayout(content_layout)
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(main_layout)

    def set_active_page(self, idx):
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self.buttons):
            if i == idx:
                btn.setStyleSheet(f'''
                    QPushButton {{
                        color: {PALETTE['sidebar_bg']};
                        background: {PALETTE['sidebar_active']};
                        border: none;
                        font-size: 16px;
                        padding: 14px 18px;
                        text-align: left;
                        border-radius: 8px;
                        margin: 2px 10px;
                        font-weight: bold;
                    }}
                ''')
                btn.setIcon(qta.icon(ICON_NAMES[i], color=PALETTE['sidebar_bg']))
            else:
                btn.setStyleSheet(f'''
                    QPushButton {{
                        color: {PALETTE['sidebar_text']};
                        background: none;
                        border: none;
                        font-size: 16px;
                        padding: 14px 18px;
                        text-align: left;
                        border-radius: 8px;
                        margin: 2px 10px;
                    }}
                    QPushButton:hover {{
                        background: {PALETTE['sidebar_hover']};
                        color: {PALETTE['sidebar_bg']};
                    }}
                ''')
                btn.setIcon(qta.icon(ICON_NAMES[i], color=PALETTE['inactive_icon'])) 