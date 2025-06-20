from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QApplication
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Connexion")
        self.setFixedSize(700, 500)
        self.center_on_screen()

        # Titre
        self.title = QLabel("Connexion")
        self.title.setFont(QFont("Arial", 20, QFont.Bold))
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setWordWrap(True)

        # Champs
        self.label_user = QLabel("Nom d'utilisateur :")
        self.label_user.setFont(QFont("Arial", 14))
        self.input_user = QLineEdit()
        self.input_user.setFont(QFont("Arial", 14))
        self.input_user.setPlaceholderText("Entrez votre nom d'utilisateur")

        self.label_pass = QLabel("Mot de passe :")
        self.label_pass.setFont(QFont("Arial", 14))
        self.input_pass = QLineEdit()
        self.input_pass.setFont(QFont("Arial", 14))
        self.input_pass.setPlaceholderText("Entrez votre mot de passe")
        self.input_pass.setEchoMode(QLineEdit.Password)

        # Boutons
        self.button_login = QPushButton("Se connecter")
        self.button_login.setFont(QFont("Arial", 14, QFont.Bold))
        self.button_register = QPushButton("Créer un compte")
        self.button_register.setFont(QFont("Arial", 13))
        self.button_register.setFlat(True)
        self.button_register.setStyleSheet("color: #273c75; background: none; border: none; text-decoration: underline;")

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.title)
        layout.addSpacing(30)
        layout.addWidget(self.label_user)
        layout.addWidget(self.input_user)
        layout.addSpacing(15)
        layout.addWidget(self.label_pass)
        layout.addWidget(self.input_pass)
        layout.addSpacing(30)
        layout.addWidget(self.button_login)
        layout.addSpacing(10)
        layout.addWidget(self.button_register)
        layout.setContentsMargins(80, 30, 80, 30)
        layout.setSpacing(20)
        self.setLayout(layout)

        # Style CSS global
        self.setStyleSheet("""
            QWidget {
                background-color: #f5f6fa;
            }
            QLineEdit {
                border: 1.5px solid #dcdde1;
                border-radius: 10px;
                padding: 14px;
                min-height: 30px;
                font-size: 16px;
                background: #ffffff;
            }
            QPushButton {
                background-color: #273c75;
                color: white;
                border-radius: 10px;
                padding: 12px;
                font-size: 16px;
                min-height: 40px;
            }
            QPushButton:flat {
                background: none;
                color: #273c75;
                text-decoration: underline;
            }
            QPushButton:hover {
                background-color: #40739e;
            }
        """)

        # Connexions
        self.button_login.clicked.connect(self.login)
        self.button_register.clicked.connect(self.open_register)

    def center_on_screen(self):
        qr = self.frameGeometry()
        cp = QApplication.primaryScreen().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def login(self):
        if not self.input_user.text() or not self.input_pass.text():
            QMessageBox.warning(self, "Erreur", "Tous les champs sont obligatoires.")
        else:
            QMessageBox.information(self, "Succès", "Connexion réussie !")

    def open_register(self):
        from interfaces.register_window import RegisterWindow
        self.register_window = RegisterWindow(parent=self)
        self.register_window.show()
        self.close()