from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QHBoxLayout, QApplication
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

class RegisterWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.setWindowTitle("Inscription")
        self.resize(600, 500)  # Fenêtre grande et redimensionnable
        self.center_on_screen()

        # Titre
        self.title = QLabel("Créer un compte utilisateur")
        self.title.setFont(QFont("Arial", 20, QFont.Bold))
        self.title.setAlignment(Qt.AlignCenter)

        self.label_user = QLabel("Nom d'utilisateur :")
        self.label_user.setFont(QFont("Arial", 13))
        self.input_user = QLineEdit()
        self.input_user.setFont(QFont("Arial", 13))
        self.input_user.setPlaceholderText("Entrez votre nom d'utilisateur")
        self.label_email = QLabel("Email :")
        self.label_email.setFont(QFont("Arial", 13))
        self.input_email = QLineEdit()
        self.input_email.setFont(QFont("Arial", 13))
        self.input_email.setPlaceholderText("Entrez votre email")
        self.label_pass = QLabel("Mot de passe :")
        self.label_pass.setFont(QFont("Arial", 13))
        self.input_pass = QLineEdit()
        self.input_pass.setFont(QFont("Arial", 13))
        self.input_pass.setPlaceholderText("Entrez votre mot de passe")
        self.input_pass.setEchoMode(QLineEdit.Password)
        self.label_confirm = QLabel("Confirmer le mot de passe :")
        self.label_confirm.setFont(QFont("Arial", 13))
        self.input_confirm = QLineEdit()
        self.input_confirm.setFont(QFont("Arial", 13))
        self.input_confirm.setPlaceholderText("Confirmez votre mot de passe")
        self.input_confirm.setEchoMode(QLineEdit.Password)
        self.button_register = QPushButton("S'inscrire")
        self.button_register.setFont(QFont("Arial", 14, QFont.Bold))

        # Ligne pour retour à la connexion
        self.label_have_account = QLabel("Vous avez déjà un compte ?")
        self.label_have_account.setFont(QFont("Arial", 12))
        self.button_login = QPushButton("Se connecter")
        self.button_login.setFont(QFont("Arial", 12, QFont.Bold))
        self.button_login.setFlat(True)
        self.button_login.setStyleSheet("color: #273c75; text-decoration: underline; background: none; border: none;")
        hbox = QHBoxLayout()
        hbox.addStretch()
        hbox.addWidget(self.label_have_account)
        hbox.addWidget(self.button_login)
        hbox.addStretch()

        self.setStyleSheet("""
            QWidget {
                background-color: #f5f6fa;
            }
            QLineEdit {
                border: 1.5px solid #dcdde1;
                border-radius: 10px;
                padding: 10px;
                font-size: 15px;
                background: #fff;
            }
            QPushButton {
                background-color: #273c75;
                color: white;
                border-radius: 10px;
                padding: 12px;
                font-size: 16px;
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

        layout = QVBoxLayout()
        layout.addWidget(self.title)
        layout.addSpacing(20)
        layout.addWidget(self.label_user)
        layout.addWidget(self.input_user)
        layout.addSpacing(10)
        layout.addWidget(self.label_email)
        layout.addWidget(self.input_email)
        layout.addSpacing(10)
        layout.addWidget(self.label_pass)
        layout.addWidget(self.input_pass)
        layout.addSpacing(10)
        layout.addWidget(self.label_confirm)
        layout.addWidget(self.input_confirm)
        layout.addSpacing(20)
        layout.addWidget(self.button_register)
        layout.addLayout(hbox)
        layout.setContentsMargins(50, 30, 50, 30)
        self.setLayout(layout)

        self.button_register.clicked.connect(self.register)
        self.button_login.clicked.connect(self.back_to_login)

    def center_on_screen(self):
        qr = self.frameGeometry()
        cp = QApplication.primaryScreen().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def back_to_login(self):
        self.close()
        if self.parent:
            self.parent.show()
        else:
            from interfaces.login_window import LoginWindow
            self.login_window = LoginWindow()
            self.login_window.show()

    def register(self):
        username = self.input_user.text()
        email = self.input_email.text()
        password = self.input_pass.text()
        confirm = self.input_confirm.text()
        if not username or not password or not confirm:
            QMessageBox.warning(self, "Erreur", "Tous les champs sont obligatoires.")
            return
        if password != confirm:
            QMessageBox.warning(self, "Erreur", "Les mots de passe ne correspondent pas.")
            return
        QMessageBox.information(self, "Succès", "Compte créé avec succès !")
        self.close()
        if self.parent:
            self.parent.show()
