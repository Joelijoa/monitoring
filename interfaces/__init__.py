from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Connexion")
        self.setGeometry(100, 100, 300, 150)

        # Création des widgets
        self.label_user = QLabel("Nom d'utilisateur :")
        self.input_user = QLineEdit()
        self.label_pass = QLabel("Mot de passe :")
        self.input_pass = QLineEdit()
        self.input_pass.setEchoMode(QLineEdit.Password)
        self.button_login = QPushButton("Se connecter")

        # Layout vertical
        layout = QVBoxLayout()
        layout.addWidget(self.label_user)
        layout.addWidget(self.input_user)
        layout.addWidget(self.label_pass)
        layout.addWidget(self.input_pass)
        layout.addWidget(self.button_login)
        self.setLayout(layout)

        # Connexion du bouton à la fonction de vérification
        self.button_login.clicked.connect(self.check_login)

    def check_login(self):
        username = self.input_user.text()
        password = self.input_pass.text()
        # Ici, tu peux mettre ta logique de vérification
        if username == "admin" and password == "admin":
            QMessageBox.information(self, "Succès", "Connexion réussie !")
        else:
            QMessageBox.warning(self, "Erreur", "Nom d'utilisateur ou mot de passe incorrect.")

# Package des interfaces utilisateur
