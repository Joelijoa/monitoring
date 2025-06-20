from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QHBoxLayout

class RegisterWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.setWindowTitle("Inscription")
        self.setFixedSize(400, 340)

        self.label_user = QLabel("Nom d'utilisateur :")
        self.input_user = QLineEdit()
        self.label_email = QLabel("Email :")
        self.input_email = QLineEdit()
        self.label_pass = QLabel("Mot de passe :")
        self.input_pass = QLineEdit()
        self.input_pass.setEchoMode(QLineEdit.Password)
        self.label_confirm = QLabel("Confirmer le mot de passe :")
        self.input_confirm = QLineEdit()
        self.input_confirm.setEchoMode(QLineEdit.Password)
        self.button_register = QPushButton("S'inscrire")

        # Ligne pour retour à la connexion
        self.label_have_account = QLabel("Vous avez déjà un compte ?")
        self.button_login = QPushButton("Se connecter")
        self.button_login.setFlat(True)
        self.button_login.setStyleSheet("color: #273c75; text-decoration: underline; background: none; border: none;")
        hbox = QHBoxLayout()
        hbox.addWidget(self.label_have_account)
        hbox.addWidget(self.button_login)
        hbox.addStretch()

        layout = QVBoxLayout()
        layout.addWidget(self.label_user)
        layout.addWidget(self.input_user)
        layout.addWidget(self.label_email)
        layout.addWidget(self.input_email)
        layout.addWidget(self.label_pass)
        layout.addWidget(self.input_pass)
        layout.addWidget(self.label_confirm)
        layout.addWidget(self.input_confirm)
        layout.addWidget(self.button_register)
        layout.addLayout(hbox)
        self.setLayout(layout)

        self.button_register.clicked.connect(self.register)
        self.button_login.clicked.connect(self.back_to_login)

    def back_to_login(self):
        self.close()
        if self.parent:
            self.parent.show()
        else:
            from interfaces.login_window import LoginWindow  # import local pour éviter l'import circulaire
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
        # Ici, tu ajoutes la logique pour vérifier si l'utilisateur existe déjà et enregistrer le compte
        QMessageBox.information(self, "Succès", "Compte créé avec succès !")
        self.close()
        if self.parent:
            self.parent.show()