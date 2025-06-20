import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont  # <--- N'oublie pas d'importer QFont
from interfaces.account.login_window import LoginWindow
# from interfaces.admin.admin_dashboard import AdminDashboard


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 12))  # 👈 Ajoute cette ligne pour augmenter la police par défaut
    window = LoginWindow()
    window.show()
    sys.exit(app.exec_())
