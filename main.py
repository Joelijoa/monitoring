import sys
import os

# Ajouter le répertoire parent au path pour permettre les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont  # <--- N'oublie pas d'importer QFont
from monitoring.interfaces.admin.admin_dashboard import AdminDashboard
# from monitoring.interfaces.account.login_window import LoginWindow



if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 12)) 
    window = AdminDashboard()
    window.show()
    sys.exit(app.exec_())
