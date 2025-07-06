"""
Configuration pour l'API Wazuh
"""

# Configuration de l'API Wazuh
WAZUH_CONFIG = {
    'api_url': 'https://localhost:55000',
    'username': 'wazuh',
    'password': 'wazuh',
    'timeout': 30,
    'verify_ssl': False
}

# Types d'événements à surveiller
EVENT_TYPES = {
    'login': {
        'name': 'Connexion',
        'description': 'Connexions/déconnexions utilisateur',
        'severity': 'info',
        'icon': '🔐'
    },
    'program_execution': {
        'name': 'Exécution Programme',
        'description': 'Programmes lancés sur les équipements',
        'severity': 'warning',
        'icon': '⚙️'
    },
    'file_access': {
        'name': 'Accès Fichier',
        'description': 'Fichiers modifiés ou accédés',
        'severity': 'info',
        'icon': '📁'
    },
    'network_access': {
        'name': 'Accès Réseau',
        'description': 'Accès réseau suspects détectés',
        'severity': 'critical',
        'icon': '🌐'
    },
    'system_event': {
        'name': 'Événement Système',
        'description': 'Événements système généraux',
        'severity': 'info',
        'icon': '🖥️'
    }
}

# Seuils de détection pour le modèle ML
ML_THRESHOLDS = {
    'suspicious_score': 0.7,      # Score minimum pour considérer comme suspect
    'critical_score': 0.9,        # Score pour événement critique
    'anomaly_threshold': 0.8      # Seuil pour détection d'anomalie
}

# Paramètres de filtrage
FILTER_OPTIONS = {
    'all_users': 'Tous les utilisateurs',
    'suspicious_only': 'Utilisateurs suspects uniquement',
    'critical_events': 'Événements critiques uniquement',
    'recent_activity': 'Activité récente (24h)'
}

# Intervalles de rafraîchissement (en secondes)
REFRESH_INTERVALS = {
    'user_activity': 60,          # Activité utilisateur
    'ml_analysis': 300,           # Analyse ML
    'alerts': 30                  # Alertes temps réel
} 