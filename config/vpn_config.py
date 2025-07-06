"""
Configuration pour la gestion VPN avec OPNsense et WireGuard
"""

# Configuration de l'API OPNsense
OPNSENSE_CONFIG = {
    'base_url': 'https://192.168.1.1',  # URL de votre OPNsense
    'api_key': 'your_api_key_here',
    'api_secret': 'your_api_secret_here',
    'verify_ssl': False,  # Désactiver la vérification SSL pour les certificats auto-signés
    'timeout': 30
}

# Configuration WireGuard
WIREGUARD_CONFIG = {
    'interface_name': 'wg0',  # Interface WireGuard principale
    'port': 51820,           # Port WireGuard par défaut
    'mtu': 1420,             # MTU pour WireGuard
    'dns_servers': ['8.8.8.8', '1.1.1.1'],  # Serveurs DNS
    'allowed_ips': '10.0.0.0/24',  # Réseau autorisé
    'persistent_keepalive': 25,  # Keepalive en secondes
    'max_peers': 100         # Nombre maximum de pairs
}

# Types d'utilisateurs VPN
VPN_USER_TYPES = {
    'agent': {
        'name': 'Agent',
        'description': 'Agent de terrain',
        'icon': '👷',
        'allowed_ips': '10.0.1.0/24',
        'max_connections': 1,
        'expiration_days': 365
    },
    'technician': {
        'name': 'Technicien',
        'description': 'Technicien IT',
        'icon': '🔧',
        'allowed_ips': '10.0.2.0/24',
        'max_connections': 3,
        'expiration_days': 730
    },
    'admin': {
        'name': 'Administrateur',
        'description': 'Administrateur système',
        'icon': '👨‍💼',
        'allowed_ips': '10.0.3.0/24',
        'max_connections': 5,
        'expiration_days': 1095
    },
    'temporary': {
        'name': 'Temporaire',
        'description': 'Accès temporaire',
        'icon': '⏰',
        'allowed_ips': '10.0.4.0/24',
        'max_connections': 1,
        'expiration_days': 30
    }
}

# Statuts des connexions VPN
VPN_STATUS = {
    'active': {
        'name': 'Actif',
        'color': '#27ae60',
        'icon': '🟢'
    },
    'inactive': {
        'name': 'Inactif',
        'color': '#95a5a6',
        'icon': '⚪'
    },
    'expired': {
        'name': 'Expiré',
        'color': '#e74c3c',
        'icon': '🔴'
    },
    'revoked': {
        'name': 'Révoqué',
        'color': '#8e44ad',
        'icon': '🚫'
    },
    'pending': {
        'name': 'En attente',
        'color': '#f39c12',
        'icon': '⏳'
    }
}

# Configuration de la base de données SQLite
DATABASE_CONFIG = {
    'path': 'monitoring/data/vpn_config.db',
    'tables': {
        'vpn_config': '''
            CREATE TABLE IF NOT EXISTS vpn_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                user_name TEXT NOT NULL,
                user_type TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expiration_date TIMESTAMP,
                last_connection TIMESTAMP,
                connection_count INTEGER DEFAULT 0,
                description TEXT,
                revoked_date TIMESTAMP,
                revoked_reason TEXT
            )
        ''',
        'vpn_connections': '''
            CREATE TABLE IF NOT EXISTS vpn_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vpn_config_id INTEGER,
                connection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                disconnect_date TIMESTAMP,
                ip_address TEXT,
                bytes_received INTEGER DEFAULT 0,
                bytes_sent INTEGER DEFAULT 0,
                duration_seconds INTEGER DEFAULT 0,
                FOREIGN KEY (vpn_config_id) REFERENCES vpn_config (id)
            )
        '''
    }
}

# Intervalles de rafraîchissement (en secondes)
REFRESH_INTERVALS = {
    'connection_status': 30,    # Statut des connexions (30s)
    'peer_sync': 300,           # Synchronisation avec OPNsense (5min)
    'expiration_check': 3600,   # Vérification des expirations (1h)
    'stats_update': 60          # Mise à jour des statistiques (1min)
}

# Seuils d'alerte
ALERT_THRESHOLDS = {
    'max_concurrent_connections': 50,  # Nombre maximum de connexions simultanées
    'connection_duration_hours': 24,   # Durée maximale d'une connexion
    'data_transfer_gb': 10,            # Transfert de données maximum par jour
    'failed_connections': 5             # Nombre d'échecs de connexion avant alerte
}

# Configuration des notifications
NOTIFICATION_CONFIG = {
    'email_enabled': False,
    'email_smtp_server': 'smtp.gmail.com',
    'email_smtp_port': 587,
    'email_username': 'your_email@gmail.com',
    'email_password': 'your_app_password',
    'email_recipients': ['admin@company.com'],
    'webhook_enabled': False,
    'webhook_url': 'https://hooks.slack.com/services/...'
} 