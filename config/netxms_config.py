"""
Configuration pour l'API NetXMS
"""

# Configuration de l'API NetXMS
NETXMS_CONFIG = {
    'api_url': 'http://localhost:8080/api/v1',
    'username': 'admin',
    'password': 'password',
    'timeout': 30,
    'verify_ssl': False
}

# Métriques à surveiller
METRICS_CONFIG = {
    'cpu_utilization': {
        'dci_name': 'CPU_UTIL',
        'description': 'Utilisation CPU (%)',
        'threshold_warning': 70,
        'threshold_critical': 85
    },
    'memory_utilization': {
        'dci_name': 'MEMORY_UTIL', 
        'description': 'Utilisation RAM (%)',
        'threshold_warning': 75,
        'threshold_critical': 90
    },
    'disk_utilization': {
        'dci_name': 'DISK_UTIL',
        'description': 'Utilisation Disque (%)',
        'threshold_warning': 80,
        'threshold_critical': 95
    },
    'network_traffic': {
        'dci_name': 'NETWORK_TRAFFIC',
        'description': 'Trafic Réseau (Mbps)',
        'threshold_warning': 150,
        'threshold_critical': 200
    }
}

# Types d'équipements
EQUIPMENT_TYPES = {
    'server': {
        'name': 'Serveur',
        'icon': '🖥️',
        'metrics': ['cpu_utilization', 'memory_utilization', 'disk_utilization', 'network_traffic']
    },
    'router': {
        'name': 'Routeur',
        'icon': '🌐',
        'metrics': ['cpu_utilization', 'network_traffic']
    },
    'switch': {
        'name': 'Switch',
        'icon': '🔌',
        'metrics': ['cpu_utilization', 'network_traffic']
    },
    'firewall': {
        'name': 'Firewall',
        'icon': '🛡️',
        'metrics': ['cpu_utilization', 'memory_utilization', 'network_traffic']
    }
}

# Intervalles de rafraîchissement (en secondes)
REFRESH_INTERVALS = {
    'real_time': 30,      # Surveillance temps réel
    'historical': 300,     # Données historiques
    'alerts': 60          # Vérification des alertes
} 