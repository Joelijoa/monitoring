"""
Configuration pour l'analyse prédictive
"""

# Configuration de l'analyse prédictive
PREDICTIVE_CONFIG = {
    'analysis_interval': 3600,  # Analyse toutes les heures (en secondes)
    'training_interval': 86400,  # Entraînement quotidien (en secondes)
    'history_days': 30,         # Historique pour l'analyse (en jours)
    'min_confidence': 0.7       # Seuil minimum de confiance pour les alertes
}

# Types d'anomalies détectées
ANOMALY_TYPES = {
    'off_hours_activity': {
        'name': 'Activité Hors Horaires',
        'description': 'Connexions ou activités en dehors des heures normales',
        'severity': 'warning',
        'icon': '🌙',
        'threshold': 0.8
    },
    'sudden_load_spike': {
        'name': 'Pic de Charge Soudain',
        'description': 'Augmentation brutale de la charge serveur',
        'severity': 'critical',
        'icon': '📈',
        'threshold': 0.9
    },
    'geolocation_anomaly': {
        'name': 'Géolocalisation Anormale',
        'description': 'Connexions depuis des localisations inhabituelles',
        'severity': 'critical',
        'icon': '🌍',
        'threshold': 0.85
    },
    'user_behavior_change': {
        'name': 'Changement Comportement Utilisateur',
        'description': 'Modification des patterns d\'activité utilisateur',
        'severity': 'warning',
        'icon': '👤',
        'threshold': 0.75
    },
    'network_traffic_anomaly': {
        'name': 'Anomalie Trafic Réseau',
        'description': 'Trafic réseau anormal ou suspect',
        'severity': 'critical',
        'icon': '🌐',
        'threshold': 0.9
    },
    'system_resource_anomaly': {
        'name': 'Anomalie Ressources Système',
        'description': 'Utilisation anormale des ressources système',
        'severity': 'warning',
        'icon': '⚙️',
        'threshold': 0.8
    }
}

# Heures normales d'activité (format 24h)
NORMAL_HOURS = {
    'weekdays': {
        'start': 7,   # 7h00
        'end': 19     # 19h00
    },
    'weekends': {
        'start': 9,   # 9h00
        'end': 17     # 17h00
    }
}

# Seuils pour les pics de charge
LOAD_THRESHOLDS = {
    'cpu_spike': 0.85,      # 85% CPU
    'memory_spike': 0.90,   # 90% RAM
    'disk_spike': 0.95,     # 95% Disque
    'network_spike': 0.80   # 80% Bande passante
}

# Configuration géolocalisation
GEO_CONFIG = {
    'allowed_countries': ['FR', 'BE', 'CH', 'LU'],  # Pays autorisés
    'suspicious_countries': ['RU', 'CN', 'KP', 'IR'],  # Pays suspects
    'max_distance_km': 1000,  # Distance maximale normale (km)
    'update_interval': 300    # Mise à jour géolocalisation (secondes)
}

# Paramètres des modèles ML
ML_MODELS_CONFIG = {
    'isolation_forest': {
        'contamination': 'auto',
        'random_state': 42,
        'n_estimators': 100
    },
    'one_class_svm': {
        'kernel': 'rbf',
        'nu': 0.1,
        'gamma': 'scale'
    },
    'local_outlier_factor': {
        'n_neighbors': 20,
        'contamination': 'auto'
    }
}

# Intervalles de rafraîchissement (en secondes)
REFRESH_INTERVALS = {
    'anomaly_detection': 3600,    # Détection d'anomalies (1h)
    'model_training': 86400,      # Entraînement modèles (24h)
    'geo_update': 300,            # Mise à jour géolocalisation (5min)
    'load_monitoring': 300        # Surveillance charge (5min)
} 