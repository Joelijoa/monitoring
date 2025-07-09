"""
Configuration pour le service de sauvegarde Bacula
"""

# Configuration Bacula
BACULA_CONFIG = {
    'bconsole_path': 'bconsole',
    'config_file': '/etc/bacula/bconsole.conf',
    'jobs_dir': '/etc/bacula/jobs.d',
    'storage_dir': '/var/lib/bacula',
    'log_dir': '/var/log/bacula',
    'default_schedule': '02:00',
    'timeout': 30,
    'max_retries': 3,
    'working_directory': 'monitoring/data/bacula'
}

# Configuration Wazuh pour les alertes
WAZUH_CONFIG = {
    'api_url': 'https://localhost:55000',
    'username': 'wazuh',
    'password': 'wazuh',
    'verify_ssl': False,
    'timeout': 10
}

# Types d'alertes de sauvegarde
BACKUP_ALERT_TYPES = {
    'backup_failed': {
        'severity': 'high',
        'category': 'backup_failure',
        'description': 'Échec de sauvegarde Bacula'
    },
    'restore_failed': {
        'severity': 'critical',
        'category': 'backup_failure',
        'description': 'Échec de restauration Bacula'
    },
    'backup_missing': {
        'severity': 'medium',
        'category': 'backup_warning',
        'description': 'Sauvegarde manquante'
    },
    'storage_full': {
        'severity': 'high',
        'category': 'backup_warning',
        'description': 'Espace de stockage plein'
    }
}

# Seuils d'alerte
BACKUP_THRESHOLDS = {
    'max_failed_jobs': 3,
    'min_success_rate': 90.0,
    'max_backup_age_hours': 24,
    'storage_usage_warning': 80.0,
    'storage_usage_critical': 95.0
}

# Intervalles de rafraîchissement
REFRESH_INTERVALS = {
    'jobs_status': 60,  # secondes
    'backup_history': 300,  # secondes
    'storage_status': 600,  # secondes
    'alert_check': 300  # secondes
} 