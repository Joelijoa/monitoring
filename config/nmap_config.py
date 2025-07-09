"""
Configuration pour le service de scans réseau Nmap
"""

# Configuration Nmap
NMAP_CONFIG = {
    'default_timeout': 300,  # secondes
    'max_hosts': 100,
    'max_ports': 1000,
    'results_dir': 'monitoring/data',
    'log_level': 'INFO'
}

# Types de scans disponibles
SCAN_TYPES = {
    'basic': {
        'name': 'Scan de base',
        'description': 'Découverte des hôtes et services de base',
        'arguments': '-sS -sV -O --version-intensity 5',
        'duration': '5-15 minutes'
    },
    'vulnerability': {
        'name': 'Scan de vulnérabilités',
        'description': 'Détection de vulnérabilités avec scripts NSE',
        'arguments': '-sS -sV -O --script=vuln --version-intensity 5',
        'duration': '15-30 minutes'
    },
    'comprehensive': {
        'name': 'Scan complet',
        'description': 'Scan exhaustif avec tous les scripts',
        'arguments': '-sS -sV -sC -O -A --script=vuln,auth,default --version-intensity 9',
        'duration': '30-60 minutes'
    },
    'quick': {
        'name': 'Scan rapide',
        'description': 'Scan rapide des ports les plus courants',
        'arguments': '-sS -sV --top-ports 100',
        'duration': '2-5 minutes'
    }
}

# Scripts de vulnérabilités NSE
VULNERABILITY_SCRIPTS = {
    'vuln': 'Scripts de vulnérabilités générales',
    'auth': 'Scripts d\'authentification',
    'default': 'Scripts par défaut',
    'discovery': 'Scripts de découverte',
    'dos': 'Scripts de déni de service',
    'exploit': 'Scripts d\'exploitation',
    'external': 'Scripts externes',
    'fuzzer': 'Scripts de fuzzing',
    'intrusive': 'Scripts intrusifs',
    'malware': 'Scripts de détection de malware',
    'safe': 'Scripts sûrs',
    'version': 'Scripts de détection de version'
}

# Seuils d'alerte pour les vulnérabilités
VULNERABILITY_THRESHOLDS = {
    'critical_count': 5,
    'high_count': 10,
    'medium_count': 20,
    'low_count': 50
}

# Intervalles de scan périodique
SCAN_INTERVALS = {
    'hourly': 1,
    'daily': 24,
    'weekly': 168,
    'monthly': 720
}

# Ports communs à scanner
COMMON_PORTS = {
    'web': '80,443,8080,8443',
    'database': '3306,5432,1433,1521',
    'mail': '25,110,143,465,587,993,995',
    'file': '21,22,23,445,139',
    'remote': '22,23,3389,5900',
    'all': '1-65535'
} 