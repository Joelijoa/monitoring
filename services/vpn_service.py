"""
Service de gestion VPN avec WireGuard via OPNsense
"""
import sqlite3
import requests
import json
import logging
import os
import secrets
import string
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from monitoring.config.vpn_config import (
    OPNSENSE_CONFIG, WIREGUARD_CONFIG, VPN_USER_TYPES, 
    VPN_STATUS, DATABASE_CONFIG, REFRESH_INTERVALS, ALERT_THRESHOLDS
)

logger = logging.getLogger(__name__)

class VPNService:
    def __init__(self):
        self.base_url = OPNSENSE_CONFIG['base_url']
        self.api_key = OPNSENSE_CONFIG['api_key']
        self.api_secret = OPNSENSE_CONFIG['api_secret']
        self.verify_ssl = OPNSENSE_CONFIG['verify_ssl']
        self.timeout = OPNSENSE_CONFIG['timeout']
        
        # Initialiser la base de données
        self.init_database()
        
        # Cache pour les connexions actives
        self.active_connections = {}
        
        try:
            self.simulation = not self.test_connection()
        except Exception:
            self.simulation = True
            
    def test_connection(self):
        # Méthode factice pour la simulation
        return False

    def init_database(self):
        """Initialise la base de données SQLite"""
        try:
            # Créer le répertoire de données si nécessaire
            os.makedirs(os.path.dirname(DATABASE_CONFIG['path']), exist_ok=True)
            
            # Connexion à la base de données
            self.conn = sqlite3.connect(DATABASE_CONFIG['path'])
            self.conn.row_factory = sqlite3.Row
            
            # Créer les tables
            cursor = self.conn.cursor()
            for table_name, create_sql in DATABASE_CONFIG['tables'].items():
                cursor.execute(create_sql)
            
            self.conn.commit()
            logger.info("Base de données VPN initialisée avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
            
    def generate_wireguard_keys(self) -> Tuple[Optional[str], Optional[str]]:
        """Génère une paire de clés WireGuard"""
        try:
            # Générer la clé privée
            private_key = x25519.X25519PrivateKey.generate()
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Générer la clé publique
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Encoder en base64
            import base64
            private_key_b64 = base64.b64encode(private_key_bytes).decode('utf-8')
            public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
            
            return private_key_b64, public_key_b64
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération des clés WireGuard: {e}")
            return None, None
            
    def generate_ip_address(self, user_type: str) -> Optional[str]:
        """Génère une adresse IP unique pour l'utilisateur"""
        try:
            # Obtenir la plage d'IP pour le type d'utilisateur
            user_config = VPN_USER_TYPES.get(user_type, VPN_USER_TYPES['agent'])
            allowed_ips = user_config['allowed_ips']
            
            # Extraire la plage réseau
            network = allowed_ips.split('/')[0]
            prefix = int(allowed_ips.split('/')[1])
            
            # Générer une IP aléatoire dans la plage
            import ipaddress
            network_obj = ipaddress.IPv4Network(allowed_ips, strict=False)
            
            # Vérifier les IPs déjà utilisées
            cursor = self.conn.cursor()
            cursor.execute("SELECT ip_address FROM vpn_config WHERE user_type = ?", (user_type,))
            used_ips = [row['ip_address'] for row in cursor.fetchall()]
            
            # Trouver une IP disponible
            for ip in network_obj.hosts():
                ip_str = str(ip)
                if ip_str not in used_ips:
                    return ip_str
                    
            # Si aucune IP disponible, retourner None
            return None
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération de l'adresse IP: {e}")
            return None
            
    def create_vpn_user(self, user_id: str, user_name: str, user_type: str, description: str = "") -> Optional[Dict]:
        """Crée un nouvel utilisateur VPN"""
        try:
            # Vérifier que le type d'utilisateur existe
            if user_type not in VPN_USER_TYPES:
                raise ValueError(f"Type d'utilisateur invalide: {user_type}")
                
            # Vérifier si l'utilisateur existe déjà
            cursor = self.conn.cursor()
            cursor.execute("SELECT id FROM vpn_config WHERE user_id = ?", (user_id,))
            if cursor.fetchone():
                raise ValueError(f"Utilisateur {user_id} existe déjà")
                
            # Générer les clés WireGuard
            private_key, public_key = self.generate_wireguard_keys()
            if not private_key or not public_key:
                raise Exception("Impossible de générer les clés WireGuard")
                
            # Générer l'adresse IP
            ip_address = self.generate_ip_address(user_type)
            if not ip_address:
                raise Exception("Aucune adresse IP disponible pour ce type d'utilisateur")
                
            # Calculer la date d'expiration
            user_config = VPN_USER_TYPES[user_type]
            expiration_date = datetime.now() + timedelta(days=user_config['expiration_days'])
            
            # Insérer dans la base de données
            cursor.execute("""
                INSERT INTO vpn_config (
                    user_id, user_name, user_type, public_key, private_key, 
                    ip_address, status, expiration_date, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, user_name, user_type, public_key, private_key,
                ip_address, 'pending', expiration_date, description
            ))
            
            vpn_id = cursor.lastrowid
            self.conn.commit()
            
            # Créer le pair WireGuard sur OPNsense
            if vpn_id is not None:
                success = self.create_wireguard_peer(vpn_id, user_name, public_key, ip_address)
                
                if success:
                    # Mettre à jour le statut
                    cursor.execute("UPDATE vpn_config SET status = 'active' WHERE id = ?", (vpn_id,))
                    self.conn.commit()
                    
                # Retourner les informations de l'utilisateur
                return self.get_vpn_user(vpn_id)
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de l'utilisateur VPN: {e}")
            raise
            
    def create_wireguard_peer(self, vpn_id: int, user_name: str, public_key: str, ip_address: str) -> bool:
        """Crée un pair WireGuard sur OPNsense via l'API"""
        try:
            # Configuration du pair WireGuard
            peer_config = {
                'enabled': '1',
                'name': f"user_{vpn_id}_{user_name}",
                'pubkey': public_key,
                'tunneladdress': ip_address,
                'descr': f"VPN User: {user_name} (ID: {vpn_id})"
            }
            
            # Appel API OPNsense pour créer le pair
            url = f"{self.base_url}/api/wireguard/service/addpeer"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Basic {self.api_key}:{self.api_secret}'
            }
            
            response = requests.post(
                url, 
                json=peer_config, 
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                logger.info(f"Pair WireGuard créé avec succès pour {user_name}")
                return True
            else:
                logger.error(f"Erreur API OPNsense: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur lors de la création du pair WireGuard: {e}")
            return False
            
    def get_vpn_user(self, vpn_id: int) -> Optional[Dict]:
        """Récupère les informations d'un utilisateur VPN"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM vpn_config WHERE id = ?
            """, (vpn_id,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur VPN: {e}")
            return None
            
    def get_all_vpn_users(self) -> List[Dict]:
        """Récupère tous les utilisateurs VPN"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM vpn_config ORDER BY created_date DESC
            """)
            
            return [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des utilisateurs VPN: {e}")
            return []
            
    def revoke_vpn_user(self, vpn_id: int, reason: str = "") -> bool:
        """Révoque un utilisateur VPN"""
        try:
            # Récupérer les informations de l'utilisateur
            user = self.get_vpn_user(vpn_id)
            if not user:
                raise ValueError(f"Utilisateur VPN {vpn_id} non trouvé")
                
            # Supprimer le pair WireGuard sur OPNsense
            success = self.delete_wireguard_peer(user['user_name'], user['public_key'])
            
            # Mettre à jour la base de données
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE vpn_config 
                SET status = 'revoked', revoked_date = ?, revoked_reason = ?
                WHERE id = ?
            """, (datetime.now(), reason, vpn_id))
            
            self.conn.commit()
            
            logger.info(f"Utilisateur VPN {user['user_name']} révoqué avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la révocation de l'utilisateur VPN: {e}")
            return False
            
    def delete_wireguard_peer(self, user_name: str, public_key: str) -> bool:
        """Supprime un pair WireGuard sur OPNsense"""
        try:
            # Appel API OPNsense pour supprimer le pair
            url = f"{self.base_url}/api/wireguard/service/delpeer"
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Basic {self.api_key}:{self.api_secret}'
            }
            
            data = {
                'pubkey': public_key
            }
            
            response = requests.post(
                url, 
                json=data, 
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                logger.info(f"Pair WireGuard supprimé avec succès pour {user_name}")
                return True
            else:
                logger.error(f"Erreur API OPNsense: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur lors de la suppression du pair WireGuard: {e}")
            return False
            
    def get_active_connections(self) -> List[Dict]:
        """Récupère les connexions VPN actives depuis OPNsense"""
        try:
            # Appel API OPNsense pour obtenir les connexions actives
            url = f"{self.base_url}/api/wireguard/service/status"
            headers = {
                'Authorization': f'Basic {self.api_key}:{self.api_secret}'
            }
            
            response = requests.get(
                url, 
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                connections = []
                
                # Traiter les données de connexion
                for peer in data.get('peers', []):
                    if peer.get('status') == 'connected':
                        connection = {
                            'public_key': peer.get('public_key'),
                            'ip_address': peer.get('endpoint'),
                            'last_handshake': peer.get('last_handshake'),
                            'bytes_received': peer.get('bytes_received', 0),
                            'bytes_sent': peer.get('bytes_sent', 0),
                            'status': 'active'
                        }
                        connections.append(connection)
                        
                return connections
            else:
                logger.error(f"Erreur API OPNsense: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des connexions actives: {e}")
            return []
            
    def update_connection_status(self):
        """Met à jour le statut des connexions dans la base de données"""
        try:
            # Récupérer les connexions actives depuis OPNsense
            active_connections = self.get_active_connections()
            
            # Mettre à jour la base de données
            cursor = self.conn.cursor()
            
            # Marquer tous les utilisateurs comme inactifs
            cursor.execute("UPDATE vpn_config SET status = 'inactive' WHERE status = 'active'")
            
            # Marquer les utilisateurs connectés comme actifs
            for connection in active_connections:
                cursor.execute("""
                    UPDATE vpn_config 
                    SET status = 'active', last_connection = ?, connection_count = connection_count + 1
                    WHERE public_key = ?
                """, (datetime.now(), connection['public_key']))
                
                # Enregistrer la connexion dans la table des connexions
                cursor.execute("""
                    INSERT INTO vpn_connections (
                        vpn_config_id, connection_date, ip_address, 
                        bytes_received, bytes_sent
                    ) SELECT id, ?, ?, ?, ? FROM vpn_config WHERE public_key = ?
                """, (
                    datetime.now(), connection['ip_address'],
                    connection['bytes_received'], connection['bytes_sent'],
                    connection['public_key']
                ))
                
            self.conn.commit()
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du statut des connexions: {e}")
            
    def get_vpn_statistics(self) -> Dict:
        """Retourne les statistiques VPN"""
        try:
            cursor = self.conn.cursor()
            
            # Statistiques générales
            cursor.execute("SELECT COUNT(*) as total FROM vpn_config")
            total_users = cursor.fetchone()['total']
            
            cursor.execute("SELECT COUNT(*) as active FROM vpn_config WHERE status = 'active'")
            active_users = cursor.fetchone()['active']
            
            cursor.execute("SELECT COUNT(*) as revoked FROM vpn_config WHERE status = 'revoked'")
            revoked_users = cursor.fetchone()['revoked']
            
            cursor.execute("SELECT COUNT(*) as expired FROM vpn_config WHERE status = 'expired'")
            expired_users = cursor.fetchone()['expired']
            
            # Statistiques par type d'utilisateur
            cursor.execute("""
                SELECT user_type, COUNT(*) as count 
                FROM vpn_config 
                GROUP BY user_type
            """)
            users_by_type = {row['user_type']: row['count'] for row in cursor.fetchall()}
            
            # Connexions récentes
            cursor.execute("""
                SELECT COUNT(*) as recent_connections 
                FROM vpn_connections 
                WHERE connection_date > datetime('now', '-24 hours')
            """)
            recent_connections = cursor.fetchone()['recent_connections']
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'revoked_users': revoked_users,
                'expired_users': expired_users,
                'users_by_type': users_by_type,
                'recent_connections': recent_connections
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques: {e}")
            return {}
            
    def generate_config_file(self, vpn_id: int) -> Optional[str]:
        """Génère le fichier de configuration WireGuard pour un utilisateur"""
        try:
            user = self.get_vpn_user(vpn_id)
            if not user:
                return None
                
            # Configuration WireGuard
            config = f"""[Interface]
PrivateKey = {user['private_key']}
Address = {user['ip_address']}/32
DNS = {', '.join(WIREGUARD_CONFIG['dns_servers'])}

[Peer]
PublicKey = {self.get_server_public_key()}
AllowedIPs = {WIREGUARD_CONFIG['allowed_ips']}
Endpoint = {self.base_url.replace('https://', '')}:{WIREGUARD_CONFIG['port']}
PersistentKeepalive = {WIREGUARD_CONFIG['persistent_keepalive']}
"""
            return config
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du fichier de configuration: {e}")
            return None
            
    def get_server_public_key(self) -> str:
        """Récupère la clé publique du serveur WireGuard"""
        try:
            # Appel API OPNsense pour obtenir la clé publique du serveur
            url = f"{self.base_url}/api/wireguard/service/status"
            headers = {
                'Authorization': f'Basic {self.api_key}:{self.api_secret}'
            }
            
            response = requests.get(
                url, 
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('server', {}).get('public_key', '')
            else:
                logger.error(f"Erreur API OPNsense: {response.status_code}")
                return ''
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la clé publique du serveur: {e}")
            return ''
            
    def check_expired_users(self):
        """Vérifie et marque les utilisateurs expirés"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE vpn_config 
                SET status = 'expired' 
                WHERE expiration_date < datetime('now') AND status = 'active'
            """)
            
            expired_count = cursor.rowcount
            if expired_count > 0:
                self.conn.commit()
                logger.info(f"{expired_count} utilisateurs VPN marqués comme expirés")
                
        except Exception as e:
            logger.error(f"Erreur lors de la vérification des utilisateurs expirés: {e}")
            
    def __del__(self):
        """Fermeture de la connexion à la base de données"""
        if hasattr(self, 'conn'):
            self.conn.close() 