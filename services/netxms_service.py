"""
Service pour l'API NetXMS
"""
import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
from monitoring.config.netxms_config import NETXMS_CONFIG, METRICS_CONFIG

logger = logging.getLogger(__name__)

class NetXMSService:
    def __init__(self):
        self.api_url = NETXMS_CONFIG['api_url']
        self.username = NETXMS_CONFIG['username']
        self.password = NETXMS_CONFIG['password']
        self.timeout = NETXMS_CONFIG['timeout']
        self.verify_ssl = NETXMS_CONFIG['verify_ssl']
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = self.verify_ssl
        try:
            self.simulation = not self.test_connection()
        except Exception:
            self.simulation = True

    def get_nodes(self) -> List[Dict]:
        if self.simulation:
            return self.simulate_nodes()
        try:
            response = self.session.get(
                f"{self.api_url}/nodes",
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur lors de la récupération des nœuds: {e}")
            return []

    def simulate_nodes(self):
        return [
            {'id': 1, 'name': 'Serveur-SIMU'},
            {'id': 2, 'name': 'PC-SIMU'},
            {'id': 3, 'name': 'Routeur-SIMU'}
        ]

    def get_node_details(self, node_id: int) -> Optional[Dict]:
        if self.simulation:
            return {'id': node_id, 'name': f'Equipement-SIMU-{node_id}', 'status': 'NORMAL'}
        try:
            response = self.session.get(
                f"{self.api_url}/nodes/{node_id}",
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur lors de la récupération du nœud {node_id}: {e}")
            return None

    def get_node_metrics(self, node_id: int, dci_name: str, hours: int = 1) -> List[Dict]:
        if self.simulation:
            return [{'timestamp': '2024-01-01T12:00:00', 'value': 42.0}]
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)

            params = {
                'from': int(start_time.timestamp() * 1000),
                'to': int(end_time.timestamp() * 1000)
            }

            response = self.session.get(
                f"{self.api_url}/nodes/{node_id}/dci/{dci_name}/values",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur lors de la récupération des métriques {dci_name} pour le nœud {node_id}: {e}")
            return []

    def get_current_metrics(self, node_id: int) -> Dict:
        if self.simulation:
            return {
                'cpu_utilization': {'value': 30, 'timestamp': '2024-01-01T12:00:00', 'threshold_warning': 70, 'threshold_critical': 85},
                'memory_utilization': {'value': 40, 'timestamp': '2024-01-01T12:00:00', 'threshold_warning': 75, 'threshold_critical': 90},
                'disk_utilization': {'value': 50, 'timestamp': '2024-01-01T12:00:00', 'threshold_warning': 80, 'threshold_critical': 95},
                'network_traffic': {'value': 10, 'timestamp': '2024-01-01T12:00:00', 'threshold_warning': 150, 'threshold_critical': 200}
            }
        metrics = {}

        for metric_name, metric_config in METRICS_CONFIG.items():
            try:
                response = self.session.get(
                    f"{self.api_url}/nodes/{node_id}/dci/{metric_config['dci_name']}/last_value",
                    timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()

                if data and 'value' in data:
                    metrics[metric_name] = {
                        'value': float(data['value']),
                        'timestamp': data.get('timestamp', datetime.now().isoformat()),
                        'threshold_warning': metric_config['threshold_warning'],
                        'threshold_critical': metric_config['threshold_critical']
                    }
            except (requests.exceptions.RequestException, ValueError, KeyError) as e:
                logger.warning(f"Impossible de récupérer la métrique {metric_name} pour le nœud {node_id}: {e}")
                continue

        return metrics

    def get_node_status(self, node_id: int) -> str:
        if self.simulation:
            return "NORMAL"
        metrics = self.get_current_metrics(node_id)

        if not metrics:
            return "INCONNU"

        # Vérification des seuils critiques
        for metric_name, metric_data in metrics.items():
            if metric_data['value'] >= metric_data['threshold_critical']:
                return "CRITIQUE"

        # Vérification des seuils d'avertissement
        for metric_name, metric_data in metrics.items():
            if metric_data['value'] >= metric_data['threshold_warning']:
                return "ATTENTION"

        return "NORMAL"

    def get_all_equipment_data(self) -> List[Dict]:
        if self.simulation:
            return [
                {'id': 1, 'name': 'Serveur-SIMU', 'status': 'NORMAL', 'uptime_hours': 123, 'timestamp': '2024-01-01T12:00:00', 'metrics': self.get_current_metrics(1)},
                {'id': 2, 'name': 'PC-SIMU', 'status': 'ATTENTION', 'uptime_hours': 45, 'timestamp': '2024-01-01T12:00:00', 'metrics': self.get_current_metrics(2)}
            ]
        nodes = self.get_nodes()
        equipment_data = []

        for node in nodes:
            node_id = node['id']
            node_name = node.get('name', f"Nœud {node_id}")

            # Récupération des métriques actuelles
            metrics = self.get_current_metrics(node_id)

            # Détermination du statut
            status = self.get_node_status(node_id)

            # Récupération de l'uptime
            uptime_hours = self.get_node_uptime(node_id)

            equipment_info = {
                'id': node_id,
                'name': node_name,
                'status': status,
                'uptime_hours': uptime_hours,
                'timestamp': datetime.now().isoformat(),
                'metrics': metrics
            }

            equipment_data.append(equipment_info)

        return equipment_data

    def get_node_uptime(self, node_id: int) -> float:
        if self.simulation:
            return 123.0
        try:
            response = self.session.get(
                f"{self.api_url}/nodes/{node_id}/dci/UPTIME/last_value",
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data and 'value' in data:
                return float(data['value']) / 3600  # Conversion en heures
        except (requests.exceptions.RequestException, ValueError, KeyError) as e:
            logger.warning(f"Impossible de récupérer l'uptime pour le nœud {node_id}: {e}")

        return 0.0

    def test_connection(self) -> bool:
        """
        Teste la connexion à l'API NetXMS
        """
        try:
            response = self.session.get(
                f"{self.api_url}/version",
                timeout=self.timeout
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur de connexion à l'API NetXMS: {e}")
            return False 