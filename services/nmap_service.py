"""
Service de scans réseau avec Nmap et détection de vulnérabilités
"""
import nmap
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import pandas as pd
import os
from monitoring.config.nmap_config import NMAP_CONFIG, SCAN_TYPES, VULNERABILITY_SCRIPTS

logger = logging.getLogger(__name__)

class NmapService:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            self.simulation = False
        except Exception:
            self.simulation = True
        self.scan_results = []
        self.scan_history = []
        self.results_file = 'monitoring/data/nmap_results.json'
        
        # Charger les résultats existants
        self.load_results()
        
    def load_results(self):
        """Charge les résultats de scan depuis le fichier"""
        try:
            if os.path.exists(self.results_file):
                with open(self.results_file, 'r') as f:
                    data = json.load(f)
                    self.scan_results = data.get('scan_results', [])
                    self.scan_history = data.get('scan_history', [])
                logger.info("Résultats Nmap chargés depuis le fichier")
        except Exception as e:
            logger.error(f"Erreur lors du chargement des résultats: {e}")
            
    def save_results(self):
        """Sauvegarde les résultats de scan dans le fichier"""
        try:
            os.makedirs(os.path.dirname(self.results_file), exist_ok=True)
            data = {
                'scan_results': self.scan_results,
                'scan_history': self.scan_history
            }
            with open(self.results_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("Résultats Nmap sauvegardés")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des résultats: {e}")
            
    def test_connection(self) -> bool:
        """Teste la disponibilité de Nmap"""
        try:
            # Test simple avec localhost
            result = self.nm.scan('127.0.0.1', arguments='-sn')
            return '127.0.0.1' in result['scan']
        except Exception as e:
            logger.error(f"Erreur lors du test Nmap: {e}")
            return False
            
    def scan_network(self, target: str, scan_type: str = 'basic', ports: str = None) -> Dict:
        """Effectue un scan réseau"""
        if self.simulation:
            return {
                'scan_id': 'simu',
                'status': 'completed',
                'hosts_found': 1,
                'duration': 1.0,
                'results': [{
                    'scan_id': 'simu',
                    'scan_type': scan_type,
                    'target': target,
                    'host': '192.168.1.100',
                    'hostname': 'simu-host',
                    'os': 'Linux',
                    'timestamp': '2024-01-01T12:00:00',
                    'ports': [
                        {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH', 'product': 'OpenSSH', 'vulnerabilities': []}
                    ],
                    'vulnerabilities': []
                }]
            }
        try:
            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            scan_start = datetime.now()
            
            # Configuration du scan selon le type
            if scan_type == 'basic':
                arguments = '-sS -sV -O --version-intensity 5'
            elif scan_type == 'vulnerability':
                arguments = '-sS -sV -O --script=vuln --version-intensity 5'
            elif scan_type == 'comprehensive':
                arguments = '-sS -sV -sC -O -A --script=vuln,auth,default --version-intensity 9'
            else:
                arguments = '-sS -sV -O --version-intensity 5'
                
            # Ajouter les ports spécifiques si fournis
            if ports:
                arguments += f' -p {ports}'
            else:
                arguments += ' --top-ports 1000'
                
            logger.info(f"Début du scan {scan_id} sur {target} avec arguments: {arguments}")
            
            # Exécution du scan
            result = self.nm.scan(target, arguments=arguments)
            
            scan_end = datetime.now()
            scan_duration = (scan_end - scan_start).total_seconds()
            
            # Traitement des résultats
            processed_results = self._process_scan_results(result, scan_id, scan_type, target)
            
            # Sauvegarder les résultats
            self.scan_results.extend(processed_results)
            self.scan_history.append({
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'start_time': scan_start.isoformat(),
                'end_time': scan_end.isoformat(),
                'duration': scan_duration,
                'hosts_found': len(processed_results),
                'status': 'completed'
            })
            
            self.save_results()
            
            logger.info(f"Scan {scan_id} terminé en {scan_duration:.2f}s - {len(processed_results)} hôtes trouvés")
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'hosts_found': len(processed_results),
                'duration': scan_duration,
                'results': processed_results
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du scan réseau: {e}")
            return {
                'scan_id': scan_id if 'scan_id' in locals() else 'unknown',
                'status': 'failed',
                'error': str(e),
                'results': []
            }
            
    def _process_scan_results(self, nmap_result: Dict, scan_id: str, scan_type: str, target: str) -> List[Dict]:
        """Traite les résultats bruts de Nmap"""
        processed_results = []
        
        try:
            for host in nmap_result['scan']:
                host_data = nmap_result['scan'][host]
                
                if host_data['status']['state'] == 'up':
                    # Informations de base de l'hôte
                    host_info = {
                        'scan_id': scan_id,
                        'scan_type': scan_type,
                        'target': target,
                        'host': host,
                        'hostname': host_data.get('hostnames', [{}])[0].get('name', ''),
                        'os': self._extract_os_info(host_data),
                        'timestamp': datetime.now().isoformat(),
                        'ports': [],
                        'vulnerabilities': []
                    }
                    
                    # Traitement des ports et services
                    if 'tcp' in host_data:
                        for port, port_data in host_data['tcp'].items():
                            port_info = {
                                'port': port,
                                'protocol': 'tcp',
                                'state': port_data.get('state', ''),
                                'service': port_data.get('name', ''),
                                'version': port_data.get('version', ''),
                                'product': port_data.get('product', ''),
                                'vulnerabilities': []
                            }
                            
                            # Extraction des vulnérabilités si disponibles
                            if 'script' in port_data:
                                port_info['vulnerabilities'] = self._extract_vulnerabilities(port_data['script'])
                                
                            host_info['ports'].append(port_info)
                            
                    # Traitement des vulnérabilités au niveau hôte
                    if 'hostscript' in host_data:
                        host_info['vulnerabilities'] = self._extract_host_vulnerabilities(host_data['hostscript'])
                        
                    processed_results.append(host_info)
                    
        except Exception as e:
            logger.error(f"Erreur lors du traitement des résultats: {e}")
            
        return processed_results
        
    def _extract_os_info(self, host_data: Dict) -> str:
        """Extrait les informations du système d'exploitation"""
        try:
            if 'osmatch' in host_data and host_data['osmatch']:
                return host_data['osmatch'][0].get('name', 'Unknown')
            elif 'os' in host_data and 'cpe' in host_data['os']:
                return host_data['os']['cpe'][0] if host_data['os']['cpe'] else 'Unknown'
            else:
                return 'Unknown'
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des infos OS: {e}")
            return 'Unknown'
            
    def _extract_vulnerabilities(self, scripts: Dict) -> List[Dict]:
        """Extrait les vulnérabilités des scripts NSE"""
        vulnerabilities = []
        
        try:
            for script_name, script_output in scripts.items():
                if 'vuln' in script_name.lower() or 'cve' in script_name.lower():
                    vuln_info = {
                        'script': script_name,
                        'output': script_output,
                        'severity': self._determine_severity(script_name, script_output),
                        'cve': self._extract_cve(script_output)
                    }
                    vulnerabilities.append(vuln_info)
                    
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des vulnérabilités: {e}")
            
        return vulnerabilities
        
    def _extract_host_vulnerabilities(self, hostscripts: List) -> List[Dict]:
        """Extrait les vulnérabilités au niveau hôte"""
        vulnerabilities = []
        
        try:
            for script in hostscripts:
                if 'vuln' in script.get('id', '').lower() or 'cve' in script.get('id', '').lower():
                    vuln_info = {
                        'script': script.get('id', ''),
                        'output': script.get('output', ''),
                        'severity': self._determine_severity(script.get('id', ''), script.get('output', '')),
                        'cve': self._extract_cve(script.get('output', ''))
                    }
                    vulnerabilities.append(vuln_info)
                    
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des vulnérabilités hôte: {e}")
            
        return vulnerabilities
        
    def _determine_severity(self, script_name: str, output: str) -> str:
        """Détermine la sévérité d'une vulnérabilité"""
        output_lower = output.lower()
        
        if any(keyword in output_lower for keyword in ['critical', 'high', 'severe']):
            return 'critical'
        elif any(keyword in output_lower for keyword in ['medium', 'moderate']):
            return 'medium'
        elif any(keyword in output_lower for keyword in ['low', 'info']):
            return 'low'
        else:
            return 'unknown'
            
    def _extract_cve(self, output: str) -> List[str]:
        """Extrait les références CVE du texte"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(cve_pattern, output, re.IGNORECASE)
        
    def get_all_results(self) -> List[Dict]:
        """Retourne tous les résultats de scan"""
        return self.scan_results
        
    def get_results_by_host(self, host: str) -> List[Dict]:
        """Retourne les résultats pour un hôte spécifique"""
        return [result for result in self.scan_results if result['host'] == host]
        
    def get_results_by_scan_id(self, scan_id: str) -> List[Dict]:
        """Retourne les résultats pour un scan spécifique"""
        return [result for result in self.scan_results if result['scan_id'] == scan_id]
        
    def get_scan_history(self) -> List[Dict]:
        """Retourne l'historique des scans"""
        return self.scan_history
        
    def export_to_csv(self, filename: str = None) -> str:
        """Exporte les résultats en CSV"""
        try:
            if not filename:
                filename = f"nmap_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                
            # Préparer les données pour l'export
            export_data = []
            
            for result in self.scan_results:
                host = result['host']
                hostname = result['hostname']
                os_info = result['os']
                scan_type = result['scan_type']
                timestamp = result['timestamp']
                
                for port_info in result['ports']:
                    port = port_info['port']
                    service = port_info['service']
                    version = port_info['version']
                    product = port_info['product']
                    
                    # Vulnérabilités du port
                    port_vulns = []
                    for vuln in port_info['vulnerabilities']:
                        port_vulns.append(f"{vuln['script']}: {vuln['severity']}")
                    
                    # Vulnérabilités de l'hôte
                    host_vulns = []
                    for vuln in result['vulnerabilities']:
                        host_vulns.append(f"{vuln['script']}: {vuln['severity']}")
                    
                    export_data.append({
                        'Hôte': host,
                        'Nom d\'hôte': hostname,
                        'Système d\'exploitation': os_info,
                        'Type de scan': scan_type,
                        'Port': port,
                        'Service': service,
                        'Version': version,
                        'Produit': product,
                        'Vulnérabilités port': '; '.join(port_vulns),
                        'Vulnérabilités hôte': '; '.join(host_vulns),
                        'Horodatage': timestamp
                    })
                    
            # Créer le DataFrame et exporter
            df = pd.DataFrame(export_data)
            df.to_csv(filename, index=False, encoding='utf-8')
            
            logger.info(f"Résultats exportés vers {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Erreur lors de l'export CSV: {e}")
            return ""
            
    def get_statistics(self) -> Dict:
        """Retourne les statistiques des scans"""
        try:
            total_scans = len(self.scan_history)
            total_hosts = len(set(result['host'] for result in self.scan_results))
            total_ports = sum(len(result['ports']) for result in self.scan_results)
            
            # Compter les vulnérabilités par sévérité
            vuln_counts = {'critical': 0, 'medium': 0, 'low': 0, 'unknown': 0}
            
            for result in self.scan_results:
                for port_info in result['ports']:
                    for vuln in port_info['vulnerabilities']:
                        severity = vuln['severity']
                        if severity in vuln_counts:
                            vuln_counts[severity] += 1
                            
                for vuln in result['vulnerabilities']:
                    severity = vuln['severity']
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1
                        
            return {
                'total_scans': total_scans,
                'total_hosts': total_hosts,
                'total_ports': total_ports,
                'vulnerabilities': vuln_counts,
                'last_scan': self.scan_history[-1]['start_time'] if self.scan_history else None
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des statistiques: {e}")
            return {
                'total_scans': 0,
                'total_hosts': 0,
                'total_ports': 0,
                'vulnerabilities': {'critical': 0, 'medium': 0, 'low': 0, 'unknown': 0},
                'last_scan': None
            }
            
    def schedule_periodic_scan(self, target: str, interval_hours: int = 24) -> bool:
        """Planifie un scan périodique (simulation)"""
        try:
            # En mode simulation, on simule juste la planification
            logger.info(f"Scan périodique planifié pour {target} toutes les {interval_hours}h")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la planification du scan: {e}")
            return False
            
    def delete_scan_results(self, scan_id: str = None) -> bool:
        """Supprime les résultats de scan"""
        try:
            if scan_id:
                # Supprimer un scan spécifique
                self.scan_results = [r for r in self.scan_results if r['scan_id'] != scan_id]
                self.scan_history = [h for h in self.scan_history if h['scan_id'] != scan_id]
            else:
                # Supprimer tous les résultats
                self.scan_results = []
                self.scan_history = []
                
            self.save_results()
            logger.info(f"Résultats supprimés pour le scan {scan_id if scan_id else 'tous'}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la suppression des résultats: {e}")
            return False 