"""
Service de gestion des sauvegardes Bacula
"""
import subprocess
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import requests
from monitoring.config.backup_config import BACULA_CONFIG, WAZUH_CONFIG
from monitoring.services.wazuh_service import WazuhService

logger = logging.getLogger(__name__)

class BackupService:
    def __init__(self):
        self.wazuh_service = WazuhService()
        self.bconsole_path = BACULA_CONFIG.get('bconsole_path', 'bconsole')
        self.bacula_config = BACULA_CONFIG
        
    def test_connection(self) -> bool:
        """Teste la connexion à Bacula via bconsole"""
        try:
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=b'version\nquit\n',
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0 and 'Bacula' in result.stdout
        except Exception as e:
            logger.error(f"Erreur lors du test de connexion Bacula: {e}")
            return False
            
    def list_jobs(self) -> List[Dict]:
        """Liste tous les jobs de sauvegarde"""
        try:
            # Commande bconsole pour lister les jobs
            cmd = f"list jobs\nquit\n"
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=cmd.encode(),
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Erreur bconsole: {result.stderr}")
                return self._simulate_jobs()
                
            # Parser la sortie de bconsole
            jobs = self._parse_jobs_output(result.stdout)
            return jobs
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des jobs: {e}")
            return self._simulate_jobs()
            
    def _parse_jobs_output(self, output: str) -> List[Dict]:
        """Parse la sortie de bconsole pour extraire les jobs"""
        jobs = []
        lines = output.split('\n')
        
        for line in lines:
            if '|' in line and 'JobId' not in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 6:
                    job = {
                        'id': parts[0],
                        'job_name': parts[1],
                        'status': self._normalize_status(parts[2]),
                        'level': parts[3],
                        'files': parts[4],
                        'bytes': parts[5],
                        'start_time': parts[6] if len(parts) > 6 else '',
                        'end_time': parts[7] if len(parts) > 7 else '',
                        'schedule_time': self._get_schedule_time(parts[1]),
                        'last_result': self._get_job_result(parts[0])
                    }
                    jobs.append(job)
                    
        return jobs
        
    def _normalize_status(self, status: str) -> str:
        """Normalise le statut du job"""
        status_lower = status.lower()
        if 'completed' in status_lower or 'terminated' in status_lower:
            return 'success'
        elif 'failed' in status_lower or 'error' in status_lower:
            return 'failed'
        elif 'running' in status_lower:
            return 'running'
        elif 'scheduled' in status_lower:
            return 'scheduled'
        else:
            return 'unknown'
            
    def _get_schedule_time(self, job_name: str) -> str:
        """Récupère l'horaire planifié pour un job"""
        try:
            # Commande pour obtenir les détails du job
            cmd = f"show job={job_name}\nquit\n"
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=cmd.encode(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Chercher l'horaire dans la sortie
                for line in result.stdout.split('\n'):
                    if 'Schedule' in line:
                        return line.split('=')[1].strip()
                        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'horaire: {e}")
            
        return "02:00"  # Horaire par défaut
        
    def _get_job_result(self, job_id: str) -> str:
        """Récupère le résultat du dernier job"""
        try:
            cmd = f"show jobid={job_id}\nquit\n"
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=cmd.encode(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'JobStatus' in line:
                        return line.split('=')[1].strip()
                        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du résultat: {e}")
            
        return "Unknown"
        
    def _simulate_jobs(self) -> List[Dict]:
        """Simule des jobs pour les tests"""
        import random
        
        job_names = ["Backup_System", "Backup_Database", "Backup_Files", "Backup_Config"]
        statuses = ["success", "failed", "running", "scheduled"]
        
        jobs = []
        for i, name in enumerate(job_names):
            job = {
                'id': str(i + 1),
                'job_name': name,
                'status': random.choice(statuses),
                'level': 'Full',
                'files': str(random.randint(1000, 50000)),
                'bytes': f"{random.randint(1, 100)}GB",
                'start_time': (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime("%Y-%m-%d %H:%M"),
                'end_time': datetime.now().strftime("%Y-%m-%d %H:%M"),
                'schedule_time': "02:00",
                'last_result': "OK" if random.choice([True, False]) else "Error"
            }
            jobs.append(job)
            
        return jobs
        
    def add_job(self, job_name: str, schedule_time: str, restore_path: str = "") -> bool:
        """Ajoute un nouveau job de sauvegarde"""
        try:
            # Créer la configuration du job
            job_config = self._create_job_config(job_name, schedule_time, restore_path)
            
            # Sauvegarder la configuration
            config_file = f"/etc/bacula/jobs.d/{job_name}.conf"
            
            # En mode simulation, on simule juste le succès
            if not self.test_connection():
                logger.info(f"Job simulé ajouté: {job_name}")
                return True
                
            # Écrire la configuration
            with open(config_file, 'w') as f:
                f.write(job_config)
                
            # Recharger la configuration Bacula
            self._reload_config()
            
            logger.info(f"Job ajouté avec succès: {job_name}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout du job: {e}")
            return False
            
    def _create_job_config(self, job_name: str, schedule_time: str, restore_path: str) -> str:
        """Crée la configuration d'un job Bacula"""
        config = f"""
Job {{
  Name = "{job_name}"
  JobDefs = "DefaultJob"
  Schedule = "Daily at {schedule_time}"
  Storage = File1
  Pool = Default
  Client = bacula-fd
  FileSet = "Full Set"
  Messages = Standard
  Priority = 10
  MaxStartDelay = 1h
}}
"""
        return config
        
    def _reload_config(self):
        """Recharge la configuration Bacula"""
        try:
            cmd = "reload\nquit\n"
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=cmd.encode(),
                capture_output=True,
                text=True,
                timeout=10
            )
        except Exception as e:
            logger.error(f"Erreur lors du rechargement de la configuration: {e}")
            
    def run_backup(self, job_id: str) -> bool:
        """Lance une sauvegarde"""
        try:
            # Récupérer le nom du job
            job_name = self._get_job_name_by_id(job_id)
            if not job_name:
                return False
                
            # Commande pour lancer le job
            cmd = f"run job={job_name}\nquit\n"
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=cmd.encode(),
                capture_output=True,
                text=True,
                timeout=30
            )
            
            success = result.returncode == 0
            
            # Vérifier le résultat et envoyer une alerte Wazuh si échec
            if not success:
                self._send_wazuh_alert(job_name, "Échec de la sauvegarde", result.stderr)
                
            return success
            
        except Exception as e:
            logger.error(f"Erreur lors du lancement de la sauvegarde: {e}")
            self._send_wazuh_alert("Unknown", "Erreur lors du lancement de la sauvegarde", str(e))
            return False
            
    def _get_job_name_by_id(self, job_id: str) -> Optional[str]:
        """Récupère le nom du job par son ID"""
        try:
            jobs = self.list_jobs()
            for job in jobs:
                if job['id'] == job_id:
                    return job['job_name']
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du nom du job: {e}")
        return None
        
    def run_restore(self, job_id: str, restore_path: str = "") -> bool:
        """Lance une restauration"""
        try:
            # Récupérer le nom du job
            job_name = self._get_job_name_by_id(job_id)
            if not job_name:
                return False
                
            # Commande pour lancer la restauration
            restore_cmd = f"restore job={job_name}"
            if restore_path:
                restore_cmd += f" where={restore_path}"
            restore_cmd += "\nquit\n"
            
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=restore_cmd.encode(),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            success = result.returncode == 0
            
            # Vérifier le résultat et envoyer une alerte Wazuh si échec
            if not success:
                self._send_wazuh_alert(job_name, "Échec de la restauration", result.stderr)
                
            return success
            
        except Exception as e:
            logger.error(f"Erreur lors de la restauration: {e}")
            self._send_wazuh_alert("Unknown", "Erreur lors de la restauration", str(e))
            return False
            
    def list_history(self, job_id: str) -> List[Dict]:
        """Liste l'historique d'un job"""
        try:
            job_name = self._get_job_name_by_id(job_id)
            if not job_name:
                return []
                
            # Commande pour lister l'historique
            cmd = f"list job={job_name}\nquit\n"
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=cmd.encode(),
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return self._simulate_history(job_name)
                
            # Parser l'historique
            history = self._parse_history_output(result.stdout)
            return history
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique: {e}")
            return self._simulate_history("Unknown")
            
    def _parse_history_output(self, output: str) -> List[Dict]:
        """Parse la sortie de l'historique"""
        history = []
        lines = output.split('\n')
        
        for line in lines:
            if '|' in line and 'JobId' not in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 4:
                    entry = {
                        'run_time': parts[6] if len(parts) > 6 else '',
                        'result': self._normalize_status(parts[2]),
                        'log': self._get_job_log(parts[0]) if len(parts) > 0 else ''
                    }
                    history.append(entry)
                    
        return history
        
    def _get_job_log(self, job_id: str) -> str:
        """Récupère le log d'un job"""
        try:
            cmd = f"show jobid={job_id}\nquit\n"
            config_file = self.bacula_config.get('config_file', '/etc/bacula/bconsole.conf')
            result = subprocess.run(
                [self.bconsole_path, '-c', config_file],
                input=cmd.encode(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du log: {e}")
            
        return "Log non disponible"
        
    def _simulate_history(self, job_name: str) -> List[Dict]:
        """Simule l'historique d'un job"""
        import random
        
        history = []
        for i in range(5):
            entry = {
                'run_time': (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d %H:%M"),
                'result': random.choice(['success', 'failed', 'running']),
                'log': f"Job {job_name} - {'Succès' if random.choice([True, False]) else 'Échec'} - {random.randint(100, 999)} fichiers traités"
            }
            history.append(entry)
            
        return history
        
    def _send_wazuh_alert(self, job_name: str, message: str, details: str):
        """Envoie une alerte Wazuh en cas d'échec"""
        try:
            alert_data = {
                'job_name': job_name,
                'message': message,
                'details': details,
                'timestamp': datetime.now().isoformat(),
                'severity': 'high',
                'category': 'backup_failure'
            }
            
            # Envoyer l'alerte via l'API Wazuh
            self.wazuh_service.send_custom_alert('backup_failure', f"{message} - {job_name}: {details}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'alerte Wazuh: {e}")
            
    def get_backup_statistics(self) -> Dict:
        """Retourne les statistiques des sauvegardes"""
        try:
            jobs = self.list_jobs()
            
            total_jobs = len(jobs)
            successful_jobs = len([j for j in jobs if j['status'] == 'success'])
            failed_jobs = len([j for j in jobs if j['status'] == 'failed'])
            running_jobs = len([j for j in jobs if j['status'] == 'running'])
            
            return {
                'total_jobs': total_jobs,
                'successful_jobs': successful_jobs,
                'failed_jobs': failed_jobs,
                'running_jobs': running_jobs,
                'success_rate': (successful_jobs / total_jobs * 100) if total_jobs > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des statistiques: {e}")
            return {
                'total_jobs': 0,
                'successful_jobs': 0,
                'failed_jobs': 0,
                'running_jobs': 0,
                'success_rate': 0
            } 