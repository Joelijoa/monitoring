"""
Service d'analyse prédictive avec détection d'anomalies
"""
import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import pickle
import os
import random
from monitoring.config.predictive_config import (
    PREDICTIVE_CONFIG, ANOMALY_TYPES, NORMAL_HOURS, 
    LOAD_THRESHOLDS, GEO_CONFIG, ML_MODELS_CONFIG, REFRESH_INTERVALS
)
from monitoring.services.netxms_service import NetXMSService
from monitoring.services.wazuh_service import WazuhService

logger = logging.getLogger(__name__)

class PredictiveService:
    def __init__(self):
        self.netxms_service = NetXMSService()
        self.wazuh_service = WazuhService()
        
        # Modèles ML
        self.isolation_forest = None
        self.one_class_svm = None
        self.local_outlier_factor = None
        self.scaler = StandardScaler()
        
        # Chemins des modèles
        self.models_path = 'monitoring/models/predictive_models.pkl'
        
        # Données historiques
        self.historical_data = []
        self.anomaly_history = []
        
        # Initialisation des modèles
        self.initialize_models()
        
    def initialize_models(self):
        """Initialise ou charge les modèles ML"""
        try:
            if os.path.exists(self.models_path):
                with open(self.models_path, 'rb') as f:
                    models = pickle.load(f)
                    self.isolation_forest = models['isolation_forest']
                    self.one_class_svm = models['one_class_svm']
                    self.local_outlier_factor = models['local_outlier_factor']
                    self.scaler = models['scaler']
                logger.info("Modèles prédictifs chargés depuis le fichier")
            else:
                self.create_new_models()
                logger.info("Nouveaux modèles prédictifs initialisés")
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des modèles: {e}")
            self.create_new_models()
            
    def create_new_models(self):
        """Crée de nouveaux modèles ML"""
        config = ML_MODELS_CONFIG['isolation_forest']
        self.isolation_forest = IsolationForest(
            contamination=config['contamination'],
            random_state=config['random_state'],
            n_estimators=config['n_estimators']
        )
        
        config = ML_MODELS_CONFIG['one_class_svm']
        self.one_class_svm = OneClassSVM(
            kernel=config['kernel'],
            nu=config['nu'],
            gamma=config['gamma']
        )
        
        config = ML_MODELS_CONFIG['local_outlier_factor']
        self.local_outlier_factor = LocalOutlierFactor(
            n_neighbors=config['n_neighbors'],
            contamination=config['contamination']
        )
        
    def save_models(self):
        """Sauvegarde les modèles ML"""
        try:
            os.makedirs(os.path.dirname(self.models_path), exist_ok=True)
            models = {
                'isolation_forest': self.isolation_forest,
                'one_class_svm': self.one_class_svm,
                'local_outlier_factor': self.local_outlier_factor,
                'scaler': self.scaler
            }
            with open(self.models_path, 'wb') as f:
                pickle.dump(models, f)
            logger.info("Modèles prédictifs sauvegardés")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des modèles: {e}")
            
    def collect_data_for_analysis(self) -> List[Dict]:
        """Collecte les données pour l'analyse prédictive"""
        data = []
        
        try:
            # Données NetXMS (équipements)
            equipment_data = self.netxms_service.get_all_equipment_data()
            for equipment in equipment_data:
                metrics = equipment.get('metrics', {})
                
                # Caractéristiques temporelles
                timestamp = datetime.now()
                hour = timestamp.hour
                weekday = timestamp.weekday()
                
                # Caractéristiques de charge
                cpu = metrics.get('cpu_utilization', {}).get('value', 0)
                ram = metrics.get('memory_utilization', {}).get('value', 0)
                disk = metrics.get('disk_utilization', {}).get('value', 0)
                network = metrics.get('network_traffic', {}).get('value', 0)
                
                # Vérification des pics de charge
                load_spike_score = self.detect_load_spike(cpu, ram, disk, network)
                
                # Vérification activité hors horaires
                off_hours_score = self.detect_off_hours_activity(hour, weekday)
                
                data_point = {
                    'equipment_id': equipment['id'],
                    'equipment_name': equipment['name'],
                    'timestamp': timestamp.timestamp(),
                    'hour': hour,
                    'weekday': weekday,
                    'cpu': cpu,
                    'ram': ram,
                    'disk': disk,
                    'network': network,
                    'load_spike_score': load_spike_score,
                    'off_hours_score': off_hours_score,
                    'data_type': 'equipment'
                }
                data.append(data_point)
            
            # Données Wazuh (activité utilisateur)
            user_activity = self.wazuh_service.get_user_activity(hours=24)
            for event in user_activity:
                timestamp = event.get('timestamp', 0)
                event_datetime = datetime.fromtimestamp(timestamp)
                hour = event_datetime.hour
                weekday = event_datetime.weekday()
                
                # Vérification activité hors horaires
                off_hours_score = self.detect_off_hours_activity(hour, weekday)
                
                # Vérification géolocalisation (simulée)
                geo_anomaly_score = self.detect_geolocation_anomaly(event)
                
                data_point = {
                    'event_id': event.get('id', ''),
                    'user': event.get('user', ''),
                    'event_type': event.get('event_type', ''),
                    'timestamp': timestamp,
                    'hour': hour,
                    'weekday': weekday,
                    'off_hours_score': off_hours_score,
                    'geo_anomaly_score': geo_anomaly_score,
                    'data_type': 'user_activity'
                }
                data.append(data_point)
                
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des données: {e}")
            
        return data
        
    def detect_load_spike(self, cpu: float, ram: float, disk: float, network: float) -> float:
        """Détecte les pics de charge soudains"""
        score = 0.0
        
        # Vérification CPU
        if cpu > LOAD_THRESHOLDS['cpu_spike'] * 100:
            score += 0.4
            
        # Vérification RAM
        if ram > LOAD_THRESHOLDS['memory_spike'] * 100:
            score += 0.3
            
        # Vérification Disque
        if disk > LOAD_THRESHOLDS['disk_spike'] * 100:
            score += 0.2
            
        # Vérification Réseau
        if network > LOAD_THRESHOLDS['network_spike'] * 100:
            score += 0.1
            
        return min(score, 1.0)
        
    def detect_off_hours_activity(self, hour: int, weekday: int) -> float:
        """Détecte l'activité hors horaires"""
        # Déterminer si c'est un jour de semaine ou weekend
        if weekday < 5:  # Lundi à Vendredi
            normal_hours = NORMAL_HOURS['weekdays']
        else:  # Samedi et Dimanche
            normal_hours = NORMAL_HOURS['weekends']
            
        # Vérifier si l'heure est dans les heures normales
        if normal_hours['start'] <= hour <= normal_hours['end']:
            return 0.0
        else:
            # Calculer un score basé sur l'éloignement des heures normales
            if hour < normal_hours['start']:
                distance = normal_hours['start'] - hour
            else:
                distance = hour - normal_hours['end']
                
            # Score maximum pour les heures très éloignées (ex: 3h du matin)
            return min(distance / 6.0, 1.0)
            
    def detect_geolocation_anomaly(self, event: Dict) -> float:
        """Détecte les anomalies de géolocalisation (simulée)"""
        # Simulation de géolocalisation
        user = event.get('user', '')
        
        # Simuler des connexions depuis différents pays
        countries = ['FR', 'BE', 'CH', 'LU', 'DE', 'IT', 'ES', 'RU', 'CN', 'US']
        weights = [0.6, 0.1, 0.1, 0.05, 0.05, 0.03, 0.02, 0.01, 0.01, 0.01]
        
        # Simuler un pays pour cet utilisateur
        country = random.choices(countries, weights=weights)[0]
        
        # Calculer le score d'anomalie
        if country in GEO_CONFIG['allowed_countries']:
            return 0.0
        elif country in GEO_CONFIG['suspicious_countries']:
            return 0.9
        else:
            return 0.5
            
    def extract_features(self, data_point: Dict) -> List[float]:
        """Extrait les caractéristiques pour l'analyse ML"""
        features = []
        
        try:
            # Caractéristiques temporelles
            features.extend([
                data_point.get('hour', 0) / 24.0,
                data_point.get('weekday', 0) / 7.0
            ])
            
            # Caractéristiques de charge (pour les équipements)
            if data_point.get('data_type') == 'equipment':
                features.extend([
                    data_point.get('cpu', 0) / 100.0,
                    data_point.get('ram', 0) / 100.0,
                    data_point.get('disk', 0) / 100.0,
                    data_point.get('network', 0) / 100.0,
                    data_point.get('load_spike_score', 0),
                    data_point.get('off_hours_score', 0)
                ])
            else:
                # Caractéristiques d'activité utilisateur
                features.extend([
                    data_point.get('off_hours_score', 0),
                    data_point.get('geo_anomaly_score', 0),
                    len(data_point.get('user', '')) / 50.0,
                    len(data_point.get('event_type', '')) / 20.0
                ])
                
            return features
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des caractéristiques: {e}")
            return []
            
    def analyze_anomalies(self) -> List[Dict]:
        """Analyse les anomalies avec les modèles ML"""
        anomalies = []
        
        try:
            # Collecter les données
            data = self.collect_data_for_analysis()
            
            if not data:
                return anomalies
                
            # Extraire les caractéristiques
            features_list = []
            valid_data = []
            
            for data_point in data:
                features = self.extract_features(data_point)
                if features:
                    features_list.append(features)
                    valid_data.append(data_point)
                    
            if not features_list:
                return anomalies
                
            # Convertir en array numpy
            X = np.array(features_list)
            
            # Normaliser les caractéristiques
            if len(self.historical_data) > 0:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = self.scaler.fit_transform(X)
                
            # Prédictions avec différents modèles
            if_anomalies = self.isolation_forest.predict(X_scaled)
            if_scores = self.isolation_forest.decision_function(X_scaled)
            
            # Analyser chaque point de données
            for i, data_point in enumerate(valid_data):
                anomaly_score = abs(if_scores[i])
                is_anomaly = if_anomalies[i] == -1
                
                if is_anomaly and anomaly_score > PREDICTIVE_CONFIG['min_confidence']:
                    # Déterminer le type d'anomalie
                    anomaly_type = self.determine_anomaly_type(data_point, anomaly_score)
                    
                    if anomaly_type:
                        anomaly_info = {
                            'equipment': data_point.get('equipment_name', data_point.get('user', 'Inconnu')),
                            'anomaly_type': anomaly_type,
                            'probability': min(anomaly_score, 1.0),
                            'timestamp': datetime.fromtimestamp(data_point.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                            'details': self.get_anomaly_details(data_point, anomaly_type),
                            'severity': ANOMALY_TYPES[anomaly_type]['severity'],
                            'icon': ANOMALY_TYPES[anomaly_type]['icon']
                        }
                        anomalies.append(anomaly_info)
                        
            # Sauvegarder les données historiques
            self.historical_data.extend(data)
            
            # Garder seulement les 30 derniers jours
            cutoff_time = datetime.now() - timedelta(days=PREDICTIVE_CONFIG['history_days'])
            self.historical_data = [
                d for d in self.historical_data 
                if datetime.fromtimestamp(d.get('timestamp', 0)) > cutoff_time
            ]
            
            # Sauvegarder l'historique des anomalies
            self.anomaly_history.extend(anomalies)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des anomalies: {e}")
            
        return anomalies
        
    def determine_anomaly_type(self, data_point: Dict, anomaly_score: float) -> Optional[str]:
        """Détermine le type d'anomalie basé sur les caractéristiques"""
        if data_point.get('data_type') == 'equipment':
            # Anomalies d'équipement
            if data_point.get('load_spike_score', 0) > ANOMALY_TYPES['sudden_load_spike']['threshold']:
                return 'sudden_load_spike'
            elif data_point.get('off_hours_score', 0) > ANOMALY_TYPES['off_hours_activity']['threshold']:
                return 'off_hours_activity'
            elif anomaly_score > ANOMALY_TYPES['system_resource_anomaly']['threshold']:
                return 'system_resource_anomaly'
        else:
            # Anomalies d'activité utilisateur
            if data_point.get('geo_anomaly_score', 0) > ANOMALY_TYPES['geolocation_anomaly']['threshold']:
                return 'geolocation_anomaly'
            elif data_point.get('off_hours_score', 0) > ANOMALY_TYPES['off_hours_activity']['threshold']:
                return 'off_hours_activity'
            elif anomaly_score > ANOMALY_TYPES['user_behavior_change']['threshold']:
                return 'user_behavior_change'
                
        return None
        
    def get_anomaly_details(self, data_point: Dict, anomaly_type: str) -> str:
        """Génère les détails de l'anomalie"""
        if anomaly_type == 'sudden_load_spike':
            return f"CPU: {data_point.get('cpu', 0):.1f}%, RAM: {data_point.get('ram', 0):.1f}%, Disque: {data_point.get('disk', 0):.1f}%"
        elif anomaly_type == 'off_hours_activity':
            hour = data_point.get('hour', 0)
            return f"Activité détectée à {hour:02d}:00"
        elif anomaly_type == 'geolocation_anomaly':
            return f"Connexion depuis une localisation suspecte"
        elif anomaly_type == 'user_behavior_change':
            return f"Changement de comportement détecté pour {data_point.get('user', 'utilisateur')}"
        else:
            return "Anomalie détectée par l'algorithme ML"
            
    def train_models(self):
        """Entraîne les modèles avec les données historiques"""
        try:
            if len(self.historical_data) < 100:
                logger.info("Pas assez de données historiques pour l'entraînement")
                return
                
            # Extraire les caractéristiques
            features_list = []
            for data_point in self.historical_data:
                features = self.extract_features(data_point)
                if features:
                    features_list.append(features)
                    
            if len(features_list) < 50:
                return
                
            # Convertir en array numpy
            X = np.array(features_list)
            
            # Entraîner le scaler
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            # Entraîner les modèles
            self.isolation_forest.fit(X_scaled)
            self.one_class_svm.fit(X_scaled)
            
            # Sauvegarder les modèles
            self.save_models()
            
            logger.info("Modèles prédictifs entraînés avec succès")
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement des modèles: {e}")
            
    def get_anomaly_statistics(self) -> Dict:
        """Retourne les statistiques des anomalies"""
        if not self.anomaly_history:
            return {
                'total_anomalies': 0,
                'critical_anomalies': 0,
                'warning_anomalies': 0,
                'anomaly_types': {}
            }
            
        total = len(self.anomaly_history)
        critical = len([a for a in self.anomaly_history if a['severity'] == 'critical'])
        warning = len([a for a in self.anomaly_history if a['severity'] == 'warning'])
        
        # Compter par type
        anomaly_types = {}
        for anomaly in self.anomaly_history:
            anomaly_type = anomaly['anomaly_type']
            anomaly_types[anomaly_type] = anomaly_types.get(anomaly_type, 0) + 1
            
        return {
            'total_anomalies': total,
            'critical_anomalies': critical,
            'warning_anomalies': warning,
            'anomaly_types': anomaly_types
        } 