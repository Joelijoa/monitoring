"""
Service pour l'API Wazuh avec analyse ML
"""
import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle
import os
from monitoring.config.wazuh_config import WAZUH_CONFIG, EVENT_TYPES, ML_THRESHOLDS

logger = logging.getLogger(__name__)

class WazuhService:
    def __init__(self):
        self.api_url = WAZUH_CONFIG['api_url']
        self.username = WAZUH_CONFIG['username']
        self.password = WAZUH_CONFIG['password']
        self.timeout = WAZUH_CONFIG['timeout']
        self.verify_ssl = WAZUH_CONFIG['verify_ssl']
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = self.verify_ssl
        
        # Modèles ML
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        self.ml_model_path = 'monitoring/models/user_activity_model.pkl'
        
        # Initialisation des modèles
        self.initialize_ml_models()
        
    def initialize_ml_models(self):
        """Initialise ou charge les modèles ML"""
        try:
            if os.path.exists(self.ml_model_path):
                with open(self.ml_model_path, 'rb') as f:
                    models = pickle.load(f)
                    self.isolation_forest = models['isolation_forest']
                    self.scaler = models['scaler']
                    self.vectorizer = models['vectorizer']
                logger.info("Modèles ML chargés depuis le fichier")
            else:
                self.isolation_forest = IsolationForest(
                    contamination=0.1,
                    random_state=42
                )
                logger.info("Nouveaux modèles ML initialisés")
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des modèles ML: {e}")
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            
    def save_ml_models(self):
        """Sauvegarde les modèles ML"""
        try:
            os.makedirs(os.path.dirname(self.ml_model_path), exist_ok=True)
            models = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'vectorizer': self.vectorizer
            }
            with open(self.ml_model_path, 'wb') as f:
                pickle.dump(models, f)
            logger.info("Modèles ML sauvegardés")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des modèles ML: {e}")
            
    def get_events(self, hours: int = 24) -> List[Dict]:
        """
        Récupère les événements depuis l'API Wazuh
        """
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            
            params = {
                'from': int(start_time.timestamp()),
                'to': int(end_time.timestamp()),
                'limit': 1000
            }
            
            response = self.session.get(
                f"{self.api_url}/events",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json().get('data', [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur lors de la récupération des événements: {e}")
            return []
            
    def get_user_activity(self, hours: int = 24) -> List[Dict]:
        """
        Récupère l'activité utilisateur spécifique
        """
        try:
            # Filtres pour les événements utilisateur
            user_filters = [
                'event_type:login',
                'event_type:program_execution',
                'event_type:file_access',
                'event_type:network_access'
            ]
            
            events = []
            for filter_query in user_filters:
                params = {
                    'q': filter_query,
                    'from': int((datetime.now() - timedelta(hours=hours)).timestamp()),
                    'to': int(datetime.now().timestamp()),
                    'limit': 500
                }
                
                response = self.session.get(
                    f"{self.api_url}/events",
                    params=params,
                    timeout=self.timeout
                )
                response.raise_for_status()
                events.extend(response.json().get('data', []))
                
            return events
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur lors de la récupération de l'activité utilisateur: {e}")
            return []
            
    def analyze_event_with_ml(self, event: Dict) -> Dict:
        """
        Analyse un événement avec les modèles ML
        """
        try:
            # Extraction des caractéristiques
            features = self.extract_features(event)
            
            if not features:
                return {
                    'suspicious_score': 0.0,
                    'anomaly_score': 0.0,
                    'risk_level': 'normal'
                }
            
            # Normalisation des caractéristiques
            features_scaled = self.scaler.transform([features])
            
            # Prédiction avec Isolation Forest
            anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
            
            # Calcul du score de suspicion
            suspicious_score = self.calculate_suspicious_score(event, anomaly_score)
            
            # Détermination du niveau de risque
            risk_level = self.determine_risk_level(suspicious_score, anomaly_score)
            
            return {
                'suspicious_score': suspicious_score,
                'anomaly_score': anomaly_score,
                'risk_level': risk_level
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse ML: {e}")
            return {
                'suspicious_score': 0.0,
                'anomaly_score': 0.0,
                'risk_level': 'normal'
            }
            
    def extract_features(self, event: Dict) -> List[float]:
        """
        Extrait les caractéristiques d'un événement pour l'analyse ML
        """
        features = []
        
        try:
            # Caractéristiques temporelles
            timestamp = event.get('timestamp', 0)
            hour = datetime.fromtimestamp(timestamp).hour
            features.extend([
                hour / 24.0,  # Heure normalisée
                datetime.fromtimestamp(timestamp).weekday() / 7.0  # Jour de la semaine
            ])
            
            # Caractéristiques de l'utilisateur
            user = event.get('user', '')
            features.append(len(user) / 50.0)  # Longueur du nom d'utilisateur
            
            # Caractéristiques de l'événement
            event_type = event.get('event_type', '')
            features.append(len(event_type) / 20.0)
            
            # Caractéristiques du message
            message = event.get('message', '')
            features.append(len(message) / 200.0)
            
            # Caractéristiques de l'agent
            agent = event.get('agent', '')
            features.append(len(agent) / 50.0)
            
            # Score de sévérité
            severity = event.get('severity', 0)
            features.append(severity / 15.0)
            
            return features
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des caractéristiques: {e}")
            return []
            
    def calculate_suspicious_score(self, event: Dict, anomaly_score: float) -> float:
        """
        Calcule un score de suspicion basé sur l'événement et l'anomalie
        """
        score = 0.0
        
        # Score de base basé sur l'anomalie
        score += abs(anomaly_score) * 0.3
        
        # Score basé sur le type d'événement
        event_type = event.get('event_type', '')
        if event_type == 'network_access':
            score += 0.4
        elif event_type == 'program_execution':
            score += 0.2
        elif event_type == 'file_access':
            score += 0.1
            
        # Score basé sur la sévérité
        severity = event.get('severity', 0)
        score += (severity / 15.0) * 0.3
        
        # Score basé sur l'heure (activité nocturne suspecte)
        timestamp = event.get('timestamp', 0)
        hour = datetime.fromtimestamp(timestamp).hour
        if 22 <= hour or hour <= 6:
            score += 0.2
            
        return min(score, 1.0)
        
    def determine_risk_level(self, suspicious_score: float, anomaly_score: float) -> str:
        """
        Détermine le niveau de risque basé sur les scores
        """
        if suspicious_score >= ML_THRESHOLDS['critical_score'] or abs(anomaly_score) >= ML_THRESHOLDS['anomaly_threshold']:
            return 'critical'
        elif suspicious_score >= ML_THRESHOLDS['suspicious_score']:
            return 'suspicious'
        else:
            return 'normal'
            
    def get_all_user_activity(self) -> List[Dict]:
        """
        Récupère et analyse toute l'activité utilisateur
        """
        events = self.get_user_activity()
        analyzed_events = []
        
        for event in events:
            # Analyse ML
            ml_analysis = self.analyze_event_with_ml(event)
            
            # Enrichissement de l'événement
            enriched_event = {
                'id': event.get('id', ''),
                'timestamp': event.get('timestamp', 0),
                'user': event.get('user', ''),
                'event_type': event.get('event_type', ''),
                'message': event.get('message', ''),
                'agent': event.get('agent', ''),
                'severity': event.get('severity', 0),
                'suspicious_score': ml_analysis['suspicious_score'],
                'anomaly_score': ml_analysis['anomaly_score'],
                'risk_level': ml_analysis['risk_level'],
                'datetime': datetime.fromtimestamp(event.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            analyzed_events.append(enriched_event)
            
        # Tri par timestamp (plus récent en premier)
        analyzed_events.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return analyzed_events
        
    def train_ml_models(self, training_data: List[Dict]):
        """
        Entraîne les modèles ML avec de nouvelles données
        """
        try:
            if not training_data:
                return
                
            # Extraction des caractéristiques
            features_list = []
            for event in training_data:
                features = self.extract_features(event)
                if features:
                    features_list.append(features)
                    
            if not features_list:
                return
                
            # Conversion en array numpy
            X = np.array(features_list)
            
            # Entraînement du scaler
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            # Entraînement de l'Isolation Forest
            self.isolation_forest.fit(X_scaled)
            
            # Sauvegarde des modèles
            self.save_ml_models()
            
            logger.info("Modèles ML entraînés avec succès")
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement des modèles ML: {e}")
            
    def test_connection(self) -> bool:
        """
        Teste la connexion à l'API Wazuh
        """
        try:
            response = self.session.get(
                f"{self.api_url}/status",
                timeout=self.timeout
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur de connexion à l'API Wazuh: {e}")
            return False 