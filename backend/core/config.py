"""
Configuration centralisée du backend via Pydantic BaseSettings.
Charge automatiquement les variables d'environnement depuis .env
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """
    Configuration principale de l'application Network Defense System (NDS).
    Cette classe centralise tous les paramètres de l'application, chargés depuis les variables d'environnement.
    Elle utilise Pydantic pour la validation automatique des types et des valeurs par défaut.
    """

    # ---- Application Core ----
    app_name: str = Field(default="Network-Defense-System", description="Nom public de l'application")
    app_env: str = Field(default="development", description="Environnement d'exécution (development/production/testing)")
    app_debug: bool = Field(default=True, description="Active le mode debug (logs détaillés, rechargement auto)")
    app_host: str = Field(default="0.0.0.0", description="Interface d'écoute du serveur web (0.0.0.0 = toutes les interfaces)")
    app_port: int = Field(default=8000, description="Port d'écoute du serveur web")
    secret_key: str = Field(default="change-me-to-a-random-secret-key", description="Clé secrète pour le chiffrement et les sessions (à changer en prod)")

    # ---- Database (PostgreSQL) ----
    db_host: str = Field(default="localhost", description="Adresse du serveur PostgreSQL")
    db_port: int = Field(default=5432, description="Port du serveur PostgreSQL")
    db_name: str = Field(default="network_defense", description="Nom de la base de données")
    db_user: str = Field(default="nds_user", description="Utilisateur de la base de données")
    db_password: str = Field(default="changeme", description="Mot de passe de la base de données")

    @property
    def database_url(self) -> str:
        """
        Construit l'URL de connexion PostgreSQL pour le driver asynchrone (asyncpg).
        Format: postgresql+asyncpg://user:password@host:port/dbname
        """
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def database_url_sync(self) -> str:
        """
        Construit l'URL de connexion PostgreSQL pour le driver synchrone (psycopg2).
        Utilisé principalement pour les migrations (Alembic) qui ne supportent pas toujours l'async.
        """
        return f"postgresql+psycopg2://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    # ---- Redis (Cache & Pub/Sub) ----
    redis_host: str = Field(default="localhost", description="Adresse du serveur Redis")
    redis_port: int = Field(default=6379, description="Port du serveur Redis")
    redis_db: int = Field(default=0, description="Numéro de la base de données Redis (0 par défaut)")

    @property
    def redis_url(self) -> str:
        """
        Construit l'URL de connexion Redis.
        Format: redis://host:port/db
        """
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # ---- GeoIP Services ----
    geoip_provider: str = Field(default="ip-api", description="Fournisseur de service de géolocalisation IP (ip-api ou maxmind)")
    geoip_api_key: str = Field(default="", description="Clé API pour le service GeoIP (si requis, ex: MaxMind)")
    geoip_cache_ttl: int = Field(default=86400, description="Temps de cache des résultats GeoIP en secondes (par défaut 24h)")

    # ---- AI Models Configuration ----
    model_dir: str = Field(default="./models", description="Répertoire local contenant les artefacts des modèles")
    supervised_model_version: str = Field(default="latest", description="Tag de version du modèle supervisé à utiliser")
    unsupervised_model_version: str = Field(default="latest", description="Tag de version du modèle non-supervisé à utiliser")
    anomaly_threshold_k: float = Field(default=3.0, description="Facteur de sensibilité pour la détection d'anomalies (seuil = μ + k*σ)")

    # ---- Network Capture ----
    capture_interface: str = Field(default="auto", description="Interface réseau à écouter (ex: eth0, wlan0). 'auto' détecte la meilleure interface.")
    capture_buffer_size: int = Field(default=1000, description="Taille du buffer circulaire pour les paquets en mémoire")
    capture_flow_timeout: int = Field(default=120, description="Durée maximale d'un flux inactif avant clôture (en secondes)")

    # ---- Auto-Learning & Feedback ----
    retrain_feedback_threshold: int = Field(default=100, description="Nombre de feedbacks utilisateurs requis pour déclencher un réentraînement")
    retrain_schedule_hours: int = Field(default=24, description="Intervalle minimal entre deux sessions d'entraînement automatique (heures)")

    # ---- API Security ----
    api_key: str = Field(default="change-me-to-a-secure-api-key", description="Clé statique pour protéger l'accès à l'API (Header: X-API-Key)")
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000",
        description="Liste des origines autorisées pour les requêtes Cross-Origin (CORS), séparées par des virgules"
    )
    rate_limit_per_minute: int = Field(default=60, description="Nombre maximum de requêtes autorisées par minute par IP")

    # ---- Data Retention Policy ----
    retention_enabled: bool = Field(default=True, description="Active le nettoyage automatique des données anciennes")
    retention_flows_days: int = Field(default=30, description="Durée de conservation des historiques de flux (en jours)")
    retention_run_interval_minutes: int = Field(default=60, description="Fréquence d'exécution de la tâche de nettoyage (minutes)")
    retention_delete_batch_size: int = Field(default=5000, description="Nombre d'enregistrements à supprimer par lot (batch)")
    retention_keep_alerted_flows: bool = Field(
        default=True,
        description="Si True, ne supprime jamais les flux associés à une alerte de sécurité",
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Convertit la chaîne cors_origins en une liste de chaînes."""
        return [origin.strip() for origin in self.cors_origins.split(",")]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache()
def get_settings() -> Settings:
    """
    Retourne une instance unique (singleton) de la configuration.
    L'utilisation de @lru_cache évite de relire le fichier .env à chaque appel.
    """
    return Settings()
