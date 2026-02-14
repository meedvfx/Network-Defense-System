"""
Configuration centralisée du backend via Pydantic BaseSettings.
Charge automatiquement les variables d'environnement depuis .env
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """Configuration principale de l'application Network Defense System."""

    # ---- Application ----
    app_name: str = Field(default="Network-Defense-System", description="Nom de l'application")
    app_env: str = Field(default="development", description="Environnement (development/production)")
    app_debug: bool = Field(default=True, description="Mode debug")
    app_host: str = Field(default="0.0.0.0", description="Host du serveur")
    app_port: int = Field(default=8000, description="Port du serveur")
    secret_key: str = Field(default="change-me-to-a-random-secret-key", description="Clé secrète")

    # ---- Database ----
    db_host: str = Field(default="localhost", description="Host PostgreSQL")
    db_port: int = Field(default=5432, description="Port PostgreSQL")
    db_name: str = Field(default="network_defense", description="Nom de la base")
    db_user: str = Field(default="nds_user", description="Utilisateur DB")
    db_password: str = Field(default="changeme", description="Mot de passe DB")

    @property
    def database_url(self) -> str:
        """URL de connexion PostgreSQL asynchrone."""
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def database_url_sync(self) -> str:
        """URL de connexion PostgreSQL synchrone (pour migrations)."""
        return f"postgresql+psycopg2://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    # ---- Redis ----
    redis_host: str = Field(default="localhost", description="Host Redis")
    redis_port: int = Field(default=6379, description="Port Redis")
    redis_db: int = Field(default=0, description="Base Redis")

    @property
    def redis_url(self) -> str:
        """URL de connexion Redis."""
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # ---- GeoIP ----
    geoip_provider: str = Field(default="ip-api", description="Fournisseur GeoIP (ip-api/maxmind)")
    geoip_api_key: str = Field(default="", description="Clé API GeoIP (si MaxMind)")
    geoip_cache_ttl: int = Field(default=86400, description="TTL cache GeoIP en secondes")

    # ---- AI Models ----
    model_dir: str = Field(default="./models", description="Répertoire des modèles")
    supervised_model_version: str = Field(default="latest", description="Version modèle supervisé")
    unsupervised_model_version: str = Field(default="latest", description="Version modèle non-supervisé")
    anomaly_threshold_k: float = Field(default=3.0, description="Multiplicateur seuil anomalie (k × std)")

    # ---- Capture ----
    capture_interface: str = Field(default="auto", description="Interface réseau de capture (auto recommandé)")
    capture_buffer_size: int = Field(default=1000, description="Taille buffer circulaire capture")
    capture_flow_timeout: int = Field(default=120, description="Timeout flux en secondes")

    # ---- Auto-Learning ----
    retrain_feedback_threshold: int = Field(default=100, description="Seuil feedback pour retraining")
    retrain_schedule_hours: int = Field(default=24, description="Intervalle retraining en heures")

    # ---- API Security ----
    api_key: str = Field(default="change-me-to-a-secure-api-key", description="Clé API")
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000",
        description="Origines CORS autorisées (séparées par virgule)"
    )
    rate_limit_per_minute: int = Field(default=60, description="Limite requêtes par minute")

    # ---- Data Retention ----
    retention_enabled: bool = Field(default=True, description="Active la rétention automatique des données")
    retention_flows_days: int = Field(default=30, description="Nombre de jours de conservation des flux")
    retention_run_interval_minutes: int = Field(default=60, description="Intervalle d'exécution de la rétention")
    retention_delete_batch_size: int = Field(default=5000, description="Taille de batch pour suppression")
    retention_keep_alerted_flows: bool = Field(
        default=True,
        description="Conserver les flux ayant généré des alertes",
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Liste des origines CORS."""
        return [origin.strip() for origin in self.cors_origins.split(",")]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache()
def get_settings() -> Settings:
    """Singleton Settings en cache."""
    return Settings()
