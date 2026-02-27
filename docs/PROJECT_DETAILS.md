# 📚 Détails Techniques — Network Defense System

Documentation exhaustive de la stack technologique, des mécanismes de sécurité, des politiques de données, et des limites connues du projet.

---

## 1. Stack Technologique Complète

### 1.1 Backend & API

| Dépendance | Version | Rôle |
|------------|---------|------|
| **FastAPI** | 0.129.1 | Framework API REST/WebSocket, OpenAPI auto-généré (Swagger + ReDoc) |
| **Uvicorn** | 0.41.0 | Serveur ASGI haute performance |
| **Pydantic** | 2.12.5 | Validation/sérialisation des schémas JSON entrées/sorties |
| **pydantic-settings** | 2.13.1 | Chargement configuration depuis `.env` via `BaseSettings` |
| **SlowAPI** | 0.1.9 | Rate limiting par IP (`get_remote_address`) — configurable via `RATE_LIMIT_PER_MINUTE` |
| **python-dotenv** | 1.2.1 | Chargement `.env` pour `os.getenv()` (reporting/LLM) |
| **python-multipart** | 0.0.22 | Support upload fichiers (forms multipart) |

### 1.2 Persistance & Cache

| Dépendance | Version | Rôle |
|------------|---------|------|
| **PostgreSQL** | 16-alpine | RDBMS principal — 7 tables, indexes composites, UUID PK, JSONB |
| **SQLAlchemy** | 2.0.45 | ORM async avec `AsyncSession`, repository pattern (35+ fonctions) |
| **asyncpg** | 0.31.0 | Driver PostgreSQL async natif (pool de connexions) |
| **psycopg2-binary** | 2.9.11 | Driver sync (fallback migrations Alembic) |
| **Redis** | 7.2.0 | Cache clé-valeur + compteurs métriques + Pub/Sub alertes + threat score global |

Redis est configuré en Docker avec : `--appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru`

### 1.3 Intelligence Artificielle

| Dépendance | Version | Rôle |
|------------|---------|------|
| **TensorFlow** | 2.20.0 | Exécution des graphes Keras (forward pass uniquement, `compile=False`) |
| **scikit-learn** | 1.7.1 | Artefacts de preprocessing chargés côté inférence (scaler, encoder, selector) |
| **NumPy** | 2.2.6 | Calcul vectoriel (features, MSE reconstruction) |
| **joblib** | 1.5.1 | Sérialisation/désérialisation des objets `.pkl` |

### 1.4 Capture Réseau

| Dépendance | Version | Rôle |
|------------|---------|------|
| **Scapy** | 2.6.1 | Sniffing paquets IP/TCP/UDP, parsing bas-niveau, gestion interfaces |

Dépendances système requises : `libpcap-dev`, `tcpdump` (Linux), **Npcap** (Windows)

### 1.5 Frontend

| Dépendance | Version | Rôle |
|------------|---------|------|
| **React** | 18 | Framework UI avec composants functionnels |
| **Vite** | 6.x | Build tool + dev server avec proxy `/api` et `/ws` |
| **Recharts** | — | Graphiques SVG (timeline, distributions, camemberts) |
| **React-Leaflet / Leaflet** | — | Carte interactive d'attaque mondiale |
| **lucide-react** | — | Bibliothèque d'icônes |

### 1.6 Reporting

| Dépendance | Version | Rôle |
|------------|---------|------|
| **openai** | 2.9.0 | Client SDK compatible OpenAI pour appels LLM (Groq, etc.) |
| **httpx** | 0.28.1 | Client HTTP async pour appels Ollama (`/api/generate`) |
| **fpdf2** | 2.8.6 | Génération de documents PDF depuis Markdown |

### 1.7 Monitoring

| Dépendance | Version | Rôle |
|------------|---------|------|
| **psutil** | 7.1.2 | Métriques système : CPU%, RAM, Disque, Uptime |

---

## 2. Mécanismes de Sécurité

### 2.1 Authentification API Key

Le header `X-API-Key` est vérifié par la dépendance `verify_api_key` dans `backend/core/security.py` :

```python
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    if not api_key or api_key != settings.api_key:
        raise HTTPException(status_code=403, detail="Clé API invalide ou manquante.")
    return api_key
```

**Périmètre actuel** : Seul le routeur `routes_reporting` utilise cette dépendance. Les autres routeurs sont ouverts.

### 2.2 CORS (Cross-Origin Resource Sharing)

Configuration dans `get_cors_config()` :
- **Origins autorisées** : `CORS_ORIGINS` (défaut : `http://localhost:5173,http://localhost:3000`)
- **Credentials** : `True`
- **Méthodes** : `["*"]` (toutes)
- **Headers** : `["*"]` (tous)

### 2.3 Rate Limiting

SlowAPI avec `get_remote_address` comme clé — configurable via `RATE_LIMIT_PER_MINUTE` (défaut 60).

### 2.4 Validation des Features IA

Le `DataValidator` dans `ai/preprocessing/data_validator.py` vérifie :
- Absence de NaN et Inf
- Clipping des valeurs aberrantes (outliers)
- Dimensions correctes du vecteur d'entrée

---

## 3. Politique de Rétention des Données

Le service `data_retention_service` est un scheduler lancé au `lifespan` de l'app :

| Variable | Défaut | Description |
|----------|--------|-------------|
| `RETENTION_ENABLED` | `true` | Active/désactive le nettoyage automatique |
| `RETENTION_FLOWS_DAYS` | `30` | Conservation des flux en jours |
| `RETENTION_RUN_INTERVAL_MINUTES` | `60` | Fréquence d'exécution |
| `RETENTION_DELETE_BATCH_SIZE` | `5000` | Nombre de lignes supprimées par batch |
| `RETENTION_KEEP_ALERTED_FLOWS` | `true` | Jamais supprimer les flux associés à une alerte |

---

## 4. Géolocalisation IP

### 4.1 Architecture (`geo/`)

| Fichier | Rôle |
|---------|------|
| `ip_resolver.py` | Classifie les IPs en privées/publiques/réservées, filtre les non-géolocalisables |
| `geo_locator.py` | Appelle `ip-api.com` pour les IPs publiques, cache en mémoire + persistance PostgreSQL |

### 4.2 Configuration

- Provider : `GEOIP_PROVIDER` (défaut `ip-api`)
- Cache TTL : `GEOIP_CACHE_TTL` (défaut 86400s = 24h)
- API Key optionnelle : `GEOIP_API_KEY` (pour MaxMind ou plans payants)

---

## 5. Lifecycle de l'Application

Le `lifespan` dans `backend/main.py` exécute séquentiellement au démarrage :

1. **`init_db()`** — Connexion PostgreSQL + création tables via `Base.metadata.create_all`
2. **`get_redis().ping()`** — Vérification connectivité Redis
3. **`data_retention_service.start_scheduler()`** — Lancement scheduler de nettoyage

À l'arrêt : `stop_scheduler()` → `close_db()` → `close_redis()`.

---

## 6. Limites Connues et Points d'Attention

### 6.1 Sécurité

- ⚠️ L'authentification `X-API-Key` n'est appliquée **que** sur le routeur reporting
- ⚠️ Pas de système RBAC/JWT — tout client ayant accès au réseau est admin
- ⚠️ Le frontend n'envoie pas le header `X-API-Key` pour les appels reporting

### 6.2 Performance

- Le `FeatureExtractor` fonctionne en mode synchrone (pas de batch GPU)
- Le `raw_features` JSONB est persisté en `None` dans le flux principal (économie disque)
- Le frontend utilise du polling API périodique, le WebSocket est configuré mais sous-utilisé côté React

### 6.3 Axes d'Amélioration

| Domaine | Proposition |
|---------|-------------|
| **Authz** | Implémenter JWT/OAuth2 avec RBAC (rôles analyste/admin/viewer) |
| **Tests** | Ajouter tests d'intégration API/DB/Redis/WS (pytest-asyncio) |
| **MLOps** | Versionning modèle automatique, validation artefacts en CI/CD |
| **Frontend** | Exploiter pleinement le WebSocket au lieu du polling |
| **Monitoring** | Intégrer Prometheus + Grafana pour les métriques `SystemMetrics` |
