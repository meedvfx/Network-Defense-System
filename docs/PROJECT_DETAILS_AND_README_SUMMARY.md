# Network Defense System - Documentation Projet Complete

## 1. Objectif du projet

Network Defense System (NDS) est une plateforme SOC orientee detection d'intrusions reseau en quasi temps reel.
Le systeme combine:
- capture reseau
- construction de flux et extraction de features
- moteur IA hybride (supervise + non supervise + reputation IP)
- backend FastAPI async
- dashboard React/Vite
- module de reporting intelligent base sur LLM

Le projet est en mode inference only: l'entrainement des modeles est externe (voir `docs/TRAINING_GUIDE.md`).

## 2. Architecture globale

### 2.1 Couches techniques
- Frontend: `dashboard/` (React 18 + Vite)
- API backend: `backend/` (FastAPI)
- Capture: `capture/` (Scapy + flow builder)
- IA: `ai/` (chargement artefacts, preprocessing, inference)
- Geolocalisation: `geo/`
- Reporting: `reporting/` (metrics + tendances + LLM + export)
- Monitoring: `monitoring/`
- Donnees: PostgreSQL + Redis

### 2.2 Orchestration runtime
- `docker-compose.yml` demarre 3 services:
  - `postgres` (postgres:16-alpine)
  - `redis` (redis:7-alpine)
  - `backend` (image construite via `Dockerfile`)
- Le dashboard est lance localement via `npm run dev` (port 3000)

## 3. Structure du depot

```text
Network-Defense-System/
|- ai/
|- backend/
|- capture/
|- dashboard/
|- docs/
|- geo/
|- monitoring/
|- reporting/
|- docker-compose.yml
|- Dockerfile
|- requirements.txt
|- README.md
```

## 4. Stack technologique reelle

### 4.1 Backend/API
- FastAPI 0.129.1
- Uvicorn 0.41.0
- Pydantic 2.12.5
- SlowAPI (rate limiting)

### 4.2 Data
- PostgreSQL 16
- SQLAlchemy 2.0 async + asyncpg
- Redis 7 (cache, metrics, pub/sub alertes)

### 4.3 IA
- TensorFlow 2.20
- scikit-learn 1.7.1 (artefacts preprocessing)
- NumPy + joblib

### 4.4 Capture reseau
- Scapy 2.6.1

### 4.5 Frontend
- React 18
- Vite 6
- Recharts
- React-Leaflet/Leaflet
- lucide-react

### 4.6 Reporting
- httpx
- openai SDK (mode provider compatible OpenAI)
- fpdf2 (export PDF)

## 5. Flux de donnees (end-to-end)

1. Capture paquets IP via `capture/packet_sniffer.py`
2. Aggregation en flux bidirectionnels 5-tuple via `capture/flow_builder.py`
3. Extraction de features CIC-compatibles via `capture/feature_extractor.py`
4. Preprocessing (`ai/preprocessing/feature_pipeline.py`): validation -> scaling -> feature selection
5. Inference:
   - supervise (`ai/inference/supervised_predictor.py`)
   - non supervise (`ai/inference/unsupervised_predictor.py`)
6. Fusion hybride (`ai/inference/hybrid_decision_engine.py`)
7. Persistance transactionnelle dans PostgreSQL:
   - `network_flows`
   - `predictions`
   - `anomaly_scores`
   - `alerts` (si decision != normal)
8. Publication alerte via Redis pub/sub (`nds:alerts:realtime`)
9. Exposition API pour dashboard, statistiques, geo, reporting

## 6. Pipeline IA detaille

### 6.1 Artefacts attendus (`ai/artifacts/`)
- `model_supervised.keras`
- `model_unsupervised.keras`
- `scaler.pkl`
- `encoder.pkl`
- `feature_selector.pkl`
- `threshold_stats.pkl` (recommande)

### 6.2 Logique de decision hybride
- Poids par defaut (`ai/config/model_config.py`):
  - supervise: 0.50
  - non supervise: 0.30
  - reputation IP: 0.20
- Score final borne entre 0 et 1
- Decisions possibles:
  - `confirmed_attack`
  - `suspicious`
  - `unknown_anomaly`
  - `normal`

### 6.3 Niveaux de severite
Mappes via `severity_config`:
- critical >= 0.85
- high >= 0.65
- medium >= 0.40
- low < 0.40

## 7. Backend FastAPI

### 7.1 Fichiers clefs
- App et lifecycle: `backend/main.py`
- Config env: `backend/core/config.py`
- API key + CORS + limiter: `backend/core/security.py`
- Session DB async: `backend/database/connection.py`
- Repository SQL: `backend/database/repository.py`
- Client Redis: `backend/database/redis_client.py`

### 7.2 Routes exposees
- System:
  - `GET /`
  - `GET /health`
  - `WS /ws/alerts`
- Detection: prefix `/api/detection`
  - `POST /analyze`
  - `GET /status`
  - `POST /capture/start`
  - `POST /capture/stop`
  - `GET /capture/status`
  - `GET /capture/interfaces`
  - `POST /capture/interface`
- Alerts: prefix `/api/alerts`
  - `GET /`
  - `PATCH /{alert_id}/status`
  - `GET /stats`
  - `GET /top-ips`
- Dashboard: prefix `/api/dashboard`
  - `GET /overview`
  - `GET /attack-distribution`
  - `GET /top-threats`
  - `GET /recent-alerts`
  - `GET /metrics`
  - `GET /traffic-timeseries`
  - `GET /protocol-distribution`
- Geo: prefix `/api/geo`
  - `GET /locate/{ip}`
  - `POST /locate-batch`
  - `GET /attack-map`
  - `GET /cached`
- Models: prefix `/api/models`
  - `GET /status`
  - `GET /config`
- Feedback: prefix `/api/feedback`
  - `POST /`
  - `GET /stats`
  - `GET /unused`
- Reporting: prefix `/api/reporting`
  - `POST /generate`
  - protege par `X-API-Key`

## 8. Base de donnees

### 8.1 Tables principales
- `network_flows`
- `predictions`
- `anomaly_scores`
- `alerts`
- `ip_geolocation`
- `model_versions`
- `feedback_labels`

### 8.2 Initialisation schema
- Fichier SQL: `backend/database/migrations/initial_schema.sql`
- Les tables sont creees aussi au demarrage via `Base.metadata.create_all` dans `init_db()`

## 9. Redis et temps reel

Usage Redis:
- cache generique
- compteurs metriques
- score global de menace (`nds:threat_score`)
- pub/sub alertes (`nds:alerts:realtime`)

WebSocket backend:
- `backend/api/websocket_handler.py`
- diffuse les alertes recues depuis Redis vers les clients connectes

## 10. Capture reseau

### 10.1 PacketSniffer
- thread dedie
- buffer circulaire (`deque`)
- fallback capture en cas de probleme BPF/L2
- extraction infos IP/TCP/UDP

### 10.2 FlowBuilder
- cle canonique 5-tuple independante du sens
- timeout configurable (`capture_flow_timeout`)
- fermeture forcee possible

### 10.3 FeatureExtractor
- vecteur d'environ 80 features
- compatible logique CIC
- calcule stats tailles paquets, IAT, flags TCP, ratios et debits

## 11. Geolocalisation

- Classification IP privee/publique: `geo/ip_resolver.py`
- Provider par defaut: ip-api.com via `geo/geo_locator.py`
- cache local in-memory dans `GeoLocator`
- API geo ignore les IP non geolocalisables

## 12. Reporting intelligent (LLM)

Pipeline reporting (`reporting/`):
1. `metrics_engine.py`
2. `trend_analysis.py`
3. `threat_index.py`
4. `prompt_builder.py`
5. `llm_engine.py`
6. `report_formatter.py`
7. `pdf_exporter.py`

Export supporte:
- `json`
- `markdown`
- `pdf`

Providers LLM:
- Ollama (par defaut)
- provider compatible OpenAI (ex: Groq) via SDK `openai`

## 13. Dashboard React

### 13.1 Vues
- Overview
- Alertes
- Trafic
- Carte
- Reporting
- Settings (placeholder)

### 13.2 Integrations API
- base: `API_BASE = '/api'`
- polling periodique (pas de client WebSocket implemente dans `App.jsx`)
- reporting frontend appelle `/api/reporting/generate` sans header `X-API-Key`

## 14. Configuration environnement

Variables importantes (voir `backend/core/config.py` et `reporting/llm_engine.py`):
- App: `APP_NAME`, `APP_ENV`, `APP_DEBUG`, `APP_HOST`, `APP_PORT`, `SECRET_KEY`
- DB: `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- Redis: `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`
- Capture: `CAPTURE_INTERFACE`, `CAPTURE_BUFFER_SIZE`, `CAPTURE_FLOW_TIMEOUT`
- Security: `API_KEY`, `CORS_ORIGINS`, `RATE_LIMIT_PER_MINUTE`
- Retention: `RETENTION_*`
- LLM: `LLM_PROVIDER`, `LLM_MODEL`, `OLLAMA_BASE_URL`, `<PROVIDER>_API_KEY`

## 15. Lancement projet

### 15.1 Backend + DB + Redis (Docker)
```bash
docker compose up --build -d
docker compose ps
```

### 15.2 Frontend
```bash
cd dashboard
npm install
npm run dev
```

### 15.3 URLs utiles
- Dashboard: `http://localhost:3000`
- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

## 16. Observabilite

- Logging centralise: `monitoring/logger.py`
- Metriques systeme (CPU/RAM/disk/uptime): `monitoring/metrics.py`
- Healthcheck app: endpoint `/health`

## 17. Limitations et points d'attention

- Securite API globalement partielle: la protection `X-API-Key` est active surtout sur reporting.
- Frontend reporting n'envoie pas de header `X-API-Key`.
- `raw_features` est en pratique enregistre a `None` dans le flux principal.
- Le frontend n'utilise pas actuellement le WebSocket `/ws/alerts` (polling API toutes les 5s).
- L'entrainement modele est externe au runtime applicatif.

## 18. Resume de README.md

`README.md` presente deja une documentation tres complete du projet. En resume:
- Le projet vise la detection d'intrusions reseau temps reel pour usage SOC.
- L'architecture combine capture, IA hybride, persistance, dashboard et reporting LLM.
- Le backend FastAPI expose des routes detection/alertes/dashboard/geo/models/feedback/reporting.
- Les modeles IA ne sont pas entraines dans l'application: il faut deposer les artefacts dans `ai/artifacts/`.
- Le demarrage recommande est Docker Compose pour backend + PostgreSQL + Redis, puis lancement du dashboard via Vite.
- Le README decrit aussi les flux de donnees, la stack, les variables d'environnement, les limitations et la documentation complementaire.

## 19. Documentation complementaire

- `README.md`
- `docs/PROBLEM_STATEMENT.md`
- `docs/TRAINING_GUIDE.md`
- `docs/USER_GUIDE.md`
