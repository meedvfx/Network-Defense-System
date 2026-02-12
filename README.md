# 🛡️ Network Defense System (NDS)

**Plateforme SOC intelligente avec Deep Learning hybride pour la détection d'intrusions réseau.**

![Python](https://img.shields.io/badge/Python-3.13+-blue?logo=python)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.20+-orange?logo=tensorflow)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green?logo=fastapi)
![React](https://img.shields.io/badge/React-18+-61DAFB?logo=react)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📋 Table des matières

- [Aperçu](#-aperçu)
- [Architecture](#-architecture)
- [Fonctionnalités](#-fonctionnalités)
- [Stack technique](#-stack-technique)
- [Structure du projet](#-structure-du-projet)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Pipeline AI](#-pipeline-ai)
- [Entraînement des modèles](#-entraînement-des-modèles)
- [API Documentation](#-api-documentation)
- [Configuration](#-configuration)

---

## 🎯 Aperçu

Le **Network Defense System (NDS)** est une plateforme SOC (Security Operations Center) de nouvelle génération qui combine le Deep Learning supervisé et non-supervisé pour offrir une détection d'intrusions réseau avancée.

### Capacités clés :
- **Classification supervisée** : Identifie 7+ types d'attaques (DDoS, PortScan, BruteForce, DoS, Botnet, Web Attacks)
- **Détection d'anomalies** : Autoencoder entraîné sur le trafic normal détecte les attaques 0-day
- **Moteur hybride** : Combine les deux approches avec la réputation IP pour des décisions fiables
- **Temps réel** : Capture, analyse et alerte en continu via WebSocket
- **Géolocalisation** : Localise les sources d'attaque sur une carte mondiale
- **Architecture production** : Séparation claire entre entraînement (Colab) et inférence (serveur)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Dashboard React (Vite)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Alertes  │ │ Charts   │ │ Map      │ │ Threat Score     │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
├───────────────────────┬─────────────────────────────────────────┤
│    FastAPI Backend     │           WebSocket Stream              │
│  ┌─────────────────┐  │  ┌───────────────────────────────────┐  │
│  │ API Routes      │  │  │ Real-time Alert Broadcasting      │  │
│  │ Services Layer  │  │  │ Redis Pub/Sub                     │  │
│  │ Repository      │  │  └───────────────────────────────────┘  │
│  └─────────────────┘  │                                         │
├───────────────────────┴─────────────────────────────────────────┤
│                  AI Inference Pipeline                            │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ Supervised    │  │ Unsupervised │  │ Hybrid Decision       │  │
│  │ Predictor     │  │ Predictor    │  │ Engine                │  │
│  │ (Classif.)    │  │ (Autoencoder)│  │ (Score + Priority)    │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Preprocessing : DataValidator → FeatureSelector → Scaler │   │
│  └──────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ Packet Capture   │  │ Flow Builder │  │ Feature Extract. │   │
│  │ (Scapy)          │  │ (5-tuple)    │  │ (CIC-compat.)   │   │
│  └──────────────────┘  └──────────────┘  └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  PostgreSQL                    Redis                  GeoIP API  │
└─────────────────────────────────────────────────────────────────┘
```

### Séparation Training / Production

```
┌───────────────────────────┐     ┌────────────────────────────────┐
│   Google Colab / Jupyter  │     │   Serveur Production (NDS)     │
│                           │     │                                │
│  Dataset CIC-IDS2017/2018 │     │  ai/artifacts/                 │
│  → Feature Selection      │     │    model_supervised.keras       │
│  → Scaling                │     │    model_unsupervised.keras     │
│  → Train MLP supervisé    │────▶│    scaler.pkl                  │
│  → Train Autoencoder      │     │    encoder.pkl                 │
│  → Export .keras + .pkl   │     │    feature_selector.pkl        │
│                           │     │                                │
│  Aucun code d'entraînement│     │  → Chargement au démarrage     │
│  dans l'app principale    │     │  → Inférence temps réel        │
└───────────────────────────┘     └────────────────────────────────┘
```

---

## ✨ Fonctionnalités

| Module | Description |
|--------|-------------|
| 🧠 **AI Supervisé** | Modèle Keras pré-entraîné (MLP/CNN-1D) pour classifier 7+ types d'attaques |
| 🔮 **AI Non-supervisé** | Autoencoder avec seuil adaptatif (μ + kσ) pour détecter les attaques 0-day |
| ⚖️ **Moteur Hybride** | Fusion pondérée (50/30/20) classification + anomalie + réputation IP |
| 📡 **Capture Réseau** | Scapy en thread séparé avec buffer circulaire et ~78 features CIC |
| 🌍 **Géolocalisation** | ip-api.com avec cache local et carte des attaques |
| 📊 **Dashboard** | React + Recharts avec threat score animé, timeline, alertes temps réel |
| 🔧 **Production-Ready** | Modèles figés, inférence optimisée, warm-up au démarrage |

---

## 🛠️ Stack technique

| Composant | Technologie |
|-----------|-------------|
| Backend | FastAPI, SQLAlchemy (async), Pydantic |
| Deep Learning | TensorFlow 2.20+, Keras 3 |
| Base de données | PostgreSQL 15 |
| Cache / Pub-Sub | Redis 7 |
| Capture réseau | Scapy (+ Npcap sur Windows) |
| Frontend | React 18, Vite, Recharts, Leaflet |
| Géolocalisation | ip-api.com |
| Monitoring | psutil, logging rotatif |

---

## 📁 Structure du projet

```
Network-Defense-System/
├── ai/                              # Module AI (inférence uniquement)
│   ├── artifacts/                   # Modèles pré-entraînés (.keras + .pkl)
│   │   ├── model_supervised.keras   # Classifieur multi-classe
│   │   ├── model_unsupervised.keras # Autoencoder (anomalie)
│   │   ├── scaler.pkl               # StandardScaler fitté
│   │   ├── encoder.pkl              # LabelEncoder des attaques
│   │   ├── feature_selector.pkl     # SelectKBest fitté
│   │   └── threshold_stats.pkl      # Seuil d'anomalie (μ, σ)
│   ├── config/
│   │   └── model_config.py          # Chemins, seuils, poids hybrides
│   ├── inference/
│   │   ├── model_loader.py          # Charge tous les artifacts
│   │   ├── supervised_predictor.py  # Classification → type + proba
│   │   ├── unsupervised_predictor.py# Anomalie → score + is_anomaly
│   │   └── hybrid_decision_engine.py# Fusion → risk score + severity
│   └── preprocessing/
│       ├── data_validator.py        # Validation NaN/Inf/types
│       └── feature_pipeline.py      # Pipeline validate → select → scale
├── backend/                         # API FastAPI
│   ├── api/                         # Routes REST + WebSocket
│   │   ├── routes_detection.py      # Analyse et capture
│   │   ├── routes_alerts.py         # CRUD alertes
│   │   ├── routes_geo.py            # Géolocalisation
│   │   ├── routes_dashboard.py      # Stats et métriques
│   │   ├── routes_models.py         # Statut des artifacts AI
│   │   ├── routes_feedback.py       # Feedback analyste
│   │   └── websocket_handler.py     # Streaming temps réel
│   ├── core/                        # Configuration et sécurité
│   │   ├── config.py                # Pydantic BaseSettings
│   │   ├── security.py              # API Key, CORS, rate limiting
│   │   └── exceptions.py            # Exceptions métier
│   ├── database/                    # Couche données
│   │   ├── connection.py            # Async SQLAlchemy
│   │   ├── models.py                # 7 modèles ORM
│   │   ├── repository.py            # Pattern Repository
│   │   ├── redis_client.py          # Cache + Pub/Sub
│   │   └── migrations/              # Schéma SQL
│   ├── services/                    # Logique métier
│   │   ├── detection_service.py     # Pipeline complet
│   │   ├── anomaly_service.py       # Interface anomalies
│   │   ├── geo_service.py           # Géolocalisation
│   │   ├── alert_service.py         # Création d'alertes
│   │   └── capture_service.py       # Gestion capture
│   └── main.py                      # Point d'entrée FastAPI
├── capture/                         # Capture réseau
│   ├── packet_sniffer.py            # Scapy en thread séparé
│   ├── flow_builder.py              # Agrégation en flux 5-tuple
│   └── feature_extractor.py         # ~78 features CIC-compatibles
├── geo/                             # Géolocalisation
│   ├── ip_resolver.py               # Classification IP
│   └── geo_locator.py               # API ip-api.com
├── dashboard/                       # Frontend React
│   ├── src/
│   │   ├── App.jsx                  # Application principale (6 vues)
│   │   ├── main.jsx                 # Point d'entrée React
│   │   └── index.css                # Thème dark cybersecurity
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
├── monitoring/                      # Monitoring
│   ├── logger.py                    # Logging rotatif
│   └── metrics.py                   # Métriques système (psutil)
├── docs/
│   └── TRAINING_GUIDE.md            # Guide d'entraînement (Colab)
├── .env.example
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

## 🚀 Installation

### Prérequis

- Python 3.13+
- Node.js 18+
- Docker & Docker Compose (optionnel, pour PostgreSQL + Redis)
- Npcap (Windows uniquement, pour la capture réseau)

### 1. Cloner le projet

```bash
git clone https://github.com/votre-repo/Network-Defense-System.git
cd Network-Defense-System
```

### 2. Configuration

```bash
cp .env.example .env
# Éditer .env avec vos paramètres
```

### 3. Démarrer les services (optionnel)

```bash
docker-compose up -d   # PostgreSQL + Redis
```

> Sans Docker, le backend fonctionne mais affiche des warnings.

### 4. Installer les dépendances Python

```bash
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

### 5. Installer le dashboard

```bash
cd dashboard
npm install
cd ..
```

### 6. Ajouter les modèles AI

Les modèles doivent être entraînés séparément dans Google Colab (voir [Guide d'entraînement](docs/TRAINING_GUIDE.md)), puis déposés dans `ai/artifacts/` :

```
ai/artifacts/
├── model_supervised.keras
├── model_unsupervised.keras
├── scaler.pkl
├── encoder.pkl
├── feature_selector.pkl
└── threshold_stats.pkl
```

---

## 🎮 Utilisation

### Démarrer le Backend

```bash
# Windows
.\venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Linux/Mac
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Démarrer le Dashboard

Dans un second terminal :

```bash
cd dashboard
npm run dev
```

### Accéder aux interfaces

| Interface | URL |
|-----------|-----|
| Dashboard | http://localhost:3000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| API Docs (ReDoc) | http://localhost:8000/redoc |
| Health Check | http://localhost:8000/health |
| Statut des modèles | http://localhost:8000/api/models/status |

---

## 🧠 Pipeline AI

### Architecture d'inférence (production)

```
Features réseau brutes
        │
        ▼
┌──────────────────┐
│  DataValidator    │  Validation NaN/Inf, types, dimensions
└────────┬─────────┘
         ▼
┌──────────────────┐
│ FeatureSelector   │  Sélection des features (SelectKBest)
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Scaler           │  Normalisation (StandardScaler)
└────────┬─────────┘
         ▼
   ┌─────┴──────┐
   ▼            ▼
┌────────┐  ┌──────────┐
│Supervisé│  │Non-sup.  │
│Predictor│  │Predictor │
│→type    │  │→anomaly  │
│→proba   │  │→score    │
└────┬───┘  └────┬─────┘
     └─────┬─────┘
           ▼
  ┌────────────────┐
  │ Hybrid Decision │  Fusion pondérée + réputation IP
  │ Engine          │  → attack_type, probability
  │                 │  → anomaly_score, final_risk_score
  │                 │  → severity, decision, priority
  └─────────────────┘
```

### Matrice de décision

| Supervisé  | Non-supervisé | Décision            |
|------------|---------------|---------------------|
| Attaque ✓  | Anomalie ✓    | `confirmed_attack`  |
| Attaque ✓  | Normal        | `suspicious`        |
| BENIGN     | Anomalie ✓    | `unknown_anomaly`   |
| BENIGN     | Normal        | `normal`            |

---

## 🧪 Entraînement des modèles

> ⚠️ **L'entraînement se fait en dehors de l'application** (Google Colab ou Jupyter Notebook).

Voir le guide complet : **[docs/TRAINING_GUIDE.md](docs/TRAINING_GUIDE.md)**

### Résumé :

1. **Modèle supervisé** : MLP entraîné sur CIC-IDS2017/2018 avec SMOTE pour le balancing
2. **Modèle non-supervisé** : Autoencoder entraîné **uniquement sur le trafic BENIGN**
3. **Preprocessing** : Scaler et FeatureSelector fittés pendant l'entraînement
4. **Export** : Fichiers `.keras` + `.pkl` déposés dans `ai/artifacts/`

### Vérification :

```bash
# Vérifier que tous les artifacts sont présents
curl http://localhost:8000/api/models/status
# → "all_artifacts_present": true
```

---

## 📡 API Documentation

### Endpoints principaux

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/detection/analyze` | Analyse un vecteur de features |
| `GET` | `/api/alerts/` | Liste les alertes avec filtres |
| `PATCH` | `/api/alerts/{id}/status` | Met à jour le statut d'une alerte |
| `GET` | `/api/geo/locate/{ip}` | Géolocalise une IP |
| `GET` | `/api/geo/attack-map` | Données carte des attaques |
| `GET` | `/api/dashboard/overview` | Vue d'ensemble métriques |
| `GET` | `/api/models/status` | Statut des artifacts AI |
| `GET` | `/api/models/config` | Configuration d'inférence |
| `POST` | `/api/feedback/` | Soumet un feedback analyste |
| `WS` | `/ws/alerts` | Stream d'alertes temps réel |

---

## ⚙️ Configuration

Les variables d'environnement sont définies dans `.env` :

| Variable | Description | Défaut |
|----------|-------------|--------|
| `APP_NAME` | Nom de l'application | Network Defense System |
| `APP_DEBUG` | Mode debug | false |
| `DATABASE_URL` | URL PostgreSQL | postgresql+asyncpg://... |
| `REDIS_URL` | URL Redis | redis://localhost:6379/0 |
| `API_KEY` | Clé d'authentification API | (à définir) |
| `CORS_ORIGINS` | Origines CORS autorisées | http://localhost:3000 |
| `ANOMALY_THRESHOLD_K` | Multiplicateur seuil anomalie | 3.0 |
| `CAPTURE_INTERFACE` | Interface réseau | eth0 |

---

## 📄 Licence

MIT License - Voir [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">
  <strong>🛡️ Network Defense System</strong><br/>
  <em>Intelligence artificielle au service de la cybersécurité</em>
</div>
