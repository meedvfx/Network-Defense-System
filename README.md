# 🛡️ Network Defense System (NDS)

**Plateforme SOC intelligente avec Deep Learning hybride pour la détection d'intrusions réseau.**

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15+-orange?logo=tensorflow)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green?logo=fastapi)
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
- **Auto-learning** : Boucle de feedback analyste → retraining automatique

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
│                        AI Pipeline                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ Supervised    │  │ Unsupervised │  │ Hybrid Decision       │  │
│  │ MLP / CNN-1D │  │ Autoencoder  │  │ Engine                │  │
│  │ (Classif.)   │  │ / VAE        │  │ (Score + Priority)    │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ Packet Capture   │  │ Flow Builder │  │ Feature Extract. │   │
│  │ (Scapy)          │  │ (5-tuple)    │  │ (CIC-compat.)   │   │
│  └──────────────────┘  └──────────────┘  └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  PostgreSQL                    Redis                  GeoIP API  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Fonctionnalités

| Module | Description |
|--------|-------------|
| 🧠 **AI Supervisé** | MLP et CNN-1D entraînés sur CIC-IDS2017/2018 avec BatchNorm, Dropout, class weighting |
| 🔮 **AI Non-supervisé** | Autoencoder dense et VAE avec seuil dynamique adaptatif (μ + kσ) |
| ⚖️ **Moteur Hybride** | Matrice de décision combinant classification, anomalie, et réputation IP |
| 📡 **Capture Réseau** | Scapy en thread séparé avec buffer circulaire et extraction de ~78 features |
| 🌍 **Géolocalisation** | ip-api.com avec cache local et carte des attaques |
| 📊 **Dashboard** | React + Recharts avec threat score animé, timeline, et alertes temps réel |
| 🔄 **Auto-Learning** | Feedback analyste → retraining → comparaison → activation automatique |
| 📋 **Model Registry** | Versioning sémantique, comparaison de métriques, rollback |

---

## 🛠️ Stack technique

| Composant | Technologie |
|-----------|-------------|
| Backend | FastAPI, SQLAlchemy (async), Pydantic |
| Deep Learning | TensorFlow 2.15+, Keras |
| Base de données | PostgreSQL 15 (données structurées) |
| Cache / Pub-Sub | Redis 7 (temps réel, métriques) |
| Capture réseau | Scapy |
| Frontend | React 18, Vite, Recharts, Leaflet |
| Geolocalisation | ip-api.com (gratuit) |
| Monitoring | psutil, logging rotatif |

---

## 📁 Structure du projet

```
Network-Defense-System/
├── ai/                          # Pipeline Deep Learning
│   ├── datasets/                # Chargement CIC-IDS2017/2018
│   │   ├── cic_loader.py        # Loader et nettoyage des CSV
│   │   └── normal_extractor.py  # Extraction du trafic BENIGN
│   ├── preprocessing/           # Prétraitement des données
│   │   ├── scaler.py            # MinMax/Standard scaler
│   │   ├── feature_selector.py  # Sélection multi-critères
│   │   └── label_encoder.py     # Encodage des labels
│   ├── supervised/              # Classification supervisée
│   │   ├── model_architecture.py # MLP + CNN-1D
│   │   ├── trainer.py           # Entraînement avec callbacks
│   │   ├── evaluator.py         # Métriques complètes
│   │   └── inference.py         # Prédiction temps réel
│   ├── unsupervised/            # Détection d'anomalies
│   │   ├── autoencoder.py       # Autoencoder + VAE
│   │   ├── trainer.py           # Entraînement sur trafic normal
│   │   └── anomaly_detector.py  # Détection avec seuil adaptatif
│   ├── hybrid/                  # Moteur de décision
│   │   └── decision_engine.py   # Fusion supervisé + non-supervisé
│   └── model_registry/          # Gestion des versions
│       ├── versioning.py        # Registre sémantique
│       └── model_loader.py      # Chargement par version
├── backend/                     # API FastAPI
│   ├── api/                     # Routes REST + WebSocket
│   │   ├── routes_detection.py  # Analyse et capture
│   │   ├── routes_alerts.py     # CRUD alertes
│   │   ├── routes_geo.py        # Géolocalisation
│   │   ├── routes_dashboard.py  # Stats et métriques
│   │   ├── routes_models.py     # Gestion des modèles
│   │   ├── routes_feedback.py   # Feedback analyste
│   │   └── websocket_handler.py # Streaming temps réel
│   ├── core/                    # Configuration et sécurité
│   │   ├── config.py            # Pydantic BaseSettings
│   │   ├── security.py          # API Key, CORS, rate limiting
│   │   └── exceptions.py        # Exceptions métier
│   ├── database/                # Couche données
│   │   ├── connection.py        # Async SQLAlchemy
│   │   ├── models.py            # 7 modèles ORM
│   │   ├── repository.py        # Pattern Repository
│   │   ├── redis_client.py      # Cache + Pub/Sub
│   │   └── migrations/          # Schéma SQL
│   ├── services/                # Logique métier
│   │   ├── detection_service.py # Pipeline complet
│   │   ├── anomaly_service.py   # Interface anomalies
│   │   ├── geo_service.py       # Géolocalisation
│   │   ├── alert_service.py     # Création d'alertes
│   │   └── capture_service.py   # Gestion capture
│   └── main.py                  # Point d'entrée FastAPI
├── capture/                     # Capture réseau
│   ├── packet_sniffer.py        # Scapy en thread séparé
│   ├── flow_builder.py          # Agrégation en flux
│   └── feature_extractor.py     # ~78 features CIC-compatibles
├── geo/                         # Géolocalisation
│   ├── ip_resolver.py           # Classification IP
│   └── geo_locator.py           # API ip-api.com
├── dashboard/                   # Frontend React
│   ├── src/
│   │   ├── App.jsx              # Application principale
│   │   ├── main.jsx             # Point d'entrée React
│   │   └── index.css            # Thème dark cybersecurity
│   ├── index.html               # HTML entry point
│   ├── vite.config.js           # Configuration Vite
│   └── package.json             # Dépendances NPM
├── monitoring/                  # Monitoring
│   ├── logger.py                # Logging rotatif
│   └── metrics.py               # Métriques système
├── scripts/                     # Scripts utilitaires
│   ├── train_initial.py         # Entraînement initial
│   └── retrain.py               # Retraining automatique
├── .env.example                 # Variables d'environnement
├── requirements.txt             # Dépendances Python
├── docker-compose.yml           # PostgreSQL + Redis
├── Dockerfile                   # Image Docker backend
└── README.md
```

---

## 🚀 Installation

### Prérequis

- Python 3.10+
- Node.js 18+
- Docker & Docker Compose
- Git

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

### 3. Démarrer les services (PostgreSQL + Redis)

```bash
docker-compose up -d
```

### 4. Installer les dépendances Python

```bash
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

### 5. Initialiser la base de données

```bash
psql -h localhost -U nds_user -d network_defense -f backend/database/migrations/initial_schema.sql
```

### 6. Installer le dashboard

```bash
cd dashboard
npm install
cd ..
```

---

## 🎮 Utilisation

### Démarrer le Backend

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Démarrer le Dashboard

```bash
cd dashboard
npm run dev
```

### Entraîner les modèles AI

```bash
python scripts/train_initial.py \
  --dataset-dir ./data/cic-ids/ \
  --output-dir ./models \
  --architecture mlp \
  --epochs-supervised 50 \
  --epochs-unsupervised 100
```

### Accéder aux interfaces

| Interface | URL |
|-----------|-----|
| Dashboard | http://localhost:3000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| API Docs (ReDoc) | http://localhost:8000/redoc |
| Health Check | http://localhost:8000/health |

---

## 🧠 Pipeline AI

### Modèle Supervisé (Classification)

```
CIC-IDS2017/2018 CSV → Feature Selection → Scaling → MLP/CNN-1D → Attack Type + Confidence
```

**Classes détectées :** BENIGN, DDoS, PortScan, BruteForce, DoS, Botnet, Web Attack

### Modèle Non-supervisé (Anomalies)

```
Trafic Normal → Scaling → Autoencoder/VAE → Reconstruction Error → Seuil Adaptatif
```

**Détection :** Seuil dynamique = μ + 3σ (calibré sur le percentile 99)

### Moteur Hybride

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│ Supervisé       │────▶│ Hybrid Decision  │────▶│ Décision     │
│ (type + conf.)  │     │ Engine           │     │ + Severity   │
├─────────────────┤     │                  │     │ + SOC Priority│
│ Non-supervisé   │────▶│ Poids configurés │     └──────────────┘
│ (anomaly score) │     │ 50% / 30% / 20%  │
├─────────────────┤     │                  │
│ Réputation IP   │────▶│                  │
└─────────────────┘     └──────────────────┘
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
| `GET` | `/api/geo/attack-map` | Données pour la carte des attaques |
| `GET` | `/api/dashboard/overview` | Vue d'ensemble des métriques |
| `GET` | `/api/models/versions/{type}` | Liste les versions d'un modèle |
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
| `SUPERVISED_ARCH` | Architecture supervisée | mlp |
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
