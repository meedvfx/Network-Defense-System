# 🛡️ Problématique — Network Defense System

## 🚨 Le Problème : L'Inadéquation des IDS Traditionnels

Les systèmes de détection d'intrusions (IDS) classiques (Snort, Suricata, Zeek) reposent majoritairement sur des **signatures** — ils comparent le trafic réseau transitant à une base de données de menaces connues.

### Limitations Structurelles

| Limitation | Impact Opérationnel |
|------------|---------------------|
| **Attaques Zero-Day** | Une attaque inconnue (sans signature répertoriée) traverse le filet sans déclencher d'alerte |
| **Alert Fatigue** | Des règles heuristiques trop strictes génèrent un bruit continu, les analystes SOC finissent par ignorer les vraies alertes |
| **Trafic Chiffré** | Le Deep Packet Inspection (DPI) est aveugle face à HTTPS/TLS 1.3 sans proxy SSL coûteux |
| **Rigidité** | Aucune adaptation aux changements légitimes de comportement réseau (migration cloud, nouveau service) |
| **Maintenance** | Les bases de signatures nécessitent des mises à jour constantes (lag entre découverte et signature) |

---

## 💡 La Solution NDS : Détection Comportementale par IA Hybride

NDS analyse **comment** les machines communiquent, pas **ce qu'elles** se disent. L'analyse porte sur les flux réseau (métadonnées statistiques), pas sur les payloads.

### 1. Analyse Flow-Based (Implémentée dans `capture/`)

Le `FeatureExtractor` extrait **~80 features CIC-IDS2017 compatibles** par flux réseau :
- Statistiques de tailles de paquets (mean, std, max, min) par direction (Forward/Backward)
- Inter-Arrival Times (IAT) — variance temporelle entre paquets
- Compteurs de drapeaux TCP (SYN, FIN, RST, PSH, ACK, URG)
- Ratios volumétriques et débits (bytes/s, packets/s)

> 🔑 **Avantage** : ces métadonnées statistiques restent exploitables même sur du trafic intégralement chiffré.

### 2. Architecture IA Hybride Dual-Brain

| Modèle | Type | Fichier Source | Cible |
|--------|------|----------------|-------|
| **Le Gardien** | Supervisé (MLP Keras multi-classe) | `ai/inference/supervised_predictor.py` | DDoS, PortScan, BruteForce, Botnet — attaques connues |
| **L'Explorateur** | Non-Supervisé (Auto-Encodeur Keras) | `ai/inference/unsupervised_predictor.py` | Anomalies pures, Zero-Day, comportements inédits |

### 3. Moteur de Fusion (`HybridDecisionEngine`)

Le `hybrid_decision_engine.py` fusionne 3 signaux avec des poids configurables :
- **50%** signal supervisé (classification connue)
- **30%** signal non-supervisé (déviation anomalie)
- **20%** réputation IP externe

4 décisions possibles hiérarchiques :
1. `confirmed_attack` — Les deux cerveaux confirment, ou classification haute confiance (≥ 80%)
2. `suspicious` — Signal ambigu nécessitant investigation
3. `unknown_anomaly` — Détection non-supervisée seule (potentiel Zero-Day)
4. `normal` — Trafic sain

---

## 🚀 Valeur Ajoutée SOC

| Bénéfice | Mécanisme NDS |
|----------|---------------|
| **Réduction du bruit** | Score de risque unifié [0,1] avec seuils configurables, alertes priorisées (1-5) |
| **Couverture Zero-Day** | Auto-Encodeur entraîné uniquement sur le trafic BENIGN, toute déviation est flaggée |
| **Visibilité temps réel** | WebSocket `/ws/alerts` + Redis Pub/Sub, carte d'attaque géolocalisée (Leaflet) |
| **Reporting intelligent** | LLM (Groq/Ollama) traduit les métriques brutes en rapports exécutifs actionnables |
| **Boucle de feedback** | Les analystes étiquettent les alertes (True/False Positive) pour améliorer les futurs modèles |
