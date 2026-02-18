# 🛡️ Problématique et Solution NDS

## 🚨 Le Problème : L'Inadéquation des IDS Traditionnels

Les systèmes de détection d'intrusions (IDS) classiques, comme Snort ou Suricata, reposent majoritairement sur des **signatures**. C'est-à-dire qu'ils comparent le trafic réseau à une base de données de menaces connues.

### Limitations Majeures :
1.  **Impuissance face aux "Zero-Day"** : Une attaque inconnue (n'ayant pas encore de signature) passe inaperçue.
2.  **Faux Positifs Élevés** : Des règles trop strictes génèrent du bruit, fatiguant les analystes (Alert Fatigue).
3.  **Trafic Chiffré** : L'analyse profonde de paquets (DPI) est aveugle face au HTTPS/TLS sans déchiffrement coûteux.
4.  **Adaptabilité Nulle** : Ils ne s'adaptent pas aux changements de comportement légitimes du réseau.

---

## 💡 La Solution : Network Defense System (NDS)

NDS propose une approche **hybride** et **comportementale** basée sur l'Intelligence Artificielle Deep Learning. Au lieu de regarder *ce que contient* le paquet (payload), nous analysons *comment* les machines communiquent (flux).

### 1. Analyse Comportementale des Flux (Flow-Based)
NDS extrait 78+ caractéristiques statistiques (durée, taille des paquets, variance des inter-arrivées, drapeaux TCP...) de chaque flux réseau.
*Avantage* : Fonctionne même sur le trafic chiffré, car les métadonnées statistiques restent visibles.

### 2. Architecture IA Hybride
Pour pallier les faiblesses des modèles uniques, NDS combine deux cerveaux :

| Composant | Type | Rôle | Cible |
|-----------|------|------|-------|
| **Le Gardien** | Supervisé (Classifier) | Reconnaitre les attaques apprises | DDoS, PortScan, BruteForce, Botnet |
| **L'Explorateur** | Non-Supervisé (Autoencoder) | Détecter l'anormalité pure | Attaques 0-day, Anomalies inconnues |

### 3. Matrice de Décision
Le moteur hybride fusionne ces scores avec la réputation de l'IP pour prendre une décision nuancée :
- **Confirmed Attack** : Le Gardien est formel OU L'Explorateur voit une anomalie extrême + IP suspecte.
- **Suspicious** : Comportement anormal détecté par l'Explorateur mais inconnu du Gardien.
- **Benign** : Trafic normal.

---

## 🚀 Valeur Ajoutée pour le SOC
- **Réduction du Bruit** : Moins d'alertes, mais plus qualifiées grâce au score de menace (Threat Score).
- **Visibilité Temps Réel** : Dashboard interactif pour visualiser les attaques en cours au lieu de lire des logs.
- **Explicabilité** : Chaque alerte fournit les raisons (ex: "Confidence IA 98%", "IP en liste noire").
