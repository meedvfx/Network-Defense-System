# 📖 Guide Utilisateur - Network Defense System

Ce guide explique comment utiliser le dashboard NDS pour surveiller votre réseau et réagir aux menaces.

## 🖥️ Le Dashboard (Vue d'Ensemble)

L'interface principale est divisée en plusieurs sections clés :

### 1. Threat Score (Jauge Animée)
- **Qu'est-ce que c'est ?** : Un score global de 0 à 100 représentant le niveau de risque actuel du réseau.
- **Interprétation** :
    - 🟢 **0-30** : Calme. Activité normale.
    - 🟡 **30-70** : Vigilance. Activité suspecte ou attaques mineures bloquées.
    - 🔴 **70-100** : Critique ! Attaque massive ou intrusions multiples en cours.

### 2. Carte des Menaces (Attack Map)
- Visualise l'origine géographique des IPs attaquantes.
- Utile pour identifier des campagnes d'attaques coordonnées provenant de pays spécifiques.

### 3. Trafic Temps Réel (Graphique)
- Affiche le volume de trafic analysé par minute.
- Les courbes distinguent le trafic **Normal**, **Suspect** et les **Attaques**.

---

## 🚨 Gestion des Alertes

L'onglet **Alertes** est le cœur opérationnel pour les analystes SOC.

### Comprendre une Alerte
Chaque carte d'alerte contient :
- **Sévérité** : Low, Medium, High, Critical.
- **Type d'Attaque** : Ex: `DoS GoldenEye`, `PortScan`, `SSH-Patator`.
- **Confiance IA** : Pourcentage de certitude du modèle.
- **Source & Destination** : Qui attaque qui.

### Actions Possibles
1.  **Analyser** : Cliquez sur l'alerte pour voir les détails (Payload size, Duration, Flags).
2.  **Feedback (Rétroaction)** :
    - Si l'IA a raison : Validez l'alerte.
    - Si c'est un Faux Positif : Signalez-le ("Marquer comme Bénin").
    - *Note : Ces feedbacks sont cruciaux pour ré-entraîner l'IA et l'améliorer.*

---

## 📊 Statistiques & Rapports

L'onglet **Stats** permet d'analyser les tendances sur 24h, 7 jours ou 30 jours.
- **Top Attaquants** : Les IPs les plus agressives.
- **Distribution** : Camembert des types d'attaques (ex: 60% DDoS, 30% PortScan).

---

## 🔧 Dépannage Rapide

**Le Dashboard n'affiche aucune donnée ?**
1. Vérifiez que le Backend tourne : `http://localhost:8000/docs` doit être accessible.
2. Vérifiez que Redis est lancé (nécessaire pour le temps réel WebSocket).
3. Vérifiez que la capture de paquets est active (Logs backend : "Sniffer démarré").

**Les géolocalisations sont "Local" ?**
- C'est normal si vous testez en réseau local. Les IPs privées (192.168.x.x) ne sont pas géolocalisables.
