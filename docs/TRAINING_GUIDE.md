# 🧪 Guide d'Entraînement des Modèles — NDS

Ce guide détaille la production des artefacts IA nécessaires au fonctionnement du *Network Defense System*. L'entraînement est effectué **hors de l'application** (Google Colab, Kaggle, Jupyter local avec GPU) et les fichiers résultants sont déposés dans `ai/artifacts/`.

> ⚠️ **Le backend NDS est en mode inférence uniquement.** Il charge les modèles pré-entraînés au démarrage via `ModelLoader.load_all()` et les vérifie via `ArtifactPaths.all_exist()`.

---

## 📦 Artefacts à Produire (6 fichiers)

| # | Fichier | Format | Utilisé par | Rôle |
|---|---------|--------|-------------|------|
| 1 | `model_supervised.keras` | Keras SavedModel | `ModelLoader` → `SupervisedPredictor` | Classifieur multi-classe (MLP) — prédit le type d'attaque |
| 2 | `model_unsupervised.keras` | Keras SavedModel | `ModelLoader` → `UnsupervisedPredictor` | Auto-Encodeur — détecte les anomalies par erreur de reconstruction |
| 3 | `scaler.pkl` | Joblib | `FeaturePipeline.transform()` | `StandardScaler` fitté — normalise les features |
| 4 | `encoder.pkl` | Joblib | `FeaturePipeline.decode_label()` | `LabelEncoder` — convertit index ↔ nom d'attaque |
| 5 | `feature_selector.pkl` | Joblib | `FeaturePipeline.transform()` | `SelectKBest` — réduit la dimensionnalité |
| 6 | `threshold_stats.pkl` | Joblib | `UnsupervisedPredictor` | Dict `{mean, std, threshold}` — seuil anomalie μ+3σ |

**Destination** : `ai/artifacts/` (vérifié par `GET /api/models/status`)

---

## 1. Entraînement du Modèle Supervisé

### Dataset Recommandé
- **CIC-IDS-2017** ou **CIC-IDS-2018** (CSV, ~2.8M lignes)
- Colonnes : ~78 features numériques + colonne `Label` (BENIGN, DDoS, PortScan, etc.)

### Script Complet

```python
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
import tensorflow as tf

# ─── 1. Chargement et nettoyage ────────────────────
df = pd.read_csv("CIC-IDS2017.csv")
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

X = df.drop(columns=["Label"]).values
y = df["Label"].values

# ─── 2. Encodage des labels ───────────────────────
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)
num_classes = len(encoder.classes_)
print(f"Classes ({num_classes}): {list(encoder.classes_)}")
joblib.dump(encoder, "encoder.pkl")  # 💾 Artefact 4/6

# ─── 3. Sélection de Features ─────────────────────
selector = SelectKBest(f_classif, k=min(50, X.shape[1]))
X_selected = selector.fit_transform(X, y_encoded)
print(f"Features: {X.shape[1]} → {X_selected.shape[1]}")
joblib.dump(selector, "feature_selector.pkl")  # 💾 Artefact 5/6

# ─── 4. Normalisation ─────────────────────────────
# ⚠️ CRITIQUE : Le scaler DOIT être fitté APRÈS le feature_selector
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_selected)
joblib.dump(scaler, "scaler.pkl")  # 💾 Artefact 3/6

# ─── 5. Split + Rééquilibrage (SMOTE) ─────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

# ─── 6. Architecture MLP ──────────────────────────
model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(X_train_bal.shape[1],)),
    tf.keras.layers.Dense(256, activation='relu'),
    tf.keras.layers.BatchNormalization(),
    tf.keras.layers.Dropout(0.3),
    tf.keras.layers.Dense(128, activation='relu'),
    tf.keras.layers.BatchNormalization(),
    tf.keras.layers.Dropout(0.3),
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(num_classes, activation='softmax')
])

model.compile(
    optimizer='adam',
    loss='sparse_categorical_crossentropy',
    metrics=['accuracy']
)

# ─── 7. Entraînement ──────────────────────────────
model.fit(
    X_train_bal, y_train_bal,
    epochs=30, batch_size=256,
    validation_data=(X_test, y_test),
    callbacks=[
        tf.keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
        tf.keras.callbacks.ReduceLROnPlateau(patience=3),
    ]
)

# ─── 8. Évaluation ────────────────────────────────
y_pred = model.predict(X_test).argmax(axis=1)
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

# ─── 9. Export ─────────────────────────────────────
model.save("model_supervised.keras")  # 💾 Artefact 1/6
print("✓ model_supervised.keras sauvegardé")
```

---

## 2. Entraînement du Modèle Non-Supervisé (Auto-Encodeur)

### Principe

L'auto-encodeur est entraîné **exclusivement sur le trafic BENIGN**. En production, les attaques produiront une erreur de reconstruction (MSE) élevée, dépassant le seuil μ+3σ calculé ici.

### Script Complet

```python
import pandas as pd
import numpy as np
import joblib
import tensorflow as tf

# ─── 1. Charger les mêmes preprocesseurs ──────────
scaler = joblib.load("scaler.pkl")
selector = joblib.load("feature_selector.pkl")

# ─── 2. Extraire uniquement le trafic BENIGN ──────
df = pd.read_csv("CIC-IDS2017.csv")
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

df_benign = df[df["Label"] == "BENIGN"]
X_benign = df_benign.drop(columns=["Label"]).values

# ⚠️ MÊME pipeline que le supervisé (selector → scaler)
X_selected = selector.transform(X_benign)
X_scaled = scaler.transform(X_selected)

n_features = X_scaled.shape[1]
print(f"Samples BENIGN: {X_scaled.shape[0]}, Features: {n_features}")

# ─── 3. Split Train/Val ───────────────────────────
split = int(0.8 * len(X_scaled))
X_train, X_val = X_scaled[:split], X_scaled[split:]

# ─── 4. Architecture Encoder-Decoder ──────────────
encoding_dim = n_features // 4  # Couche goulot (bottleneck)

autoencoder = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(n_features,)),
    # Encoder
    tf.keras.layers.Dense(n_features // 2, activation='relu'),
    tf.keras.layers.Dense(encoding_dim, activation='relu'),
    # Decoder
    tf.keras.layers.Dense(n_features // 2, activation='relu'),
    tf.keras.layers.Dense(n_features, activation='sigmoid')
])

autoencoder.compile(optimizer='adam', loss='mse')

# ─── 5. Entraînement (input = output) ─────────────
autoencoder.fit(
    X_train, X_train,  # L'AE apprend à reproduire le trafic normal
    epochs=50, batch_size=256,
    validation_data=(X_val, X_val),
    callbacks=[
        tf.keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
    ]
)

# ─── 6. Calcul du seuil d'anomalie ────────────────
reconstructed = autoencoder.predict(X_val)
mse = np.mean(np.square(X_val - reconstructed), axis=1)

threshold_stats = {
    "mean": float(np.mean(mse)),
    "std": float(np.std(mse)),
    "threshold": float(np.mean(mse) + 3 * np.std(mse)),  # μ + 3σ
}
print(f"Seuil anomalie : μ={threshold_stats['mean']:.6f}, σ={threshold_stats['std']:.6f}")
print(f"Threshold (μ+3σ): {threshold_stats['threshold']:.6f}")

joblib.dump(threshold_stats, "threshold_stats.pkl")  # 💾 Artefact 6/6

# ─── 7. Export ─────────────────────────────────────
autoencoder.save("model_unsupervised.keras")  # 💾 Artefact 2/6
print("✓ model_unsupervised.keras sauvegardé")
```

---

## 3. Compatibilité Pipeline : Entraînement ↔ Production

### Ordre de Traitement (CRITIQUE)

L'ordre dans `FeaturePipeline.transform()` (production) **doit être identique** à l'entraînement :

| Étape | Entraînement (Colab) | Production (`feature_pipeline.py`) |
|-------|----------------------|------------------------------------|
| 1 | `DataValidator` (implicite via `dropna`, `replace`) | `DataValidator.validate()` |
| 2 | `selector.transform(X)` | `self.feature_selector.transform(X)` |
| 3 | `scaler.transform(X)` | `self.scaler.transform(X)` |

> ⚠️ Si vous inversez l'ordre scaler/selector entre entraînement et production, les prédictions seront **complètement invalides** sans aucune erreur visible.

### Checklist Avant Déploiement

- [ ] L'`encoder.classes_` contient toutes les classes attendues (BENIGN + types d'attaques)
- [ ] Le `scaler` a été fitté sur les données **après** `feature_selector.transform()`
- [ ] Le `threshold_stats.pkl` a été calculé sur le trafic BENIGN du set de **validation** (pas train)
- [ ] Les 6 fichiers sont nommés **exactement** comme dans le tableau ci-dessus
- [ ] Les fichiers sont déposés dans `ai/artifacts/` (pas dans un sous-dossier)

---

## 4. Déploiement des Artefacts

```bash
# Copier depuis Colab/Jupyter vers le projet
cp model_supervised.keras  /chemin/Network-Defense-System/ai/artifacts/
cp model_unsupervised.keras /chemin/Network-Defense-System/ai/artifacts/
cp scaler.pkl              /chemin/Network-Defense-System/ai/artifacts/
cp encoder.pkl             /chemin/Network-Defense-System/ai/artifacts/
cp feature_selector.pkl    /chemin/Network-Defense-System/ai/artifacts/
cp threshold_stats.pkl     /chemin/Network-Defense-System/ai/artifacts/
```

### Vérification

```bash
# Via Docker (les artefacts sont bind-mountés via docker-compose.yml)
docker compose restart backend

# Vérifier le chargement
curl http://localhost:8000/api/models/status
```

Réponse attendue :
```json
{
  "is_ready": true,
  "artifacts": {
    "supervised_model": {"loaded": true, "exists": true},
    "unsupervised_model": {"loaded": true, "exists": true},
    "scaler": {"loaded": true, "exists": true},
    "encoder": {"loaded": true, "exists": true},
    "feature_selector": {"loaded": true, "exists": true}
  },
  "missing": []
}
```

> **Note** : Si les artefacts sont absents, le backend démarre quand même en **mode dégradé** (pas d'inférence IA). Le log affichera : `⚠ Artifacts AI non disponibles. Le service fonctionnera sans AI.`
