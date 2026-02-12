# 🧪 Guide d'Entraînement des Modèles — Google Colab / Jupyter

Ce guide explique comment entraîner les modèles AI du Network Defense System
**en dehors de l'application principale** (Google Colab ou Jupyter Notebook),
puis les exporter pour la production.

---

## 📦 Artifacts à Produire

| Fichier | Format | Description |
|---------|--------|-------------|
| `model_supervised.keras` | Keras SavedModel | Classifieur multi-classe (MLP ou CNN-1D) |
| `model_unsupervised.keras` | Keras SavedModel | Autoencoder entraîné sur BENIGN uniquement |
| `scaler.pkl` | joblib/pickle | StandardScaler ou MinMaxScaler fitté sur le dataset |
| `encoder.pkl` | joblib/pickle | LabelEncoder avec les classes d'attaques |
| `feature_selector.pkl` | joblib/pickle | SelectKBest ou VarianceThreshold fitté |
| `threshold_stats.pkl` | joblib/pickle | Dict `{"mean", "std", "threshold"}` pour l'anomalie |

Tous ces fichiers doivent être placés dans `ai/artifacts/` avant le lancement.

---

## 1. Entraînement du Modèle Supervisé

### Dataset
- CIC-IDS2017 ou CIC-IDS2018 (CSV)
- ~78 features réseau + colonne `Label`

### Code Colab

```python
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import tensorflow as tf

# ─── 1. Chargement ─────────────────────────────────
df = pd.read_csv("/content/drive/MyDrive/CIC-IDS2017.csv")
df.columns = df.columns.str.strip()

# Nettoyer les infinies et NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Séparer features et labels
X = df.drop(columns=["Label"]).values
y = df["Label"].values

# ─── 2. Encoding des labels ───────────────────────
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)
num_classes = len(encoder.classes_)
print(f"Classes ({num_classes}): {list(encoder.classes_)}")

# Sauvegarder l'encoder
joblib.dump(encoder, "encoder.pkl")

# ─── 3. Feature Selection ─────────────────────────
selector = SelectKBest(f_classif, k=min(50, X.shape[1]))
X_selected = selector.fit_transform(X, y_encoded)
print(f"Features: {X.shape[1]} → {X_selected.shape[1]}")

# Sauvegarder le selector
joblib.dump(selector, "feature_selector.pkl")

# ─── 4. Scaling ───────────────────────────────────
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_selected)

# Sauvegarder le scaler
joblib.dump(scaler, "scaler.pkl")

# ─── 5. Split + SMOTE ─────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

# ─── 6. Modèle MLP ────────────────────────────────
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

model.fit(
    X_train_bal, y_train_bal,
    epochs=30,
    batch_size=256,
    validation_data=(X_test, y_test),
    callbacks=[
        tf.keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
        tf.keras.callbacks.ReduceLROnPlateau(patience=3),
    ]
)

# ─── 7. Évaluation ────────────────────────────────
from sklearn.metrics import classification_report

y_pred = model.predict(X_test).argmax(axis=1)
print(classification_report(y_test, y_pred, target_names=encoder.classes_))

# ─── 8. Export ─────────────────────────────────────
model.save("model_supervised.keras")
print("✓ model_supervised.keras sauvegardé")
```

---

## 2. Entraînement du Modèle Non-Supervisé (Autoencoder)

### Principe
L'autoencoder est entraîné **uniquement sur le trafic BENIGN**.
En production, les attaques produisent une erreur de reconstruction élevée.

### Code Colab

```python
import pandas as pd
import numpy as np
import joblib
import tensorflow as tf

# ─── 1. Charger les mêmes objets de preprocessing ─
scaler = joblib.load("scaler.pkl")
selector = joblib.load("feature_selector.pkl")

# ─── 2. Extraire uniquement le trafic BENIGN ──────
df = pd.read_csv("/content/drive/MyDrive/CIC-IDS2017.csv")
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

df_benign = df[df["Label"] == "BENIGN"]
X_benign = df_benign.drop(columns=["Label"]).values

# Appliquer le MÊME preprocessing que le supervisé
X_selected = selector.transform(X_benign)
X_scaled = scaler.transform(X_selected)

n_features = X_scaled.shape[1]
print(f"Samples BENIGN: {X_scaled.shape[0]}, Features: {n_features}")

# ─── 3. Split ─────────────────────────────────────
X_train, X_val = X_scaled[:int(0.8*len(X_scaled))], X_scaled[int(0.8*len(X_scaled)):]

# ─── 4. Autoencoder ───────────────────────────────
encoding_dim = n_features // 4

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

autoencoder.fit(
    X_train, X_train,
    epochs=50,
    batch_size=256,
    validation_data=(X_val, X_val),
    callbacks=[
        tf.keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
    ]
)

# ─── 5. Calculer le seuil d'anomalie ──────────────
reconstructed = autoencoder.predict(X_val)
mse = np.mean(np.square(X_val - reconstructed), axis=1)

threshold_stats = {
    "mean": float(np.mean(mse)),
    "std": float(np.std(mse)),
    "threshold": float(np.mean(mse) + 3 * np.std(mse)),  # μ + 3σ
}
print(f"Seuil: μ={threshold_stats['mean']:.6f}, σ={threshold_stats['std']:.6f}")
print(f"Threshold (μ+3σ): {threshold_stats['threshold']:.6f}")

joblib.dump(threshold_stats, "threshold_stats.pkl")

# ─── 6. Export ─────────────────────────────────────
autoencoder.save("model_unsupervised.keras")
print("✓ model_unsupervised.keras sauvegardé")
```

---

## 3. Compatibilité Preprocessing / Production

> ⚠️ **CRITIQUE** : L'ordre d'application DOIT être identique entre l'entraînement et la production.

### Ordre dans le code Colab :
1. `feature_selector.transform(X)` → sélection des features
2. `scaler.transform(X)` → normalisation

### Ordre dans `ai/preprocessing/feature_pipeline.py` (production) :
1. `feature_selector.transform(X)` → sélection des features
2. `scaler.transform(X)` → normalisation

✅ Les deux sont synchronisés.

### Checklist avant déploiement :

- [ ] Les mêmes colonnes CSV sont utilisées en entraînement et production
- [ ] Le `scaler` a été fitté APRÈS le `feature_selector`
- [ ] L'`encoder.classes_` contient toutes les classes attendues
- [ ] Le `threshold_stats.pkl` a été calculé sur le trafic BENIGN du set de validation
- [ ] Les fichiers sont nommés exactement comme attendu (voir tableau ci-dessus)

---

## 4. Déploiement des Artifacts

```bash
# Copier les fichiers depuis Colab/Jupyter vers le serveur
cp model_supervised.keras    /path/to/Network-Defense-System/ai/artifacts/
cp model_unsupervised.keras  /path/to/Network-Defense-System/ai/artifacts/
cp scaler.pkl                /path/to/Network-Defense-System/ai/artifacts/
cp encoder.pkl               /path/to/Network-Defense-System/ai/artifacts/
cp feature_selector.pkl      /path/to/Network-Defense-System/ai/artifacts/
cp threshold_stats.pkl       /path/to/Network-Defense-System/ai/artifacts/
```

Puis relancer l'application :
```bash
uvicorn backend.main:app --reload
```

L'API `GET /api/models/status` doit retourner `"all_artifacts_present": true`.
