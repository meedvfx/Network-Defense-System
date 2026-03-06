"""
Service de configuration LLM sécurisé.
Gère le stockage et la récupération de la configuration LLM côté serveur.
La clé API n'est jamais exposée côté frontend.
"""

import json
import logging
from typing import Any, Dict, Optional
from pathlib import Path

logger = logging.getLogger("NDS.LLMConfig")

# Fichier de configuration stocké côté serveur (hors du dépôt git si ajouté au .gitignore)
CONFIG_FILE = Path(__file__).parent.parent / ".llm_config.json"

# ──────────────────────────────────────────────────────────────────────────────
# Référentiel des fournisseurs LLM supportés
# ──────────────────────────────────────────────────────────────────────────────
PROVIDERS: Dict[str, Dict[str, Any]] = {
    "openai": {
        "name": "ChatGPT (OpenAI)",
        "base_url": None,
        "requires_api_key": True,
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "description": "Modèles GPT d'OpenAI. Puissants et polyvalents. Idéal pour l'analyse SOC approfondie.",
        "doc_url": "https://platform.openai.com/api-keys",
    },
    "deepseek": {
        "name": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "requires_api_key": True,
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "description": "Modèle open-source de DeepSeek. Excellent rapport qualité/prix, faible coût par token.",
        "doc_url": "https://platform.deepseek.com/api_keys",
    },
    "gemini": {
        "name": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "requires_api_key": True,
        "models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "description": "Modèle multimodal de Google. Grande fenêtre de contexte. Tier gratuit disponible.",
        "doc_url": "https://aistudio.google.com/app/apikey",
    },
    "groq": {
        "name": "Groq (Ultra-rapide)",
        "base_url": "https://api.groq.com/openai/v1",
        "requires_api_key": True,
        "models": ["llama-3.3-70b-versatile", "llama3-70b-8192", "mixtral-8x7b-32768"],
        "description": "Inférence ultra-rapide grâce aux puces LPU de Groq. Tier gratuit très généreux.",
        "doc_url": "https://console.groq.com/keys",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "base_url": "http://localhost:11434/api",
        "requires_api_key": False,
        "models": ["llama3.1", "llama3", "mistral", "mixtral", "phi3", "gemma2", "codellama"],
        "description": "Modèles open-source exécutés localement. Gratuit, privé, aucune donnée envoyée en ligne.",
        "doc_url": "https://ollama.ai",
    },
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "provider": "ollama",
    "model": "llama3",
    "api_key": "",
    "temperature": 0.2,
    "max_tokens": 2048,
    "ollama_base_url": "http://localhost:11434/api",
}


def load_config() -> Dict[str, Any]:
    """Charge la configuration LLM depuis le fichier de stockage."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Merge avec les valeurs par défaut pour les nouveaux champs
            return {**DEFAULT_CONFIG, **data}
        except Exception as e:
            logger.error(f"Erreur lecture config LLM: {e}")
    return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> bool:
    """
    Sauvegarde la configuration LLM.
    Si api_key vaut '****' (valeur masquée), conserve l'ancienne clé.
    """
    try:
        current = load_config()
        new_api_key = config.get("api_key", "")

        # Si la clé fournie est la clé masquée ou vide, on garde l'ancienne
        if not new_api_key or "****" in new_api_key:
            new_api_key = current.get("api_key", "")

        safe_config = {
            "provider": str(config.get("provider", DEFAULT_CONFIG["provider"])),
            "model": str(config.get("model", DEFAULT_CONFIG["model"])),
            "api_key": new_api_key,
            "temperature": float(config.get("temperature", DEFAULT_CONFIG["temperature"])),
            "max_tokens": int(config.get("max_tokens", DEFAULT_CONFIG["max_tokens"])),
            "ollama_base_url": str(config.get("ollama_base_url", DEFAULT_CONFIG["ollama_base_url"])),
        }

        CONFIG_FILE.write_text(json.dumps(safe_config, indent=2), encoding="utf-8")
        logger.info(f"Config LLM sauvegardée: provider={safe_config['provider']}, model={safe_config['model']}")
        return True
    except Exception as e:
        logger.error(f"Erreur sauvegarde config LLM: {e}")
        return False


def get_public_config() -> Dict[str, Any]:
    """
    Retourne la configuration LLM sans exposer la clé API complète.
    La clé est masquée (ex: 'sk-l****ABCD').
    """
    cfg = load_config()
    raw_key = cfg.get("api_key", "")
    has_key = bool(raw_key)

    masked_key = ""
    if has_key and len(raw_key) > 8:
        masked_key = raw_key[:4] + "****" + raw_key[-4:]
    elif has_key:
        masked_key = "****"

    return {
        "provider": cfg["provider"],
        "model": cfg["model"],
        "has_api_key": has_key,
        "masked_api_key": masked_key,
        "temperature": cfg["temperature"],
        "max_tokens": cfg["max_tokens"],
        "ollama_base_url": cfg.get("ollama_base_url", DEFAULT_CONFIG["ollama_base_url"]),
        "providers": PROVIDERS,
    }


def get_provider_info(provider_id: str) -> Optional[Dict[str, Any]]:
    """Retourne les informations d'un fournisseur LLM."""
    return PROVIDERS.get(provider_id)
