"""
Moteur LLM unifié — Network Defense System.
Supporte dynamiquement : OpenAI (ChatGPT), DeepSeek, Google Gemini,
Groq et Ollama (local).
La configuration est lue depuis le service llm_config_service
ou peut être passée directement (pour les tests de connexion).
"""

import json
import logging
import httpx
from openai import AsyncOpenAI
from typing import Any, Dict, Optional

logger = logging.getLogger("NDS.Reporting.LLM")

# Mapping provider_id → base_url compatible OpenAI
PROVIDER_BASE_URLS: Dict[str, Optional[str]] = {
    "openai":   None,                                                           # API officielle OpenAI
    "deepseek": "https://api.deepseek.com/v1",
    "gemini":   "https://generativelanguage.googleapis.com/v1beta/openai/",    # Endpoint OpenAI-compatible de Google
    "groq":     "https://api.groq.com/openai/v1",
}

# Ces fournisseurs supportent fiablement response_format=json_object
SUPPORTS_JSON_FORMAT = {"openai", "deepseek", "groq"}


async def generate_llm_analysis(
    prompt: str,
    config: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    Génère l'analyse LLM à partir du prompt et d'une configuration dynamique.

    Args:
        prompt:  Texte complet à envoyer au LLM.
        config:  Dictionnaire de configuration (provider, model, api_key, …).
                 Si None, la configuration sauvegardée est utilisée.

    Returns:
        Dictionnaire JSON structuré produit par le LLM.

    Raises:
        ValueError: API key manquante, provider inconnu.
        httpx.HTTPStatusError: Problème réseau / réponse HTTP non-200.
        Exception: Toute autre erreur remontée pour gestion par l'appelant.
    """
    # Charger la config sauvegardée si aucune n'est passée
    if config is None:
        from backend.services.llm_config_service import load_config
        config = load_config()

    provider        = config.get("provider", "ollama").lower()
    model           = config.get("model", "llama3")
    api_key         = config.get("api_key", "")
    temperature     = float(config.get("temperature", 0.2))
    max_tokens      = int(config.get("max_tokens", 2048))
    ollama_base_url = config.get("ollama_base_url", "http://localhost:11434/api")

    logger.info(f"Génération LLM — fournisseur: {provider} | modèle: {model}")

    fallback_response = {
        "executive_summary": (
            "Impossible de générer le résumé. "
            "Le serveur LLM est indisponible ou a échoué."
        ),
        "technical_analysis": "Pas d'analyse technique disponible.",
        "attacker_behavior":  "Pas d'analyse comportementale disponible.",
        "recommendations": [
            "Vérifiez votre configuration LLM dans la section Reporting.",
            "Assurez-vous que la clé API est valide et que le service est accessible.",
        ],
    }

    # ── Ollama (local) ─────────────────────────────────────────────────────────
    if provider == "ollama":
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{ollama_base_url}/generate",
                json={
                    "model":  model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            response.raise_for_status()
            data        = response.json()
            result_text = data.get("response", "{}")

            try:
                return json.loads(result_text)
            except json.JSONDecodeError as e:
                logger.error(f"Ollama — JSON invalide: {e}. Brut: {result_text[:300]}")
                return fallback_response

    # ── Fournisseurs cloud compatibles OpenAI ──────────────────────────────────
    if provider not in PROVIDER_BASE_URLS:
        raise ValueError(f"Fournisseur LLM inconnu : '{provider}'")

    if not api_key:
        raise ValueError(
            f"Clé API manquante pour le fournisseur '{provider}'. "
            "Configurez-la dans la section Reporting."
        )

    base_url = PROVIDER_BASE_URLS[provider]
    client   = AsyncOpenAI(api_key=api_key, base_url=base_url)

    create_kwargs: Dict[str, Any] = {
        "model": model,
        "messages": [
            {
                "role":    "system",
                "content": "You are a cybersecurity SOC analyst. Output ONLY valid JSON, no markdown fences.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens":  max_tokens,
    }

    # response_format n'est pas supporté par tous les fournisseurs
    if provider in SUPPORTS_JSON_FORMAT:
        create_kwargs["response_format"] = {"type": "json_object"}

    response = await client.chat.completions.create(**create_kwargs)
    content  = response.choices[0].message.content or ""

    # Nettoyer les éventuels blocs markdown (Gemini peut en insérer)
    content = content.strip()
    if content.startswith("```"):
        lines   = content.splitlines()
        content = "\n".join(
            line for line in lines if not line.startswith("```")
        ).strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"LLM ({provider}) — JSON invalide: {e}. Brut: {content[:300]}")
        return fallback_response


async def test_llm_connection(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Effectue un test de connexion minimal avec la configuration fournie.

    Returns:
        {"success": bool, "message": str, "provider": str, "model": str}
    """
    provider        = config.get("provider", "ollama").lower()
    model           = config.get("model", "llama3")
    api_key         = config.get("api_key", "")
    ollama_base_url = config.get("ollama_base_url", "http://localhost:11434/api")

    try:
        if provider == "ollama":
            base = ollama_base_url.rstrip("/")
            if base.endswith("/api"):
                base = base[:-4]
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{base}/api/tags")
                r.raise_for_status()
                tags             = r.json()
                models_available = [m["name"] for m in tags.get("models", [])]
                match            = model in models_available or any(
                    model in m for m in models_available
                )
                if match:
                    return {
                        "success": True,
                        "message": f"Ollama connecté. Modèle '{model}' disponible.",
                        "provider": provider,
                        "model": model,
                    }
                return {
                    "success": False,
                    "message": (
                        f"Ollama connecté mais modèle '{model}' introuvable. "
                        f"Modèles disponibles : {', '.join(models_available[:5]) or 'aucun'}."
                    ),
                    "provider": provider,
                    "model": model,
                }

        # Cloud providers
        if not api_key:
            return {
                "success": False,
                "message": "Clé API manquante. Veuillez saisir votre clé API.",
                "provider": provider,
                "model": model,
            }

        if provider not in PROVIDER_BASE_URLS:
            return {
                "success": False,
                "message": f"Fournisseur '{provider}' non reconnu.",
                "provider": provider,
                "model": model,
            }

        base_url = PROVIDER_BASE_URLS[provider]
        client   = AsyncOpenAI(api_key=api_key, base_url=base_url)

        resp  = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with the single word: OK"}],
            max_tokens=5,
        )
        reply = resp.choices[0].message.content or ""

        return {
            "success": True,
            "message": f"Connexion réussie. Réponse du modèle : '{reply.strip()}'",
            "provider": provider,
            "model": model,
        }

    except httpx.ConnectError:
        return {
            "success": False,
            "message": (
                f"Impossible de joindre le serveur Ollama à '{ollama_base_url}'. "
                "Vérifiez qu'il est bien démarré."
            ),
            "provider": provider,
            "model": model,
        }
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "message": f"Erreur HTTP {e.response.status_code}: {e.response.text[:200]}",
            "provider": provider,
            "model": model,
        }
    except Exception as e:
        err = str(e)
        if "api_key" in err.lower() or "authentication" in err.lower() or "unauthorized" in err.lower() or "401" in err:
            msg = "Clé API invalide ou non autorisée."
        elif "model" in err.lower() and ("not found" in err.lower() or "does not exist" in err.lower()):
            msg = f"Modèle '{model}' introuvable chez ce fournisseur."
        elif "rate limit" in err.lower() or "429" in err:
            msg = "Limite de débit (rate limit) atteinte. Réessayez dans quelques secondes."
        elif "connect" in err.lower() or "timeout" in err.lower():
            msg = "Délai de connexion dépassé. Vérifiez votre réseau."
        else:
            msg = f"Erreur : {err}"

        return {
            "success": False,
            "message": msg,
            "provider": provider,
            "model": model,
        }
