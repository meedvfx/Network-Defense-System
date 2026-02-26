import os
import json
import logging
import httpx
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()
from backend.core.config import get_settings

logger = logging.getLogger("NDS.Reporting.LLM")

# Assurez-vous que GET_SETTINGS() récupère ces variables, ou on les lit via os.environ ici.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")
LLM_MODEL = os.getenv("LLM_MODEL", "llama3")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/api")

async def generate_llm_analysis(prompt: str) -> dict:
    """
    Envoie le prompt au LLM (Ollama ou autre API compatible OpenAI)
    et récupère le résultat sous forme de JSON structuré.
    """
    logger.info(f"Début de la génération LLM via le fournisseur {LLM_PROVIDER} (Modèle: {LLM_MODEL})")

    # Valeurs par défaut en cas d'échec
    fallback_response = {
        "executive_summary": "Impossible de générer le résumé. Le serveur LLM est indisponible ou a échoué.",
        "technical_analysis": "Pas d'analyse technique disponible.",
        "attacker_behavior": "Pas d'analyse comportementale disponible.",
        "recommendations": ["Vérifiez votre configuration LLM.", "Assurez-vous qu'Ollama/l'API est en ligne."]
    }

    try:
        if LLM_PROVIDER.lower() == "ollama":
            # Appel API Ollama Direct
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{OLLAMA_BASE_URL}/generate",
                    json={
                        "model": LLM_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json" # Ollama supporte la contrainte JSON
                    }
                )
                response.raise_for_status()
                data = response.json()
                result_text = data.get("response", "{}")
                
                try:
                    parsed_json = json.loads(result_text)
                    return parsed_json
                except json.JSONDecodeError as e:
                    logger.error(f"Le LLM (Ollama) n'a pas renvoyé un JSON valide: {e}. Texte brut: {result_text}")
                    return fallback_response

        # Sinon (ex: Groq ou OpenAI compatible API)
        else:
            api_key = os.getenv(f"{LLM_PROVIDER.upper()}_API_KEY", "no_key")
            base_url = None
            if LLM_PROVIDER.lower() == "groq":
                base_url = "https://api.groq.com/openai/v1"
            
            client = AsyncOpenAI(api_key=api_key, base_url=base_url)
            
            response = await client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that strictly outputs JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" },
                temperature=0.2, # Faible créativité, forte précision
            )
            
            content = response.choices[0].message.content
            try:
                parsed_json = json.loads(content)
                return parsed_json
            except json.JSONDecodeError as e:
                logger.error(f"Le LLM n'a pas renvoyé un JSON valide: {e}")
                return fallback_response
                
    except Exception as e:
        logger.error(f"Erreur globale lors de la génération LLM : {str(e)}")
        return fallback_response
