"""
Service de capture réseau : gère le sniffer et le flow builder.
"""

import logging
from typing import List, Dict, Any

from capture.packet_sniffer import PacketSniffer
from capture.flow_builder import FlowBuilder, NetworkFlow

logger = logging.getLogger(__name__)


# ---- Global Instances ----
# Singleton pour gérer l'état global du sniffer et du constructeur de flux
_sniffer = PacketSniffer(interface="auto", buffer_size=1000)
_flow_builder = FlowBuilder(flow_timeout=120)


def configure_capture(interface: str = "auto", buffer_size: int = 1000, flow_timeout: int = 120) -> None:
    """
    Configure les paramètres de capture si le service n'est pas déjà en cours d'exécution.
    
    Args:
        interface: Nom de l'interface réseau (ex: "eth0", "Wi-Fi") ou "auto".
        buffer_size: Taille du buffer circulaire pour éviter la perte de paquets.
        flow_timeout: Temps d'inactivité avant de considérer un flux comme terminé (en secondes).
    """
    global _sniffer, _flow_builder

    if _sniffer.is_running:
        logger.warning("Tentative de configuration pendant la capture ignorée.")
        return

    _sniffer = PacketSniffer(interface=interface, buffer_size=buffer_size)
    _flow_builder = FlowBuilder(flow_timeout=flow_timeout)


def start_capture() -> bool:
    """
    Démarre le thread de capture de paquets.
    Retourne True si le démarrage est réussi.
    """
    logger.info("Démarrage de la capture réseau...")
    try:
        _sniffer.start()
        return _sniffer.is_running
    except Exception as e:
        logger.error(f"Erreur lors du démarrage de la capture: {e}")
        return False


def start_capture_with_fallback() -> bool:
    """
    Tente de démarrer la capture sur l'interface configurée.
    En cas d'échec (ex: interface invalide), bascule automatiquement sur "auto" et réessaie.
    C'est la méthode recommandée pour le démarrage au boot.
    """
    if start_capture():
        return True

    configured = _sniffer.interface
    logger.warning(f"Échec capture sur interface '{configured}', tentative de bascule en mode 'auto'")
    
    # Reconfiguration en mode auto
    _sniffer.interface = "auto"
    try:
        _sniffer.start()
    except Exception as e:
        logger.error(f"Erreur critique: capture impossible même en mode auto: {e}")
        return False
        
    return _sniffer.is_running


def stop_capture() -> None:
    """Arrête proprement le thread de capture et libère les ressources."""
    logger.info("Arrêt de la capture réseau...")
    _sniffer.stop()


def process_captured_packets() -> List[NetworkFlow]:
    """
    Récupère les paquets du buffer, les assemble en flux, et retourne les flux terminés.
    Cette fonction doit être appelée périodiquement par la boucle principale.
    
    Returns:
        List[NetworkFlow]: Liste des flux terminés (timeout ou fin de connexion TCP) prêts pour l'analyse.
    """
    # 1. Vidage du buffer de paquets bruts
    packets = _sniffer.drain_buffer()
    if not packets:
        return []

    # 2. Reconstitution des flux (TCP Stream Reassembly conceptuel)
    return _flow_builder.process_batch(packets)


def force_complete_all() -> List[NetworkFlow]:
    """Force la clôture de tous les flux actifs (ex: lors de l'arrêt du service)."""
    return _flow_builder.force_complete_all()


def is_running() -> bool:
    """Indique si la capture est active."""
    return _sniffer.is_running


def set_interface(interface: str) -> None:
    """Change l'interface de capture (nécessite un redémarrage du service)."""
    if _sniffer.is_running:
        logger.warning("Impossible de changer l'interface pendant la capture.")
        return
    _sniffer.interface = interface


def get_interface() -> str:
    """Retourne l'interface actuellement configurée."""
    return _sniffer.interface


def get_status() -> Dict[str, Any]:
    """
    Retourne un état complet du service pour le monitoring.
    Inclut les statistiques de paquets, l'usage mémoire buffer, et les erreurs éventuelles.
    """
    return {
        "is_running": _sniffer.is_running,
        "interface": _sniffer.interface,
        "packets_captured": _sniffer.packet_count,
        "buffer_usage": _sniffer.buffer_usage, # Pourcentage remplissage buffer
        "active_flows": _flow_builder.active_flow_count, # Flux en cours de construction
        "completed_flows": _flow_builder.completed_flow_count, # Flux terminés depuis le début
        "last_error": _sniffer.last_error,
        "available_interfaces": _sniffer.available_interfaces, # Liste des interfaces détectées par Scapy
    }
