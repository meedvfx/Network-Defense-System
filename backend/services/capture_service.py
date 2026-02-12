"""
Service de capture réseau : gère le sniffer et le flow builder.
"""

import logging
from typing import List, Dict, Any

from capture.packet_sniffer import PacketSniffer
from capture.flow_builder import FlowBuilder, NetworkFlow

logger = logging.getLogger(__name__)


_sniffer = PacketSniffer(interface="auto", buffer_size=1000)
_flow_builder = FlowBuilder(flow_timeout=120)


def configure_capture(interface: str = "auto", buffer_size: int = 1000, flow_timeout: int = 120) -> None:
    """Configure les composants de capture (si arrêtés)."""
    global _sniffer, _flow_builder

    if _sniffer.is_running:
        return

    _sniffer = PacketSniffer(interface=interface, buffer_size=buffer_size)
    _flow_builder = FlowBuilder(flow_timeout=flow_timeout)


def start_capture() -> bool:
    """Démarre la capture réseau."""
    logger.info("Démarrage de la capture réseau...")
    _sniffer.start()
    return _sniffer.is_running


def start_capture_with_fallback() -> bool:
    """Démarre la capture; si échec, bascule en interface auto."""
    if start_capture():
        return True

    configured = _sniffer.interface
    logger.warning(f"Échec capture sur interface '{configured}', tentative en mode auto")
    _sniffer.interface = "auto"
    _sniffer.start()
    return _sniffer.is_running


def stop_capture() -> None:
    """Arrête la capture réseau."""
    logger.info("Arrêt de la capture réseau...")
    _sniffer.stop()


def process_captured_packets() -> List[NetworkFlow]:
    """Traite les paquets capturés et retourne les flux complétés."""
    packets = _sniffer.drain_buffer()
    if not packets:
        return []

    return _flow_builder.process_batch(packets)


def force_complete_all() -> List[NetworkFlow]:
    return _flow_builder.force_complete_all()


def is_running() -> bool:
    return _sniffer.is_running


def set_interface(interface: str) -> None:
    if _sniffer.is_running:
        return
    _sniffer.interface = interface


def get_interface() -> str:
    return _sniffer.interface


def get_status() -> Dict[str, Any]:
    """Retourne l'état du service de capture."""
    return {
        "is_running": _sniffer.is_running,
        "interface": _sniffer.interface,
        "packets_captured": _sniffer.packet_count,
        "buffer_usage": _sniffer.buffer_usage,
        "active_flows": _flow_builder.active_flow_count,
        "completed_flows": _flow_builder.completed_flow_count,
        "last_error": _sniffer.last_error,
        "available_interfaces": _sniffer.available_interfaces,
    }
