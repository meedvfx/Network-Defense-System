"""
Service de capture réseau : gère le sniffer et le flow builder.
"""

import logging
from typing import List, Dict, Any

from capture.packet_sniffer import PacketSniffer
from capture.flow_builder import FlowBuilder, NetworkFlow

logger = logging.getLogger(__name__)


class CaptureService:
    """Service encapsulant la capture réseau et le traitement des flux."""

    def __init__(
        self,
        interface: str = "eth0",
        buffer_size: int = 1000,
        flow_timeout: int = 120,
    ):
        self.sniffer = PacketSniffer(
            interface=interface,
            buffer_size=buffer_size,
        )
        self.flow_builder = FlowBuilder(flow_timeout=flow_timeout)

    def start_capture(self):
        """Démarre la capture réseau."""
        logger.info("Démarrage de la capture réseau...")
        self.sniffer.start()

    def stop_capture(self):
        """Arrête la capture réseau."""
        logger.info("Arrêt de la capture réseau...")
        self.sniffer.stop()

    def process_captured_packets(self) -> List[NetworkFlow]:
        """
        Traite les paquets capturés et retourne les flux complétés.

        Returns:
            Liste de flux réseau complétés.
        """
        # Drainer le buffer de paquets
        packets = self.sniffer.drain_buffer()
        if not packets:
            return []

        # Construire les flux
        completed_flows = self.flow_builder.process_batch(packets)

        return completed_flows

    def get_status(self) -> Dict[str, Any]:
        """Retourne l'état du service de capture."""
        return {
            "is_running": self.sniffer.is_running,
            "packets_captured": self.sniffer.packet_count,
            "buffer_usage": self.sniffer.buffer_usage,
            "active_flows": self.flow_builder.active_flow_count,
            "completed_flows": self.flow_builder.completed_flow_count,
        }
