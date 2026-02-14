"""
Constructeur de flux réseau (Flow Builder).
Agrège les paquets en flux basés sur le 5-tuple avec timeout.
"""

import logging
import time
from typing import Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class NetworkFlow:
    """Représente un flux réseau (session bidirectionnelle)."""

    def __init__(self, flow_key: tuple, first_packet: dict):
        self.flow_key = flow_key
        self.src_ip = first_packet["src_ip"]
        self.dst_ip = first_packet["dst_ip"]
        self.src_port = first_packet["src_port"]
        self.dst_port = first_packet["dst_port"]
        self.protocol = first_packet["protocol"]

        self.start_time = first_packet["timestamp"]
        self.last_time = first_packet["timestamp"]

        # Compteurs
        self.fwd_packets: List[dict] = []
        self.bwd_packets: List[dict] = []

        # Ajouter le premier paquet
        self._add_packet(first_packet)

    def _add_packet(self, packet: dict):
        """Ajoute un paquet au flux (forward ou backward)."""
        if packet["src_ip"] == self.src_ip:
            self.fwd_packets.append(packet)
        else:
            self.bwd_packets.append(packet)

        self.last_time = max(self.last_time, packet["timestamp"])

    def add_packet(self, packet: dict):
        """Ajoute un paquet et met à jour les timestamps."""
        self._add_packet(packet)

    @property
    def duration(self) -> float:
        """Durée du flux en secondes."""
        return max(0.0, self.last_time - self.start_time)

    @property
    def total_fwd_packets(self) -> int:
        return len(self.fwd_packets)

    @property
    def total_bwd_packets(self) -> int:
        return len(self.bwd_packets)

    @property
    def total_packets(self) -> int:
        return self.total_fwd_packets + self.total_bwd_packets

    @property
    def is_complete(self) -> bool:
        """Un flux est considéré complet s'il a des paquets dans les deux directions."""
        return self.total_fwd_packets > 0 and self.total_bwd_packets > 0

    def to_dict(self) -> dict:
        """Convertit le flux en dictionnaire."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": self.duration,
            "start_time": self.start_time,
            "end_time": self.last_time,
            "total_fwd_packets": self.total_fwd_packets,
            "total_bwd_packets": self.total_bwd_packets,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
        }


class FlowBuilder:
    """
    Agrège les paquets capturés en flux réseau (5-tuple + timeout).

    Un flux est identifié par : (src_ip, dst_ip, src_port, dst_port, protocol)
    Les paquets de la direction inverse sont regroupés dans le même flux.
    """

    def __init__(self, flow_timeout: int = 120):
        """
        Args:
            flow_timeout: Timeout d'inactivité d'un flux en secondes.
        """
        self.flow_timeout = flow_timeout
        self.active_flows: Dict[tuple, NetworkFlow] = {}
        self._completed_flows: List[NetworkFlow] = []

    def _get_flow_key(self, packet: dict) -> tuple:
        """
        Génère la clé de flux bidirectionnelle.
        Trie src/dst pour que les deux directions mappent au même flux.
        """
        src = (packet["src_ip"], packet["src_port"])
        dst = (packet["dst_ip"], packet["dst_port"])
        proto = packet["protocol"]

        # Normaliser : le plus petit IP en premier
        if src < dst:
            return (src[0], dst[0], src[1], dst[1], proto)
        else:
            return (dst[0], src[0], dst[1], src[1], proto)

    def process_packet(self, packet: dict) -> Optional[NetworkFlow]:
        """
        Traite un paquet et l'ajoute au flux correspondant.

        Args:
            packet: Dictionnaire de métadonnées du paquet.

        Returns:
            NetworkFlow complété si le timeout est dépassé, None sinon.
        """
        flow_key = self._get_flow_key(packet)

        if flow_key in self.active_flows:
            flow = self.active_flows[flow_key]
            flow.add_packet(packet)
        else:
            flow = NetworkFlow(flow_key, packet)
            self.active_flows[flow_key] = flow

        return None

    def process_batch(self, packets: List[dict]) -> List[NetworkFlow]:
        """
        Traite un batch de paquets et retourne les flux complétés.

        Args:
            packets: Liste de paquets.

        Returns:
            Liste de flux complétés (timeout dépassé).
        """
        for packet in packets:
            self.process_packet(packet)

        # Vérifier les timeouts
        completed = self.check_timeouts()
        return completed

    def check_timeouts(self) -> List[NetworkFlow]:
        """Vérifie et retourne les flux qui ont dépassé le timeout."""
        current_time = time.time()
        completed = []
        expired_keys = []

        for key, flow in self.active_flows.items():
            if current_time - flow.last_time > self.flow_timeout:
                completed.append(flow)
                expired_keys.append(key)

        for key in expired_keys:
            del self.active_flows[key]

        if completed:
            logger.debug(f"{len(completed)} flux complétés par timeout")

        self._completed_flows.extend(completed)
        return completed

    def force_complete_all(self) -> List[NetworkFlow]:
        """Force la complétion de tous les flux actifs."""
        completed = list(self.active_flows.values())
        self._completed_flows.extend(completed)
        self.active_flows.clear()
        logger.info(f"Force complete : {len(completed)} flux")
        return completed

    @property
    def active_flow_count(self) -> int:
        return len(self.active_flows)

    @property
    def completed_flow_count(self) -> int:
        return len(self._completed_flows)
