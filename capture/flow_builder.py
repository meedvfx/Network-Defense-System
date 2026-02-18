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
    """
    Représente un flux réseau (session bidirectionnelle) identifié par son 5-tuple.
    Stocke les métadonnées et un résumé des paquets échangés (forward/backward).
    """

    def __init__(self, flow_key: tuple, first_packet: dict):
        self.flow_key = flow_key
        # Métadonnées basées sur le premier paquet
        self.src_ip = first_packet["src_ip"]
        self.dst_ip = first_packet["dst_ip"]
        self.src_port = first_packet["src_port"]
        self.dst_port = first_packet["dst_port"]
        self.protocol = first_packet["protocol"]

        self.start_time = first_packet["timestamp"]
        self.last_time = first_packet["timestamp"]

        # Listes de paquets bruts (limitées en taille par l'usage mémoire si nécessaire)
        self.fwd_packets: List[dict] = []
        self.bwd_packets: List[dict] = []

        # Ajouter le premier paquet explicitement
        self._add_packet(first_packet)

    def _add_packet(self, packet: dict):
        """
        Ajoute un paquet au flux en déterminant sa direction (Forward/Backward).
        Met à jour le timestamp de dernière activité.
        """
        if packet["src_ip"] == self.src_ip:
            self.fwd_packets.append(packet)
        else:
            self.bwd_packets.append(packet)

        self.last_time = max(self.last_time, packet["timestamp"])

    def add_packet(self, packet: dict):
        """Interface publique pour ajouter un paquet."""
        self._add_packet(packet)

    @property
    def duration(self) -> float:
        """Durée active du flux en secondes (fin - début)."""
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
        """
        Vérifie si le flux a vu du trafic dans les deux sens.
        Utile pour ignorer les scans SYN sans réponse ou le trafic unidirectionnel (UDP spoofé).
        """
        return self.total_fwd_packets > 0 and self.total_bwd_packets > 0

    def to_dict(self) -> dict:
        """Sérialise le flux pour le stockage ou l'analyse."""
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
    Agrégateur de paquets en flux réseau.
    Groupe les paquets par 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Proto).
    Gère l'expiration des flux inactifs (timeout).
    """

    def __init__(self, flow_timeout: int = 120):
        """
        Args:
            flow_timeout: Temps (sec) après lequel un flux inactif est considéré clos.
        """
        self.flow_timeout = flow_timeout
        self.active_flows: Dict[tuple, NetworkFlow] = {}
        self._completed_flows: List[NetworkFlow] = []

    def _get_flow_key(self, packet: dict) -> tuple:
        """
        Génère une clé unique pour le flux, indépendamment de la direction.
        Trie les IP/Port pour que A->B et B->A aient la même clé.
        """
        src = (packet["src_ip"], packet["src_port"])
        dst = (packet["dst_ip"], packet["dst_port"])
        proto = packet["protocol"]

        # Normalisation canonique : Tuple le plus petit en premier
        if src < dst:
            return (src[0], dst[0], src[1], dst[1], proto)
        else:
            return (dst[0], src[0], dst[1], src[1], proto)

    def process_packet(self, packet: dict) -> Optional[NetworkFlow]:
        """
        Intègre un nouveau paquet. Crée un nouveau flux ou met à jour l'existant.
        Note: Ne retourne pas le flux immédiatement, l'analyse se fait par batch ou timeout.
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
        Traite une liste de paquets et retourne les flux qui viennent d'expirer.
        C'est la méthode principale appelée par le service de capture.
        """
        for packet in packets:
            self.process_packet(packet)

        # Vérification et extraction des flux terminés (timeout)
        completed = self.check_timeouts()
        return completed

    def check_timeouts(self) -> List[NetworkFlow]:
        """Scanne les flux actifs pour détecter ceux qui ont dépassé le timeout d'inactivité."""
        current_time = time.time()
        completed = []
        expired_keys = []

        for key, flow in self.active_flows.items():
            if current_time - flow.last_time > self.flow_timeout:
                completed.append(flow)
                expired_keys.append(key)

        # Nettoyage dict
        for key in expired_keys:
            del self.active_flows[key]

        if completed:
            logger.debug(f"{len(completed)} flux complétés par timeout")

        self._completed_flows.extend(completed)
        return completed

    def force_complete_all(self) -> List[NetworkFlow]:
        """
        Force la fermeture de tous les flux actifs (ex: arrêt du service).
        Renvoie tout ce qui reste en mémoire.
        """
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
