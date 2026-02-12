"""
Capture de paquets réseau en temps réel via Scapy.
Thread séparé avec buffer circulaire pour absorber les pics.
"""

import logging
import threading
import time
from typing import Callable, Optional
from collections import deque

from scapy.all import sniff, IP, TCP, UDP, Packet

logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Capture de paquets réseau en thread séparé.
    Utilise un buffer circulaire pour découpler capture et traitement.
    """

    def __init__(
        self,
        interface: str = "eth0",
        buffer_size: int = 1000,
        bpf_filter: str = "ip",
        callback: Optional[Callable] = None,
    ):
        """
        Args:
            interface: Interface réseau à écouter.
            buffer_size: Taille du buffer circulaire.
            bpf_filter: Filtre BPF (Berkeley Packet Filter).
            callback: Fonction appelée pour chaque paquet.
        """
        self.interface = interface
        self.buffer_size = buffer_size
        self.bpf_filter = bpf_filter
        self.callback = callback

        self.packet_buffer: deque = deque(maxlen=buffer_size)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0

    def _packet_handler(self, packet: Packet):
        """Handler appelé par Scapy pour chaque paquet capturé."""
        if IP not in packet:
            return

        self._packet_count += 1

        # Extraire les métadonnées essentielles
        packet_info = self._extract_packet_info(packet)
        if packet_info:
            self.packet_buffer.append(packet_info)

            # Callback optionnel
            if self.callback:
                self.callback(packet_info)

    def _extract_packet_info(self, packet: Packet) -> Optional[dict]:
        """Extrait les informations essentielles d'un paquet IP."""
        try:
            ip_layer = packet[IP]
            info = {
                "timestamp": float(packet.time),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "protocol": ip_layer.proto,
                "ip_len": ip_layer.len,
                "ttl": ip_layer.ttl,
                "ip_flags": int(ip_layer.flags),
            }

            # TCP
            if TCP in packet:
                tcp = packet[TCP]
                info.update({
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "tcp_flags": int(tcp.flags),
                    "tcp_window": tcp.window,
                    "tcp_seq": tcp.seq,
                    "tcp_ack": tcp.ack,
                    "payload_size": len(tcp.payload) if tcp.payload else 0,
                })
            # UDP
            elif UDP in packet:
                udp = packet[UDP]
                info.update({
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "tcp_flags": 0,
                    "tcp_window": 0,
                    "tcp_seq": 0,
                    "tcp_ack": 0,
                    "payload_size": len(udp.payload) if udp.payload else 0,
                })
            else:
                info.update({
                    "src_port": 0,
                    "dst_port": 0,
                    "tcp_flags": 0,
                    "tcp_window": 0,
                    "tcp_seq": 0,
                    "tcp_ack": 0,
                    "payload_size": 0,
                })

            return info

        except Exception as e:
            logger.debug(f"Erreur extraction paquet: {e}")
            return None

    def start(self):
        """Démarre la capture en thread séparé."""
        if self._running:
            logger.warning("Le sniffer est déjà en cours d'exécution")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="PacketSniffer"
        )
        self._thread.start()
        logger.info(f"Sniffer démarré sur {self.interface} (filtre: {self.bpf_filter})")

    def _sniff_loop(self):
        """Boucle de capture Scapy."""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            logger.error(f"Erreur capture : {e}")
            self._running = False

    def stop(self):
        """Arrête la capture."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info(f"Sniffer arrêté. {self._packet_count} paquets capturés au total.")

    def get_buffered_packets(self, count: int = None) -> list:
        """Récupère les paquets du buffer."""
        packets = list(self.packet_buffer)
        if count:
            packets = packets[-count:]
        return packets

    def drain_buffer(self) -> list:
        """Vide le buffer et retourne tous les paquets."""
        packets = list(self.packet_buffer)
        self.packet_buffer.clear()
        return packets

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def buffer_usage(self) -> float:
        """Pourcentage d'utilisation du buffer."""
        return len(self.packet_buffer) / self.buffer_size
