"""
Capture de paquets réseau en temps réel via Scapy.
Thread séparé avec buffer circulaire pour absorber les pics.
"""

import logging
import threading
import time
from typing import Callable, Optional
from collections import deque

from scapy.all import sniff, IP, TCP, UDP, Packet, get_if_list, conf

logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Module de capture réseau basé sur Scapy.
    Fonctionne dans un thread dédié pour ne pas bloquer le thread principal.
    Utilise un tampon (deque) pour stocker temporairement les paquets avant traitement.
    """

    def __init__(
        self,
        interface: str = "eth0",
        buffer_size: int = 1000,
        bpf_filter: str = "ip",
        callback: Optional[Callable] = None,
    ):
        """
        Initialise le sniffer.
        
        Args:
            interface: Nom de l'interface (ex: 'eth0', 'wlan0').
            buffer_size: Nombre max de paquets conservés en mémoire si le consommateur est lent.
            bpf_filter: Filtre de capture (syntaxe tcpdump). Défaut: 'ip' (tout trafic IP).
            callback: Fonction optionnelle appelée à chaque paquet (synchrone, attention perf).
        """
        self.interface = interface
        self.buffer_size = buffer_size
        self.bpf_filter = bpf_filter
        self.callback = callback

        self.packet_buffer: deque = deque(maxlen=buffer_size)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._last_error: Optional[str] = None

    def _resolve_interface(self) -> Optional[str]:
        """
        Détermine l'interface réseau à utiliser.
        Si 'auto' ou vide, laisse Scapy choisir l'interface par défaut du système.
        """
        iface = (self.interface or "").strip()
        if not iface or iface.lower() in {"auto", "default"}:
            return None
        return iface

    def _packet_handler(self, packet: Packet):
        """
        Callback interne appelé par Scapy pour chaque paquet capturé.
        Filtre, parse et stocke le paquet dans le buffer.
        """
        if IP not in packet:
            return

        self._packet_count += 1

        # Extraction des métadonnées (Parsing L3/L4)
        packet_info = self._extract_packet_info(packet)
        if packet_info:
            self.packet_buffer.append(packet_info)

            if self.callback:
                self.callback(packet_info)

    def _extract_packet_info(self, packet: Packet) -> Optional[dict]:
        """
        Convertit un paquet Scapy brut en dictionnaire structuré.
        Extrait les champs clés pour l'analyse de flux (IPs, Ports, Flags, Taille...).
        """
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

            # Gestion spécifique TCP
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
            # Gestion spécifique UDP
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
                # Autres protocoles sur IP (ICMP, etc.)
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
        """
        Lance la capture en arrière-plan (daemon thread).
        """
        if self._running:
            logger.warning("Le sniffer est déjà en cours d'exécution")
            return

        self._last_error = None
        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="PacketSniffer"
        )
        self._thread.start()
        iface = self._resolve_interface() or str(conf.iface)
        logger.info(f"Sniffer démarré sur {iface} (filtre: {self.bpf_filter})")

    def _sniff_loop(self):
        """
        Boucle principale de capture.
        Gère les spécificités OS (Windows/Npcap) et les fallbacks (L2 vs L3 socket).
        """
        iface = self._resolve_interface()

        def _run_sniff(filter_value: Optional[str] = None, use_l3_socket: bool = False):
            kwargs = {
                "prn": self._packet_handler,
                "store": False, # Ne pas garder les paquets en mémoire RAM (leak)
                "stop_filter": lambda _: not self._running,
            }

            if filter_value:
                kwargs["filter"] = filter_value

            if use_l3_socket:
                kwargs["opened_socket"] = conf.L3socket(iface=iface)
            else:
                kwargs["iface"] = iface

            sniff(**kwargs)

        try:
            _run_sniff(filter_value=self.bpf_filter)
        except Exception as e:
            err = str(e)
            # Gestion robuste des erreurs Windows / Driver Npcap manquant ou incompatible
            if self.bpf_filter and ("filter" in err.lower() or "pcap" in err.lower()):
                logger.warning(f"Filtre BPF indisponible ({err}), retry sans filtre")
                try:
                    _run_sniff()
                    return
                except Exception as retry_e:
                    retry_err = str(retry_e)
                    # Ultime secours : Socket niveau 3 (OS raw socket) si driver L2 absent
                    if "layer 2" in retry_err.lower() or "winpcap" in retry_err.lower():
                        logger.warning("Capture L2 indisponible, tentative en Layer-3")
                        try:
                            _run_sniff(use_l3_socket=True)
                            return
                        except Exception as l3_e:
                            self._last_error = str(l3_e)
                            logger.error(f"Erreur capture (Layer-3) : {l3_e}")
                            self._running = False
                            return

                    self._last_error = retry_err
                    logger.error(f"Erreur capture (sans filtre) : {retry_e}")
                    self._running = False
                    return

            if "layer 2" in err.lower() or "winpcap" in err.lower():
                logger.warning("Capture L2 indisponible, tentative en Layer-3")
                try:
                    _run_sniff(use_l3_socket=True)
                    return
                except Exception as l3_e:
                    self._last_error = str(l3_e)
                    logger.error(f"Erreur capture (Layer-3) : {l3_e}")
                    self._running = False
                    return

            self._last_error = err
            logger.error(f"Erreur capture : {e}")
            self._running = False

    def stop(self):
        """Arrête la capture proprement et attend la fin du thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info(f"Sniffer arrêté. {self._packet_count} paquets capturés au total.")

    def get_buffered_packets(self, count: int = None) -> list:
        """Retourne une copie des paquets sans vider le buffer (Peeking)."""
        packets = list(self.packet_buffer)
        if count:
            packets = packets[-count:]
        return packets

    def drain_buffer(self) -> list:
        """Vide le buffer et retourne tous les paquets (Consuming)."""
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
        """Taux d'occupation du buffer (0.0 à 1.0)."""
        return len(self.packet_buffer) / self.buffer_size

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    @property
    def available_interfaces(self) -> list:
        """Liste les interfaces détectées par Scapy."""
        try:
            return list(get_if_list())
        except Exception:
            return []
