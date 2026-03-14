"""
Résolution et classification des adresses IP.
Détermine si une IP est publique, privée, ou réservée.
"""

import ipaddress
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Plages IP privées (RFC 1918) et réservées (RFC 5735)
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

RESERVED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback (Localhost)
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (APIPA)
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Réservé (Future Use)
    ipaddress.ip_network("0.0.0.0/8"),         # Réseau courant
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
]


def is_public_ip(ip: str) -> bool:
    """
    Détermine si une adresse IP est publique et routable sur Internet.
    Exclut les IPs privées (LAN), réservées, loopback et link-local.
    Utile pour éviter d'envoyer des IPs locales aux services de géolocalisation.
    """
    try:
        addr = ipaddress.ip_address(sanitize_ip(ip))
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_link_local
            or addr.is_unspecified
        )
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Vérifie si une IP appartient à un réseau privé (RFC 1918)."""
    try:
        addr = ipaddress.ip_address(ip)
        for network in PRIVATE_RANGES:
            if addr in network:
                return True
        return False
    except ValueError:
        return False


def classify_ip(ip: str) -> Dict[str, Any]:
    """
    Analyse une IP pour retourner son type précis.
    Types possibles: public, private, loopback, multicast, reserved, invalid.
    Indique aussi si l'IP est éligible à la géolocalisation (is_geolocatable).
    """
    try:
        addr = ipaddress.ip_address(ip)

        # Loopback (127.0.0.1, ::1)
        if addr.is_loopback:
            return {"ip": ip, "type": "loopback", "is_geolocatable": False}

        # Multicast
        if addr.is_multicast:
            return {"ip": ip, "type": "multicast", "is_geolocatable": False}

        # Réseau Privé
        if is_private_ip(ip):
            return {"ip": ip, "type": "private", "is_geolocatable": False}

        # Plages Réservées
        for network in RESERVED_RANGES:
            if addr in network:
                return {"ip": ip, "type": "reserved", "is_geolocatable": False}

        # IP Publique Standard
        return {
            "ip": ip,
            "type": "public",
            "is_geolocatable": True,
            "version": addr.version,
        }

    except ValueError:
        return {"ip": ip, "type": "invalid", "is_geolocatable": False}


def sanitize_ip(ip: str) -> str:
    """
    Nettoie et valide format d'une adresse IP.
    Supprime les espaces et vérifie la conformité (v4/v6).
    Lève une erreur si l'IP est malformée.
    """
    if ip is None:
        raise ValueError("Adresse IP invalide : None")

    raw = str(ip).strip()
    if not raw:
        raise ValueError("Adresse IP invalide : vide")

    # Support des formats observés en entrée: "1.2.3.4:443", "[2001:db8::1]:443",
    # IPv6 link-local avec zone "fe80::1%eth0", ou valeurs encapsulées dans des tokens.
    if raw.startswith("[") and "]" in raw:
        ip = raw[1:raw.index("]")]
    else:
        ip = raw

    if "%" in ip:
        ip = ip.split("%", 1)[0]

    # IPv4:port -> IPv4
    if "." in ip and ip.count(":") == 1:
        candidate_ip, candidate_port = ip.rsplit(":", 1)
        if candidate_port.isdigit():
            ip = candidate_ip

    ip = ip.strip("\"'[](),; ")

    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"Adresse IP invalide : {ip}")
