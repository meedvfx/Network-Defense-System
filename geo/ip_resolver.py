"""
Résolution et classification des adresses IP.
Détermine si une IP est publique, privée, ou réservée.
"""

import ipaddress
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Plages IP privées et réservées
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

RESERVED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
]


def is_public_ip(ip: str) -> bool:
    """Vérifie si une IP est publique (géolocalisable)."""
    try:
        addr = ipaddress.ip_address(ip)

        # IPv6 check
        if addr.version == 6:
            return not addr.is_private and not addr.is_loopback

        # IPv4 checks
        for network in PRIVATE_RANGES + RESERVED_RANGES:
            if addr in network:
                return False

        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Vérifie si une IP est privée."""
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
    Classifie une IP et retourne ses informations.

    Returns:
        Dict avec type (public/private/reserved/invalid), is_geolocatable, etc.
    """
    try:
        addr = ipaddress.ip_address(ip)

        # Loopback
        if addr.is_loopback:
            return {"ip": ip, "type": "loopback", "is_geolocatable": False}

        # Multicast
        if addr.is_multicast:
            return {"ip": ip, "type": "multicast", "is_geolocatable": False}

        # Private
        if is_private_ip(ip):
            return {"ip": ip, "type": "private", "is_geolocatable": False}

        # Reserved
        for network in RESERVED_RANGES:
            if addr in network:
                return {"ip": ip, "type": "reserved", "is_geolocatable": False}

        # Public
        return {
            "ip": ip,
            "type": "public",
            "is_geolocatable": True,
            "version": addr.version,
        }

    except ValueError:
        return {"ip": ip, "type": "invalid", "is_geolocatable": False}


def sanitize_ip(ip: str) -> str:
    """Nettoie et valide une adresse IP."""
    ip = ip.strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"Adresse IP invalide : {ip}")
