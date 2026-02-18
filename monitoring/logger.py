"""
Configuration du logging centralisé pour le système NDS.
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path


def setup_logging(
    log_level: str = "INFO",
    log_dir: str = "./logs",
    app_name: str = "NDS",
    max_bytes: int = 10_485_760,   # 10 MB
    backup_count: int = 5,
):
    """
    Configure le système de logging centralisé de l'application.
    Crée plusieurs fichiers de logs avec rotation automatique.

    Args:
        log_level: Niveau minimal de log (DEBUG, INFO, WARNING, ERROR).
        log_dir: Dossier de destination des logs (créé si inexistant).
        app_name: Préfixe des fichiers de log.
        max_bytes: Taille max d'un fichier avant rotation (défaut: 10MB).
        backup_count: Nombre d'archives à conserver.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Conversion string -> constante logging
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Format détaillé pour les fichiers (avec ligne et fonction)
    detailed_fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Format simplifié pour la console (lisibilité dev)
    simple_fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

    # Reset du Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    # 1. Console Handler (Sortie standard)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(simple_fmt)
    root_logger.addHandler(console)

    # 2. Main Log File (Rotation par taille)
    # Capture tout ce qui passe (selon le niveau global)
    main_file = RotatingFileHandler(
        filename=log_path / f"{app_name.lower()}.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    main_file.setLevel(level)
    main_file.setFormatter(detailed_fmt)
    root_logger.addHandler(main_file)

    # 3. Error Log File (Erreurs uniquement)
    # Pour isoler les problèmes critiques
    error_file = RotatingFileHandler(
        filename=log_path / f"{app_name.lower()}_errors.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    error_file.setLevel(logging.ERROR)
    error_file.setFormatter(detailed_fmt)
    root_logger.addHandler(error_file)

    # 4. Security Alerts Log File
    # Log dédié pour les alertes de sécurité (audit trail)
    # Usage: logging.getLogger("NDS.security").warning("...")
    security_file = RotatingFileHandler(
        filename=log_path / f"{app_name.lower()}_alerts.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    security_file.setLevel(logging.WARNING)
    security_file.setFormatter(detailed_fmt)
    security_logger = logging.getLogger("NDS.security")
    security_logger.addHandler(security_file)

    # Réduction du bruit des librairies tierces bavardes
    for noisy in ["urllib3", "httpx", "asyncio", "sqlalchemy.engine", "multipart"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(app_name).info(
        f"Logging configuré : level={log_level}, dir={log_dir}"
    )
