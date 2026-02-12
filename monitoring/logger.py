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
    Configure le logging centralisé.

    Args:
        log_level: Niveau de log (DEBUG, INFO, WARNING, ERROR).
        log_dir: Répertoire des fichiers de log.
        app_name: Nom de l'application.
        max_bytes: Taille max d'un fichier de log.
        backup_count: Nombre de fichiers de backup.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, log_level.upper(), logging.INFO)

    # Format
    detailed_fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    simple_fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(simple_fmt)
    root_logger.addHandler(console)

    # Fichier principal (rotation par taille)
    main_file = RotatingFileHandler(
        filename=log_path / f"{app_name.lower()}.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    main_file.setLevel(level)
    main_file.setFormatter(detailed_fmt)
    root_logger.addHandler(main_file)

    # Fichier erreurs uniquement
    error_file = RotatingFileHandler(
        filename=log_path / f"{app_name.lower()}_errors.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    error_file.setLevel(logging.ERROR)
    error_file.setFormatter(detailed_fmt)
    root_logger.addHandler(error_file)

    # Fichier alertes de sécurité
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

    # Réduire le bruit des dépendances
    for noisy in ["urllib3", "httpx", "asyncio", "sqlalchemy.engine"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(app_name).info(
        f"Logging configuré : level={log_level}, dir={log_dir}"
    )
