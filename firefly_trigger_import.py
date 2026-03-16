#!/usr/bin/env python3
"""
Firefly III — Manual Import Trigger
=====================================
Triggers a manual autoimport run on the Firefly-Importer-Auto container
via its localhost-bound port (127.0.0.1:8088).

Requires the port binding in docker-compose.yml:
  ports:
    - "127.0.0.1:8088:8080"

Usage:
  python3 /volume1/docker/firefly/firefly_trigger_import.py

The script will:
  1. POST to the autoimport endpoint
  2. Wait for completion
  3. Print the result and tail the log file for confirmation
"""

import importlib.util
import os
import sys
import time
from datetime import datetime

import requests

# ============================================================
# LOAD CONFIGURATION
# ============================================================
import importlib.util, os as _os
_cfg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "config.py")
_spec = importlib.util.spec_from_file_location("config", _cfg_path)
_cfg  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cfg)

# ============================================================
# CONFIGURATION — loaded from config.py
# ============================================================

IMPORTER_URL    = "http://127.0.0.1:8088"
AUTO_IMPORT_SECRET   = "YOUR_AUTO_IMPORT_SECRET"   # must match AUTO_IMPORT_SECRET in compose
IMPORT_DIRECTORY     = "/var/www/html/storage/upload"
IMPORTER_LOG_FILE    = _cfg.IMPORTER_LOG_FILE

# ============================================================
# MAIN
# ============================================================

def tail_log(path: str, last_n: int = 20) -> list:
    """Return the last N lines of a file."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.readlines()[-last_n:]
    except IOError:
        return []

def main():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] Déclenchement de l'autoimport Firefly III")
    print(f"  URL    : {IMPORTER_URL}/autoimport")
    print(f"  Dossier: {IMPORT_DIRECTORY}")
    print()

    url = f"{IMPORTER_URL}/autoimport"
    params = {
        "secret":    AUTO_IMPORT_SECRET,
        "directory": IMPORT_DIRECTORY,
    }

    try:
        print("Envoi de la requête...")
        resp = requests.post(url, params=params, timeout=120)
        print(f"  → HTTP {resp.status_code}")
        if resp.text.strip():
            print(f"  → Réponse : {resp.text.strip()[:200]}")
    except requests.exceptions.ConnectionError:
        print("  ❌ Connexion refusée — vérifiez que le port 8088 est bien exposé dans docker-compose.yml")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("  ⚠️  Timeout après 120s — l'import est peut-être encore en cours")
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        sys.exit(1)

    # Wait a moment for the log to be flushed
    print()
    print("Attente de 3s pour que les logs soient écrits...")
    time.sleep(3)

    # Tail the log file
    print()
    print(f"Dernières lignes du journal ({IMPORTER_LOG_FILE}) :")
    print("─" * 60)
    lines = tail_log(IMPORTER_LOG_FILE)
    if lines:
        for line in lines:
            print(line, end="")
    else:
        print("  (fichier log vide ou non disponible)")
    print("─" * 60)

if __name__ == "__main__":
    main()
