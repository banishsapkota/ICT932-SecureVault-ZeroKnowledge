"""Create missing tables without dropping or modifying existing data."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.app import create_app
from src.extensions import db

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "init":
        raise SystemExit("Only non-destructive initialization is supported.")
    with create_app().app_context():
        db.create_all()
        print("SecureVault database initialized.")
