#!/usr/bin/env python3
"""EC308: verify external issuer signed CAS claim, without CAS access."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "construction"))
from ec308_cas_receipt.operator import main

if __name__ == "__main__":
    raise SystemExit(main())
