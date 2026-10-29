#!/usr/bin/env python3
"""EC412 fixed isolated original LOTL operator X509 CRL verification."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "construction"))
from lotl_crl.operator import main
if __name__ == "__main__":
    raise SystemExit(main())
