#!/usr/bin/env python3
"""EC359 fixed isolated offline issuer-signed owner distribution auditor."""
from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'construction'))
from owner_distribution.operator import main
if __name__ == '__main__':raise SystemExit(main())
