#!/usr/bin/env python3
"""EC284: independently authorized exact local knowledge metadata saver."""
from __future__ import annotations
from pathlib import Path
import sys

HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HOME / 'construction'))
from knowledge_save_host.operator import main

if __name__ == '__main__':
    sys.exit(main())
