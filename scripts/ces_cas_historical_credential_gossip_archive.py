#!/usr/bin/env python3
"""EC395 isolated, receiver-only outside-accreditation/gossip/offsite archive audit."""
from __future__ import annotations

import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from accredited_gossip.operator import main
if __name__=='__main__':
    raise SystemExit(main())
