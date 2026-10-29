#!/usr/bin/env python3
"""EC370 fixed detached-only, offline publication/observation audit entrypoint."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from ec370_publication_accountability.operator import main
if __name__=='__main__':raise SystemExit(main())
