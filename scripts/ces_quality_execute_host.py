#!/usr/bin/env python3
"""EC286 standalone original EC187 QualityRun.Execute exact AF_UNIX host."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec286_quality_execute_host.operator import main
if __name__=='__main__':
    raise SystemExit(main())
