#!/usr/bin/env python3
"""EC358 fixed isolated offline reviewer issue / rotate / revoke auditor."""
from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from reviewer_epochs.operator import main
if __name__=='__main__':raise SystemExit(main())
