#!/usr/bin/env python3
"""Isolated read-only EC409 original signed ETSI trust list receiver."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from trust_list.operator import main
if __name__=='__main__':
    raise SystemExit(main())
