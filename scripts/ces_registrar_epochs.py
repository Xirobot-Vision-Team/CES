#!/usr/bin/env python3
"""EC306 standalone offline registrar epoch history/registration CLI."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from registrar_epochs.operator import main

if __name__=='__main__':
    raise SystemExit(main())
