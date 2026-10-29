#!/usr/bin/env python3
"""EC305 standalone offline signed registrar cutover and governed registration."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec305_registrar_rollover.operator import main

if __name__=='__main__':
    raise SystemExit(main())
