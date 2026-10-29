#!/usr/bin/env python3
"""EC364 isolated offline cross-EC361-window verification entry."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec364_cross_epoch.operator import main
if __name__=='__main__':raise SystemExit(main())
