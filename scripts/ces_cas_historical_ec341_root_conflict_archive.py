#!/usr/bin/env python3
"""EC386 fixed receiver-only authentic old EC341 root conflict audit."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec386_historical_root.operator import main
if __name__=='__main__':raise SystemExit(main())
