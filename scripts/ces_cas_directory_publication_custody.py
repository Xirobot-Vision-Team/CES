#!/usr/bin/env python3
"""EC362 fixed isolated offline multi-source signed directory evidence audit."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec362_publication_custody.operator import main
if __name__=='__main__':raise SystemExit(main())
