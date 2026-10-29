#!/usr/bin/env python3
"""EC335 standalone source-trace nested original closure and receiver audit."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from nested_source_closure.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
