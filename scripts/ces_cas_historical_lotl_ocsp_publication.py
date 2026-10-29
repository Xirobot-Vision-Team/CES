#!/usr/bin/env python3
"""EC414 genuine original WARC OCSP and dual witness signatures, offline."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'construction'))
from ocsp_publication.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
