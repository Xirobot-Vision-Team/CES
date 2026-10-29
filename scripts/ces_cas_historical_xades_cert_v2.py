#!/usr/bin/env python3
"""EC411 fixed offline XAdES V2 genuine original signed-certificate receiver."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'construction'))
from xades_certificate.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
