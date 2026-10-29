#!/usr/bin/env python3
"""EC360 isolated, offline authority/revocation/directory evidence auditor.

Never fetch external URL/OS trust stores; never sign, create keys, or write CAS.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from authority_directory.operator import main
if __name__=='__main__':raise SystemExit(main())
