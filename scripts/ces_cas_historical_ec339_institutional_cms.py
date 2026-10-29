#!/usr/bin/env python3
"""Isolated EC407 read-only CMS receiver, preserving every real EC406 ancestor."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from ec407_institutional_cms.operator import main

if __name__=='__main__':
    raise SystemExit(main())
