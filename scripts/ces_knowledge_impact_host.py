#!/usr/bin/env python3
"""Pinned EC282 source/reader authorized KnowledgeImpact host (separate CLI)."""
from __future__ import annotations

from pathlib import Path
import sys

# The only injected import path is this shipped, fixed sibling code tree.
HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HOME / 'construction'))
from knowledge_impact_host.operator import main

if __name__ == '__main__':
    sys.exit(main())
