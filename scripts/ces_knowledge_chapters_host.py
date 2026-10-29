#!/usr/bin/env python3
"""EC283: standalone independently authorized KnowledgeQuery.Chapters reader."""
from __future__ import annotations
from pathlib import Path
import sys

HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HOME / 'construction'))
from ec283_knowledge_chapters_host.operator import main

if __name__ == '__main__':
    sys.exit(main())
