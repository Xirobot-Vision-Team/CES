#!/usr/bin/env python3
"""Standalone EC349 offline dual SHA/time witness read-only importer."""
from __future__ import annotations
import sys
from pathlib import Path

# The installed, fixed sibling project root is the only trusted module source.
root = str(Path(__file__).resolve().parents[1] / 'construction')
sys.path.insert(0, root)
from ec349_dual_channel_anchor.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
