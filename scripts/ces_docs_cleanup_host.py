#!/usr/bin/env python3
"""EC292: exact original EC230 clean local EC229 linked worktree only."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec292_docs_cleanup_host.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
