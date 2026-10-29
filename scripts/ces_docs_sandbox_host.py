#!/usr/bin/env python3
"""EC285 exact DocsOnlyPublish.LocalSandbox AF_UNIX client/operator."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec285_docs_sandbox_host.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
