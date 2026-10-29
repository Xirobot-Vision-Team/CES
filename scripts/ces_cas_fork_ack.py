#!/usr/bin/env python3
"""EC322 isolated, independently pinned seventh-signer fork case acknowledgement."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec322_receiver_fork_ack.operator import main
if __name__=='__main__':
    raise SystemExit(main())
