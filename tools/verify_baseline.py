"""Verify CES baseline bytes without executing project code."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

def main():
    parser=argparse.ArgumentParser(description='Verify CES 1.0 local file integrity')
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent)
    args=parser.parse_args()
    root=args.root.resolve()
    manifest=json.loads((root/'BASELINE_SHA256.json').read_text(encoding='utf-8'))
    mismatch=[]
    for relative,expected in manifest['sha256'].items():
        path=(root/relative)
        if not path.resolve().is_relative_to(root) or path.is_symlink() or not path.is_file():
            mismatch.append(relative)
        elif hashlib.sha256(path.read_bytes()).hexdigest()!=expected:mismatch.append(relative)
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()
            and '.venv' not in p.relative_to(root).parts and '__pycache__' not in p.relative_to(root).parts
            and p.suffix not in ('.pyc','.pyo')}
    extra=sorted(actual-set(manifest['sha256'])-{'BASELINE_SHA256.json'})
    result={'version':manifest['version'],'checked':len(manifest['sha256']),
            'mismatch_or_missing':mismatch,'unexpected_files':extra,
            'status':'PASS' if not mismatch and not extra else 'FAIL'}
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':sys.exit(main())
