"""Create the owner-private Linux CES runtime; run inside WSL."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import venv

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--source',type=Path,default=Path(__file__).resolve().parent.parent)
    ap.add_argument('--runtime',type=Path,default=Path('/var/tmp/ces-1.0.0'))
    ap.add_argument('--pip-wheel',type=Path)
    args=ap.parse_args()
    if os.name!='posix':raise RuntimeError('Run this installer using Linux Python')
    os.umask(0o077)
    source=args.source.resolve()
    target=args.runtime.absolute()
    if not target.is_relative_to(Path('/var/tmp')) or target==Path('/var/tmp'):
        raise RuntimeError('Use a dedicated runtime directory under /var/tmp')
    if target.exists():
        info=target.lstat()
        if not stat.S_ISDIR(info.st_mode) or target.is_symlink() or info.st_uid!=os.getuid() or info.st_mode & 0o077:
            raise RuntimeError('Existing runtime must be an owner-private regular directory')
    else:target.mkdir(mode=0o700)
    if target.resolve()==source:raise RuntimeError('Source and runtime must be separate')
    # Install the current operator, rather than the historical source snapshot.
    manifest=json.loads((source/'PRODUCT_SHA256.json').read_text(encoding='utf-8'))
    for rel in list(manifest['sha256'])+['PRODUCT_SHA256.json']:
        src=source/rel; dst=target/rel
        if not dst.resolve().is_relative_to(target) or src.is_symlink() or not src.is_file():
            raise RuntimeError('Unsafe runtime/source path')
        data=src.read_bytes()
        expected=manifest['sha256'].get(rel)
        if expected and hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('Source checksum mismatch: '+rel)
        if dst.exists() and dst.read_bytes()!=data:raise RuntimeError('Existing runtime differs: '+rel)
        if not dst.exists():
            dst.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with dst.open('xb') as file:file.write(data)
    python=target/'.venv/bin/python'
    if not python.exists():venv.EnvBuilder(with_pip=False).create(target/'.venv')
    pip_ok=subprocess.run([str(python),'-B','-m','pip','--version'],capture_output=True).returncode==0
    if not pip_ok:
        if not args.pip_wheel or not args.pip_wheel.is_file():
            raise RuntimeError('pip wheel required for initial installation; use setup-posix.ps1')
        wheel=args.pip_wheel.resolve()
        subprocess.run([str(python),'-B',str(wheel/'pip'),'install','--no-index',str(wheel)],check=True)
    subprocess.run([str(python),'-B','-m','pip','install','-r',str(target/'requirements-local.txt')],check=True)
    subprocess.run([str(python),'-B','-m','pip','check'],check=True)
    subprocess.run([str(python),'-B',str(target/'tools/verify_product.py')],check=True)
    print(json.dumps({'status':'READY','operator_version':manifest['operator_version'],'core_protocol_version':'1.0.0','runtime':str(target),'python':str(python)},indent=2))

if __name__=='__main__':main()
