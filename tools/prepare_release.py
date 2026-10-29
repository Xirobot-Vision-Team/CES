"""Create a fresh public-source projection without mutating the installed deployment."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,json,re,shutil,sys
import verify_product

EXCLUDE_DIRS={'.venv','__pycache__','.git','.pytest_cache','results','profiles','cache','state','outputs','dist','.release'}
EXCLUDE_SUFFIX={'.pyc','.pyo','.log','.db','.sqlite','.sqlite3','.pem','.key','.pfx','.p12','.zip','.whl'}
OMIT={'docs/validation.json'}
def prepare(source,destination):
    source=source.resolve();destination=destination.absolute()
    if destination.exists() or destination.resolve().is_relative_to(source):raise RuntimeError('Destination must be a new directory outside the product tree')
    # Preserve legacy protocol bytes; these are not sanitized or rebaselined.
    violations,_=verify_product.legacy_review(source,verify_product.collect(source))
    if violations:raise RuntimeError('Protected legacy source changed: '+','.join(violations))
    destination.mkdir(parents=True);omitted=[];count=0
    for path in source.rglob('*'):
        rel=path.relative_to(source);name=rel.as_posix()
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):raise RuntimeError('Reparse/symlink source refused: '+name)
        if any(part in EXCLUDE_DIRS for part in rel.parts) or path.suffix.lower() in EXCLUDE_SUFFIX or path.name=='.env' or path.name.startswith('.env.') or name in OMIT:
            if path.is_file() and not any(part in {'.venv','__pycache__','.git','.pytest_cache'} for part in rel.parts):omitted.append(name)
            continue
        if not path.is_file() or name in {'PRODUCT_SHA256.json','RELEASE.json'}:continue
        raw=path.read_bytes()
        if not name.startswith(('scripts/','construction/','references/')):
            raw=raw.replace(b'\r\n',b'\n')
        target=destination/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);count+=1
    (destination/'ces-product').chmod(0o755)
    product=json.loads((destination/'PRODUCT.json').read_text(encoding='utf-8'))
    cleanup=(source/'tools/legacy_cleanup.json').is_file()
    release=dict(schema='ces.public_source_release.v1',operator_version=product['operator_version'],license='Apache-2.0',prepared_at=datetime.now(timezone.utc).isoformat(),project_data_included=False,git_history_included=False,protected_legacy_bytes_preserved=not cleanup,legacy_cleanup_ledger='tools/legacy_cleanup.json' if cleanup else None,omitted_paths=sorted(omitted),normalization='LF for maintained files; retained compatibility source bytes preserved subject to explicit cleanup ledger',historical_validation='deployment path-bearing JSON omitted; human-readable historical summary retained with its known failures')
    (destination/'RELEASE.json').write_text(json.dumps(release,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    actual=verify_product.collect(destination);actual.pop('PRODUCT_SHA256.json',None)
    manifest=dict(schema='ces.product_manifest.v1',operator_version=product['operator_version'],legacy_core_version='1.0.0',created_at=release['prepared_at'],sha256=dict(sorted(actual.items())))
    (destination/'PRODUCT_SHA256.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return dict(status='source_prepared',destination=str(destination),files=len(actual)+1,omitted=omitted,license=release['license'])
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--destination',type=Path,required=True)
    a=p.parse_args();print(json.dumps(prepare(a.source,a.destination),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
