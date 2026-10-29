"""Verify CES product bytes and preserved 1.0 protocol implementation separately."""
from pathlib import Path
import argparse,hashlib,json
EXCLUDED_DIRS={".git",".venv","__pycache__",".pytest_cache","results"}
def collect_file_hash(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def collect(root):
    files={}
    for path in root.rglob("*"):
        rel=path.relative_to(root)
        if any(x in EXCLUDED_DIRS for x in rel.parts) or path.suffix in (".pyc",".pyo",".log"):continue
        if path.is_file():files[rel.as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    return files
def legacy_review(root,actual):
    baseline=json.loads((root/'BASELINE_SHA256.json').read_text(encoding='utf-8'))['sha256']
    protected={p:h for p,h in baseline.items() if p.startswith(('scripts/','construction/','references/'))}
    path=root/'tools/legacy_cleanup.json'
    review=json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {'schema':'ces.legacy_cleanup.v1','removed':[],'modified':[]}
    errors=[];seen=set()
    if review.get('schema')!='ces.legacy_cleanup.v1':return ['INVALID_LEGACY_CLEANUP_SCHEMA'],protected
    for kind in ('removed','modified'):
        rows=review.get(kind,[])
        if not isinstance(rows,list):return ['INVALID_LEGACY_CLEANUP_ROWS'],protected
        for row in rows:
            name=row.get('path')
            if name not in protected or name in seen or row.get('baseline_sha256')!=protected.get(name) or not row.get('reason'):
                errors.append('INVALID_LEGACY_CLEANUP:'+str(name));continue
            seen.add(name)
            if kind=='removed':
                if name in actual:errors.append('RETIRED_FILE_REINTRODUCED:'+name)
            elif actual.get(name)!=row.get('current_sha256') or not isinstance(row.get('current_sha256'),str) or len(row['current_sha256'])!=64:
                errors.append('REVIEWED_LEGACY_FILE_CHANGED:'+name)
    errors += [name for name,value in protected.items() if name not in seen and actual.get(name)!=value]
    return errors,protected
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--root",type=Path,default=Path(__file__).resolve().parent.parent)
    a=p.parse_args();root=a.root.resolve()
    manifest=json.loads((root/"PRODUCT_SHA256.json").read_text(encoding="utf-8"))
    actual=collect(root);actual.pop("PRODUCT_SHA256.json",None)
    mismatches=[name for name,value in manifest["sha256"].items() if actual.get(name)!=value]
    extras=sorted(set(actual)-set(manifest["sha256"]))
    core_changed,protected=legacy_review(root,actual)
    result=dict(product_version=manifest["operator_version"],product_files_checked=len(manifest["sha256"]),
                product_mismatch_or_missing=mismatches,product_unexpected_files=extras,
                legacy_protocol_files_checked=len(protected),legacy_protocol_changed=core_changed,
                status="PASS" if not mismatches and not extras and not core_changed else "FAIL",
                scope="Unsigned local byte consistency only; not functional or production acceptance.")
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())

