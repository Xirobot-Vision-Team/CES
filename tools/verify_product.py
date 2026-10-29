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
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--root",type=Path,default=Path(__file__).resolve().parent.parent)
    a=p.parse_args();root=a.root.resolve()
    manifest=json.loads((root/"PRODUCT_SHA256.json").read_text(encoding="utf-8"))
    actual=collect(root);actual.pop("PRODUCT_SHA256.json",None)
    mismatches=[name for name,value in manifest["sha256"].items() if actual.get(name)!=value]
    extras=sorted(set(actual)-set(manifest["sha256"]))
    legacy=json.loads((root/"BASELINE_SHA256.json").read_text(encoding="utf-8"))
    protected={name:value for name,value in legacy["sha256"].items() if name.startswith(("scripts/","construction/","references/"))}
    core_changed=[name for name,value in protected.items() if actual.get(name)!=value]
    result=dict(product_version=manifest["operator_version"],product_files_checked=len(manifest["sha256"]),
                product_mismatch_or_missing=mismatches,product_unexpected_files=extras,
                legacy_protocol_files_checked=len(protected),legacy_protocol_changed=core_changed,
                status="PASS" if not mismatches and not extras and not core_changed else "FAIL",
                scope="Unsigned local byte consistency only; not functional or production acceptance.")
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())

