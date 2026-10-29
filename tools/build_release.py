"""Build source-only release archives from the verified manifest; never upload or tag."""
from pathlib import Path
import argparse,gzip,hashlib,io,json,tarfile,zipfile
import release_check

def build(root,output):
    root=root.resolve();output=output.absolute()
    if output.resolve().is_relative_to(root):raise RuntimeError('Release assets must be outside the source checkout')
    result=release_check.check(root)
    if result['status']!='PASS':raise RuntimeError('Source release check failed')
    product=json.loads((root/'PRODUCT.json').read_text(encoding='utf-8'));version=product['operator_version']
    manifest=json.loads((root/'PRODUCT_SHA256.json').read_text(encoding='utf-8'))
    names=sorted(set(manifest['sha256'])|{'PRODUCT_SHA256.json'})
    output.mkdir(parents=True,exist_ok=False);prefix='CES-'+version
    zip_path=output/(prefix+'.zip');tar_path=output/(prefix+'.tar.gz')
    with zipfile.ZipFile(zip_path,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name in names:
            data=(root/name).read_bytes();info=zipfile.ZipInfo(prefix+'/'+name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(0o100755 if name=='ces-product' else 0o100644)<<16
            archive.writestr(info,data)
    with tar_path.open('xb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as archive:
                for name in names:
                    data=(root/name).read_bytes();info=tarfile.TarInfo(prefix+'/'+name);info.size=len(data);info.mtime=0;info.mode=0o755 if name=='ces-product' else 0o644;info.uid=info.gid=0;info.uname=info.gname=''
                    archive.addfile(info,io.BytesIO(data))
    assets=[zip_path,tar_path];checksums=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in assets)
    (output/'SHA256SUMS').write_text(checksums,encoding='utf-8')
    return dict(version=version,files=len(names),assets=[str(x) for x in assets],checksums=str(output/'SHA256SUMS'),source_only=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(build(a.root,a.output),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
