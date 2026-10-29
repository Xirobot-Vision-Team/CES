"""Read-only public-source checks; report locations and hashes, never secret values."""
from pathlib import Path
import argparse,ast,hashlib,json,re,subprocess,sys
import verify_product

DENIED_DIRS={'.venv','venv','__pycache__','.git','.pytest_cache','profiles','cache','state','outputs','dist','.release'}
DENIED_EXT={'.pyc','.pyo','.log','.db','.sqlite','.sqlite3','.pem','.key','.pfx','.p12','.zip','.whl'}
PATTERNS={
    'credential_token':re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9]{30,})\b'),
    'private_key_marker':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'personal_windows_path':re.compile(r'[A-Za-z]:[\\/]+Users[\\/]+[^\\/ ]+',re.I),
    'private_home_path':re.compile(r'/home/(?!operator/|user/|example/)[A-Za-z0-9_.-]+/'),
}
PLACEHOLDERS={'owner/repository','example/project','example/repo','example-org/project'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def files(root):
    for path in root.rglob('*'):
        rel=path.relative_to(root)
        if any(part in {'.git','.venv','__pycache__','.pytest_cache'} for part in rel.parts):continue
        if path.is_file():yield path,rel.as_posix()
def candidates(root):
    found=[]
    for path,name in files(root):
        try:content=path.read_text(encoding='utf-8-sig')
        except UnicodeDecodeError:continue
        for number,line in enumerate(content.splitlines(),1):
            for rule,pattern in PATTERNS.items():
                if pattern.search(line):found.append(dict(path=name,line=number,rule=rule,line_sha256=sha(line.encode('utf-8'))))
    return found
def check(root,manifest=True):
    errors=[];warnings=[];paths=list(files(root))
    required=['LICENSE','NOTICE','README.md','CONTRIBUTING.md','SECURITY.md','THIRD_PARTY.md','.github/workflows/ci.yml','operator/profile.example.json','tools/release_check.py','tools/prepare_release.py']
    for name in required:
        if not (root/name).is_file():errors.append(dict(path=name,reason='required_file_missing'))
    if (root/'LICENSE').is_file():
        license=(root/'LICENSE').read_text(encoding='utf-8')
        if 'Apache License' not in license or 'Version 2.0, January 2004' not in license or len(license)<10000:errors.append(dict(path='LICENSE',reason='apache_license_incomplete'))
    for path,name in paths:
        rel=Path(name)
        if any(part in DENIED_DIRS for part in rel.parts) or path.suffix.lower() in DENIED_EXT or path.name=='.env' or path.name.startswith('.env.'):errors.append(dict(path=name,reason='runtime_or_private_file'))
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):errors.append(dict(path=name,reason='symlink_or_junction'))
        if path.suffix=='.py':
            try:ast.parse(path.read_text(encoding='utf-8-sig'),filename=name)
            except (SyntaxError,UnicodeError):errors.append(dict(path=name,reason='python_syntax_invalid'))
    for path in root.rglob('*'):
        if any(part in {'.git','.venv','__pycache__'} for part in path.relative_to(root).parts):continue
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):errors.append(dict(path=str(path.relative_to(root)),reason='symlink_or_junction'))
    allow_path=root/'tools/release_allowlist.json';allow=json.loads(allow_path.read_text(encoding='utf-8')) if allow_path.exists() else {'entries':[]}
    allowed={(row['path'],row['line'],row['rule'],row['line_sha256']) for row in allow['entries'] if row.get('reason')}
    discovered=candidates(root);observed={(row['path'],row['line'],row['rule'],row['line_sha256']) for row in discovered}
    errors += [dict(**row,reason='unreviewed_sensitive_pattern') for row in discovered if (row['path'],row['line'],row['rule'],row['line_sha256']) not in allowed]
    for row in allow['entries']:
        if (row['path'],row['line'],row['rule'],row['line_sha256']) not in observed:errors.append(dict(path=row['path'],reason='stale_scanner_exception'))
    profile_path=root/'operator/profile.example.json'
    if profile_path.exists():
        cfg=json.loads(profile_path.read_text(encoding='utf-8'))
        for section,key in [('github','allow_create'),('github','allow_improvements'),('notifications','allow_publish'),('repository_docs','allow_write'),('repository_docs','allow_git_commit'),('repository_docs','allow_git_push'),('repository_sync','allow_pull'),('repository_push','allow'),('testing','enabled'),('testing','allow_execute'),('testing','allow_publish'),('execution_policy','run_runtime_tests')]:
            if cfg.get(section,{}).get(key) is not False:errors.append(dict(path='operator/profile.example.json',reason='unsafe_default:'+section+'.'+key))
        if cfg.get('notifications',{}).get('cc_recipients') or cfg.get('testing',{}).get('project_owners') or cfg.get('testing',{}).get('test_maintainers'):errors.append(dict(path='operator/profile.example.json',reason='real_recipients_in_template'))
        if cfg['github']['repository'] not in PLACEHOLDERS:errors.append(dict(path='operator/profile.example.json',reason='real_repository_in_template'))
    # Maintained docs only. Historical protocol notes retain their original archival links.
    docs=[path for path,name in paths if (path.suffix=='.md' and (len(Path(name).parts)==1 or name.startswith('docs/'))) and path.name!='VALIDATION.md']
    for path in docs:
        content=path.read_text(encoding='utf-8-sig')
        for target in re.findall(r'(?<!!)\[[^]\n]+\]\(([^)\n]+)\)',content):
            target=target.split('#',1)[0]
            if not target or '://' in target or target.startswith(('mailto:','<')):continue
            if target.startswith('/') or re.match(r'^[A-Za-z]:',target):errors.append(dict(path=str(path.relative_to(root)),reason='absolute_document_link'));continue
            if not (path.parent/target).resolve().exists():errors.append(dict(path=str(path.relative_to(root)),reason='broken_local_link:'+target))
        if re.search(r'D:[/\\]Tool[/\\]CES|C:[/\\]Users[/\\][0-9]',content,re.I):errors.append(dict(path=str(path.relative_to(root)),reason='deployment_path_in_maintained_docs'))
    integrity=None
    if manifest:
        proc=subprocess.run([sys.executable,'-B',str(root/'tools/verify_product.py'),'--root',str(root)],capture_output=True,text=True,encoding='utf-8')
        try:integrity=json.loads(proc.stdout)
        except Exception:integrity={'status':'FAIL','reason':'manifest_check_output_invalid'}
        if proc.returncode:errors.append(dict(path='PRODUCT_SHA256.json',reason='integrity_failed'))
    for row in allow['entries']:
        if row.get('rule')=='private_key_marker':warnings.append('Reviewed key-marker negative fixture/detection code: '+row['path'])
    return dict(status='PASS' if not errors else 'FAIL',files_checked=len(paths),errors=errors,reviewed_sensitive_patterns=len(allowed),warnings=sorted(set(warnings)),integrity=integrity,scope='Conservative source-tree check, not a Git-history scan, license ownership proof or security certification.')
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent);parser.add_argument('--skip-manifest',action='store_true')
    args=parser.parse_args();result=check(args.root.resolve(),not args.skip_manifest);print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
