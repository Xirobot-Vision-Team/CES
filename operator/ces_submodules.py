"""Opt-in, allowlisted Git submodule snapshots. No branch-following or child publication.

Paths remain superproject-relative; every source binds the complete gitlink chain.
The parent commit is the integration boundary, never a child remote's moving HEAD.
"""
from __future__ import annotations
import copy,re,subprocess
from pathlib import Path
from urllib.parse import quote
import ces_workflow as w

def enabled(c):return c.get('repository_sync',{}).get('submodules',{}).get('enabled') is True
def safe(path):
    w.need(isinstance(path,str) and path and not path.startswith(('/','-')) and ':' not in path and '\\' not in path and
           all(x and x not in ('.','..') and x.casefold()!='.git' for x in path.split('/')) and
           not any(ord(x)<32 or ord(x)==127 for x in path),'SUBMODULE_PATH_INVALID')
    return path
def repository(url):
    match=re.fullmatch(r'https://github[.]com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:[.]git)?/?',url or '')
    w.need(match is not None,'SUBMODULE_HTTPS_GITHUB_URL_REQUIRED')
    return match[1]
def policy(c):
    cfg=c.get('repository_sync',{}).get('submodules',{})
    w.need(enabled(c) and isinstance(cfg.get('entries'),list) and 1<=len(cfg['entries'])<=32,'SUBMODULE_ALLOWLIST_REQUIRED')
    result={};folded=set()
    for item in cfg['entries']:
        name=safe(item['path']);repo=item['repository']
        w.need(name.casefold() not in folded and repository('https://github.com/'+repo)==repo,'SUBMODULE_ALLOWLIST_INVALID')
        result[name]=repo;folded.add(name.casefold())
    return result
def raw(c,*args,check=True):
    p=subprocess.run(['git','--no-optional-locks','-c','core.quotePath=false','-c','core.hooksPath=','-C',c['repository_path'],*args],
                     capture_output=True,env=w.clean_env(),timeout=180)
    if check:
        if p.returncode and b'not our ref' in p.stderr:raise RuntimeError('SUBMODULE_PIN_UNAVAILABLE_ON_REMOTE')
        w.need(p.returncode==0,'SUBMODULE_GIT_FAILED:'+args[0])
    return p.stdout if check else p
def entries(c,revision):
    rows=[]
    for entry in raw(c,'ls-tree','-r','-z',revision).split(b'\0'):
        if not entry:continue
        meta,name=entry.split(b'\t',1);mode,kind,sha=meta.decode('ascii').split()
        rows.append(dict(path=safe(name.decode('utf-8')),mode=mode,kind=kind,sha=sha))
    return rows
def links(c,revision):return [x for x in entries(c,revision) if x['mode']=='160000']
def declarations(c,revision):
    if not links(c,revision):return {}
    doc=raw(c,'config','--null','--blob',revision+':.gitmodules','--get-regexp',r'^submodule\..*\.(path|url)$')
    values={}
    for entry in doc.split(b'\0'):
        if not entry:continue
        key,value=entry.decode('utf-8').split('\n',1)
        name,field=key[len('submodule.'):].rsplit('.',1)
        w.need(re.fullmatch(r'[A-Za-z0-9_./-]+',name) is not None and not name.startswith('-'),'SUBMODULE_NAME_INVALID')
        w.need(field not in values.setdefault(name,{}),'SUBMODULE_DECLARATION_DUPLICATE')
        values[name][field]=value
    result={}
    for name,value in values.items():
        path=safe(value.get('path',''));repo=repository(value.get('url'))
        w.need(path not in result,'SUBMODULE_DECLARATION_DUPLICATE')
        result[path]=dict(name=name,repository=repo,url='https://github.com/'+repo+'.git')
    return result
def approved(c,revision,prefix=''):
    allow=policy(c);declared=declarations(c,revision);result=[]
    for row in links(c,revision):
        full=prefix+row['path'];binding=declared.get(row['path'])
        w.need(binding and allow.get(full,'').casefold()==binding['repository'].casefold(),'SUBMODULE_NOT_ALLOWLISTED:'+full)
        result.append(dict(**row,**binding,full_path=full))
    return result
def child(c,row):
    path=Path(c['repository_path'])/row['path'];root=Path(c['repository_path']).resolve()
    for p in [path,*path.parents]:
        if p==root:break
        w.need(not p.is_symlink() and not (hasattr(p,'is_junction') and p.is_junction()),'SUBMODULE_REPARSE_REFUSED')
    w.need(path.resolve().is_relative_to(root) and (path/'.git').exists(),'SUBMODULE_NOT_INITIALIZED:'+row['full_path'])
    result=copy.deepcopy(c);result['repository_path']=str(path.resolve())
    result['github']={**c.get('github',{}),'repository':row['repository']}
    w.need(Path(raw(result,'rev-parse','--show-toplevel').decode().strip()).resolve()==path.resolve(),'SUBMODULE_ROOT_MISMATCH')
    origin=raw(result,'remote','get-url','origin').decode().strip()
    w.need(repository(origin).casefold()==row['repository'].casefold(),'SUBMODULE_ORIGIN_MISMATCH')
    return result
def inventory(c,revision=None,strict=False,prefix='',depth=0,allow_uninitialized=False):
    if not enabled(c):return []
    w.need(depth<5,'SUBMODULE_DEPTH_LIMIT')
    revision=revision or w.git(c,'rev-parse','HEAD');result=[]
    for row in approved(c,revision,prefix):
        path=Path(c['repository_path'])/row['path']
        if allow_uninitialized and not (path/'.git').exists():
            w.need(not path.exists() or (path.is_dir() and not any(path.iterdir())),'SUBMODULE_INITIALIZATION_PATH_NOT_EMPTY:'+row['full_path'])
            continue
        cc=child(c,row)
        probe=raw(cc,'cat-file','-t',row['sha'],check=False)
        w.need(probe.returncode==0 and probe.stdout.strip()==b'commit','SUBMODULE_PIN_UNAVAILABLE:'+row['full_path']+':'+row['sha'])
        actual=raw(cc,'rev-parse','HEAD').decode().strip();status=raw(cc,'status','--porcelain=v1','-uall').decode('utf-8')
        if strict:w.need(actual==row['sha'] and not status,'SUBMODULE_DIRTY_OR_WRONG_PIN:'+row['full_path'])
        result.append(dict(path=row['full_path'],repository=row['repository'],pinned_commit=row['sha'],checkout_commit=actual,clean=not status))
        result+=inventory(cc,row['sha'],strict,row['full_path']+'/',depth+1,allow_uninitialized)
    w.need(len(result)<=32,'SUBMODULE_COUNT_LIMIT');return result
def sync(c,revision=None,prefix='',depth=0):
    if not enabled(c):
        w.need(not links(c,revision or 'HEAD'),'SUBMODULE_SYNC_NOT_CONFIGURED')
        return []
    w.need(depth<5,'SUBMODULE_DEPTH_LIMIT');cfg=c['repository_sync']['submodules']
    w.need(cfg.get('allow_init') is True,'SUBMODULE_INITIALIZATION_NOT_AUTHORIZED')
    for row in approved(c,revision or 'HEAD',prefix):
        path=Path(c['repository_path'])/row['path']
        # A pre-existing checkout must be clean. Lifecycle checks its old pin before parent sync.
        # Existing non-repository directories are never removed to make room for a clone.
        if (path/'.git').exists():
            cc=child(c,row);w.need(not raw(cc,'status','--porcelain=v1','-uall').strip(),'SUBMODULE_LOCAL_EDITS:'+row['full_path'])
        else:
            w.need(not path.exists() or (path.is_dir() and not any(path.iterdir())),'SUBMODULE_INITIALIZATION_PATH_NOT_EMPTY:'+row['full_path'])
        raw(c,'-c','protocol.file.allow=never','-c','submodule.recurse=false',
            '-c','submodule.'+row['name']+'.url='+row['url'],
            '-c','submodule.'+row['name']+'.update=checkout',
            'submodule','update','--init','--checkout','--',row['path'])
        cc=child(c,row);sync(cc,row['sha'],row['full_path']+'/',depth+1)
    return inventory(c,revision,True,prefix,depth)
def resolve(c,revision,path):
    """Return immutable owner/blob metadata, including parent anchors, or None."""
    safe(path);parent=w.git(c,'rev-parse','--verify',revision+'^{commit}');current=c;rev=parent;tail=path;chain=[];prefix=''
    for depth in range(5):
        rows=entries(current,rev);direct=next((x for x in rows if x['path']==tail),None)
        if direct and direct['mode']!='160000':
            w.need(direct['mode'] in ('100644','100755'),'SOURCE_NONREGULAR')
            return dict(repository=c['github']['repository'],parent_commit=parent,path=path,source_repository=current['github']['repository'],
                        source_commit=rev,source_path=tail,blob=direct['sha'],mode=direct['mode'],chain=chain,_config=current)
        mount=next((x for x in rows if x['mode']=='160000' and (tail==x['path'] or tail.startswith(x['path']+'/'))),None)
        if not mount:return None
        w.need(tail!=mount['path'],'REVIEW_NONREGULAR_SOURCE')
        w.need(enabled(c),'SUBMODULE_READ_NOT_CONFIGURED')
        row=next(x for x in approved(current,rev,prefix) if x['path']==mount['path'])
        chain.append(dict(path=row['full_path'],repository=row['repository'],commit=row['sha']))
        current=child(current,row);rev=row['sha'];tail=tail[len(row['path'])+1:];prefix=row['full_path']+'/'
    raise RuntimeError('SUBMODULE_DEPTH_LIMIT')
def binding(c,revision,path):
    value=resolve(c,revision,path)
    return {k:v for k,v in value.items() if k!='_config'} if value else None
def read(c,revision,path):
    value=resolve(c,revision,path)
    return raw(value['_config'],'cat-file','blob',value['blob']) if value else None
def text(c,revision,path):
    value=read(c,revision,path);w.need(value is not None,'SOURCE_NOT_TRACKED:'+path)
    return value.decode('utf-8-sig').rstrip('\r\n')
def names(c,revision,prefix='',depth=0):
    w.need(depth<5,'SUBMODULE_DEPTH_LIMIT');result=[]
    for row in entries(c,revision):
        if row['mode']!='160000':result.append(prefix+row['path']);continue
        approved_row=next(x for x in approved(c,revision,prefix) if x['path']==row['path'])
        result+=names(child(c,approved_row),row['sha'],prefix+row['path']+'/',depth+1)
    w.need(len(result)<=100000,'SUBMODULE_SOURCE_INVENTORY_LIMIT');return result
def changed(c,base,head):
    """Compare virtual immutable blobs: flat-to-submodule moves retain their bytes."""
    def blobs(cfg,revision,prefix='',depth=0):
        w.need(depth<5,'SUBMODULE_DEPTH_LIMIT');result={};allowed=None
        for row in entries(cfg,revision):
            if row['mode']!='160000':result[prefix+row['path']]=row['sha'];continue
            allowed=allowed if allowed is not None else {x['path']:x for x in approved(cfg,revision,prefix)}
            result.update(blobs(child(cfg,allowed[row['path']]),row['sha'],prefix+row['path']+'/',depth+1))
        w.need(len(result)<=100000,'SUBMODULE_SOURCE_INVENTORY_LIMIT');return result
    old=blobs(c,base);new=blobs(c,head)
    return sorted(p for p in old.keys()|new.keys() if old.get(p)!=new.get(p))
def source_url(c,revision,path):
    item=binding(c,revision,path);w.need(item is not None,'SOURCE_NOT_TRACKED:'+path)
    return 'https://github.com/'+item['source_repository']+'/blob/'+item['source_commit']+'/'+quote(item['source_path'],safe='/')
def mount(c,revision,path):
    """Identify a configured child path without reading its source or touching it."""
    return next((row for row in approved(c,revision) if path.startswith(row['path']+'/')),None) if enabled(c) else None
def changes(c,base,head):
    """Child commit inventory stays separate from integration-author statistics."""
    if not enabled(c):return []
    old={x['path']:x for x in approved(c,base)};new={x['path']:x for x in approved(c,head)};result=[]
    for path in sorted(old.keys()|new.keys()):
        before=old.get(path);after=new.get(path)
        if before and after and before['sha']==after['sha'] and before['repository']==after['repository']:continue
        record=dict(path=path,before=before['sha'] if before else None,after=after['sha'] if after else None,
                    repository=(after or before)['repository'],parent_base=base,parent_head=head,commits=[],
                    migration='added_or_flat_to_submodule' if not before else 'removed' if not after else 'pin_changed')
        if before and after and before['repository']==after['repository']:
            cc=child(c,after)
            log=raw(cc,'log','--format=%H%x00%aI%x00%cI%x00%an%x00%cn%x00%s',before['sha']+'..'+after['sha']).decode('utf-8')
            for line in log.splitlines():
                sha,author_at,committer_at,author,committer,subject=line.split('\0',5)
                record['commits'].append(dict(sha=sha,author_at=author_at,committer_at=committer_at,author_name=author,committer_name=committer,subject=subject,
                    url='https://github.com/'+after['repository']+'/commit/'+sha))
            w.need(len(record['commits'])<=2048,'SUBMODULE_COMMIT_INVENTORY_LIMIT')
        result.append(record)
    return result
