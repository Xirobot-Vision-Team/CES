"""Source-bound README fragments triggered by knowledge updates; human text stays intact."""
from __future__ import annotations
import copy,json,os,posixpath,re,subprocess
from pathlib import Path,PurePosixPath
import ces_workflow as w
import ces_documents as docs

START=b'<!-- ces-readme:start -->'
END=b'<!-- ces-readme:end -->'
MANIFEST='readme-manifest.json'
README=re.compile(r'readme(?:\.[a-z0-9_-]+)?\.md\Z',re.I)
PROJECT_FILES={'cmakelists.txt','package.json','pyproject.toml','cargo.toml','go.mod','pom.xml','build.gradle','build.gradle.kts','meson.build'}
PROJECT_SUFFIXES={'.vcxproj','.csproj','.fsproj','.vbproj','.vcproj','.xcodeproj'}
EXCLUDED={'.git','vendor','third_party','third-party','node_modules','build','dist','.venv','venv'}

def policy(c):
    cfg=c.get('knowledge',{}).get('readme_maintenance',{})
    w.need(isinstance(cfg,dict) and type(cfg.get('enabled',True)) is bool,'README_POLICY_INVALID')
    return cfg.get('enabled',True)

def relative(name):
    w.need(isinstance(name,str) and name and not name.startswith('/') and '\\' not in name and ':' not in name and
           all(ord(x)>=32 and ord(x)!=127 for x in name) and
           all(x and x not in ('.','..') and x.casefold()!='.git' for x in name.split('/')),'README_PATH_INVALID')
    return PurePosixPath(name)

def target(c,name):
    relative(name);w.need(README.fullmatch(PurePosixPath(name).name) is not None,'README_TARGET_NAME_INVALID')
    repo=Path(c['repository_path']).resolve();path=repo/name
    for parent in [path,*path.parents]:
        if parent==repo:break
        w.need(not docs.unsafe(parent),'README_REPARSE_POINT_REFUSED')
    w.need(path.resolve().is_relative_to(repo),'README_OUTSIDE_REPOSITORY')
    return path

def blob(c,head,name):
    relative(name)
    p=subprocess.run(['git','--no-optional-locks','-C',c['repository_path'],'cat-file','blob',head+':'+name],
                     capture_output=True,env=w.clean_env(),timeout=45)
    w.need(p.returncode==0 and len(p.stdout)<=1024*1024,'README_BLOB_UNAVAILABLE_OR_LIMIT')
    p.stdout.decode('utf-8-sig');return p.stdout

def split(raw):
    w.need(raw.count(START)==raw.count(END) and raw.count(START)<=1,'README_MARKERS_INVALID')
    if START not in raw:return raw,None,b''
    before,rest=raw.split(START);block,after=rest.split(END)
    w.need(START not in block and END not in before,'README_MARKERS_INVALID')
    return before,START+block+END,after

def human(raw):
    before,block,after=split(raw)
    return docs.text_hash(before+after)

def manifest(c):
    path=docs.root(c)/MANIFEST
    if not path.exists():return dict(schema='ces.readme_manifest.v1',repository_id=c['github']['repository_id'],files={})
    w.need(not docs.unsafe(path),'README_MANIFEST_UNSAFE');data=w.load(path)
    w.need(data.get('schema')=='ces.readme_manifest.v1' and data.get('repository_id')==c['github']['repository_id'] and
           isinstance(data.get('files'),dict) and len(data['files'])<=64,'README_MANIFEST_INVALID')
    for name in data['files']:target(c,name)
    return data

def discover(c,head,sources):
    """Position and same-directory tracked build descriptors are evidence, never execution."""
    if not policy(c):return dict(enabled=False,targets=[],gaps=[])
    names=[x for x in w.git(c,'ls-tree','-r','--name-only','-z',head).split('\0') if x]
    prefix=docs.root(c).relative_to(Path(c['repository_path']).resolve()).as_posix()+'/'
    grouped={};found=[];gaps=[]
    for name in names:
        relative(name);p=PurePosixPath(name)
        if name.startswith(prefix) or any(x.casefold() in EXCLUDED for x in p.parts[:-1]):continue
        if p.suffix.casefold() in ('.sln','.slnx'):grouped.setdefault(str(p.parent),[]).append((name,'solution'))
        elif p.name.casefold() in PROJECT_FILES or p.suffix.casefold() in PROJECT_SUFFIXES:grouped.setdefault(str(p.parent),[]).append((name,'project'))
    for name in names:
        p=PurePosixPath(name)
        if not README.fullmatch(p.name) or name.startswith(prefix) or any(x.casefold() in EXCLUDED for x in p.parts[:-1]):continue
        descriptors=grouped.get(str(p.parent),[])
        roles=(['repository'] if str(p.parent)=='.' else [])+sorted({kind for _,kind in descriptors})
        if not roles:
            gaps.append(dict(path=name,reason='no_same_directory_project_or_solution_descriptor'));continue
        scope='' if str(p.parent)=='.' else str(p.parent)+'/'
        relevant=[s['path'] for s in sources if not scope or s['path'].startswith(scope)]
        if not relevant:continue
        if not any(not README.fullmatch(PurePosixPath(x).name) and not x.startswith(prefix) for x in relevant):
            gaps.append(dict(path=name,reason='no_code_or_build_source_selected'));continue
        path=target(c,name);w.need(path.is_file() and path.stat().st_size<=1024*1024,'README_FILE_UNAVAILABLE_OR_LIMIT')
        current=path.read_bytes();committed=blob(c,head,name)
        w.need(docs.text_hash(current)==docs.text_hash(committed),'README_MEMBER_EDIT_PENDING:'+name)
        split(current)
        found.append(dict(path=name,roles=roles,scope_directory=scope.rstrip('/'),
                          descriptors=[n for n,_ in descriptors],source_paths=relevant,
                          current_sha256=w.sha(current),text_sha256=docs.text_hash(current),human_sha256=human(current)))
    w.need(len(found)<=32,'README_TARGET_LIMIT')
    for folder,items in grouped.items():
        if not any(str(PurePosixPath(x).parent)==folder and README.fullmatch(PurePosixPath(x).name) for x in names):
            gaps.append(dict(directory=folder,reason='no_existing_readme',descriptors=[n for n,_ in items]))
    return dict(enabled=True,targets=sorted(found,key=lambda x:x['path']),gaps=gaps,
                authoring='Read actual README, same-directory descriptors, source and affected knowledge chapters; author a cited fragment or a reasoned unchanged decision. No code/build command is executed for discovery.')

def citations(c,inp,refs,allowed):
    w.need(isinstance(refs,list) and 1<=len(refs)<=16,'README_CITATIONS_REQUIRED');lines=[]
    prefix=docs.root(c).relative_to(Path(c['repository_path']).resolve()).as_posix()+'/'
    w.need(any(isinstance(ref,dict) and isinstance(ref.get('path'),str) and
               not README.fullmatch(PurePosixPath(ref['path']).name) and not ref['path'].startswith(prefix) for ref in refs),'README_CODE_OR_BUILD_CITATION_REQUIRED')
    sources={s['path']:s for s in inp['sources']}
    for ref in refs:
        name=ref['path'];w.need(name in sources and name in allowed,'README_CITATION_OUTSIDE_SCOPE')
        text=w.git(c,'show',inp['head']+':'+name)
        w.need(w.sha(text)==sources[name]['content_sha256'],'README_SOURCE_CHANGED')
        a,b=ref['line_start'],ref['line_end'];source=text.splitlines()
        w.need(type(a) is int and type(b) is int and 1<=a<=b<=len(source) and b-a<100,'README_CITATION_RANGE_INVALID')
        w.need(isinstance(ref.get('quote'),str) and ref['quote'].strip() and ref['quote'] in '\n'.join(source[a-1:b]),'README_CITATION_NOT_PRESENT')
        lines.append('- ['+name+':L'+str(a)+']('+w.source_link(c,inp['head'],name)+'#L'+str(a)+'-L'+str(b)+')')
    return lines

def plan(c,inp,draft):
    enabled=policy(c);bound=inp.get('readme_maintenance')
    if not enabled:return dict(status='disabled',updates=[],gaps=[]),None
    if bound is None:return dict(status='input_upgrade_required',updates=[],gaps=[dict(reason='rerun_knowledge_prepare_for_readme_binding')]),None
    w.need(bound.get('enabled') is True,'README_POLICY_CHANGED_RERUN_PREPARE')
    entries=draft.get('readmes',[]);w.need(isinstance(entries,list) and len(entries)<=32,'README_DRAFT_INVALID')
    targets={x['path']:x for x in bound['targets']};seen=set();updates=[];gaps=list(bound.get('gaps',[]));data=manifest(c);olddata=copy.deepcopy(data)
    for entry in entries:
        name=entry.get('path');w.need(name in targets and name not in seen,'README_TARGET_NOT_BOUND_OR_DUPLICATE');seen.add(name);item=targets[name]
        path=target(c,name);raw=path.read_bytes();w.need(w.sha(raw)==item['current_sha256'],'README_CHANGED_AFTER_PREPARE:'+name)
        w.need(docs.text_hash(raw)==docs.text_hash(blob(c,inp['head'],name)),'README_MEMBER_EDIT_PENDING:'+name)
        before,block,after=split(raw);owned=data['files'].get(name)
        if block is not None:w.need(owned and owned.get('block_sha256')==docs.text_hash(block),'README_BLOCK_MEMBER_EDIT_OR_NOT_OWNED:'+name)
        elif owned:raise RuntimeError('README_MANAGED_BLOCK_REMOVED:'+name)
        if owned:owned.update(sha256=docs.text_hash(raw),human_sha256=human(raw))
        # A source-only no-op still needs reasoning and at least one exact source citation.
        w.need(isinstance(entry.get('reasoning'),str) and 20<=len(entry['reasoning'])<=8000,'README_REASONING_REQUIRED')
        refs=citations(c,inp,entry.get('citations'),item['source_paths'])
        action=entry.get('action','update');w.need(action in ('update','unchanged'),'README_ACTION_INVALID')
        if action=='unchanged':continue
        body=entry.get('markdown');w.need(isinstance(body,str) and 50<=len(body.encode())<=128*1024,'README_FRAGMENT_SIZE_INVALID')
        w.need('<!-- ces-readme:' not in body.casefold(),'README_MARKER_IN_DRAFT')
        chapter_names=entry.get('knowledge_paths');w.need(isinstance(chapter_names,list) and chapter_names and len(chapter_names)==len(set(chapter_names)),'README_KNOWLEDGE_LINK_REQUIRED')
        chapters={x['path']:x for x in draft['chapters']}
        w.need(all(n in chapters for n in chapter_names),'README_KNOWLEDGE_CHAPTER_NOT_IN_BATCH')
        relevant=set(item['source_paths'])
        w.need(all(any(ref.get('path') in relevant for ref in chapters[n].get('citations',[])) for n in chapter_names),'README_KNOWLEDGE_OUTSIDE_SCOPE')
        nl=b'\r\n' if b'\r\n' in raw and b'\n' not in raw.replace(b'\r\n',b'') else b'\n'
        links=[];docprefix=docs.root(c).relative_to(Path(c['repository_path']).resolve()).as_posix()
        for chapter in chapter_names:
            link=posixpath.relpath(docprefix+'/knowledge/'+docs.relative(chapter).as_posix(),str(PurePosixPath(name).parent))
            links.append('- ['+chapter+']('+link+')')
        # Do not touch a fragment merely because HEAD/binding/time advanced.
        semantic=docs.digest(dict(body=body.replace('\r\n','\n').rstrip(),knowledge_paths=chapter_names,citations=entry['citations'],roles=item['roles']))
        if owned and owned.get('semantic_sha256')==semantic:continue
        text='\n'.join([START.decode(),body.replace('\r\n','\n').rstrip(),'','### Knowledge / 来源','',*links,'',*refs,END.decode()])
        newblock=text.encode('utf-8').replace(b'\n',nl)
        # Keep every original human byte, including BOM and final whitespace.
        if block is None:before=raw+nl+nl;after=nl
        content=before+newblock+after
        data['files'][name]=dict(sha256=docs.text_hash(content),block_sha256=docs.text_hash(newblock),human_sha256=human(content),
                                 semantic_sha256=semantic,source_head=inp['head'],roles=item['roles'],knowledge_paths=chapter_names)
        updates.append(dict(path=name,prior_sha256=w.sha(raw),content=content,sha256=docs.text_hash(content)))
    for name in sorted(set(targets)-seen):gaps.append(dict(path=name,reason='readme_draft_missing',action='retain_existing_and_report'))
    status='planned' if updates else 'already_current'
    return dict(status=status,updates=updates,gaps=gaps),data if data!=olddata else None

def apply(c,plan):
    w.need(c.get('repository_docs',{}).get('allow_write') is True,'README_WRITE_NOT_AUTHORIZED')
    for row in plan['updates']:
        path=target(c,row['path']);w.need(w.sha(path.read_bytes())==row['prior_sha256'],'README_CHANGED_AFTER_PLAN:'+row['path'])
    # Caller holds the knowledge publication lock; each replace is atomic, interrupted batches remain visible.
    for row in plan['updates']:
        path=target(c,row['path']);temporary=path.with_name(path.name+'.ces-new')
        w.need(not temporary.exists(),'README_TEMP_EXISTS')
        with temporary.open('xb') as stream:stream.write(row['content']);stream.flush();os.fsync(stream.fileno())
        w.need(w.sha(path.read_bytes())==row['prior_sha256'],'README_CHANGED_BEFORE_REPLACE')
        os.replace(temporary,path)

def managed_files(c):
    """Validate exact generated README bytes and unchanged human content against current HEAD."""
    if not policy(c):return {}
    metadata=docs.root(c)/MANIFEST
    if not metadata.exists():return {}
    data=manifest(c);head=w.git(c,'rev-parse','HEAD');result={}
    for name,row in data['files'].items():
        path=target(c,name);w.need(path.is_file(),'README_MANAGED_FILE_MISSING')
        raw=path.read_bytes();committed=blob(c,head,name)
        committed_unchanged=docs.text_hash(raw)==docs.text_hash(committed)
        w.need(docs.text_hash(raw)==row['sha256'] or committed_unchanged,'README_EXTERNAL_CHANGE:'+name)
        _,block,_=split(raw);w.need(block is not None and docs.text_hash(block)==row['block_sha256'] and
                                  (human(raw)==row['human_sha256'] or committed_unchanged),'README_MANIFEST_CONTENT_MISMATCH')
        before,prior,after=split(committed)
        # First append has two separators and a final newline; require the exact known append shape.
        if prior is None:
            nl=b'\r\n' if b'\r\n' in committed and b'\n' not in committed.replace(b'\r\n',b'') else b'\n'
            expected=committed+nl+nl+block+nl
            w.need(docs.text_hash(expected)==docs.text_hash(raw),'README_HUMAN_CONTENT_CHANGED')
        else:w.need(human(committed)==human(raw),'README_HUMAN_CONTENT_CHANGED')
        result[name]=path
    return result

def audit_paths(c,sha,parent,external,prefix):
    """Historical Git-only check: only marked README blocks changed, matching the owned manifest."""
    data=json.loads(w.git(c,'show',sha+':'+prefix+'/'+MANIFEST))
    w.need(data.get('schema')=='ces.readme_manifest.v1' and data.get('repository_id')==c['github']['repository_id'],'README_AUDIT_MANIFEST_INVALID')
    for name in external:
        relative(name);w.need(README.fullmatch(PurePosixPath(name).name) and name in data['files'],'README_AUDIT_TARGET_NOT_OWNED')
        row=data['files'][name];new=blob(c,sha,name);old=blob(c,parent,name);_,block,_=split(new)
        w.need(block and docs.text_hash(new)==row['sha256'] and docs.text_hash(block)==row['block_sha256'],'README_AUDIT_HASH_MISMATCH')
        if split(old)[1] is None:
            before,_,after=split(new)
            w.need(docs.text_hash(before)==docs.text_hash(old+b'\n\n') and docs.text_hash(after)==docs.text_hash(b'\n'),'README_AUDIT_HUMAN_CHANGE')
        else:w.need(human(new)==human(old),'README_AUDIT_HUMAN_CHANGE')
    return set(external)

def summary(plan):return {**plan,'updates':[{k:v for k,v in row.items() if k!='content'} for row in plan['updates']]}
