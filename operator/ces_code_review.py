"""Bounded, resumable code-reading batches and source-bound functional reports.

This is an operator evidence lane, not a replacement for native Finding/Issue
validation. It never runs project code, builds, publishes or calls a model.
"""
from __future__ import annotations
import argparse,codecs,json,subprocess
from pathlib import Path,PurePosixPath
import ces_workflow as w
import ces_submodules as subs

DEFAULTS=dict(max_files=256,max_file_bytes=8*1024*1024,max_total_bytes=32*1024*1024,
              batch_bytes=128*1024,target_tokens=60000,max_tokens=120000)
BOUNDS=dict(max_files=(1,2048),max_file_bytes=(1024,32*1024*1024),
            max_total_bytes=(1024,128*1024*1024),batch_bytes=(1024,1024*1024),
            target_tokens=(1000,1000000),max_tokens=(1000,2000000))
FIELDS=('purpose','behavior_change','mechanism','correctness','optimization')
DETAIL_FIELDS=dict(context='功能背景与使用场景',data_flow='调用链与数据流',
                   algorithm='算法分步推导',examples='具体输入与前后结果',
                   edge_cases='边界与反例',complexity='复杂度与性能热点',
                   alternatives='优化方案比较',verification='验证设计与后续行动')

def report_policy(c):
    cfg=c.get('review',{}).get('report_detail',{})
    w.need(isinstance(cfg,dict) and set(cfg)<={'target_chars','require_extended_analysis'},'REPORT_DETAIL_POLICY_INVALID')
    result=dict(target_chars=cfg.get('target_chars',12000),require_extended_analysis=cfg.get('require_extended_analysis',False))
    w.need(type(result['target_chars']) is int and 1000<=result['target_chars']<=200000 and
           type(result['require_extended_analysis']) is bool,'REPORT_DETAIL_POLICY_INVALID')
    return result

def detail_lines(feature):
    lines=[]
    for key,label in DETAIL_FIELDS.items():
        if key in feature.get('details',{}):lines+=['','#### '+label,'',feature['details'][key]]
    return lines

def digest(obj):return w.sha(json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':')))
def policy(c):
    cfg=c.get('review',{}).get('budget',{})
    w.need(isinstance(cfg,dict) and set(cfg)<=set(DEFAULTS),'REVIEW_BUDGET_INVALID')
    result={**DEFAULTS,**cfg}
    for key,(low,high) in BOUNDS.items():
        w.need(type(result[key]) is int and low<=result[key]<=high,'REVIEW_BUDGET_INVALID:'+key)
    w.need(result['target_tokens']<=result['max_tokens'],'REVIEW_TOKEN_RANGE_INVALID')
    return result

def raw_git(c,*args):
    p=subprocess.run(['git','--no-optional-locks','-c','core.quotePath=false','-C',c['repository_path'],*args],
                     capture_output=True,env=w.clean_env(),timeout=90)
    w.need(p.returncode==0,'REVIEW_GIT_READ_FAILED:'+args[0]);return p.stdout

def safe_path(path):
    w.need(isinstance(path,str) and path and not PurePosixPath(path).is_absolute() and
           ':' not in path and '\\' not in path and all(x not in ('','.','..','.git') for x in path.split('/')) and
           not any(ord(x)<32 for x in path),'REVIEW_PATH_INVALID')
    return path

def read_blob(c,revision,path):
    safe_path(path)
    if subs.enabled(c):return subs.read(c,revision,path)
    # Reject symlinks/submodules rather than interpreting their contents as code.
    entry=raw_git(c,'ls-tree','-z',revision,'--',':(literal)'+path).split(b'\t',1)
    if len(entry)!=2:return None
    w.need(entry[0].split()[0] in (b'100644',b'100755'),'REVIEW_NONREGULAR_SOURCE')
    return raw_git(c,'cat-file','blob',revision+':'+path)

def decode(c,path,raw):
    encoding=c.get('review',{}).get('encoding_overrides',{}).get(path,'utf-8-sig')
    codecs.lookup(encoding)
    if b'\0' in raw and not encoding.lower().startswith(('utf-16','utf-32')):
        return None,'binary_or_unregistered_encoding'
    try:return raw.decode(encoding),encoding
    except UnicodeError:return None,'encoding_review_required'

def parts(text,limit):
    lines=text.splitlines();chunks=[];start=1;current=[];size=0
    for i,line in enumerate(lines,1):
        n=len((line+'\n').encode('utf-8'))
        if n>limit:return None # Do not split a literal into misleading partial lines.
        if current and size+n>limit:
            chunks.append((start,i-1,'\n'.join(current)));start=i;current=[];size=0
        current.append(line);size+=n
    if current:chunks.append((start,len(lines),'\n'.join(current)))
    return chunks

def prepare(c,base,target='HEAD',context=()):
    import ces_audit
    limits=policy(c);base=w.git(c,'rev-parse','--verify',base+'^{commit}');head=w.git(c,'rev-parse','--verify',target+'^{commit}')
    w.need(head==w.git(c,'rev-parse','HEAD') and not w.git(c,'status','--porcelain=v1','-uall'),'REVIEW_CLEAN_CURRENT_HEAD_REQUIRED')
    w.need(len(context)==len(set(context)),'REVIEW_CONTEXT_DUPLICATE')
    commits=[dict(sha=x) for x in w.git(c,'rev-list',base+'..'+head).splitlines()]
    kept,excluded,warnings=ces_audit.filter_commits(c,commits)
    # Ignore only proven generated tail commits. Earlier human/mixed documentation
    # remains eligible even if a later CES block append preserves its human bytes.
    effective_tip=kept[0]['sha'] if kept else base
    changes=set(subs.changed(c,base,effective_tip)) if subs.enabled(c) else set(raw_git(c,'diff','--name-only','-z','--no-renames',base,effective_tip).decode('utf-8').rstrip('\0').split('\0'))-{''}
    origins={}
    for row in kept:
        paths=raw_git(c,'diff-tree','--root','-m','--no-commit-id','--name-only','-r','-z',row['sha']).decode('utf-8').split('\0')
        for path in paths:
            if path in changes:origins.setdefault(path,[]).append(row['sha'])
        if subs.enabled(c):
            for path in changes:
                if any(path.startswith(p+'/') for p in paths if p):origins.setdefault(path,[]).append(row['sha'])
    if subs.enabled(c) and kept:
        for path in changes:origins.setdefault(path,[effective_tip])
    selected=sorted(set(origins)|{safe_path(x) for x in context})
    before=w.snapshot(c);files=[];units=[];total=0
    for index,path in enumerate(selected):
        safe_path(path);role='change' if path in origins else 'context'
        revisions=[('before',base),('after',head)] if role=='change' else [('after',head)]
        for side,revision in revisions:
            row=dict(path=path,side=side,revision=revision,role=role,commits=origins.get(path,[]))
            if index>=limits['max_files']:
                files.append(dict(**row,status='deferred',reason='file_budget'));continue
            try:raw=read_blob(c,revision,path)
            except RuntimeError as exc:
                files.append(dict(**row,status='deferred',reason=str(exc)));continue
            if raw is None:
                files.append(dict(**row,status='absent'));continue
            if subs.enabled(c):row['source_binding']=subs.binding(c,revision,path)
            row.update(raw_sha256=w.sha(raw),bytes=len(raw))
            if len(raw)>limits['max_file_bytes'] or total+len(raw)>limits['max_total_bytes']:
                files.append(dict(**row,status='deferred',reason='byte_budget'));continue
            total+=len(raw);text,encoding=decode(c,path,raw);row['encoding']=encoding
            if text is None:
                files.append(dict(**row,status='deferred',reason=encoding));continue
            chunks=parts(text,limits['batch_bytes'])
            if chunks is None:
                files.append(dict(**row,status='deferred',reason='single_line_exceeds_batch'));continue
            row.update(status='available',line_count=len(text.splitlines()));files.append(row)
            for start,end,content in chunks:
                unit=dict(path=path,side=side,revision=revision,raw_sha256=row['raw_sha256'],
                          line_start=start,line_end=end,text=content,encoding=encoding,role=role)
                if 'source_binding' in row:unit['source_binding']=row['source_binding']
                unit['id']=digest(unit);units.append(unit)
    body=dict(schema='ces.code_review_plan.v1',repository_id=c['github']['repository_id'],base=base,head=head,effective_tip=effective_tip,
              budget=limits,effective_commits=kept,excluded_commits=excluded,audit_warnings=warnings,files=files,units=units,
              token_budget_kind='operator planning preference; not measured usage or a host/model hard limit')
    if subs.enabled(c):body['submodule_changes']=subs.changes(c,base,head)
    body['binding_sha256']=digest(body)
    w.need(before==w.snapshot(c),'REVIEW_SOURCE_CHANGED_DURING_PREPARE')
    folder=Path(c.get('cache_root',c['state_root']))/'code-review'/body['binding_sha256'];folder.mkdir(parents=True,exist_ok=True)
    path=folder/'plan.json';w.save(path,body)
    for unit in units:
        (folder/(unit['id']+'.md')).write_text(f"{unit['path']} ({unit['side']} {unit['revision']}) L{unit['line_start']}-{unit['line_end']}\n\n"+unit['text'],encoding='utf-8')
    return dict(status='review_batches_ready',plan=str(path),binding_sha256=body['binding_sha256'],
                files=len(selected),units=len(units),gaps=[x for x in files if x['status']=='deferred'],budget=limits)

def validate(c,plan,draft):
    core=dict(plan);binding=core.pop('binding_sha256',None)
    w.need(plan.get('schema')=='ces.code_review_plan.v1' and binding==digest(core) and
           plan['repository_id']==c['github']['repository_id'],'REVIEW_PLAN_BINDING_INVALID')
    w.need(w.git(c,'rev-parse','HEAD')==plan['head'] and not w.git(c,'status','--porcelain=v1','-uall'),'REVIEW_SOURCE_CHANGED')
    w.need(draft.get('schema')=='ces.functional_review.v1' and draft.get('input_binding_sha256')==binding,'FUNCTIONAL_REVIEW_BINDING_INVALID')
    sources={}
    for row in plan['files']:
        if row.get('raw_sha256'):
            if 'source_binding' in row:w.need(subs.binding(c,row['revision'],row['path'])==row['source_binding'],'REVIEW_SUBMODULE_BINDING_CHANGED')
            raw=read_blob(c,row['revision'],row['path']);w.need(raw is not None and w.sha(raw)==row['raw_sha256'],'REVIEW_SOURCE_HASH_CHANGED')
            if row['status']=='available':sources[(row['path'],row['side'])]=(raw.decode(row['encoding']).splitlines(),row)
    units={u['id']:u for u in plan['units']};decisions=draft.get('coverage',[])
    w.need(len(units)==len(plan['units']),'REVIEW_DUPLICATE_UNIT')
    for unit in units.values():
        body=dict(unit);ident=body.pop('id');source=sources.get((unit['path'],unit['side']))
        w.need(ident==digest(body) and source is not None,'REVIEW_UNIT_BINDING_INVALID')
        lines,row=source;a,b=unit['line_start'],unit['line_end']
        w.need(unit.get('source_binding')==row.get('source_binding'),'REVIEW_UNIT_OWNER_MISMATCH')
        w.need(unit['revision']==row['revision'] and unit['raw_sha256']==row['raw_sha256'] and
               1<=a<=b<=len(lines) and unit['text']=='\n'.join(lines[a-1:b]),'REVIEW_UNIT_SOURCE_MISMATCH')
    for key,(lines,row) in sources.items():
        intervals=sorted((u['line_start'],u['line_end']) for u in units.values() if (u['path'],u['side'])==key)
        cursor=1
        for start,end in intervals:
            w.need(start==cursor,'REVIEW_SOURCE_INTERVAL_GAP_OR_OVERLAP');cursor=end+1
        w.need(cursor==len(lines)+1 and row['line_count']==len(lines),'REVIEW_SOURCE_INTERVAL_INCOMPLETE')
    w.need(isinstance(decisions,list) and len(decisions)==len(units) and {x.get('unit_id') for x in decisions}==set(units),'REVIEW_COVERAGE_INCOMPLETE')
    reviewed=set()
    for row in decisions:
        w.need(row.get('status') in ('reviewed','deferred') and isinstance(row.get('reason'),str) and len(row['reason'].strip())>=8,'REVIEW_DECISION_REQUIRED')
        if row['status']=='reviewed':reviewed.add(row['unit_id'])
    features=draft.get('features',[]);w.need(isinstance(features,list) and len(features)<=128,'FUNCTIONAL_FEATURE_LIMIT')
    ids=set();cited=set()
    for feature in features:
        ident=feature.get('id');w.need(isinstance(ident,str) and ident and ident not in ids,'FEATURE_ID_INVALID');ids.add(ident)
        for key in ('title',*FIELDS):
            value=feature.get(key);w.need(isinstance(value,str) and 8<=len(value.strip())<=64000,'FUNCTIONAL_REASONING_REQUIRED:'+key)
        details=feature.get('details',{})
        w.need(isinstance(details,dict) and set(details)<=set(DETAIL_FIELDS),'FUNCTIONAL_DETAILS_INVALID')
        for key,value in details.items():
            w.need(isinstance(value,str) and 20<=len(value.strip())<=64000,'FUNCTIONAL_DETAIL_REASONING_REQUIRED:'+key)
        if report_policy(c)['require_extended_analysis']:
            w.need(set(details)==set(DETAIL_FIELDS),'EXTENDED_FUNCTIONAL_ANALYSIS_REQUIRED')
        # An optimization can explicitly conclude that no change is warranted,
        # but must explain why rather than inventing an issue or speedup.
        refs=feature.get('citations',[]);w.need(isinstance(refs,list) and refs,'FUNCTIONAL_CITATIONS_REQUIRED')
        commits=feature.get('commits',[])
        w.need(isinstance(commits,list) and commits and set(commits)<={x['sha'] for x in plan['effective_commits']},'FEATURE_COMMIT_SCOPE_INVALID')
        change_refs=[]
        for ref in refs:
            unit=units.get(ref.get('unit_id'));w.need(unit is not None and unit['id'] in reviewed,'FEATURE_UNREVIEWED_SOURCE')
            a,b=ref.get('line_start'),ref.get('line_end');w.need(type(a) is int and type(b) is int and unit['line_start']<=a<=b<=unit['line_end'],'FEATURE_LINE_RANGE_INVALID')
            lines=unit['text'].splitlines();quote=ref.get('quote','')
            w.need(isinstance(quote,str) and quote.strip() and quote in '\n'.join(lines[a-unit['line_start']:b-unit['line_start']+1]),'FEATURE_QUOTE_MISSING')
            cited.add(unit['id'])
            if unit['role']=='change':change_refs.append(unit)
        w.need(change_refs,'FEATURE_CHANGE_EVIDENCE_REQUIRED')
        source_commits={x for row in plan['files'] if row['path'] in {u['path'] for u in change_refs} for x in row['commits']}
        w.need(set(commits)<=source_commits,'FEATURE_UNRELATED_COMMIT')
    w.need(reviewed<=cited,'REVIEWED_BATCH_WITHOUT_ANALYSIS')
    if reviewed:w.need(features,'FUNCTIONAL_ANALYSIS_MISSING')
    elif units:w.need(isinstance(draft.get('summary'),str) and len(draft['summary'])>=20,'DEFERRED_REVIEW_REASON_REQUIRED')
    w.need(w.git(c,'rev-parse','HEAD')==plan['head'],'REVIEW_HEAD_MOVED')
    gaps=[x for x in plan['files'] if x['status']=='deferred']
    return dict(schema='ces.functional_review_receipt.v1',plan_sha256=binding,draft_sha256=digest(draft),
                head=plan['head'],reviewed_units=len(reviewed),deferred_units=len(units)-len(reviewed),source_gaps=gaps,
                semantic_review_by='Codex/operator; exact citations are not independent correctness proof')

def complete(c,plan_path,draft_path,output):
    plan=w.load(plan_path);draft=w.load(draft_path);receipt=validate(c,plan,draft)
    w.save(output,dict(schema='ces.functional_review_record.v1',plan=plan,draft=draft,receipt=receipt))
    return dict(status='functional_review_recorded',output=str(output),**receipt)

def for_run(c,run):
    path=Path(run)/'functional-review.json'
    if not path.exists():
        w.need(not c.get('review',{}).get('require_functional_analysis',False),'FUNCTIONAL_REVIEW_REQUIRED');return None
    record=w.load(path);w.need(record.get('schema')=='ces.functional_review_record.v1','FUNCTIONAL_RECORD_INVALID')
    receipt=validate(c,record['plan'],record['draft']);w.need(receipt==record['receipt'],'FUNCTIONAL_RECORD_CHANGED')
    w.need(receipt['head']==w.load(Path(run)/'run.json')['head'],'FUNCTIONAL_RUN_HEAD_MISMATCH')
    # Recompute, never use a formatted cached copy as validation.
    return record

def feature_lines(c,record,commits):
    units={u['id']:u for u in record['plan']['units']};lines=[]
    for feature in record['draft']['features']:
        if not set(feature['commits']).intersection(commits):continue
        lines+=['','### '+w.md(feature['title']),'',feature['purpose'],'',
                '**功能变化**：'+feature['behavior_change'],'','**实现与算法**：'+feature['mechanism'],'',
                '**正确性分析**：'+feature['correctness'],'','**优化判断**：'+feature['optimization'],'']
        lines+=detail_lines(feature)
        for ref in feature['citations']:
            u=units[ref['unit_id']];lines.append('- ['+u['path']+':L'+str(ref['line_start'])+' ('+u['side']+')]('+w.source_link(c,u['revision'],u['path'])+'#L'+str(ref['line_start'])+')')
    if record['plan'].get('submodule_changes'):
        lines+=['','### 子模块集成与来源提交','']
        for change in record['plan']['submodule_changes']:
            lines.append('- '+change['path']+'：'+str(change['before'])+' → '+str(change['after'])+'；'+change['repository']+'；迁移/集成作者与子提交作者分别保留。')
            for commit in change['commits']:
                lines.append('- ['+commit['sha'][:12]+']('+commit['url']+') '+w.md(commit['subject'])+'；author='+w.md(commit['author_name'])+'；committer='+w.md(commit['committer_name']))
    return lines

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('prepare');a.add_argument('--config',required=True);a.add_argument('--base',required=True);a.add_argument('--target',default='HEAD');a.add_argument('--context',action='append',default=[])
    a=sub.add_parser('complete');a.add_argument('--config',required=True);a.add_argument('--plan',required=True);a.add_argument('--draft',required=True);a.add_argument('--run',required=True)
    args=p.parse_args();c=w.config(args.config)
    if args.command=='prepare':result=prepare(c,args.base,args.target,args.context)
    else:
        run=Path(args.run).resolve();w.need(Path(c['output_root']).resolve() in run.parents,'RUN_OUTSIDE_CONFIGURED_ROOT')
        result=complete(c,args.plan,args.draft,run/'functional-review.json')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
