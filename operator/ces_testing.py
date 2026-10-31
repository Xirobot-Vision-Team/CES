"""Opt-in project test contracts, execution evidence and Codex-authored test reports."""
from __future__ import annotations
import argparse,copy,contextlib,json,os,re,signal,subprocess,threading,time,uuid
from pathlib import Path,PurePosixPath
from datetime import datetime,timezone
import ces_workflow as w
import ces_reports as reports
import ces_notifications as notifications
import ces_test_results as results
import ces_test_ownership as ownership
from ces_documents import unsafe

def digest(value):return reports.digest(value)
def now():return datetime.now(timezone.utc).isoformat()
def home(c):
    path=Path(c.get('cache_root',c['state_root']))/'testing'/str(c['github']['repository_id'])
    w.need(not path.resolve().is_relative_to(Path(c['repository_path']).resolve()),'TEST_CACHE_MUST_BE_OUTSIDE_REPOSITORY')
    return path
def safe_name(name):
    w.need(isinstance(name,str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}',name) is not None,'TEST_ENTRY_NAME_INVALID')
    return name
def relative(name):
    w.need(isinstance(name,str) and name and '\\' not in name and ':' not in name and not name.startswith('/') and all(x not in ('','..','.') for x in name.split('/')),'TEST_RELATIVE_PATH_INVALID')
    return PurePosixPath(name)
def bounded_path(root,name):
    root=Path(root).resolve();path=root/relative(name)
    for part in [path,*path.parents]:
        w.need(not unsafe(part),'TEST_REPARSE_PATH_REFUSED')
        if part==root:break
    w.need(path.resolve().is_relative_to(root),'TEST_PATH_ESCAPE')
    return path
def entry(c,name):
    safe_name(name);cfg=c.get('testing',{});items=cfg.get('entries',[])
    w.need(isinstance(items,list) and len(items)<=32,'TEST_ENTRIES_INVALID')
    w.need(len({safe_name(x['name']) for x in items})==len(items),'TEST_DUPLICATE_ENTRY')
    item=next((x for x in items if x['name']==name),None);w.need(item is not None,'TEST_ENTRY_NOT_CONFIGURED')
    argv=item.get('argv');w.need(isinstance(argv,list) and argv and all(isinstance(x,str) and x for x in argv),'TEST_ARGV_REQUIRED')
    sources=item.get('sources',[])
    w.need(isinstance(sources,list) and 1<=len(sources)<=32 and len(set(sources))==len(sources),'TEST_SOURCES_REQUIRED')
    for path in sources:relative(path)
    timeout=item.get('timeout_seconds',600);w.need(type(timeout) is int and 1<=timeout<=7200,'TEST_TIMEOUT_INVALID')
    environment(item)
    return item

def environment(item):
    values=item.get('environment',{})
    w.need(isinstance(values,dict) and len(values)<=32,'TEST_ENVIRONMENT_INVALID')
    seen=set()
    for key,value in values.items():
        w.need(isinstance(key,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',key) and key.upper() not in seen and not key.upper().startswith('GIT_'),'TEST_ENVIRONMENT_KEY_INVALID')
        w.need(isinstance(value,str) and len(value)<=32768 and not any(ch in value for ch in ('\0','\r','\n')),'TEST_ENVIRONMENT_VALUE_INVALID');seen.add(key.upper())
    return values

def process_environment(item,variables):
    env=w.clean_env();substitutions={**variables,'path':env.get('PATH',env.get('Path',''))}
    for key,value in environment(item).items():
        if os.name=='nt':
            for prior in list(env):
                if prior.casefold()==key.casefold():del env[prior]
        expanded=value.format_map(substitutions)
        w.need(len(expanded)<=32768 and not any(ch in expanded for ch in ('\0','\r','\n')),'TEST_ENVIRONMENT_VALUE_INVALID')
        env[key]=expanded
    return env
def execution_spec(item):
    spec={key:item.get(key,default) for key,default in (('name',None),('argv',None),('cwd','{repository}'),('timeout_seconds',600),('sources',[]))}
    if item.get('environment'):spec['environment']=environment(item)
    return spec
def sources(c,item,head):
    output=[]
    for path in item['sources']:
        w.need(w.git(c,'ls-files','--',':(literal)'+path).splitlines()==[path],'TEST_SOURCE_NOT_TRACKED')
        text=w.git(c,'show',head+':'+path)
        w.need(len(text.encode('utf-8'))<=4*1024*1024,'TEST_SOURCE_SIZE_LIMIT')
        output.append(dict(path=path,sha256=w.sha(text),text=text))
    return output
def fingerprint(items):return [dict(path=x['path'],sha256=x['sha256']) for x in items]
def pinned_head(c):
    head=w.git(c,'rev-parse','HEAD');branch=c.get('repository_sync',{}).get('branch') or w.git(c,'branch','--show-current')
    w.need(branch and not branch.startswith('-'),'TEST_BRANCH_REQUIRED')
    remote=w.git(c,'ls-remote','--exit-code','origin','refs/heads/'+branch).split()[0]
    w.need(head==remote,'TEST_HEAD_NOT_CURRENT_REMOTE_HEAD')
    w.need(not w.git(c,'status','--porcelain=v1','-uall'),'TEST_DIRTY_WORKTREE')
    return head
@contextlib.contextmanager
def lock(c,name):
    root=home(c);root.mkdir(parents=True,exist_ok=True);path=root/(safe_name(name)+'.lock')
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.write(fd,str(os.getpid()).encode());os.close(fd)
    try:yield
    finally:path.unlink(missing_ok=True)
def checked_doc(path,key,schema):
    doc=w.load(path);core={k:v for k,v in doc.items() if k!=key}
    w.need(doc.get('schema')==schema and doc.get(key)==digest(core),'TEST_DOCUMENT_BINDING_INVALID')
    return doc
def effective_ownership(c,item):
    root=home(c)/'ownership'/item['name'];pointer=root/'current.json';version=None
    if 'ownership' in item:
        rows=ownership.mappings(item['ownership']);origin='entry_profile'
    elif pointer.exists():
        key=w.load(pointer).get('ownership_id');w.need(re.fullmatch(r'[0-9a-f]{64}',key or '') is not None,'TEST_OWNERSHIP_POINTER_INVALID')
        record=checked_doc(root/(key+'.json'),'ownership_id','ces.test_ownership_record.v1')
        w.need(record['repository_id']==c['github']['repository_id'] and record['entry']==item['name'],'TEST_OWNERSHIP_REPOSITORY_MISMATCH')
        rows=ownership.mappings(record['mappings']);origin='entry_registry';version=key
    else:
        rows=ownership.mappings(c.get('testing',{}).get('ownership',[]));origin='project_profile'
    for path in sorted({path for row in rows for path in row['source_paths']}):
        w.need(w.git(c,'ls-files','--',':(literal)'+path).splitlines()==[path],'TEST_OWNERSHIP_SOURCE_NOT_TRACKED')
    snapshot=dict(schema='ces.test_ownership_snapshot.v1',repository_id=c['github']['repository_id'],entry=item['name'],origin=origin,registry_version=version,mappings=rows)
    snapshot['ownership_snapshot_id']=digest(snapshot)
    return snapshot
def owners(c,name,input_path=None,execute=False):
    item=entry(c,name)
    if not input_path:return effective_ownership(c,item)
    doc=w.load(input_path)
    w.need(doc.get('schema')=='ces.test_ownership.v1' and doc.get('entry')==name,'TEST_OWNERSHIP_INPUT_INVALID')
    rows=ownership.mappings(doc.get('mappings'))
    for path in sorted({path for row in rows for path in row['source_paths']}):
        w.need(w.git(c,'ls-files','--',':(literal)'+path).splitlines()==[path],'TEST_OWNERSHIP_SOURCE_NOT_TRACKED')
    record=dict(schema='ces.test_ownership_record.v1',repository_id=c['github']['repository_id'],entry=name,registered_head=w.git(c,'rev-parse','HEAD'),mappings=rows)
    record['ownership_id']=digest(record)
    if execute:
        with lock(c,name):
            root=home(c)/'ownership'/name;w.save(root/(record['ownership_id']+'.json'),record)
            w.save(root/'current.json',dict(ownership_id=record['ownership_id']))
    return dict(status='test_ownership_registered' if execute else 'test_ownership_preview',ownership_id=record['ownership_id'],entry=name,mappings=rows,profile_override='ownership' in item,next_step='Applied to future test runs; historical run ownership snapshots are retained. No test or message sent.')
def run_ownership(c,run,receipt,normalized):
    if receipt.get('ownership_sha256'):
        path=bounded_path(run,'ownership.json');w.need(w.sha(path.read_bytes())==receipt['ownership_sha256'],'TEST_OWNERSHIP_CHANGED')
        snapshot=checked_doc(path,'ownership_snapshot_id','ces.test_ownership_snapshot.v1')
        w.need(snapshot['repository_id']==c['github']['repository_id'] and snapshot['entry']==receipt['entry'],'TEST_OWNERSHIP_REPOSITORY_MISMATCH')
        result=ownership.resolve(normalized,snapshot['mappings'])
        result.update(ownership_snapshot_id=snapshot['ownership_snapshot_id'],ownership_origin=snapshot['origin'],registry_version=snapshot['registry_version'])
        return result
    return ownership.resolve(normalized,[])
def prepare(c,name):
    item=entry(c,name);head=w.git(c,'rev-parse','HEAD');selected=sources(c,item,head)
    hints=[]
    patterns={'junit_xml':r'junit|testsuites?|junitxml','trx_xml':r'\btrx\b|UnitTestResult','json':r'json\.(?:dump|dumps)|\.json\b','csv':r'csv\.(?:writer|DictWriter)|\.csv\b','console_regex':r'\bprint\s*\(|std::cout|Console\.Write'}
    for source in selected:
        for number,line in enumerate(source['text'].splitlines(),1):
            for fmt,pattern in patterns.items():
                if re.search(pattern,line,re.I) and len(hints)<128:hints.append(dict(format_candidate=fmt,path=source['path'],line=number,quote=line[:600],certainty='hint_only_requires_source_review'))
    body=dict(schema='ces.test_discovery.v1',repository_id=c['github']['repository_id'],entry=execution_spec(item),head=head,sources=selected,format_hints=hints,created_at=now(),remote_content_untrusted=True)
    body['input_binding_sha256']=digest(body);dest=home(c)/'discovery'/(body['input_binding_sha256']+'.json');w.save(dest,body)
    return dict(status='test_discovery_ready',input=str(dest),input_binding_sha256=body['input_binding_sha256'],head=head,hints=len(hints),next_step='Codex reads actual test entry, writer and runner sources; writes a cited result contract. No test executed.')
def validate_contract(doc,inp):
    w.need(doc.get('schema')=='ces.test_contract.v1' and doc.get('input_binding_sha256')==inp['input_binding_sha256'],'TEST_CONTRACT_INPUT_MISMATCH')
    w.need(isinstance(doc.get('summary'),str) and 30<=len(doc['summary'])<=12000,'TEST_CONTRACT_REASONING_REQUIRED')
    artifacts=doc.get('artifacts',[]);console=doc.get('console')
    w.need(isinstance(artifacts,list) and len(artifacts)<=16 and (artifacts or console),'TEST_RESULT_PROTOCOL_REQUIRED')
    specs=artifacts+([console] if console else [])
    for spec in specs:
        w.need(isinstance(spec,dict) and spec.get('format') in results.FORMATS,'TEST_FORMAT_UNSUPPORTED')
        w.need(set(spec)<= {'format','glob','mapping','pattern'},'TEST_PROTOCOL_FIELD_UNSUPPORTED')
        if spec in artifacts:
            relative(spec.get('glob'));w.need(spec['format']!='console_regex','TEST_CONSOLE_PROTOCOL_SEPARATE')
        if spec is console:w.need(spec['format'] in ('console_regex','json_lines'),'TEST_CONSOLE_FORMAT_UNSUPPORTED')
        if spec['format']=='console_regex':
            regex=spec.get('pattern','');w.need(0<len(regex)<=1000 and {'id','status'}<=set(re.compile(regex).groupindex),'TEST_CONSOLE_GROUPS_REQUIRED')
        mapping=spec.get('mapping',{});w.need(isinstance(mapping,dict) and set(mapping)<={'cases','id','status','message','duration','statuses','total'},'TEST_MAPPING_INVALID')
        for key,value in mapping.items():
            if key!='statuses':w.need(isinstance(value,str) and len(value)<=200,'TEST_MAPPING_INVALID')
        if 'statuses' in mapping:
            w.need(isinstance(mapping['statuses'],dict) and mapping['statuses'] and all(isinstance(x,str) for x in mapping['statuses']) and set(mapping['statuses'].values())<=results.STATUSES,'TEST_STATUS_MAPPING_INVALID')
    required=doc.get('required_cases',[]);w.need(isinstance(required,list) and len(required)<=results.MAX_CASES and all(isinstance(x,str) and x for x in required) and len(set(required))==len(required),'TEST_REQUIRED_CASES_INVALID')
    citations=doc.get('citations',[]);w.need(isinstance(citations,list) and 1<=len(citations)<=64,'TEST_CONTRACT_CITATIONS_REQUIRED')
    verify_source_citations(citations,inp['sources'])
def verify_source_citations(citations,selected):
    texts={x['path']:x['text'] for x in selected}
    for ref in citations:
        w.need(ref.get('path') in texts,'TEST_CITATION_SOURCE_INVALID')
        lines=texts[ref['path']].splitlines();a,b=ref.get('line_start'),ref.get('line_end')
        w.need(type(a) is int and type(b) is int and 1<=a<=b<=len(lines) and b-a<100,'TEST_CITATION_RANGE_INVALID')
        w.need(isinstance(ref.get('quote'),str) and ref['quote'].strip() and ref['quote'] in '\n'.join(lines[a-1:b]),'TEST_CITATION_QUOTE_INVALID')
def register(c,input_path,draft_path,execute=False):
    inp=checked_doc(input_path,'input_binding_sha256','ces.test_discovery.v1');doc=w.load(draft_path)
    w.need(inp['repository_id']==c['github']['repository_id'],'TEST_REPOSITORY_MISMATCH')
    item=entry(c,inp['entry']['name']);head=w.git(c,'rev-parse','HEAD')
    w.need(execution_spec(item)==inp['entry'] and head==inp['head'] and fingerprint(sources(c,item,head))==fingerprint(inp['sources']),'TEST_DISCOVERY_STALE')
    validate_contract(doc,inp)
    record=dict(schema='ces.test_contract_record.v1',repository_id=inp['repository_id'],entry=inp['entry'],reviewed_head=head,sources=fingerprint(inp['sources']),contract=doc,parser_version=1)
    record['contract_id']=digest(record)
    if execute:
        with lock(c,item['name']):
            path=home(c)/'contracts'/item['name']/(record['contract_id']+'.json');w.save(path,record)
            w.save(path.parent/'current.json',dict(contract_id=record['contract_id']))
    return dict(status='test_contract_registered' if execute else 'test_contract_preview',entry=item['name'],contract_id=record['contract_id'],sources=len(record['sources']),execution_enabled=c.get('testing',{}).get('enabled',False))
def current_contract(c,item):
    root=home(c)/'contracts'/item['name'];pointer=w.load(root/'current.json');key=pointer.get('contract_id')
    w.need(re.fullmatch(r'[0-9a-f]{64}',key or '') is not None,'TEST_CONTRACT_POINTER_INVALID')
    doc=checked_doc(root/(key+'.json'),'contract_id','ces.test_contract_record.v1')
    w.need(doc['repository_id']==c['github']['repository_id'] and doc['entry']==execution_spec(item) and doc['parser_version']==1,'TEST_CONTRACT_CONFIGURATION_CHANGED')
    w.need(fingerprint(sources(c,item,w.git(c,'rev-parse','HEAD')))==doc['sources'],'TEST_CONTRACT_SOURCE_CHANGED_REREVIEW')
    return doc
def execute_process(argv,cwd,timeout,console,environment=None):
    """Bounded console capture, timeout kills the process tree; never launches via shell."""
    state=dict(truncated=False,output_complete=True);flags={'start_new_session':True} if os.name!='nt' else {}
    proc=subprocess.Popen(argv,cwd=cwd,env=environment if environment is not None else w.clean_env(),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,**flags)
    def drain():
        total=0
        with console.open('wb') as stream:
            while True:
                chunk=proc.stdout.read(65536)
                if not chunk:break
                remaining=max(0,results.MAX_BYTES-total);stream.write(chunk[:remaining]);total+=len(chunk)
                if total>results.MAX_BYTES:state['truncated']=True
    thread=threading.Thread(target=drain,daemon=True);thread.start();timed_out=False
    try:code=proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out=True
        if os.name=='nt':subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],capture_output=True)
        else:os.killpg(proc.pid,signal.SIGKILL)
        proc.wait();code=-1
    thread.join(5)
    if thread.is_alive():state['output_complete']=False
    else:proc.stdout.close()
    return dict(exit_code=code,timed_out=timed_out,console_truncated=state['truncated'],output_complete=state['output_complete'])
def collect(run,contract):
    cases=[];artifacts=[];errors=[];seen=set();count=0
    def take(path,spec):
        nonlocal count
        count+=1;w.need(count<=64,'TEST_ARTIFACT_COUNT_LIMIT')
        rel=path.relative_to(run).as_posix();path=bounded_path(run,rel)
        w.need(path.is_file() and path.stat().st_size<=results.MAX_BYTES,'TEST_RESULT_SIZE_LIMIT')
        raw=path.read_bytes();artifacts.append(dict(path=rel,sha256=w.sha(raw),bytes=len(raw),format=spec['format']))
        for row in results.parse(raw,spec):
            w.need(row['id'] not in seen,'TEST_DUPLICATE_CASE_ID');seen.add(row['id'])
            cases.append({**row,'artifact':rel});w.need(len(cases)<=results.MAX_CASES,'TEST_CASE_LIMIT')
    for spec in contract.get('artifacts',[]):
        matches=sorted((run/'results').glob(spec['glob']))
        if not matches:errors.append(dict(artifact=spec['glob'],reason='TEST_ARTIFACT_MISSING'))
        for path in matches:
            try:take(path,spec)
            except Exception as exc:errors.append(dict(artifact=path.relative_to(run).as_posix(),reason=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__))
    if contract.get('console'):
        try:take(run/'console.log',contract['console'])
        except Exception as exc:errors.append(dict(artifact='console.log',reason=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__))
    return cases,artifacts,errors
def run_test(c,name,execute=False):
    item=entry(c,name)
    if not execute:return dict(status='test_execution_preview',entry=execution_spec(item),enabled=c.get('testing',{}).get('enabled',False),next_step='Review/register result contract and explicitly authorize execution. No test executed.')
    cfg=c.get('testing',{});w.need(cfg.get('enabled') is True and cfg.get('allow_execute') is True,'PROJECT_TEST_EXECUTION_DISABLED')
    w.need(c.get('execution_policy',{}).get('run_runtime_tests') is True,'RUNTIME_TESTS_DISABLED_BY_USER_POLICY')
    with lock(c,name):
        head=pinned_head(c);contract=current_contract(c,item);registered_owners=effective_ownership(c,item);before=w.snapshot(c)
        run=home(c)/'runs'/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:10]);run.mkdir(parents=True)
        (run/'results').mkdir();variables=dict(repository=c['repository_path'],run=str(run),results=str(run/'results'))
        argv=[x.format_map(variables) for x in item['argv']];cwd=Path(item.get('cwd','{repository}').format_map(variables)).resolve();repo=Path(c['repository_path']).resolve()
        w.need(cwd.is_relative_to(repo) and cwd.is_dir(),'TEST_CWD_OUTSIDE_REPO')
        w.need(Path(argv[0]).is_absolute() and Path(argv[0]).is_file(),'TEST_EXECUTABLE_ABSOLUTE_PATH_REQUIRED')
        exe_hash=w.sha(Path(argv[0]).read_bytes());started=now();selected=sources(c,item,head)
        w.save(run/'contract.json',contract);w.save(run/'sources.json',dict(head=head,sources=selected));w.save(run/'ownership.json',registered_owners)
        ownership_hash=w.sha((run/'ownership.json').read_bytes())
        errors=[];start=time.monotonic()
        env=process_environment(item,variables)
        try:process=execute_process(argv,str(cwd),item.get('timeout_seconds',600),run/'console.log',environment=env)
        except OSError as exc:
            process=dict(exit_code=None,timed_out=False,console_truncated=False,output_complete=True)
            (run/'console.log').write_text('Test process failed to start: '+type(exc).__name__,encoding='utf-8');errors.append(dict(artifact='console.log',reason='TEST_PROCESS_START_FAILED'))
        if process['console_truncated'] or not process['output_complete']:errors.append(dict(artifact='console.log',reason='TEST_CONSOLE_INCOMPLETE'))
        try:stable=pinned_head(c)==head and w.snapshot(c)==before and fingerprint(sources(c,item,head))==fingerprint(selected) and w.sha(Path(argv[0]).read_bytes())==exe_hash
        except Exception:stable=False
        cases,artifacts,parse_errors=collect(run,contract['contract']);errors+=parse_errors
        normalized=dict(schema='ces.test_results.v1',repository_id=c['github']['repository_id'],entry=name,head=head,cases=cases,summary=results.summarize(cases,process['exit_code'],process['timed_out'],errors,contract['contract'].get('required_cases',[]),stable))
        receipt=dict(schema='ces.project_test_receipt.v1',repository_id=c['github']['repository_id'],entry=name,head=head,contract_id=contract['contract_id'],argv=argv,cwd=str(cwd),executable_sha256=exe_hash,started_at=started,completed_at=now(),seconds=round(time.monotonic()-start,2),**process,source_stable=stable,console_sha256=w.sha((run/'console.log').read_bytes()),artifacts=artifacts,normalized_sha256=digest(normalized),sources_sha256=w.sha((run/'sources.json').read_bytes()),binary_source_binding_verified=False,semantic_fix_verification=False)
        receipt['ownership_sha256']=ownership_hash
        if environment(item):receipt['environment_spec_sha256']=digest(environment(item));receipt['effective_environment_sha256']=digest(env)
        receipt['receipt_id']=digest(receipt);w.save(run/'receipt.json',receipt);w.save(run/'results.json',normalized)
        developer_routing=run_ownership(c,run,receipt,normalized)
        packet=dict(schema='ces.test_analysis_input.v1',receipt_id=receipt['receipt_id'],normalized_sha256=receipt['normalized_sha256'],head=head,summary=normalized['summary'],cases=cases,artifacts=artifacts,untrusted_test_output=True,next_step='Codex reads logs, normalized failures and relevant code; authors evidence-bound analysis.json. Exit code and parsing do not determine root cause.')
        packet['developer_routing']=developer_routing
        w.save(run/'analysis-input.json',packet);w.save(home(c)/'latest-run.json',dict(run_directory=str(run)))
        return dict(status='test_evidence_ready',run=str(run),receipt_id=receipt['receipt_id'],result=normalized['summary'],analysis_input=str(run/'analysis-input.json'))
def verify_run(c,path):
    run=Path(path).resolve();w.need(run.parent== (home(c)/'runs').resolve() and not unsafe(run),'TEST_RUN_OUTSIDE_PROJECT_CACHE')
    receipt=checked_doc(bounded_path(run,'receipt.json'),'receipt_id','ces.project_test_receipt.v1')
    w.need(receipt['repository_id']==c['github']['repository_id'],'TEST_REPOSITORY_MISMATCH')
    normalized=w.load(bounded_path(run,'results.json'));w.need(digest(normalized)==receipt['normalized_sha256'],'TEST_RESULTS_CHANGED')
    w.need(w.sha(bounded_path(run,'console.log').read_bytes())==receipt['console_sha256'],'TEST_CONSOLE_CHANGED')
    w.need(w.sha(bounded_path(run,'sources.json').read_bytes())==receipt['sources_sha256'],'TEST_SOURCES_CHANGED')
    contract=checked_doc(bounded_path(run,'contract.json'),'contract_id','ces.test_contract_record.v1')
    w.need(contract['contract_id']==receipt['contract_id'],'TEST_CONTRACT_CHANGED')
    for artifact in receipt['artifacts']:
        file=bounded_path(run,artifact['path']);w.need(file.is_file() and w.sha(file.read_bytes())==artifact['sha256'],'TEST_ARTIFACT_CHANGED')
    run_ownership(c,run,receipt,normalized)
    return run,receipt,normalized
def analysis_record(c,run,receipt,normalized,draft):
    w.need(draft.get('schema')=='ces.test_analysis.v1' and draft.get('receipt_id')==receipt['receipt_id'] and draft.get('normalized_sha256')==receipt['normalized_sha256'],'TEST_ANALYSIS_BINDING_INVALID')
    w.need(draft.get('observed_status')==normalized['summary']['status'],'TEST_ANALYSIS_CANNOT_CHANGE_RESULT')
    for field in ('summary','root_cause','recommendation','verification','limitations'):
        w.need(isinstance(draft.get(field),str) and 20<=len(draft[field])<=16000,'TEST_ANALYSIS_SECTION_REQUIRED:'+field)
    citations=draft.get('citations',[]);w.need(isinstance(citations,list) and 1<=len(citations)<=64,'TEST_ANALYSIS_CITATIONS_REQUIRED')
    allowed={'console.log','results.json'}|{x['path'] for x in receipt['artifacts']};source_refs=[]
    selected=w.load(run/'sources.json')['sources']
    for ref in citations:
        if ref.get('kind')=='source':source_refs.append(ref);continue
        w.need(ref.get('kind')=='artifact' and ref.get('path') in allowed,'TEST_ANALYSIS_CITATION_INVALID')
        content=bounded_path(run,ref['path']).read_text(encoding='utf-8-sig',errors='replace')
        w.need(isinstance(ref.get('quote'),str) and 0<len(ref['quote'])<=2000 and ref['quote'] in content,'TEST_ANALYSIS_QUOTE_INVALID')
    verify_source_citations(source_refs,selected)
    w.need(any(x.get('kind')=='artifact' for x in citations),'TEST_ANALYSIS_OUTPUT_EVIDENCE_REQUIRED')
    lines=['# 测试审查报告','',f"测试入口：{receipt['entry']}；来源提交：{receipt['head']}",f"执行时间：{receipt['started_at']} 至 {receipt['completed_at']}",f"执行结果：{normalized['summary']['status']}；退出码：{receipt['exit_code']}；用例：{normalized['summary']['total']}",f"汇总：{json.dumps(normalized['summary']['counts'],ensure_ascii=False)}",'']
    for field,label in (('summary','分析结论'),('root_cause','原因分析与待证实项'),('recommendation','处理建议'),('verification','后续验证'),('limitations','覆盖与限制')):lines+=['## '+label,'',draft[field].replace('@','&#64;'),'']
    lines+=['## 用例证据','']
    ordered=sorted(normalized['cases'],key=lambda case:({'failed':0,'error':1,'skipped':2,'passed':3}[case['status']],case['id']))
    for case in ordered[:100]:lines.append('- '+reports.safe(case['id'])+'：'+case['status']+'；'+reports.safe(case['message']))
    if len(normalized['cases'])>100:lines.append('- 完整用例清单保存在本轮外部结构化产物；此处优先展示失败/错误，最多100项。')
    for error in normalized['summary']['parse_errors']:lines.append('- 结果读取缺口：'+reports.safe(str(error)))
    if receipt.get('ownership_sha256'):
        routing=run_ownership(c,run,receipt,normalized)
        lines+=['','## 问题用例与登记开发者','', '登记快照：'+routing['ownership_snapshot_id']+'；来源：'+routing['ownership_origin'],'']
        shown=0;total=sum(len(match['subjects']) for match in routing['matches'])
        for match in routing['matches']:
            for subject in match['subjects']:
                if shown<100:lines.append('- '+reports.safe(match['case_id'])+' → '+reports.safe(subject['name'])+'（'+subject['kind']+'）；开发者：'+', '.join(subject['developers'])+'；依据：'+subject['matched_by'])
                shown+=1
        if total>100:lines.append('- 显示前100条归属匹配；完整关系保留在本轮证据及发送回执中，抄送仍按全部匹配去重。')
        for case_id in routing['unmapped_problem_cases'][:100]:lines.append('- '+reports.safe(case_id)+'：未登记匹配开发者，交由测试维护工程师核对。')
        if len(routing['unmapped_problem_cases'])>100:lines.append('- 其余未匹配用例保留在本轮完整结构化记录中。')
        if not routing['matches'] and not routing['unmapped_problem_cases']:lines.append('- 无可归属的失败/错误用例；不据超时、全跳过或报告缺失猜测开发者。')
        lines.append('- 登记关系用于问题知会，不证明根因或个人责任；不自动改变Assignee。')
    lines+=['','## 证据引用','']
    for ref in citations:
        if ref['kind']=='source':lines.append('- ['+reports.safe(ref['path'])+':L'+str(ref['line_start'])+']('+w.source_link(c,receipt['head'],ref['path'])+'#L'+str(ref['line_start'])+')')
        else:lines.append('- '+reports.safe(ref['path'])+'：'+reports.safe(ref['quote']))
    lines+=['','本报告使用固定执行回执和Codex来源审阅；不等同于缺陷根因已证实、全库正确性或Issue修复验收。HEAD记录执行时源码上下文，实际可执行文件哈希不独立证明二进制与该源码的构建对应。原始日志和附件保留在仓库外，不自动上传。']
    markdown='\n'.join(lines)+'\n';record=dict(schema='ces.test_analysis_record.v1',receipt_id=receipt['receipt_id'],draft=draft,markdown=markdown)
    record['analysis_id']=digest(record)
    return record
def analyze(c,path,draft_path):
    run,receipt,normalized=verify_run(c,path);record=analysis_record(c,run,receipt,normalized,w.load(draft_path))
    w.save(run/'analysis.json',record);(run/'report.md').write_text(record['markdown'],encoding='utf-8')
    return dict(status='test_analysis_ready',analysis_id=record['analysis_id'],report=str(run/'report.md'))
def publish(c,path,execute=False):
    run,receipt,normalized=verify_run(c,path);record=checked_doc(run/'analysis.json','analysis_id','ces.test_analysis_record.v1')
    w.need(record['receipt_id']==receipt['receipt_id'],'TEST_ANALYSIS_BINDING_INVALID')
    w.need(analysis_record(c,run,receipt,normalized,record['draft'])==record,'TEST_ANALYSIS_RENDERING_CHANGED')
    cfg=c.get('testing',{});owners=notifications.unique(cfg.get('project_owners',[]));engineers=notifications.unique(cfg.get('test_maintainers',[]))
    w.need(owners or engineers or notifications.configured_cc(c),'TEST_REPORT_RECIPIENT_REQUIRED')
    developer_routing=run_ownership(c,run,receipt,normalized)
    developers=developer_routing['developers'];copies=notifications.unique(notifications.configured_cc(c)+owners+engineers+developers)
    if not execute:return dict(status='test_report_publish_preview',project_owners=owners,test_maintainers=engineers,developers=developers,developer_routing=developer_routing,cc_recipients=copies,report=str(run/'report.md'))
    w.need(cfg.get('enabled') is True and cfg.get('allow_publish') is True,'TEST_REPORT_PUBLICATION_DISABLED')
    notification_cfg=copy.deepcopy(c);notification_cfg.setdefault('notifications',{})['cc_recipients']=copies
    client=reports.Client(notification_cfg)
    roles=dict(project_owners=owners,test_maintainers=engineers)
    if receipt.get('ownership_sha256'):roles['developers']=developers
    semantic=digest(dict(analysis=record['analysis_id'],roles=roles))
    result=client.publish(f"test:{c['github']['repository_id']}:{receipt['entry']}",semantic,'[CES 测试审查] '+receipt['entry'],record['markdown'],[])
    result.update(project_owners=owners,test_maintainers=engineers,developers=developers,developer_routing=developer_routing,receipt_id=receipt['receipt_id'],test_report_only=True,automatic_code_issue_created=False,assignees_changed=False)
    w.save(run/'publication.json',result);return result
def status(c):
    cfg=c.get('testing',{});entries=[]
    for row in cfg.get('entries',[]):
        item=entry(c,row['name'])
        try:contract=current_contract(c,item);state='current';key=contract['contract_id']
        except FileNotFoundError:state='not_registered';key=None
        except RuntimeError as exc:state=str(exc);key=None
        registered_owners=effective_ownership(c,item)
        entries.append(dict(name=item['name'],contract_status=state,contract_id=key,ownership_origin=registered_owners['origin'],ownership_mapping_count=len(registered_owners['mappings']),ownership_snapshot_id=registered_owners['ownership_snapshot_id']))
    return dict(schema='ces.testing_status.v1',enabled=cfg.get('enabled',False),execution_allowed=cfg.get('allow_execute',False),runtime_policy=c.get('execution_policy',{}).get('run_runtime_tests',False),publication_allowed=cfg.get('allow_publish',False),project_owners=cfg.get('project_owners',[]),test_maintainers=cfg.get('test_maintainers',[]),entries=entries)
def export_reports(c):
    """Latest reviewed report per entry; raw runs remain outside the repository."""
    latest={}
    for path in sorted((home(c)/'runs').glob('*/analysis.json')):
        run,receipt,normalized=verify_run(c,path.parent)
        record=checked_doc(path,'analysis_id','ces.test_analysis_record.v1')
        w.need(analysis_record(c,run,receipt,normalized,record['draft'])==record,'TEST_ANALYSIS_RENDERING_CHANGED')
        name='reports/tests/'+safe_name(receipt['entry'])+'/latest.md'
        if name not in latest or receipt['completed_at']>latest[name][0]:latest[name]=(receipt['completed_at'],record['markdown'])
    return {name:value[1] for name,value in latest.items()}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['prepare','register','owners','run','analyze','publish','status'])
    p.add_argument('--config',required=True);p.add_argument('--entry');p.add_argument('--input');p.add_argument('--draft');p.add_argument('--run');p.add_argument('--execute',action='store_true')
    args=p.parse_args();c=w.config(args.config)
    if args.command=='prepare':result=prepare(c,args.entry)
    elif args.command=='register':result=register(c,args.input,args.draft,args.execute)
    elif args.command=='owners':result=owners(c,args.entry,args.input,args.execute)
    elif args.command=='run':result=run_test(c,args.entry,args.execute)
    elif args.command=='analyze':result=analyze(c,args.run,args.draft)
    elif args.command=='publish':result=publish(c,args.run,args.execute)
    else:result=status(c)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
