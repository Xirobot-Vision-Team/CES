"""Generic lifecycle: safe remote fast-forward, configured build-only validation, managed-doc Git publishing."""
from __future__ import annotations
import argparse,json,os,re,subprocess,sys,uuid,time
from pathlib import Path
from datetime import datetime,timezone
import ces_workflow as w
import ces_documents as docs

def home(c):
    path=Path(c.get("cache_root",c["state_root"]))/"lifecycle";path.mkdir(parents=True,exist_ok=True);return path
def time_now():return datetime.now(timezone.utc).isoformat()
def build_only_policy(c):
    policy=c.get('execution_policy',{}).get('run_runtime_tests')
    testing=c.get('testing',{})
    # Build steps stay build-only even when a separately authorized project test lane is enabled.
    return policy is False or (policy is True and testing.get('enabled') is True and testing.get('allow_execute') is True)
def run(c,*args,env=None,input_data=None,timeout=120):
    p=subprocess.run(["git","--no-optional-locks","-c","core.quotePath=false","-C",c["repository_path"],*args],
                     input=input_data,capture_output=True,env=env or w.clean_env(),timeout=timeout)
    if p.returncode:raise RuntimeError("GIT_LIFECYCLE_FAILED:"+args[0])
    return p.stdout.decode("utf-8").rstrip("\r\n")
def write_git(c,*args,**kw):return run(c,*args,**kw)
def branch(c):
    b=run(c,"branch","--show-current")
    w.need(b and b==c["repository_sync"]["branch"],"EXACT_CONFIGURED_BRANCH_REQUIRED")
    w.need(c["repository_sync"].get("remote","origin")=="origin","CONFIGURED_ORIGIN_REQUIRED")
    return b
def file_inventory(c):
    """Hash tracked/untracked modified source files, including deletions, without reading ignored outputs."""
    names=run(c,"diff","--name-only","-z","HEAD","--").split("\0")
    names+=run(c,"ls-files","--others","--exclude-standard","-z").split("\0")
    result={}
    for name in names:
        if not name:continue
        path=Path(c["repository_path"])/name
        w.need(not path.is_symlink() and (not hasattr(path,"is_junction") or not path.is_junction()),"CHANGED_PATH_REPARSE_REFUSED")
        if path.is_file():result[name]=w.sha(path.read_bytes())
        elif not path.exists():result[name]=None
        else:raise RuntimeError("UNSUPPORTED_CHANGED_FILE")
    return result
def business_changes(c):
    docroot=docs.root(c).relative_to(Path(c["repository_path"]).resolve()).as_posix()
    return run(c,"status","--porcelain=v1","-uall","--",".",":(exclude,top,glob)"+docroot+"/**",":(exclude,top,glob).codex/ces/**")
def sync(c):
    cfg=c.get("repository_sync",{})
    w.need(cfg.get("enabled") and cfg.get("allow_pull"),"AUTO_PULL_NOT_AUTHORIZED")
    b=branch(c);before=w.snapshot(c)
    w.need(not run(c,"diff","--cached","--name-only"),"STAGED_USER_CHANGES_BLOCK_AUTO_PULL")
    preserved=file_inventory(c)
    write_git(c,"fetch","--no-tags","origin","refs/heads/"+b,timeout=180)
    remote=run(c,"rev-parse","FETCH_HEAD")
    old=before["head"]
    if old!=remote:
        ancestry=subprocess.run(["git","--no-optional-locks","-C",c["repository_path"],"merge-base","--is-ancestor",old,remote],capture_output=True,env=w.clean_env())
        w.need(ancestry.returncode==0,"LOCAL_REMOTE_DIVERGED_NO_AUTOMATIC_REBASE_OR_RESET")
        incoming=set(run(c,"diff","--name-only",old,remote,"--").splitlines())
        w.need(not incoming.intersection(preserved),"PULL_WOULD_OVERWRITE_LOCAL_CHANGES")
        write_git(c,"-c","merge.autoStash=false","merge","--ff-only","--no-edit",remote)
    for name,expected in preserved.items():
        p=Path(c["repository_path"])/name
        w.need((w.sha(p.read_bytes()) if p.is_file() else None)==expected,"LOCAL_EDIT_CHANGED_DURING_PULL")
    after=w.snapshot(c)
    w.need(after["head"]==remote,"PULL_NOT_AT_REMOTE_HEAD")
    result=dict(schema="ces.source_sync.v1",status="up_to_date" if old==remote else "fast_forwarded",
                branch=b,old_head=old,head=remote,preserved_local_paths=list(preserved),completed_at=time_now(),
                stash_used=False,rebase_used=False,reset_used=False)
    w.save(home(c)/"last-sync.json",result);return result
def expand(c,argv,log):
    root=c["repository_path"]
    variables={"repository":root,"build_log":str(log),"cache":str(home(c))}
    return [arg.format_map(variables) for arg in argv]
def build(c):
    cfg=c.get("build_validation",{})
    w.need(cfg.get("enabled") is True,"BUILD_NOT_CONFIGURED")
    w.need(build_only_policy(c),"EXPLICIT_BUILD_ONLY_POLICY_REQUIRED")
    steps=cfg.get("steps",[]);w.need(steps and len(steps)<=8,"BUILD_STEPS_REQUIRED")
    w.need(all(x.get("kind")=="build" for x in steps),"RUNTIME_TEST_STEPS_FORBIDDEN")
    w.need(not business_changes(c),"UNCOMMITTED_BUSINESS_SOURCE_BLOCKS_REPRODUCIBLE_BUILD")
    before=w.snapshot(c);head=before["head"]
    runid=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:6]
    logdir=home(c)/"builds"/runid;logdir.mkdir(parents=True)
    results=[]
    for index,step in enumerate(steps):
        w.need(isinstance(step.get("argv"),list) and step["argv"] and all(isinstance(x,str) and x for x in step["argv"]),"BUILD_ARGV_INVALID")
        log=logdir/(str(index)+"-build.log");console=logdir/(str(index)+"-console.log")
        argv=expand(c,step["argv"],log)
        cwd=Path(step.get("cwd",c["repository_path"]).format(repository=c["repository_path"])).resolve()
        root=Path(c["repository_path"]).resolve()
        w.need(cwd==root or root in cwd.parents,"BUILD_CWD_OUTSIDE_REPOSITORY")
        timeout=step.get("timeout_seconds",1800);w.need(type(timeout) is int and 1<=timeout<=7200,"BUILD_TIMEOUT_INVALID")
        w.need(cwd.is_dir() and Path(argv[0]).is_file(),'CONFIGURED_BUILD_EXECUTABLE_OR_DIRECTORY_UNAVAILABLE')
        start=time.monotonic()
        with console.open("wb") as f:
            p=subprocess.Popen(argv,cwd=cwd,env=w.clean_env(),stdout=f,stderr=subprocess.STDOUT)
            timed_out=False
            try:code=p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                if os.name=="nt":subprocess.run(["taskkill","/PID",str(p.pid),"/T","/F"],capture_output=True)
                else:p.kill()
                p.wait();code=-1
        # Logs can be large; they remain in external cache, not API stdout or the repository.
        results.append(dict(name=step["name"],kind="build",argv=argv,cwd=str(cwd),exit_code=code,timed_out=timed_out,
                            timeout_seconds=timeout,build_log_target=str(log),seconds=round(time.monotonic()-start,2),console_log=str(console),console_sha256=w.sha(console.read_bytes()),
                            build_log=str(log) if log.exists() else None,build_log_sha256=w.sha(log.read_bytes()) if log.exists() else None))
        if code!=0:break
    after=w.snapshot(c)
    source_stable=after["head"]==head and before["index_sha256"]==after["index_sha256"] and not business_changes(c)
    result=dict(schema="ces.build_validation.v1",head=head,source_stable=source_stable,
                status="passed" if source_stable and len(results)==len(steps) and all(x["exit_code"]==0 for x in results) else "failed",
                configuration=cfg.get("configuration"),platform=cfg.get("platform"),steps=results,
                completed_at=time_now(),runtime_tests_executed=False,application_launched=False)
    w.save(logdir/"receipt.json",result);w.save(home(c)/"last-build.json",result)
    return result
def preflight(c):
    path=home(c)/"analysis.lock";fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    os.write(fd,str(os.getpid()).encode());os.close(fd)
    try:
        result=dict(schema="ces.analysis_preflight.v1",started_at=time_now(),runtime_tests_executed=False)
        try:
            result["sync"]=sync(c);result["build"]=build(c)
            result["status"]="ready" if result["build"]["status"]=="passed" else "build_failed"
        except Exception as exc:
            result.update(status="blocked",error_type=type(exc).__name__,reason=str(exc) if isinstance(exc,RuntimeError) else "details_redacted")
            w.save(home(c)/"last-preflight.json",result);raise
        result["completed_at"]=time_now();w.save(home(c)/"last-preflight.json",result)
        return result
    finally:path.unlink(missing_ok=True)
def resume_preflight(c):
    """Finish an existing period analysis without replacing its bound build with a second run."""
    path=home(c)/"last-preflight.json"
    w.need(path.is_file(),"ANALYSIS_PREFLIGHT_REQUIRED")
    receipt=w.load(path);record=receipt.get("build",{})
    w.need(receipt.get("status") in ("ready","build_failed") and record.get("source_stable") is True,"ANALYSIS_PREFLIGHT_NOT_USABLE")
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(receipt["completed_at"])).total_seconds()
    w.need(0<=age<=86400,"ANALYSIS_PREFLIGHT_EXPIRED")
    head=run(c,"rev-parse","HEAD");b=branch(c)
    w.need(head==record.get("head") and not business_changes(c),"ANALYSIS_SOURCE_CHANGED_RERUN_PREFLIGHT")
    w.need(run(c,"ls-remote","--exit-code","origin","refs/heads/"+b).split()[0]==head,"ANALYSIS_REMOTE_ADVANCED_RERUN_PREFLIGHT")
    cfg=c["build_validation"];steps=cfg["steps"];actual=record.get("steps",[])
    w.need(cfg.get("enabled") is True,"BUILD_NOT_CONFIGURED")
    w.need(build_only_policy(c) and
           record.get("runtime_tests_executed") is False and record.get("application_launched") is False,
           "EXPLICIT_BUILD_ONLY_POLICY_REQUIRED")
    w.need(record.get("configuration")==cfg.get("configuration") and record.get("platform")==cfg.get("platform") and
           actual and len(actual)<=len(steps),"ANALYSIS_BUILD_CONFIGURATION_CHANGED")
    for expected,observed in zip(steps,actual):
        log=observed.get("build_log")
        w.need(expected.get("kind")=="build" and expected["name"]==observed["name"] and
               expand(c,expected["argv"],observed.get("build_log_target") or log)==observed["argv"] and
               expected.get("timeout_seconds",1800)==observed.get("timeout_seconds",expected.get("timeout_seconds",1800)) and
               str(Path(expected.get("cwd",c["repository_path"]).format(repository=c["repository_path"])).resolve())==observed["cwd"],
               "ANALYSIS_BUILD_CONFIGURATION_CHANGED")
        for filekey,hashkey in (("console_log","console_sha256"),("build_log","build_log_sha256")):
            if observed.get(filekey):
                p=Path(observed[filekey])
                w.need(p.is_file() and w.sha(p.read_bytes())==observed.get(hashkey),"ANALYSIS_BUILD_LOG_CHANGED")
    return receipt
def managed_files(c):
    root=docs.root(c);manifest_path=root/".ces-documents.json"
    w.need(manifest_path.is_file(),"MANAGED_DOCUMENT_MANIFEST_REQUIRED")
    w.need(not docs.unsafe(manifest_path),"DOC_MANIFEST_UNSAFE")
    m=w.load(manifest_path)
    w.need(m.get("schema")=="ces.repository_documents.v1" and m["repository_id"]==c["github"]["repository_id"],"DOC_MANIFEST_WRONG_REPOSITORY")
    files={}
    for name,entry in m["files"].items():
        w.need(name not in (".ces-documents.json",".ces-publish.lock"),"DOC_RESERVED_METADATA_PATH")
        p=root/docs.relative(name)
        for ancestor in [p,*p.parents]:
            if ancestor==root:break
            w.need(not docs.unsafe(ancestor),"DOC_REPARSE_POINT_REFUSED")
        w.need(p.is_file() and not docs.unsafe(p) and docs.text_hash(p.read_bytes())==entry["sha256"],"DOC_EXTERNAL_CHANGE_OR_MISSING:"+name)
        files[p.relative_to(Path(c["repository_path"]).resolve()).as_posix()]=p
    w.need(len(files)<=512,"DOC_PUBLISH_LIMIT")
    files[manifest_path.relative_to(Path(c["repository_path"]).resolve()).as_posix()]=manifest_path
    return files
def publish(c,execute=False):
    cfg=c.get("repository_push",{});b=branch(c)
    w.need(cfg.get("allow") is True and c.get("repository_docs",{}).get("allow_git_push") is True,"AUTO_DOC_PUSH_NOT_AUTHORIZED")
    guard=home(c)/"publish.lock";fd=os.open(guard,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,str(os.getpid()).encode());os.close(fd)
    shadow=None
    try:
        files=managed_files(c);before=w.snapshot(c);head=before["head"]
        w.need(not run(c,"diff","--cached","--name-only"),"STAGED_CHANGES_BLOCK_DOC_PUBLICATION")
        remote_line=run(c,"ls-remote","--exit-code","origin","refs/heads/"+b)
        remote=remote_line.split()[0]
        # Always synchronize first; documents produced against an older tree must not overwrite newer remote docs.
        w.need(remote==head,"REMOTE_ADVANCED_RERUN_PREFLIGHT_AND_REVIEW_DOCUMENTS")
        docroot=docs.root(c).relative_to(Path(c["repository_path"]).resolve()).as_posix()
        changes=set(run(c,"diff","--name-only",head,"--",docroot).splitlines())|set(run(c,"ls-files","--others","--exclude-standard","--",docroot).splitlines())
        w.need(changes<=set(files),"UNOWNED_DOC_CHANGE_BLOCKS_AUTOPUBLISH")
        result=dict(schema="ces.document_git_publish.v1",branch=b,parent=head,paths=sorted(changes),mode="isolated_index_docs_only",
                    no_force=True,runtime_tests_executed=False)
        if not changes:
            result["status"]="already_current";w.save(home(c)/"last-publish.json",result);return result
        if not execute:result["status"]="preview";return result
        w.need(c["repository_docs"].get("allow_git_commit") is True,"AUTO_DOC_COMMIT_NOT_AUTHORIZED")
        originals=file_inventory(c)
        index_path=Path(run(c,"rev-parse","--path-format=absolute","--git-path","index"))
        shadow=home(c)/("publish-"+uuid.uuid4().hex+".index")
        env=w.clean_env();env["GIT_INDEX_FILE"]=str(shadow)
        run(c,"read-tree",head,env=env)
        # Feed exact managed paths via stdin; never stage the rest of the working tree.
        payload=b"\0".join(name.encode("utf-8") for name in sorted(changes))+b"\0"
        run(c,"add","--pathspec-from-file=-","--pathspec-file-nul",env=env,input_data=payload)
        changed=run(c,"diff","--cached","--name-only",head,env=env).splitlines()
        w.need(set(changed)==changes and all(x.startswith(docroot+"/") for x in changed),"COMMIT_SCOPE_INVALID")
        tree=run(c,"write-tree",env=env)
        commit=run(c,"commit-tree",tree,"-p",head,"-m",cfg.get("commit_message","docs: update CES reports and project knowledge"),
                   "-m","CES-Generated-By: CES\nCES-Repository-Id: "+str(c['github']['repository_id']),env=env)
        w.need(re.fullmatch(r"[0-9a-f]{40}",commit) is not None,"DOC_COMMIT_INVALID")
        w.need(w.snapshot(c)==before and file_inventory(c)==originals,"WORKTREE_CHANGED_BEFORE_PUSH")
        # If push result is uncertain, the retained commit receipt permits remote reconciliation; never force.
        result.update(commit=commit,status="commit_prepared")
        w.save(home(c)/"last-publish.json",result)
        run(c,"push","origin",commit+":refs/heads/"+b,timeout=180)
        actual=run(c,"ls-remote","--exit-code","origin","refs/heads/"+b).split()[0]
        w.need(actual==commit,"DOC_PUSH_RESULT_UNCERTAIN")
        result["status"]="pushed_remote_verified";w.save(home(c)/"last-publish.json",result)
        result['repository_id']=c['github']['repository_id']
        w.save(home(c)/'publications'/(commit+'.json'),result)
        # Local branch/index advance only if still unchanged. No reset/stash; unrelated unstaged edits survive.
        w.need(w.snapshot(c)==before and file_inventory(c)==originals,"LOCAL_STATE_CHANGED_AFTER_REMOTE_PUSH_LOCAL_SYNC_PENDING")
        index_lock=Path(str(index_path)+".lock")
        lockfd=os.open(index_lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            with os.fdopen(lockfd,"wb") as stream:
                stream.write(shadow.read_bytes());stream.flush();os.fsync(stream.fileno())
            w.need(w.snapshot(c)==before and file_inventory(c)==originals,'LOCAL_STATE_CHANGED_BEFORE_BRANCH_UPDATE')
            # The shadow index contains the same complete source tree and only the authorized doc delta.
            run(c,"update-ref","refs/heads/"+b,commit,head)
            os.replace(index_lock,index_path)
        finally:
            index_lock.unlink(missing_ok=True)
        result.update(status="published_and_local_branch_synchronized",head=commit,
                      url="https://github.com/"+c["github"]["repository"]+"/commit/"+commit,
                      business_edits_preserved=True,only_managed_docs_committed=True)
        w.save(home(c)/"last-publish.json",result)
        w.save(home(c)/'publications'/(commit+'.json'),result);return result
    finally:
        if shadow is not None:shadow.unlink(missing_ok=True)
        guard.unlink(missing_ok=True)
def autocommit(c):
    if c.get("repository_push",{}).get("allow") and c.get("repository_push",{}).get("automatic_after_document_write"):
        return publish(c,True)
    return dict(status="automatic_git_publish_disabled")
def build_lines(c,run_path=None,receipt=None):
    if receipt is None:
        path=Path(run_path)/'preflight.json' if run_path else home(c)/'last-preflight.json'
        if path.exists():receipt=w.load(path).get('build')
    if receipt is None:return ['- 本次尚无绑定的构建结果；不据历史VS构建成功推断本轮已通过。']
    lines=['- 实际构建：'+str(receipt.get('configuration'))+'｜'+str(receipt.get('platform'))+'；结果：'+receipt['status']+'。',
           '- 构建来源提交：'+receipt['head']+'；运行测试：未执行；程序启动：未执行。']
    for step in receipt['steps']:lines.append('- '+step['name']+'：退出码 '+str(step['exit_code'])+'；耗时 '+str(step['seconds'])+'秒。')
    return lines
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("command",choices=["preflight","pull","build","publish","status"])
    p.add_argument("--config",required=True);p.add_argument("--execute",action="store_true")
    a=p.parse_args();c=w.config(a.config)
    if a.command=="status":
        result={x:w.load(home(c)/("last-"+x+".json")) for x in ("sync","build","publish","preflight") if (home(c)/("last-"+x+".json")).exists()}
    elif a.command=="publish":result=publish(c,a.execute)
    else:
        w.need(a.execute,"SOURCE_SYNC_OR_BUILD_REQUIRES_EXECUTE")
        result={"preflight":preflight,"pull":sync,"build":build}[a.command](c)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=="__main__":main()

