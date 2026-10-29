"""Generic CES operator workflow: real Git evidence, local reports, bounded GitHub Issue host.
The CES 1.0 native/legacy Host routes and their authorization gates remain unchanged.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, re, sqlite3, subprocess, sys, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError, URLError

SCHEMA="ces.operator_workflow.v1"
def sha(value):
    return hashlib.sha256(value if isinstance(value,bytes) else value.encode("utf-8")).hexdigest()
def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
def need(ok,reason):
    if not ok: raise RuntimeError(reason)
def clean_env():
    env={k:v for k,v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GCM_INTERACTIVE="Never")
    return env
def command(argv,timeout=45,input_text=None):
    p=subprocess.run(argv,input=input_text,capture_output=True,text=True,encoding="utf-8",env=clean_env(),timeout=timeout)
    need(len(p.stdout.encode("utf-8"))<16*1024*1024,"OUTPUT_LIMIT_EXCEEDED")
    return p
def git(cfg,*args):
    p=command(["git","--no-optional-locks","-c","core.quotePath=false","-C",cfg["repository_path"],*args])
    need(p.returncode==0,"GIT_READ_FAILED:"+args[0])
    return p.stdout.rstrip("\r\n")
def config(path):
    c=load(path);need(c["schema"]==SCHEMA,"CONFIG_SCHEMA_INVALID")
    import ces_notifications
    ces_notifications.configured_cc(c)
    repo=Path(c["repository_path"]).resolve();need(repo.is_dir(),"REPOSITORY_MISSING")
    c["repository_path"]=str(repo)
    need(Path(git(c,"rev-parse","--show-toplevel")).resolve()==repo,"EXACT_REPOSITORY_ROOT_REQUIRED")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",c["github"]["repository"]) is not None,"GITHUB_TARGET_INVALID")
    origin=git(c,"remote","get-url","origin")
    match=re.fullmatch(r"(?:https://github[.]com/|git@github[.]com:)([^/]+/[^/]+?)(?:[.]git)?/?",origin)
    need(match and match[1].lower()==c["github"]["repository"].lower(),"REMOTE_TARGET_MISMATCH")
    need(Path(c["output_root"]).resolve()!=repo and repo not in Path(c["output_root"]).resolve().parents,"REPORTS_MUST_BE_OUTSIDE_REPOSITORY")
    return c
def snapshot(c):
    ix=Path(git(c,"rev-parse","--path-format=absolute","--git-path","index"))
    return dict(head=git(c,"rev-parse","HEAD"),branch=git(c,"branch","--show-current"),
                index_sha256=sha(ix.read_bytes()) if ix.exists() else None,status=git(c,"status","--porcelain=v1","-uall"))
def ces(c,run,name,action,*more,expected=(0,)):
    p=command(["pwsh","-NoLogo","-NoProfile","-File",str(Path(c["ces_root"])/"scripts/ces.ps1"),
               "-Action",action,"-RepoPath",c["repository_path"],"-Json",*more],timeout=90)
    (run/(name+".json")).write_text(p.stdout,encoding="utf-8")
    (run/(name+".stderr.txt")).write_text(p.stderr,encoding="utf-8")
    doc=json.loads(p.stdout)
    need(p.returncode in expected,"CES_"+name+"_FAILED:"+doc.get("reason_code","UNKNOWN"))
    return doc
def prepare(c):
    preflight=None
    if c.get('execution_policy',{}).get('build_before_analysis'):
        import ces_lifecycle
        preflight=ces_lifecycle.preflight(c)
    root=Path(c["output_root"]).resolve();root.mkdir(parents=True,exist_ok=True)
    run=root/"runs"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+uuid.uuid4().hex[:8]);run.mkdir(parents=True)
    before=snapshot(c);save(run/"before.json",before)
    if preflight:save(run/'preflight.json',preflight)
    inspect=ces(c,run,"inspect","Inspect")
    # Repository-agnostic policy: inspect a live working-tree diff if there is business change,
    # otherwise review the latest first-parent commit.
    docs_rel=c.get('repository_docs',{}).get('relative_directory','docs/ces')
    need(re.fullmatch(r'[A-Za-z0-9_./-]+',docs_rel) is not None and '..' not in docs_rel.split('/'),'DOCUMENT_SCOPE_INVALID')
    changes=git(c,"status","--porcelain=v1","-uall","--",".",":(exclude,top,glob).codex/ces/**",':(exclude,top,glob)'+docs_rel+'/**')
    scope=[]
    if changes:
        scope=["-Mode","WorkingTree","-IncludePatches"]
    else:
        base_ref=c.get("review",{}).get("base_ref","HEAD^")
        need(isinstance(base_ref,str) and base_ref and not base_ref.startswith("-"),"REVIEW_BASE_REF_INVALID")
        parent=command(["git","--no-optional-locks","-C",c["repository_path"],"rev-parse","--verify",base_ref+"^{commit}"])
        if parent.returncode==0:
            ref=git(c,"symbolic-ref","HEAD")
            scope=["-Mode","DeliveredTarget","-BaseSha",parent.stdout.strip(),"-TargetSha",before["head"],"-TargetRef",ref,"-IncludePatches"]
        else:
            need(base_ref=="HEAD^","CONFIGURED_REVIEW_BASE_UNAVAILABLE")
            scope=["-Mode","WorkingTree","-IncludePatches"]
    ces(c,run,"collect","Collect",*scope)
    ev=str(run/"collect.json")
    ces(c,run,"reconcile","Reconcile","-Mode","Snapshot","-EvidencePath",ev)
    prepared=ces(c,run,"prepare","CodePrepare","-Mode","Snapshot","-EvidencePath",ev,"-IncludePatches")
    need(prepared["data"]["prepared"],"REVIEW_PACKET_UNAVAILABLE")
    after=snapshot(c);need(before==after,"REPOSITORY_CHANGED_DURING_PREPARE")
    save(run/"after-prepare.json",after)
    save(run/"run.json",dict(schema=SCHEMA,repository=c["repository_path"],head=before["head"],
         source_mode=prepared["data"]["scope"]["source_mode"],packet_sha256=prepared["data"]["packet_sha256"],
         evidence_sha256=sha((run/"collect.json").read_bytes()),config_repository=c["github"]["repository"]))
    save(root/"latest-run.json",dict(run_directory=str(run)))
    print(json.dumps(dict(status="review_input_ready",run_directory=str(run),packet_sha256=prepared["data"]["packet_sha256"],
                          next_step="Author review-draft.json from the real packet, then complete."),ensure_ascii=False))
def offset(c):
    text=c.get("utc_offset","+00:00");need(re.fullmatch(r"[+-][0-9]{2}:[0-9]{2}",text),"UTC_OFFSET_INVALID")
    sign=1 if text[0]=="+" else -1
    return timezone(sign*timedelta(hours=int(text[1:3]),minutes=int(text[4:6])))
def activity(c,start,end,with_exclusions=False):
    text=git(c,"log","--since-as-filter="+start.isoformat(),"--until="+end.isoformat(),"--format=%H%x00%cI%x00%s","HEAD")
    rows=[]
    for line in text.splitlines():
        parts=line.split("\0",2)
        if len(parts)==3:
            when=datetime.fromisoformat(parts[1])
            if start<=when<=end: rows.append(dict(sha=parts[0],committed_at=parts[1],subject=parts[2]))
    import ces_audit
    kept,excluded,warnings=ces_audit.filter_commits(c,rows)
    return (kept,excluded,warnings) if with_exclusions else kept
def md(text):
    return str(text).replace("\r"," ").replace("\n"," ").replace("|","\\|")
def source_link(c,commit,path):
    return "https://github.com/"+c["github"]["repository"]+"/blob/"+commit+"/"+quote(path,safe="/")
def render_analysis(c,run,checked):
    d=checked["data"];info=load(run/"run.json")
    lines=["# 代码分析报告","",f"仓库：{c['github']['repository']}",f"审阅提交：{info['head']}",
           f"来源模式：{info['source_mode']}","",d["summary"],"",
           "本报告由实际 CES Collect → Reconcile → CodePrepare → CodeValidate 证据链生成。字面绑定通过不等于缺陷语义已获证明。",""]
    for i,f in enumerate(d["checked_findings"],1):
        location=(f"[{f['path']}]({source_link(c,info['head'],f['path'])})" if info["source_mode"]=="delivered_target_diff" else f"本地工作区 {f['path']}（不能用 HEAD 链接证明未提交内容）")
        lines += [f"## {i}. {f['title']}","",f"级别：{f['severity']}；置信度：{f['confidence']}",
                  f"代码证据：{location}","",
                  f"观察与分析：{f['reasoning']}","",f"影响：{f['impact']}","",f"建议：{f['recommendation']}",""]
    lines+=["## 构建与运行证据",""]
    lines += [f"- {x}" for x in c.get("user_observations",[])]
    import ces_lifecycle
    lines += ces_lifecycle.build_lines(c,run)
    lines += ["- 本流程没有运行程序、运行测试、设备操作或远端CI。","", "## 覆盖限制",""]
    lines += ["- "+x for x in d.get("limitations",[])]
    (run/"代码分析报告.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
def render_period(c,run,kind,start,end,checked):
    rows,excluded,audit_warnings=activity(c,start,end,True)
    title="日报" if kind=="daily" else "周报"
    info=load(run/"run.json")
    lines=[f"# {title}","",f"项目：{c['github']['repository']}",
           f"统计区间：{start.isoformat()} 至 {end.isoformat()}（截至当前，未结束周期）",
           f"当前 HEAD：{info['head']}","",f"当前分支可达、提交时间位于区间内的提交：{len(rows)} 条。","",
           "## 提交记录","","| 提交 | 时间 | 说明 |","| --- | --- | --- |"]
    for row in rows:
        link="https://github.com/"+c["github"]["repository"]+"/commit/"+row["sha"]
        lines.append(f"| [{row['sha'][:10]}]({link}) | {md(row['committed_at'])} | {md(row['subject'])} |")
    if not rows: lines+=["| — | — | 本区间未发现符合统计口径的本地提交 |"]
    lines+=["","## 本轮代码分析","",checked["data"]["summary"],""]
    for f in checked["data"]["checked_findings"]:
        lines.append(f"- [{f['severity']}] {f['title']}：{f['recommendation']}")
    lines+=["","代码分析仅覆盖本轮审阅包，不代表全部周期提交均完成代码审阅。","",
            "## 构建、问题与后续",""]
    lines += ["- "+x for x in c.get("user_observations",[])]
    import ces_lifecycle
    lines += ces_lifecycle.build_lines(c,run)
    lines += ["- 不运行程序或测试；不将提交数用于个人绩效评价。",
              "- Issue 创建/去重结果见本目录 issue-results.json；没有结果文件时尚未提交。",
              "- 待办仅采用有来源证据的缺陷或改进建议。"]
    issue_file=run/"issue-results.json"
    if issue_file.exists():
        lines += ["", "## Issue 处理记录", ""]
        for item in load(issue_file):
            lines.append(f"- [{item['title']}]({item.get('url','')})：{item['status']}")
    import ces_audit
    lines+=ces_audit.lines(excluded,audit_warnings)
    (run/(title+".md")).write_text("\n".join(lines)+"\n",encoding="utf-8")
    save(run/(kind+"-activity.json"),dict(start=start.isoformat(),end=end.isoformat(),commits=rows,excluded_maintenance_commits=excluded,audit_filter_warnings=audit_warnings,
         basis="local reachable commits filtered by committer timestamp; not remote delivery or complete work evidence"))
def complete(c,run):
    info=load(run/"run.json");need(info["repository"]==c["repository_path"],"RUN_SOURCE_MISMATCH")
    need(sha((run/"collect.json").read_bytes())==info["evidence_sha256"],"EVIDENCE_CHANGED")
    before=snapshot(c)
    checked=ces(c,run,"validate","CodeValidate","-Mode","Snapshot","-EvidencePath",str(run/"collect.json"),
                "-InputPath",str(run/"review-draft.json"),"-IncludePatches")
    need(checked["data"]["validated"],"VALIDATED_REVIEW_REQUIRED")
    render_analysis(c,run,checked)
    now=datetime.now(offset(c));start=now.replace(hour=0,minute=0,second=0,microsecond=0)
    render_period(c,run,"daily",start,now,checked)
    after=snapshot(c);need(before==after,"REPOSITORY_CHANGED_DURING_REPORT")
    save(run/"report-receipt.json",dict(schema=SCHEMA,status="local_reports_generated",head=info["head"],repository_unchanged=True,
         validation_sha256=sha((run/"validate.json").read_bytes()),reports=[
             dict(path=str(run/name),sha256=sha((run/name).read_bytes())) for name in ("代码分析报告.md","日报.md")],
         renderer="CES generic operator workflow; not the legacy ReportRender cryptographic protocol"))
    print(json.dumps(dict(status="analysis_and_daily_ready",run_directory=str(run),reports=["代码分析报告.md","日报.md"],next_step="Run ces_reports.py daily to route/notify; weekly aggregates the archived daily records only."),ensure_ascii=False))
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*a,**kw): raise RuntimeError("PROVIDER_REDIRECT_REFUSED")
def credential(c):
    p=command(["git","-C",c["repository_path"],"credential","fill"],input_text="protocol=https\nhost=github.com\n\n")
    need(p.returncode==0,"GIT_CREDENTIAL_MANAGER_LOGIN_REQUIRED")
    fields=dict(x.split("=",1) for x in p.stdout.splitlines() if "=" in x)
    token=fields.get("password","");need(bool(token) and "\n" not in token,"PROVIDER_CREDENTIAL_UNAVAILABLE")
    return token
def api(token,path,payload=None,method=None):
    need(path.startswith("/") and not path.startswith("//"),"PROVIDER_PATH_INVALID")
    verb=method or ("POST" if payload is not None else "GET")
    need(verb in ("GET","POST","PATCH"),"PROVIDER_METHOD_INVALID")
    native=Path(__file__).with_name('native-http.ps1')
    if os.name=='nt' and native.is_file():
        for attempt in range(3 if verb=='GET' else 1):
            process=command(['pwsh','-NoLogo','-NoProfile','-File',str(native)],timeout=40,
                            input_text=json.dumps(dict(token=token,path=path,method=verb,payload=payload),ensure_ascii=False))
            reply=json.loads(process.stdout)
            if process.returncode==0:
                status=reply['status_code']
                if not 200<=status<300:raise HTTPError('https://api.github.com'+path,status,'PROVIDER_HTTP_FAILED',None,None)
                return json.loads(base64.b64decode(reply['body_base64'])),status
            if verb!='GET' or attempt==2:raise RuntimeError('NATIVE_PROVIDER_REQUEST_FAILED_NO_WRITE_RETRY')
            time.sleep(1)
    req=Request("https://api.github.com"+path,data=json.dumps(payload,ensure_ascii=False).encode("utf-8") if payload is not None else None,
                headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","Content-Type":"application/json","User-Agent":"CES-operator-host"},
                method=verb)
    for attempt in range(3 if verb=="GET" else 1):
        try:
            with build_opener(NoRedirect()).open(req,timeout=25) as response:
                raw=response.read(4*1024*1024+1);need(len(raw)<=4*1024*1024,"PROVIDER_RESPONSE_TOO_LARGE")
                return json.loads(raw),response.status
        except HTTPError:
            raise
        except URLError:
            if verb!="GET" or attempt==2: raise
            time.sleep(1)
def issue_host(c,run,execute):
    need(execute,"ISSUE_EXECUTION_OPT_IN_REQUIRED")
    policy=c["github"]
    need(policy.get("allow_create") is True and policy.get("allow_improvements") is True,"ISSUE_POLICY_NOT_AUTHORIZED")
    proposals=load(run/"issue-proposals.json")
    need(isinstance(proposals,list) and len(proposals)<=policy.get("max_new_issues_per_run",3),"ISSUE_BATCH_LIMIT")
    # Independent process replays source-bound validation, owns credentials and fixed provider URL.
    checked=ces(c,run,"host-validate","CodeValidate","-Mode","Snapshot","-EvidencePath",str(run/"collect.json"),
                "-InputPath",str(run/"review-draft.json"),"-IncludePatches")
    need(checked["data"]["validated"],"HOST_FRESH_CODE_VALIDATION_REQUIRED")
    findings={f["id"]:f for f in checked["data"]["checked_findings"]}
    info=load(run/"run.json")
    need(info["source_mode"]=="delivered_target_diff","REMOTE_ISSUES_REQUIRE_PINNED_COMMITTED_EVIDENCE")
    import ces_reports
    import ces_issue_quality
    attribution_client=ces_reports.Client(c)
    origins=ces_reports.resolve_origins(c,run,attribution_client)
    assignable={x['login'] for x in attribution_client.pages(attribution_client.prefix+'/assignees')}
    token=credential(c);account,_=api(token,"/user")
    need(account["id"]==policy["account_id"],"HOST_ACCOUNT_ID_MISMATCH")
    remote,_=api(token,"/repos/"+policy["repository"])
    need(remote["id"]==policy["repository_id"] and remote["has_issues"] and remote.get("permissions",{}).get("push"),"HOST_REPOSITORY_PERMISSION_MISMATCH")
    need(git(c,"rev-parse","HEAD")==info["head"],"HEAD_CHANGED_BEFORE_ISSUE")
    api(token,"/repos/"+policy["repository"]+"/commits/"+info["head"])
    existing=[]
    for page in range(1,11):
        docs,_=api(token,"/repos/"+policy["repository"]+f"/issues?state=all&per_page=100&page={page}")
        existing.extend(x for x in docs if "pull_request" not in x)
        if len(docs)<100: break
    else: raise RuntimeError("REMOTE_ISSUE_INVENTORY_TRUNCATED_NO_POST")
    state=Path(c["state_root"]);state.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(state/"issue-attempts.sqlite3",timeout=20,isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY,state TEXT NOT NULL,url TEXT,payload_sha256 TEXT NOT NULL,created_at TEXT NOT NULL)")
    outcomes=[]
    for p in proposals:
        need(p["kind"] in ("defect","improvement"),"ISSUE_KIND_INVALID")
        selected=[findings[x] for x in p["finding_ids"]]
        import ces_audit
        source_rows=[dict(sha=o['commit']) for f in selected for o in origins.get(f['id'],[])]
        _,excluded,_=ces_audit.filter_commits(c,source_rows)
        excluded_shas={x['sha'] for x in excluded}
        if any(origins.get(f['id']) and all(o['commit'] in excluded_shas for o in origins[f['id']]) for f in selected):
            outcomes.append(dict(title=p['title'],status='excluded_generated_maintenance',reason='CES automatic document publication is outside work audit'));continue
        deep_content,_=ces_issue_quality.details(c,run,p,origins)
        need(bool(selected) and len(selected)<=8 and len(p["title"])<=160,"ISSUE_SOURCE_OR_TITLE_INVALID")
        if p["kind"]=="defect":
            need(all(f["severity"] in ("critical","high","medium") and f["confidence"]=="high" for f in selected),"DEFECT_CONFIDENCE_POLICY")
        fingerprint=sha(json.dumps(dict(repo=remote["id"],kind=p["kind"],anchors=sorted((f["path"],f["quote_sha256"]) for f in selected)),sort_keys=True))
        marker="<!-- ces-issue:"+fingerprint+" -->"
        duplicate=next((x for x in existing if marker in (x.get("body") or "") or x["title"].casefold()==p["title"].casefold()),None)
        if duplicate:
            outcomes.append(dict(title=p["title"],status="duplicate_skipped",url=duplicate["html_url"],number=duplicate["number"],fingerprint=fingerprint));continue
        previous=db.execute("SELECT state,url FROM attempts WHERE key=?",(fingerprint,)).fetchone()
        if previous:
            outcomes.append(dict(title=p["title"],status="previous_attempt_not_retried",previous_state=previous[0],url=previous[1],fingerprint=fingerprint));continue
        lines=[marker,"","## 类型",p["kind"],"","## 分析范围",f"提交：{info['head']}",f"来源：CES {info['source_mode']}；本地证据已重新校验。","",
               "本 Issue 为代码证据支持的改进建议，未认定已发生构建或运行故障。" if p["kind"]=="improvement" else "本 Issue 为代码审阅发现，仍需维护者复核运行影响。"]
        for f in selected:
            lines+=["",f"## {f['title']}",f"位置：[{f['path']}]({source_link(c,info['head'],f['path'])})",
                    f"观察：{f['reasoning']}",f"影响与限制：{f['impact']}",f"建议：{f['recommendation']}"]
        people=set()
        lines += ["", "## 来源提交与对应提交人"]
        for f in selected:
            for origin in origins.get(f['id'],[]):
                author=origin['author_login']
                if ces_reports.login(author):people.add(author)
                lines.append(f"- [{origin['path']}:L{origin['line']}]({origin['code_url']})；来源提交 [{origin['commit'][:12]}]({origin['commit_url']})；作者 "+('@'+author if ces_reports.login(author) else 'GitHub账号未映射')+'。')
        lines += ["- 代码行最近修改者仅作来源定位，不作为个人责任裁定。"]
        lines+=["","## 已知验证情况"]+["- "+x for x in c.get("user_observations",[])]
        lines+=["- CES 字面证据校验已通过；没有据此证明缺陷语义、远端 CI 或运行结果。",
                "- 自动创建已由仓库操作人授权；CES 可补充自建问题的来源及指派，报告线程可追加快照，不自动关闭既有 Issue。"]
        import ces_notifications
        routing=ces_notifications.route(c,sorted(people))
        payload=dict(title=p["title"],body=ces_notifications.message(c,"\n".join(lines)+'\n\n'+deep_content,sorted(people)),assignees=sorted(people.intersection(assignable)))
        need(len(payload['assignees'])<=10,'ISSUE_ASSIGNEE_LIMIT')
        need(len(json.dumps(payload).encode("utf-8"))<24000,"ISSUE_PAYLOAD_TOO_LARGE")
        save(run/("issue-payload-"+fingerprint[:12]+".json"),payload)
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("INSERT INTO attempts VALUES (?,?,?,?,?)",(fingerprint,"reserved",None,sha(json.dumps(payload,sort_keys=True)),datetime.now(timezone.utc).isoformat()))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK");raise
        try:
            created,status=api(token,"/repos/"+policy["repository"]+"/issues",payload)
            need(status==201 and isinstance(created.get("number"),int),"ISSUE_CREATE_RESULT_UNCERTAIN")
            number=created["number"]
            observed,_=api(token,"/repos/"+policy["repository"]+"/issues/"+str(number))
            need(marker in (observed.get("body") or "") and observed["title"]==p["title"],"ISSUE_READBACK_MISMATCH")
            need(observed.get('body')==payload['body'],'ISSUE_BODY_READBACK_MISMATCH')
            db.execute("UPDATE attempts SET state='created_readback_verified',url=? WHERE key=?",(observed["html_url"],fingerprint))
            need(set(payload['assignees'])<={x['login'] for x in observed.get('assignees',[])},'ISSUE_ASSIGNEE_READBACK_MISMATCH')
            outcome=dict(title=p["title"],status="created_readback_verified",url=observed["html_url"],number=number,fingerprint=fingerprint,**routing,
                         cc_mentions_readback_verified=ces_notifications.mentions_verified([observed.get('body') or ''],routing['cc_recipients']),email_delivery_verified=False)
            outcomes.append(outcome);existing.append(observed)
        except BaseException as exc:
            db.execute("UPDATE attempts SET state='uncertain_no_retry' WHERE key=?",(fingerprint,))
            outcomes.append(dict(title=p["title"],status="uncertain_no_retry",error_type=type(exc).__name__,fingerprint=fingerprint))
            save(run/"issue-results.json",outcomes);raise RuntimeError("ISSUE_ATTEMPT_UNCERTAIN_DO_NOT_RETRY")
    db.close();save(run/"issue-results.json",outcomes)
    if c.get('issue_tracking',{}).get('enabled'):
        import ces_tracking
        ces_tracking.sync(c,False)
    print(json.dumps(dict(status="issue_workflow_completed",results=outcomes,credentials_stored=False),ensure_ascii=False))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("command",choices=["prepare","complete","issue"])
    p.add_argument("--config",required=True);p.add_argument("--run");p.add_argument("--execute",action="store_true")
    a=p.parse_args();c=config(a.config)
    if a.command=="prepare":prepare(c);return
    need(bool(a.run),"RUN_REQUIRED")
    run=Path(a.run).resolve();need(Path(c["output_root"]).resolve() in run.parents,"RUN_OUTSIDE_CONFIGURED_OUTPUT_ROOT")
    if a.command=="complete":complete(c,run)
    else:issue_host(c,run,a.execute)
if __name__=="__main__":
    try: main()
    except Exception as exc:
        print(json.dumps(dict(status="failed",error_type=type(exc).__name__,reason=str(exc) if isinstance(exc,RuntimeError) else "DETAILS_REDACTED"),ensure_ascii=False));sys.exit(1)

