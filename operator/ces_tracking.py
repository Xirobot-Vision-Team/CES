"""Persistent, repository-scoped Issue lifecycle tracking with source/test-bound review."""
from __future__ import annotations
import argparse,base64,json,re,sqlite3,sys,os,subprocess
from pathlib import Path
from datetime import datetime,timezone,timedelta
from urllib.error import HTTPError
from urllib.parse import quote
import ces_workflow as w
import ces_reports as reports
import ces_notifications as notifications

SCHEMA="ces.issue_tracking.v1"
HEX=re.compile(r"[0-9a-f]{40}\Z")
STATES={"open","not_fixed","in_progress","fix_candidate","closed_unverified","resolved_verified","regression_suspected","unknown"}
def now():return datetime.now(timezone.utc)
def stamp(t):return t.isoformat(timespec="microseconds")
def dt(s):return datetime.fromisoformat(s.replace("Z","+00:00"))
def digest(v):return reports.digest(v)
def home(c):
    return Path(c["state_root"])/"issue-tracking"/str(c["github"]["repository_id"])
def output(c):return Path(c["output_root"])/"tracking"
def policy(c):
    p=c.get("issue_tracking",{})
    w.need(p.get("enabled") is True,"ISSUE_TRACKING_NOT_ENABLED")
    for key,default,maximum in (('max_issues',100,500),('stale_days',7,365),('reminder_cooldown_days',7,365),('review_max_age_days',7,90)):
        value=p.get(key,default);w.need(type(value) is int and 1<=value<=maximum,'TRACKING_POLICY_RANGE_INVALID:'+key)
    steps=p.get('required_test_steps',[])
    w.need(type(p.get('track_closed',False)) is bool,'TRACK_CLOSED_POLICY_INVALID')
    w.need(isinstance(steps,list) and len(steps)<=32 and all(isinstance(x,str) and x.strip() for x in steps) and len(set(steps))==len(steps),'TRACKING_REQUIRED_STEPS_INVALID')
    return p
def dbopen(c):
    root=home(c);root.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(root/"tracking.sqlite3",isolation_level=None,timeout=20)
    db.row_factory=sqlite3.Row
    db.execute("PRAGMA synchronous=FULL")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS issues(number INTEGER PRIMARY KEY,issue_id INTEGER NOT NULL,snapshot_sha TEXT NOT NULL,snapshot_json TEXT NOT NULL,lifecycle TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,last_change TEXT NOT NULL,last_reminder TEXT);
    CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY AUTOINCREMENT,number INTEGER NOT NULL,kind TEXT NOT NULL,before_sha TEXT,after_sha TEXT NOT NULL,at TEXT NOT NULL,UNIQUE(number,kind,before_sha,after_sha));
    CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,number INTEGER NOT NULL,issue_id INTEGER NOT NULL,head_sha TEXT NOT NULL,issue_sha TEXT NOT NULL,verdict TEXT NOT NULL,record_json TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS deliveries(key TEXT PRIMARY KEY,state TEXT NOT NULL,url TEXT,created_at TEXT NOT NULL);
    """)
    columns={x[1] for x in db.execute('PRAGMA table_info(deliveries)')}
    if 'number' not in columns:db.execute('ALTER TABLE deliveries ADD COLUMN number INTEGER')
    return db
def lock(c):
    root=home(c);root.mkdir(parents=True,exist_ok=True)
    path=root/"sync.lock"
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.write(fd,str(os.getpid()).encode());os.close(fd)
    return path
def default_head(client):
    repo=client.get(client.prefix)
    branch=repo["default_branch"]
    doc=client.get(client.prefix+"/commits/"+quote(branch,safe=""))
    w.need(HEX.fullmatch(doc["sha"]) is not None,"TRACKING_HEAD_INVALID")
    return doc["sha"]
def managed(issue):
    return re.search(r"<!-- ces-issue:[0-9a-f]{64} -->",issue.get("body") or "") is not None and "pull_request" not in issue
def projection(issue,comments,events,pulls,head):
    # Our monitoring comments do not constitute outside progress.
    actual_comments=[dict(id=x["id"],body=x.get("body") or "",updated_at=x["updated_at"],author=x["user"]["login"],url=x["html_url"])
                     for x in comments if "<!-- ces-tracking:" not in (x.get("body") or "")]
    relevant=[]
    for x in events:
        if x.get("event") in ("closed","reopened","referenced","cross-referenced","assigned","unassigned","labeled","unlabeled"):
            src=(x.get("source") or {}).get("issue") or {}
            relevant.append(dict(id=x.get("id"),event=x["event"],created_at=x.get("created_at"),commit_id=x.get("commit_id"),
                                 source_url=src.get("html_url"),source_number=src.get("number"),source_is_pr="pull_request" in src))
    return dict(number=issue["number"],issue_id=issue["id"],title=issue["title"],body=issue.get("body") or "",url=issue["html_url"],
                state=issue["state"],state_reason=issue.get("state_reason"),closed_at=issue.get("closed_at"),created_at=issue["created_at"],
                assignees=sorted(a["login"] for a in issue["assignees"]),labels=sorted(a["name"] for a in issue["labels"]),
                comments=actual_comments,events=relevant,pulls=pulls,remote_head=head)
def issue_sha(snapshot):
    return digest({k:v for k,v in snapshot.items() if k!="remote_head"})
def classify(s,previous,review):
    if s.get("unavailable"):return "unknown"
    if review and review["head_sha"]==s["remote_head"] and review["issue_sha"]==issue_sha(s):
        if review["verdict"]=="fixed":return "resolved_verified"
        if review["verdict"]=="regression":return "regression_suspected"
        if review['verdict']=='not_fixed' and s['state']=='open':return 'not_fixed'
    if previous and previous["lifecycle"]=="resolved_verified" and s["state"]=="open":return "regression_suspected"
    if s["state"]=="closed":return "closed_unverified"
    if any(p.get("merged") or p.get("state")=="open" for p in s["pulls"]) or any(e["event"]=="referenced" and e["commit_id"] for e in s["events"]):
        return "fix_candidate"
    if s["comments"] or any("progress" in x.lower() for x in s["labels"]):return "in_progress"
    return "open"
def observe(client,issue,head):
    number=issue["number"]
    comments=client.pages(client.prefix+f"/issues/{number}/comments")
    events=client.pages(client.prefix+f"/issues/{number}/timeline")
    pr_numbers=set()
    for event in events:
        src=(event.get("source") or {}).get("issue") or {}
        if "pull_request" in src and src.get("repository_url")==("https://api.github.com"+client.prefix) and type(src.get("number")) is int:
            pr_numbers.add(src["number"])
    w.need(len(pr_numbers)<=20,"TOO_MANY_RELATED_PULL_REQUESTS")
    pulls=[]
    for n in sorted(pr_numbers):
        p=client.get(client.prefix+f"/pulls/{n}")
        pulls.append(dict(number=n,url=p["html_url"],state=p["state"],merged=p["merged"],merged_at=p.get("merged_at"),
                          merge_commit_sha=p.get("merge_commit_sha"),head_sha=p["head"]["sha"],draft=p.get("draft",False),
                          association="timeline reference only; not proof this PR fixes the issue"))
    return projection(issue,comments,events,pulls,head)
def markdown(record):
    lines=["# Issue 生命周期追踪","",f"仓库：{record['repository']}",f"检查时间：{record['observed_at']}",
           f"远端默认分支：{record['remote_head']}","",
           "| Issue | GitHub状态 | CES验证状态 | 负责人 | 待办 |","| --- | --- | --- | --- | --- |"]
    for x in record["issues"]:
        people=", ".join(x["assignees"]) or "未指派"
        lines.append(f"| [#{x['number']} {reports.safe(x['title'])}]({x['url']}) | {x['remote_state']} | {x['lifecycle']} | {people} | {reports.safe(x['next_step'])} |")
    lines+=["","## 本轮变化",""]
    for e in record["changes"]:lines.append(f"- #{e['number']}：{e['kind']}")
    if not record["changes"]:lines+=["- 本轮没有新的语义状态变化；首次建立基线不代表刚产生问题。"]
    lines+=["","## 核验规则","",
            "- closed_unverified：GitHub已关闭，但未通过本地固定来源与测试的修复验证。",
            "- fix_candidate：存在提交或PR引用，不等于修复已确认。",
            "- resolved_verified：当前固定源码引用经复核且必需的构建/测试证据通过；仍是有范围的审阅。",
            "- regression_suspected：已验证后重新打开或新代码需复核，不能直接认定复发。",
            "- unknown：读取失败、无权访问或证据不足，不等于Issue不存在。",
            "- 定期提醒按配置的静默阈值与冷却时间去重。不会因报告引用、原代码行消失或有人留言就自动关闭问题。"]
    return "\n".join(lines)+"\n"
def status(c,db=None):
    owned=db is None
    if db is None:db=dbopen(c)
    rows=db.execute("SELECT * FROM issues ORDER BY number").fetchall()
    head=None;items=[]
    for row in rows:
        s=json.loads(row["snapshot_json"]);head=s.get("remote_head") or head
        nxt={"open":"复核问题并安排处理","not_fixed":"当前固定源码仍见问题，继续处理并提供修复证据","in_progress":"核实处理进展与修复证据","fix_candidate":"复核关联代码并运行相关测试",
             "closed_unverified":"补充修复验证；关闭状态不证明已修复","resolved_verified":"后续代码变化时复核是否需要重新验证",
             "regression_suspected":"复核重新打开/代码变化的影响","unknown":"恢复远端读取后重新对账"}[row["lifecycle"]]
        active=s['state']!='closed' or c.get('issue_tracking',{}).get('track_closed',False)
        if not active:nxt='已关闭，停止主动跟踪；保留历史，不认定修复已验证'
        items.append(dict(number=row["number"],issue_id=row["issue_id"],title=s["title"],url=s["url"],remote_state=s["state"],
                          lifecycle=row["lifecycle"],assignees=s["assignees"],last_seen=row["last_seen"],last_change=row["last_change"],
                          last_reminder=row["last_reminder"],snapshot_sha256=row["snapshot_sha"],next_step=nxt,active_tracking=active))
    if owned:db.close()
    return dict(schema=SCHEMA,repository=c["github"]["repository"],repository_id=c["github"]["repository_id"],
                observed_at=stamp(now()),remote_head=head,issues=items,changes=[])
def history(c,number=None):
    db=dbopen(c)
    try:
        rows=db.execute('SELECT * FROM observations '+('WHERE number=? ' if number else '')+'ORDER BY id DESC LIMIT 200',(number,) if number else ()).fetchall()
        return dict(schema=SCHEMA,events=[dict(x) for x in rows],limit=200)
    finally:db.close()
def publish_projection(c,record):
    output(c).mkdir(parents=True,exist_ok=True)
    w.save(output(c)/"latest.json",record)
    (output(c)/"Issue追踪.md").write_text(markdown(record),encoding="utf-8")
def for_report(c):
    if not c.get('issue_tracking',{}).get('enabled'):return None
    latest=output(c)/'latest.json'
    if not latest.exists():return dict(status='tracking_not_yet_synchronized',issues=[])
    record=w.load(latest)
    w.need(record.get('repository_id')==c['github']['repository_id'],'TRACKING_REPORT_REPOSITORY_MISMATCH')
    rows=record['issues'];track_closed=c.get('issue_tracking',{}).get('track_closed',False)
    items=[{k:v for k,v in row.items() if k not in ('last_seen','last_reminder')} for row in rows if row['remote_state']!='closed' or track_closed]
    error=output(c)/'sync-error.json'
    stale=error.exists() and dt(w.load(error)['observed_at'])>dt(record['observed_at'])
    return dict(status='last_observation_stale_after_failure' if stale else 'observed',remote_head=record['remote_head'],issues=items,
                binding_sha256=digest(items),observation_is_atomic=False,closed_tracking_enabled=track_closed,
                inactive_closed_count=sum(row['remote_state']=='closed' for row in rows) if not track_closed else 0)
def report_lines(info):
    if not info:return []
    lines=['','## Issue处理闭环','', '追踪状态：'+info['status'],'']
    if info.get('inactive_closed_count'):lines.append('- '+str(info['inactive_closed_count'])+'项已关闭Issue仅保留历史，不列入主动跟踪或修复待办。')
    for x in info['issues']:
        lines.append(f"- [#{x['number']} {reports.safe(x['title'])}]({x['url']})：{x['lifecycle']}；GitHub={x['remote_state']}；下一步：{x['next_step']}")
    lines+=['','GitHub关闭、修复候选、源码审阅与测试通过分别记录；没有验证不宣称已修复。']
    return lines
def sync(c,execute=False):
    p=policy(c);guard=lock(c);db=None
    try:
        client=reports.Client(c)
        db=dbopen(c);head=default_head(client)
        # Do not apply partial discovery as absence. A whole enumeration failure aborts.
        docs=client.pages(client.prefix+"/issues?state=all&sort=updated&direction=desc")
        targets={x["number"]:x for x in docs if managed(x)}
        prior={x["number"]:dict(x) for x in db.execute("SELECT * FROM issues")}
        for n in p.get("include_numbers",[]):
            w.need(type(n) is int and n>0,"TRACK_NUMBER_INVALID")
            if n not in targets:targets[n]=None
        for n in prior:
            if n not in targets:
                if not p.get('track_closed',False) and json.loads(prior[n]['snapshot_json'])['state']=='closed':continue
                targets[n]=None
        # Closed Issues are passive archive records by default, even if explicitly included.
        # The lightweight all-state list also detects an actual reopen without polling closed detail endpoints.
        if not p.get('track_closed',False):
            targets={n:issue for n,issue in targets.items() if issue is None or issue['state']!='closed' or n in prior}
        active_count=sum(issue is None or issue['state']!='closed' or p.get('track_closed',False) for issue in targets.values())
        w.need(active_count<=p.get("max_issues",100),"TRACKING_ISSUE_LIMIT")
        observations={};unavailable={}
        for n,issue in sorted(targets.items()):
            try:
                issue=issue or client.get(client.prefix+f"/issues/{n}")
                w.need(managed(issue) or n in p.get("include_numbers",[]) or n in prior,"UNAUTHORIZED_TRACKING_TARGET")
                if issue['state']=='closed' and not p.get('track_closed',False):
                    # Record closure metadata once without comments/timeline/PR/source review.
                    old=json.loads(prior[n]['snapshot_json']) if n in prior else {}
                    minimal=projection(issue,[],[],[],old.get('remote_head',head))
                    for key in ('comments','events','pulls'):minimal[key]=old.get(key,[])
                    observations[n]=minimal
                else:observations[n]=observe(client,issue,head)
            except Exception as exc:
                unavailable[n]=type(exc).__name__
                if n in prior:
                    observations[n]={**json.loads(prior[n]["snapshot_json"]),"unavailable":True,"read_error_type":type(exc).__name__}
                elif issue is not None:
                    observations[n]={**projection(issue,[],[],[],head),'unavailable':True,'read_error_type':type(exc).__name__}
        w.need(default_head(client)==head,"REMOTE_HEAD_MOVED_DURING_TRACKING")
        at=stamp(now());changes=[]
        db.execute("BEGIN IMMEDIATE")
        for n,s in observations.items():
            prev=prior.get(n)
            if prev:w.need(prev["issue_id"]==s["issue_id"],"ISSUE_IDENTITY_CHANGED")
            sha=digest(s)
            rv=db.execute("SELECT * FROM reviews WHERE number=? AND issue_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1",(n,s["issue_id"])).fetchone()
            lifecycle=classify(s,prev,dict(rv) if rv else None)
            if not prev:kind="baseline"
            elif s.get("unavailable"):kind="read_unavailable" if prev["lifecycle"]!="unknown" else None
            elif prev["snapshot_sha"]==sha and prev["lifecycle"]==lifecycle:kind=None
            else:
                old=json.loads(prev["snapshot_json"])
                if prev["lifecycle"]=="unknown":kind="access_restored"
                elif old["state"]=="closed" and s["state"]=="open":kind="reopened"
                elif old["state"]=="open" and s["state"]=="closed":kind="closed_unverified"
                elif old["remote_head"]!=s["remote_head"] and issue_sha(old)==issue_sha(s):kind="source_head_changed"
                else:kind="issue_progress_changed"
            last_change=at if not prev or kind and kind!="source_head_changed" else prev["last_change"]
            db.execute("INSERT INTO issues VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(number) DO UPDATE SET snapshot_sha=excluded.snapshot_sha,snapshot_json=excluded.snapshot_json,lifecycle=excluded.lifecycle,last_seen=excluded.last_seen,last_change=excluded.last_change",
                       (n,s["issue_id"],sha,canon(s),lifecycle,prev["first_seen"] if prev else at,at,last_change,prev["last_reminder"] if prev else None))
            if kind:
                db.execute("INSERT OR IGNORE INTO observations(number,kind,before_sha,after_sha,at) VALUES (?,?,?,?,?)",(n,kind,prev["snapshot_sha"] if prev else None,sha,at))
                changes.append(dict(number=n,kind=kind,before_sha=prev["snapshot_sha"] if prev else None,after_sha=sha,lifecycle=lifecycle))
            snap=home(c)/"snapshots"/(sha+".json")
            if not snap.exists():w.save(snap,s)
        db.execute("COMMIT")
        record=status(c,db);record.update(remote_head=head,changes=changes,unavailable=unavailable,
                remote_writes=False,sync_id=digest(dict(head=head,issues=[(x["number"],x["snapshot_sha256"],x["lifecycle"]) for x in status(c,db)["issues"]])))
        publish_projection(c,record)
        record["notifications"]=remind(c,client,db,record,execute)
        record['remote_writes']=any(x['status'] in ('published_readback_verified','verified') for x in record['notifications'])
        w.save(output(c)/"last-sync.json",record)
        return record
    except BaseException as exc:
        if db and db.in_transaction:db.execute("ROLLBACK")
        w.save(output(c)/'sync-error.json',dict(schema=SCHEMA,observed_at=stamp(now()),error_type=type(exc).__name__,latest_confirmed_snapshot_preserved=True))
        raise
    finally:
        if db:db.close()
        guard.unlink(missing_ok=True)
def canon(v):return reports.canon(v)
def remind(c,client,db,record,execute):
    p=policy(c);result=[];moment=now()
    for row in db.execute("SELECT * FROM issues ORDER BY number").fetchall():
        if row["lifecycle"] in ("unknown","resolved_verified","closed_unverified"):continue
        if (moment-dt(row["last_change"])).total_seconds()<86400*p.get("stale_days",7):continue
        if row["last_reminder"] and (moment-dt(row["last_reminder"])).total_seconds()<86400*p.get("reminder_cooldown_days",7):continue
        s=json.loads(row["snapshot_json"])
        if s['state']=='closed' and not p.get('track_closed',False):continue
        users=s["assignees"]
        if not users:continue
        key=digest(dict(repo=c["github"]["repository_id"],number=row["number"],change=row["last_change"],bucket=moment.date().isoformat()))
        marker="<!-- ces-tracking:"+key+" -->"
        body=marker+"\n\n"+" ".join("@"+x for x in users)+"\n\nCES周期跟踪：该问题自最近进展已超过配置阈值。当前状态："+row["lifecycle"]+"。请更新处理进展，或提供修复提交/PR和相关验证结果。\n本提醒不判定个人责任或自动关闭问题。"
        body=notifications.message(c,body,users)
        outcome=dict(number=row["number"],reason="stale",status="reminder_due",**notifications.route(c,users),email_delivery_verified=False)
        if execute:
            w.need(p.get("allow_reminders") is True,"TRACKING_REMINDERS_NOT_AUTHORIZED")
            unresolved=db.execute("SELECT 1 FROM deliveries WHERE number=? AND state IN ('reserved','uncertain_no_retry')",(row['number'],)).fetchone()
            if unresolved:
                comments=client.pages(client.prefix+f"/issues/{row['number']}/comments")
                pending=db.execute("SELECT * FROM deliveries WHERE number=? AND state IN ('reserved','uncertain_no_retry')",(row['number'],)).fetchall()
                matched=[]
                for delivery in pending:
                    marker_old='<!-- ces-tracking:'+delivery['key']+' -->'
                    match=next((x for x in comments if marker_old in (x.get('body') or '')),None)
                    if match:
                        db.execute("UPDATE deliveries SET state='verified',url=? WHERE key=?",(match['html_url'],delivery['key']))
                        db.execute('UPDATE issues SET last_reminder=? WHERE number=?',(delivery['created_at'],row['number']))
                        matched.append(match['html_url'])
                outcome.update(status='previous_delivery_reconciled' if matched else 'unresolved_previous_delivery_no_retry',urls=matched)
                result.append(outcome);continue
            prior_delivery=db.execute("SELECT * FROM deliveries WHERE key=?",(key,)).fetchone()
            if prior_delivery:
                outcome["status"]="previous_attempt_not_retried";result.append(outcome);continue
            comments=client.pages(client.prefix+f"/issues/{row['number']}/comments")
            duplicate=next((x for x in comments if marker in (x.get("body") or "")),None)
            if duplicate:
                db.execute("INSERT INTO deliveries(key,state,url,created_at,number) VALUES (?,?,?,?,?)",(key,"verified",duplicate["html_url"],stamp(moment),row['number']))
                outcome["status"]="duplicate_skipped";outcome["url"]=duplicate["html_url"]
            else:
                db.execute("INSERT INTO deliveries(key,state,url,created_at,number) VALUES (?,?,?,?,?)",(key,"reserved",None,stamp(moment),row['number']))
                try:
                    doc,st=client.write(client.prefix+f"/issues/{row['number']}/comments",dict(body=body))
                    db.execute("UPDATE deliveries SET state='verified',url=? WHERE key=?",(doc["html_url"],key))
                    outcome.update(status=st,url=doc["html_url"])
                except BaseException:
                    db.execute("UPDATE deliveries SET state='uncertain_no_retry' WHERE key=?",(key,));raise
            db.execute("UPDATE issues SET last_reminder=? WHERE number=?",(stamp(moment),row["number"]))
        result.append(outcome)
    return result

def source(c,client,head,path):
    from ces_documents import relative
    relative(path)
    data=client.get(client.prefix+"/contents/"+quote(path,safe="/")+"?ref="+head)
    w.need(isinstance(data,dict) and data.get('type')=='file' and 0<data.get('size',0)<=2*1024*1024,'SOURCE_CONTENT_UNAVAILABLE_OR_LIMITED')
    if data.get('encoding')!='base64':
        blob=client.get(client.prefix+'/git/blobs/'+data['sha'])
        w.need(blob.get('sha')==data['sha'] and blob.get('encoding')=='base64' and blob.get('size')==data['size'],'SOURCE_GIT_BLOB_UNAVAILABLE')
        data={**data,'encoding':'base64','content':blob['content']}
    raw=base64.b64decode(data["content"],validate=False)
    w.need(len(raw)==data["size"] and __import__("hashlib").sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==data["sha"],"SOURCE_BLOB_MISMATCH")
    text=raw.decode("utf-8-sig");return dict(path=path,sha256=w.sha(raw),git_blob_sha=data["sha"],text=text)
def review_input(c,number,paths):
    policy(c);w.need(type(number) is int and number>0,"ISSUE_NUMBER_INVALID")
    w.need(isinstance(paths,list) and 1<=len(paths)<=16 and len(set(paths))==len(paths),"REVIEW_SOURCE_PATHS_REQUIRED")
    client=reports.Client(c);db=dbopen(c)
    try:
        row=db.execute("SELECT * FROM issues WHERE number=?",(number,)).fetchone();w.need(row is not None,"ISSUE_NOT_TRACKED")
        issue=client.get(client.prefix+f"/issues/{number}");head=default_head(client)
        w.need(issue['state']!='closed' or c.get('issue_tracking',{}).get('track_closed',False),'CLOSED_ISSUE_TRACKING_DISABLED')
        snap=observe(client,issue,head)
        w.need(digest(snap)==row["snapshot_sha"],"TRACKING_STALE_RUN_SYNC_FIRST")
        sources=[source(c,client,head,path) for path in paths]
        w.need(default_head(client)==head,"REVIEW_HEAD_MOVED")
        body=dict(schema="ces.issue_fix_input.v1",repository_id=c["github"]["repository_id"],number=number,issue_id=row["issue_id"],
                  head_sha=head,issue_sha=issue_sha(snap),snapshot_sha=row["snapshot_sha"],issue=dict(title=issue["title"],body=issue.get("body") or ""),
                  sources=sources,linked_pulls=snap["pulls"],remote_content_untrusted=True)
        body["input_sha256"]=digest(body)
        dest=home(c)/"review-inputs"/(body["input_sha256"]+".json");w.save(dest,body)
        return dict(status="review_input_ready",path=str(dest),input_sha256=body["input_sha256"],head_sha=head,number=number)
    finally:db.close()
def verify_review(c,doc,inp,receipt_loader=None):
    w.need(doc.get("schema")=="ces.issue_fix_review.v1" and inp.get("schema")=="ces.issue_fix_input.v1","FIX_REVIEW_SCHEMA_INVALID")
    original=dict(inp);pin=original.pop("input_sha256")
    w.need(digest(original)==pin and doc.get("input_sha256")==pin and inp["repository_id"]==c["github"]["repository_id"],"FIX_REVIEW_BINDING_INVALID")
    verdict=doc.get("verdict");w.need(verdict in ("fixed","not_fixed","inconclusive","regression"),"FIX_REVIEW_VERDICT_INVALID")
    w.need(isinstance(doc.get("reasoning"),str) and 30<=len(doc["reasoning"])<=16000 and isinstance(doc.get("verification_criteria"),str) and len(doc["verification_criteria"])>=20,"FIX_REVIEW_REASONING_REQUIRED")
    citations=doc.get("citations",[]);w.need(1<=len(citations)<=32,"FIX_REVIEW_CITATIONS_REQUIRED")
    sources={x["path"]:x for x in inp["sources"]}
    w.need(1<=len(sources)<=16 and len(sources)==len(inp['sources']),'FIX_REVIEW_SOURCE_SET_INVALID')
    for ref in citations:
        w.need(ref["path"] in sources,"FIX_CITATION_PATH_NOT_BOUND")
        lines=sources[ref["path"]]["text"].splitlines();a,b=ref["line_start"],ref["line_end"]
        w.need(type(a) is int and type(b) is int and 1<=a<=b<=len(lines) and b-a<=100,"FIX_CITATION_LINE_INVALID")
        w.need(ref.get("quote","").strip() and ref["quote"] in "\n".join(lines[a-1:b]),"FIX_CITATION_NOT_PRESENT")
    tests=doc.get("test_receipts",[])
    w.need(isinstance(tests,list) and len(tests)<=16 and all(isinstance(x,str) for x in tests) and len(set(tests))==len(tests),'TEST_RECEIPT_LIST_INVALID')
    verified=[]
    for key in tests:
        w.need(re.fullmatch("[0-9a-f]{64}",key) is not None,"TEST_RECEIPT_ID_INVALID")
        r=receipt_loader(key) if receipt_loader else w.load(home(c)/"test-receipts"/(key+".json"))
        core=dict(r);record_id=core.pop("receipt_id")
        w.need(record_id==key==digest(core),"TEST_RECEIPT_HASH_INVALID")
        w.need(r["repository_id"]==inp["repository_id"] and r["number"]==inp["number"] and r["head_sha"]==inp["head_sha"] and r["source_clean_before_and_after"],"TEST_RECEIPT_SOURCE_MISMATCH")
        age=(now()-dt(r['completed_at'])).total_seconds()
        w.need(0<=age<=86400*policy(c).get('review_max_age_days',7),'TEST_RECEIPT_EXPIRED')
        configured=next((s for s in c.get('build_validation',{}).get('steps',[]) if s['name']==r['step']),None)
        w.need(configured and configured.get('kind')=='test' and r.get('kind')=='test' and r.get('configuration_sha256')==digest(configured) and configured['argv']==r['argv'] and str(Path(configured.get('cwd',c['repository_path'])).resolve())==r['cwd'],'TEST_RECEIPT_CONFIG_CHANGED')
        if receipt_loader is None:
            log=home(c)/'test-receipts'/(key+'.log')
            w.need(log.is_file() and w.sha(log.read_bytes())==r['log_sha256'],'TEST_LOG_HASH_MISMATCH')
        verified.append(r)
    if verdict in ("fixed","regression"):
        required=policy(c).get("required_test_steps",[])
        w.need(required and verified,"FIX_REVIEW_REQUIRES_REAL_TEST_RECEIPTS")
        for step in required:
            selected=[r for r in verified if r["step"]==step]
            w.need(selected and all(r["exit_code"]==0 for r in selected) if verdict=="fixed" else bool(selected),"REQUIRED_TEST_STEP_MISSING_OR_FAILED")
        if verdict=="regression":w.need(any(r["exit_code"]!=0 for r in verified),"REGRESSION_REQUIRES_FAILURE_EVIDENCE")
    return dict(verdict=verdict,source_review_bound=True,test_receipts=len(verified),semantic_assessment_by="Codex/operator; literal validation is not independent proof",auto_state_change=False)
def review(c,input_path,review_path):
    policy(c);inp=w.load(input_path);doc=w.load(review_path)
    checked=verify_review(c,doc,inp);client=reports.Client(c)
    w.need(default_head(client)==inp["head_sha"],"FIX_REVIEW_REMOTE_HEAD_CHANGED")
    snap=observe(client,client.get(client.prefix+f"/issues/{inp['number']}"),inp["head_sha"])
    w.need(digest(snap)==inp["snapshot_sha"],"FIX_REVIEW_ISSUE_CHANGED")
    for s in inp['sources']:
        actual=source(c,client,inp['head_sha'],s['path'])
        w.need(actual['sha256']==s['sha256'] and actual['git_blob_sha']==s['git_blob_sha'] and actual['text']==s['text'],'FIX_REVIEW_SOURCE_CHANGED')
    record=dict(schema="ces.issue_fix_assessment.v1",input_sha256=inp["input_sha256"],head_sha=inp["head_sha"],issue_sha=inp["issue_sha"],
                number=inp["number"],issue_id=inp["issue_id"],review=doc,checks=checked)
    key=digest(record);db=dbopen(c)
    try:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute("SELECT * FROM issues WHERE number=?",(inp["number"],)).fetchone()
        w.need(row is not None and row["snapshot_sha"]==inp["snapshot_sha"],"TRACKING_CHANGED_AFTER_REVIEW")
        db.execute("INSERT OR IGNORE INTO reviews VALUES (?,?,?,?,?,?,?,?)",(key,inp["number"],inp["issue_id"],inp["head_sha"],inp["issue_sha"],doc["verdict"],canon(record),stamp(now())))
        lifecycle=classify(snap,dict(row),dict(head_sha=inp["head_sha"],issue_sha=inp["issue_sha"],verdict=doc["verdict"]))
        db.execute("UPDATE issues SET lifecycle=? WHERE number=?",(lifecycle,inp["number"]))
        db.execute("INSERT OR IGNORE INTO observations(number,kind,before_sha,after_sha,at) VALUES (?,?,?,?,?)",(inp["number"],"review:"+doc["verdict"],row["snapshot_sha"],key,stamp(now())))
        db.execute("COMMIT");w.save(home(c)/"reviews"/(key+".json"),record)
        result=status(c,db);publish_projection(c,result)
        return dict(status="review_recorded",review_id=key,number=inp["number"],verdict=doc["verdict"],lifecycle=lifecycle,remote_mutation=False)
    finally:db.close()
def run_test(c,number,step):
    w.need(c.get('execution_policy',{}).get('run_runtime_tests') is True,'RUNTIME_TESTS_DISABLED_BY_USER_POLICY')
    p=policy(c);steps=c.get("build_validation",{}).get("steps",[])
    w.need(type(number) is int and number>0,'TEST_ISSUE_NUMBER_REQUIRED')
    selected=next((s for s in steps if s["name"]==step),None)
    w.need(selected and c.get("build_validation",{}).get("enabled") is True,"BUILD_TEST_STEP_NOT_CONFIGURED")
    w.need(selected.get('kind')=='test','BUILD_ONLY_STEP_IS_NOT_TEST_EVIDENCE')
    w.need(p.get("allow_test_execution") is True,"TRACKING_TEST_EXECUTION_NOT_AUTHORIZED")
    client=reports.Client(c);head=default_head(client)
    w.need(w.git(c,"rev-parse","HEAD")==head,"LOCAL_HEAD_NOT_CURRENT_REMOTE_HEAD")
    docroot=c.get('repository_docs',{}).get('relative_directory','docs/ces')
    from ces_documents import relative
    relative(docroot)
    w.need(not w.git(c,"status","--porcelain=v1","-uall","--",".",':(exclude,top,glob)'+docroot+'/**',":(exclude,top,glob).codex/ces/**"),"SOURCE_DIRTY_TEST_REFUSED")
    argv=selected["argv"];w.need(isinstance(argv,list) and argv and all(isinstance(x,str) and x for x in argv),"BUILD_ARGV_INVALID")
    directory=Path(selected.get("cwd",c["repository_path"])).resolve()
    w.need(directory==Path(c["repository_path"]).resolve() or Path(c["repository_path"]).resolve() in directory.parents,"BUILD_CWD_OUTSIDE_REPO")
    timeout=selected.get("timeout_seconds",600);w.need(type(timeout) is int and 1<=timeout<=3600,"BUILD_TIMEOUT_INVALID")
    before=w.snapshot(c);started=stamp(now())
    try:
        proc=subprocess.run(argv,cwd=directory,env=w.clean_env(),capture_output=True,timeout=timeout)
        exit_code=proc.returncode;raw=proc.stdout+proc.stderr
    except subprocess.TimeoutExpired as exc:exit_code=-1;raw=(exc.stdout or b"")+(exc.stderr or b"")
    w.need(len(raw)<=16*1024*1024,"BUILD_LOG_LIMIT")
    after=w.snapshot(c)
    clean=before['head']==after['head']==head and before['index_sha256']==after['index_sha256'] and not w.git(c,'status','--porcelain=v1','-uall','--','.',':(exclude,top,glob)'+docroot+'/**',':(exclude,top,glob).codex/ces/**')
    w.need(default_head(client)==head and clean,"SOURCE_CHANGED_DURING_TEST")
    receipt=dict(schema="ces.issue_test_receipt.v1",repository_id=c["github"]["repository_id"],number=number,step=step,kind='test',configuration_sha256=digest(selected),head_sha=head,
                 argv=argv,cwd=str(directory),started_at=started,completed_at=stamp(now()),exit_code=exit_code,
                 source_clean_before_and_after=True,log_sha256=w.sha(raw))
    key=digest(receipt);receipt["receipt_id"]=key
    dest=home(c)/"test-receipts";dest.mkdir(parents=True,exist_ok=True)
    (dest/(key+".log")).write_bytes(raw);w.save(dest/(key+".json"),receipt)
    return receipt
def transition(c,number,target,execute):
    p=policy(c);w.need(target in ("closed","open"),"ISSUE_TARGET_STATE_INVALID")
    allowed=p.get('allow_auto_close' if target=='closed' else 'allow_auto_reopen') is True
    if execute:w.need(allowed,'ISSUE_STATE_TRANSITION_NOT_AUTHORIZED')
    client=reports.Client(c);db=dbopen(c)
    try:
        row=db.execute("SELECT * FROM issues WHERE number=?",(number,)).fetchone()
        w.need(row is not None,"ISSUE_NOT_TRACKED")
        latest=db.execute("SELECT * FROM reviews WHERE number=? ORDER BY created_at DESC,rowid DESC LIMIT 1",(number,)).fetchone()
        w.need(latest is not None and latest["verdict"]==("fixed" if target=="closed" else "regression"),"STATE_CHANGE_REQUIRES_VERIFIED_REVIEW")
        assessment=json.loads(latest['record_json'])
        input_path=home(c)/'review-inputs'/(assessment['input_sha256']+'.json')
        w.need(input_path.is_file(),'STATE_CHANGE_REVIEW_INPUT_MISSING')
        verify_review(c,assessment['review'],w.load(input_path))
        head=default_head(client);snap=observe(client,client.get(client.prefix+f"/issues/{number}"),head)
        w.need(latest["head_sha"]==head and latest["issue_sha"]==issue_sha(snap) and not snap.get("unavailable"),"STATE_REVIEW_STALE")
        if snap["state"]==target:return dict(status="already_in_requested_state",number=number)
        payload=dict(state=target,state_reason="completed" if target=="closed" else "reopened")
        if not execute:return dict(status="state_change_preview",number=number,payload=payload,review_id=latest["id"],execution_allowed=allowed)
        # Uses repository-scoped current review, no unknown POST retry, readback required.
        observed,st=client.write(client.prefix+f"/issues/{number}",payload,"PATCH")
        w.need(observed["state"]==target,"STATE_TRANSITION_READBACK_MISMATCH")
        post=observe(client,client.get(client.prefix+f'/issues/{number}'),head)
        w.need(default_head(client)==head and post['state']==target,'STATE_TRANSITION_POSTCHECK_INCONSISTENT')
        for field in ('issue_id','title','body','assignees','labels','comments','pulls'):
            w.need(post[field]==snap[field],'CONCURRENT_ISSUE_CHANGE_DURING_TRANSITION')
        # Preserve the same verified source/test assessment across our own state event only.
        followup={**assessment,'issue_sha':issue_sha(post),'parent_review_id':latest['id'],'state_transition':target}
        key=digest(followup)
        db.execute('BEGIN IMMEDIATE')
        db.execute('INSERT OR IGNORE INTO reviews VALUES (?,?,?,?,?,?,?,?)',(key,number,row['issue_id'],head,issue_sha(post),latest['verdict'],canon(followup),stamp(now())))
        db.execute('COMMIT');w.save(home(c)/'reviews'/(key+'.json'),followup)
        return dict(status=st,number=number,state=target,url=observed["html_url"],next_step="Run track sync again to reconcile the new remote state")
    finally:db.close()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("command",choices=["sync","status","history","prepare","review","test","transition"])
    p.add_argument("--config",required=True);p.add_argument("--execute",action="store_true");p.add_argument("--number",type=int)
    p.add_argument("--path",action="append");p.add_argument("--input");p.add_argument("--review");p.add_argument("--step");p.add_argument("--state",choices=["open","closed"])
    a=p.parse_args();c=w.config(a.config);policy(c)
    if a.command=="sync":result=sync(c,a.execute)
    elif a.command=="status":result=status(c)
    elif a.command=='history':result=history(c,a.number)
    elif a.command=="prepare":result=review_input(c,a.number,a.path)
    elif a.command=="review":result=review(c,a.input,a.review)
    elif a.command=='test':
        if a.execute:result=run_test(c,a.number,a.step)
        else:result=dict(status='test_execution_preview',number=a.number,step=a.step,configured_steps=[s['name'] for s in c.get('build_validation',{}).get('steps',[])],next_step='Provide configured command and --execute to run tests; no test has run.')
    else:result=transition(c,a.number,a.state,a.execute)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=="__main__":main()

