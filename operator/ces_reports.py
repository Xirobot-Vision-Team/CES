"""Generic CES attribution and GitHub-notification reporting; weekly reads archived dailies only."""
from __future__ import annotations
import argparse,json,re,sqlite3,sys
from pathlib import Path
from datetime import datetime,timedelta,timezone
import ces_workflow as w
import ces_notifications as notifications

def canon(obj):return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(",",":"))
def digest(obj):return w.sha(canon(obj))
def safe(text):return w.md(text).replace("@","&#64;")
def login(value):return isinstance(value,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}",value) is not None
def code_url(c,commit,path,line=None):
    return w.source_link(c,commit,path)+(f"#L{line}" if line else "")
class Client:
    def __init__(self,c):
        self.c=c;self.token=w.credential(c);self.prefix="/repos/"+c["github"]["repository"];self.cache={}
        account,_=w.api(self.token,"/user")
        self.account_login=account['login']
        repo,_=w.api(self.token,self.prefix)
        w.need(account["id"]==c["github"]["account_id"] and repo["id"]==c["github"]["repository_id"] and repo.get("permissions",{}).get("push"),"REPORT_HOST_IDENTITY_OR_TARGET_MISMATCH")
        self.cc_recipients=notifications.validate_access(c,self)
    def get(self,path):return w.api(self.token,path)[0]
    def recipient_status(self,recipients):
        return [dict(login=x,sender_is_recipient=x==self.account_login,
                     github_personal_inbox_verified=False,email_delivery_verified=False,
                     delivery_requirement='own_activity_email_setting_or_independent_sender' if x==self.account_login else 'recipient_email_and_participating_mention_notification_settings') for x in recipients]
    def pages(self,path):
        rows=[]
        for page in range(1,21):
            batch=self.get(path+("&" if "?" in path else "?")+f"per_page=100&page={page}")
            w.need(isinstance(batch,list),"PROVIDER_LIST_INVALID");rows+=batch
            if len(batch)<100:return rows
        raise RuntimeError("PROVIDER_INVENTORY_TRUNCATED")
    def commit(self,sha):
        if sha not in self.cache:
            d=self.get(self.prefix+"/commits/"+sha)
            self.cache[sha]=dict(sha=d["sha"],author_login=(d.get("author") or {}).get("login"),committer_login=(d.get("committer") or {}).get("login"),author_name=d["commit"]["author"]["name"],committer_name=d["commit"]["committer"]["name"],url=d["html_url"])
        return self.cache[sha]
    def maintainers(self):
        members=self.pages(self.prefix+"/collaborators?affiliation=all")
        permission=self.c["notifications"].get("weekly_permission","push")
        w.need(permission in ("push","maintain","admin"),"MAINTAINER_PERMISSION_INVALID")
        return sorted({x["login"] for x in members if x.get("permissions",{}).get(permission) and login(x["login"])},key=str.casefold)
    def write(self,path,payload,method="POST"):
        w.need(self.c["notifications"].get("allow_publish") is True,"REPORT_PUBLISH_NOT_AUTHORIZED")
        if 'body' in payload:
            payload={**payload,'body':notifications.message(self.c,payload['body'])}
            w.need(len(payload['body'].encode('utf-8'))<60000,'REPORT_BODY_LIMIT')
        directory=Path(self.c["state_root"]);directory.mkdir(parents=True,exist_ok=True)
        db=sqlite3.connect(directory/"report-notification-attempts.sqlite3",isolation_level=None,timeout=20)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY,state TEXT NOT NULL,response_json TEXT)")
        key=digest(dict(repo=self.c["github"]["repository_id"],method=method,path=path,payload=payload))
        previous=db.execute("SELECT state,response_json FROM attempts WHERE key=?",(key,)).fetchone()
        if previous:
            if previous[0]=="verified":
                db.close();return json.loads(previous[1]),"ledger_reused"
            if method!='PATCH':
                db.close();raise RuntimeError("NOTIFICATION_PREVIOUS_POST_UNCERTAIN_NO_RETRY")
            # A PATCH sets exact fields and is idempotent. Reconcile first; never replay POST.
            current=self.get(path)
            equal=all(current.get(k)==v for k,v in payload.items() if k!='assignees')
            if 'assignees' in payload:equal=equal and set(payload['assignees'])=={x['login'] for x in current['assignees']}
            if equal:
                db.execute("UPDATE attempts SET state='verified',response_json=? WHERE key=?",(canon(current),key));db.close()
                return current,"patch_reconciled_readback"
            db.execute("UPDATE attempts SET state='reconciled_idempotent_patch' WHERE key=?",(key,))
        else:
            db.execute("BEGIN IMMEDIATE")
            try:db.execute("INSERT INTO attempts VALUES (?,?,?)",(key,"reserved",None));db.execute("COMMIT")
            except BaseException:db.execute("ROLLBACK");db.close();raise
        try:
            response,status=w.api(self.token,path,payload,method)
            w.need(status in (200,201) and isinstance(response,dict),"NOTIFICATION_RESULT_UNCERTAIN")
            if "/comments" in path:
                readpath=self.prefix+"/issues/comments/"+str(response["id"])
            else:readpath=self.prefix+"/issues/"+str(response["number"])
            observed=self.get(readpath)
            for field in ("body","title"):
                if field in payload:w.need(observed.get(field)==payload[field],"NOTIFICATION_READBACK_MISMATCH")
            if "assignees" in payload:
                w.need(set(payload["assignees"])<={x["login"] for x in observed["assignees"]},"ASSIGNEE_READBACK_MISMATCH")
            db.execute("UPDATE attempts SET state='verified',response_json=? WHERE key=?",(canon(observed),key))
            return observed,"published_readback_verified"
        except BaseException:
            db.execute("UPDATE attempts SET state='uncertain_no_retry' WHERE key=?",(key,))
            raise
        finally:db.close()
    def publish(self,topic,snapshot,title,body,recipients):
        w.need(isinstance(recipients,list) and (recipients or notifications.configured_cc(self.c)) and all(login(x) for x in recipients),"REPORT_RECIPIENTS_INVALID")
        routing=notifications.route(self.c,recipients)
        if notifications.configured_cc(self.c):
            snapshot=digest(dict(content_snapshot=snapshot,notification_routing=routing))
        marker="<!-- ces-report-topic:"+topic+" -->"
        revision="<!-- ces-report-snapshot:"+snapshot+" -->"
        direct='收件人：'+ ' '.join('@'+x for x in recipients)+'\n\n' if recipients else ''
        body=marker+"\n"+revision+"\n\n"+direct+body
        body=notifications.message(self.c,body,recipients)
        w.need(len(body.encode("utf-8"))<60000,"REPORT_BODY_LIMIT")
        issues=[x for x in self.pages(self.prefix+"/issues?state=all") if "pull_request" not in x]
        existing=next((x for x in issues if marker in (x.get("body") or "")),None)
        if existing:
            comments=self.pages(self.prefix+f"/issues/{existing['number']}/comments")
            found=next((x for x in [existing,*comments] if revision in (x.get("body") or "")),None)
            if found:return dict(status="duplicate_skipped",url=found["html_url"],number=existing["number"],**routing,snapshot=snapshot,sender=self.account_login,recipient_delivery=self.recipient_status(routing['recipients']),email_delivery_verified=False)
            observed,status=self.write(self.prefix+f"/issues/{existing['number']}/comments",dict(body=body))
            number=existing["number"]
        else:
            observed,status=self.write(self.prefix+"/issues",dict(title=title,body=body))
            number=observed["number"]
        return dict(status=status,url=observed["html_url"],number=number,**routing,snapshot=snapshot,
                    notification_channel="github_mentions",sender=self.account_login,recipient_delivery=self.recipient_status(routing['recipients']),email_delivery_verified=False)

def resolve_origins(c,run,client):
    info=w.load(run/"run.json");draft=w.load(run/"review-draft.json");checked=w.load(run/"validate.json")
    w.need(checked["data"]["validated"] and checked["data"]["packet_sha256"]==info["packet_sha256"] and checked["data"]["draft_sha256"]==w.sha((run/"review-draft.json").read_bytes()),"ATTRIBUTION_REVIEW_BINDING_INVALID")
    w.need(w.git(c,"rev-parse","HEAD")==info["head"],"ATTRIBUTION_HEAD_MOVED")
    drafts={x["id"]:x for x in draft["findings"]};result={}
    for finding in checked["data"]["checked_findings"]:
        raw=drafts[finding["id"]]["evidence_quote"];w.need(w.sha(raw)==finding["quote_sha256"],"ATTRIBUTION_QUOTE_CHANGED")
        literal=raw[1:] if raw.startswith("+") else raw
        file=w.git(c,"show",info["head"]+":"+finding["path"])
        matches=[i for i,line in enumerate(file.splitlines(),1) if line==literal]
        w.need(matches and len(matches)<=20,"ATTRIBUTION_LITERAL_AMBIGUOUS_OR_MISSING")
        origins=[]
        for line in matches:
            blame=w.git(c,"blame","--line-porcelain","-L",f"{line},{line}",info["head"],"--",finding["path"])
            commit=blame.split()[0].lstrip("^")
            w.need(re.fullmatch("[0-9a-f]{40}",commit) is not None,"ATTRIBUTION_COMMIT_INVALID")
            identity=client.commit(commit)
            origins.append(dict(line=line,path=finding["path"],commit=commit,author_login=identity["author_login"],committer_login=identity["committer_login"],
                                commit_url=identity["url"],code_url=code_url(c,info["head"],finding["path"],line),
                                basis="git blame exact current line + GitHub commit identity mapping; not proof of fault"))
        result[finding["id"]]=origins
    w.save(run/"attribution.json",dict(schema="ces.finding_attribution.v1",target=info["head"],findings=result))
    return result

def attributed(c,run,client,execute):
    result=resolve_origins(c,run,client)
    issue_results={x["title"]:x for x in w.load(run/"issue-results.json")}
    assignable={x["login"] for x in client.pages(client.prefix+"/assignees")}
    outcomes=[]
    for proposal in w.load(run/"issue-proposals.json"):
        target=issue_results.get(proposal["title"])
        if not target or not target.get("number"):continue
        number=target["number"];issue=client.get(client.prefix+f"/issues/{number}")
        rows=[];people=set()
        for fid in proposal["finding_ids"]:
            for origin in result[fid]:
                author=origin["author_login"];committer=origin["committer_login"]
                if login(author):people.add(author)
                rows.append(f"- [{safe(origin['path'])}:L{origin['line']}]({origin['code_url']})；来源提交 [{origin['commit'][:12]}]({origin['commit_url']})；作者 "+("@"+author if login(author) else "未映射到 GitHub 账号")+"；committer "+("@"+committer if login(committer) else "未映射")+"。")
        section="<!-- ces-attribution:start -->\n## 来源提交与对应提交人\n"+"\n".join(rows)+"\n\n此处列出对应代码行的最近修改者，不据此判定个人责任。\n<!-- ces-attribution:end -->"
        old=issue.get("body") or ""
        if "<!-- ces-attribution:start -->" in old:
            body=re.sub(r"<!-- ces-attribution:start -->.*?<!-- ces-attribution:end -->",lambda _:section,old,flags=re.S)
        else:body=old+"\n\n"+section
        body=notifications.message(c,body,sorted(people))
        assigned=sorted({x["login"] for x in issue.get("assignees",[])}|people.intersection(assignable),key=str.casefold)
        w.need(len(assigned)<=10,"ASSIGNEE_LIMIT")
        payload=dict(body=body,assignees=assigned)
        if old==body and set(assigned)=={x["login"] for x in issue.get("assignees",[])}:status="already_attributed"
        elif execute:
            _,status=client.write(client.prefix+f"/issues/{number}",payload,"PATCH")
        else:status="prepared_not_published"
        outcomes.append(dict(number=number,url=issue["html_url"],status=status,source_authors=sorted(people),assignees=assigned,**notifications.route(c,sorted(people))))
    w.save(run/"attribution-results.json",outcomes)
    return result

def daily_reports(c,run,client,origins,execute):
    import ces_tracking
    import ces_audit
    tracking=ces_tracking.for_report(c)
    data=w.load(run/"daily-activity.json");checked=w.load(run/"validate.json")["data"];info=w.load(run/"run.json")
    review=dict(head=info["head"],packet_sha256=checked["packet_sha256"],summary=checked["summary"],source_mode=info["source_mode"])
    preflight_path=run/"preflight.json"
    w.need(preflight_path.exists() or not c.get("execution_policy",{}).get("build_before_analysis"),"DAILY_BOUND_BUILD_RECEIPT_REQUIRED")
    preflight=w.load(preflight_path) if preflight_path.exists() else None
    if preflight:
        w.need(preflight.get("status") in ("ready","build_failed") and preflight.get("build",{}).get("head")==info["head"],"DAILY_BUILD_SOURCE_MISMATCH")
    day=datetime.fromisoformat(data["start"]).date().isoformat()
    kept,excluded,audit_warnings=ces_audit.filter_commits(c,data['commits'])
    excluded_by_sha={x['sha']:x for x in data.get('excluded_maintenance_commits',[])}
    excluded_by_sha.update({x['sha']:x for x in excluded});excluded=sorted(excluded_by_sha.values(),key=lambda x:x['sha'])
    grouped={};unmapped=[]
    for row in kept:
        ident=client.commit(row["sha"]);author=ident["author_login"]
        if not login(author):unmapped.append(row["sha"]);continue
        grouped.setdefault(author,[]).append({**row,"author_login":author,"committer_login":ident["committer_login"]})
    issues={}
    by_title={p["title"]:p for p in w.load(run/"issue-proposals.json")}
    for x in w.load(run/"issue-results.json"):
        for fid in by_title.get(x["title"],{}).get("finding_ids",[]):issues[fid]=x.get("url")
    records=[]
    if not grouped and not kept:grouped['_repository']=[]
    for author,commits in sorted(grouped.items()):
        own=[]
        for f in checked["checked_findings"]:
            if origins.get(f['id']) and all(o.get('commit') in excluded_by_sha for o in origins[f['id']]):continue
            if any(o["author_login"]==author for o in origins.get(f["id"],[])):
                own.append({**f,"origins":origins[f["id"]],"issue_url":issues.get(f["id"])})
        semantic=dict(repository_id=c["github"]["repository_id"],date=day,recipient=author,
                      commits=sorted(commits,key=lambda x:x["sha"]),findings=own,coverage_limitations=checked["limitations"],source_review=review)
        if preflight:semantic['preanalysis_build']=preflight
        if ces_audit.enabled(c):semantic.update(audit_policy='exclude_verified_ces_document_publications_v1',excluded_maintenance_commits=excluded,audit_filter_warnings=audit_warnings)
        if tracking:semantic['issue_tracking']=tracking
        record_id=digest(semantic)
        dest=Path(c["output_root"])/"reports/daily"/day/author/(record_id+".json")
        if dest.exists():
            record=w.load(dest);w.need(record["core_sha256"]==digest(record["core"]),"DAILY_RECORD_HASH_MISMATCH")
        else:
            repository_status=author=='_repository'
            lines=[f"# 日报 · {day} · "+('仓库状态' if repository_status else author),"",f"仓库：{c['github']['repository']}",f"统计截至：{data['end']}",
                   '本轮无有效工作提交；保存仓库状态，不创建个人工作报告提醒。' if repository_status else f"本日报收件人：{author}。按 GitHub commit author 映射分组；author 与 committer 分别保留，不推断个人绩效。","",
                   f"## 有效提交：{len(commits)} 条",""]
            for row in commits:
                lines.append(f"- [{row['sha'][:12]}](https://github.com/{c['github']['repository']}/commit/{row['sha']}) {safe(row['subject'])}")
            import ces_lifecycle
            lines+=["","## 本轮审阅与实际构建","",('自动维护提交已排除；本轮无有效工作提交，保存构建与问题追踪状态。' if repository_status else safe(review["summary"])),"",
                    "- 审阅来源提交："+review["head"]+"；来源模式："+review["source_mode"]+"。"]
            lines+=ces_lifecycle.build_lines(c,run)
            lines+=["","## 与本人变更关联的代码审阅",""]
            if not own:lines+=["本轮没有已校验且可归属到该账号的 Finding；这不代表全部提交已审阅或不存在问题。"]
            for f in own:
                lines += [f"### [{f['severity']}] {safe(f['title'])}","",safe(f["reasoning"]),"",safe(f["impact"]),"","建议："+safe(f["recommendation"])]
                if f.get("issue_url"):lines+=["","Issue："+f["issue_url"]]
            lines+=["","## 验证与覆盖",""]+["- "+safe(x) for x in c.get("user_observations",[])]
            lines+=["- 本日报复用已校验的分析结果；未为报告重新分析全部源码。"]+["- "+safe(x) for x in checked["limitations"]]
            lines+=ces_tracking.report_lines(tracking)
            lines+=ces_audit.lines(excluded,audit_warnings)
            markdown="\n".join(lines)+"\n"
            core=dict(**semantic,id=record_id,generated_at=datetime.now(timezone.utc).isoformat(),period_start=data["start"],period_end=data["end"],
                      markdown=markdown,source_review_packet_sha256=checked["packet_sha256"],unmapped_commit_count=len(unmapped))
            record=dict(schema="ces.daily_report_record.v1",core=core,core_sha256=digest(core),publication=None)
        if execute and author!='_repository':
            record["publication"]=client.publish(f"daily:{c['github']['repository_id']}:{day}:{author}",record_id,
                                                 f"[CES 日报] {day} · {author}",record["core"]["markdown"],[author])
        w.save(dest,record);records.append(dict(path=str(dest),**record))
    w.save(run/"daily-report-records.json",dict(date=day,records=[dict(path=x["path"],id=x["core"]["id"],recipient=x["core"]["recipient"],core_sha256=x["core_sha256"],publication=x["publication"]) for x in records],unmapped_commits=unmapped))
    overview=["# 日报投递记录",""]
    for x in records:
        publication=x["publication"] or {}
        overview += [f"- {x['core']['recipient']}：{publication.get('url',x['path'])}；{publication.get('status','local_only')}"]
    if unmapped:overview+=["- "+str(len(unmapped))+" 个提交未映射到 GitHub 账号，未猜测收件人。"]
    (run/"日报-收件人.md").write_text("\n".join(overview)+"\n",encoding="utf-8")
    return records

def weekly_report(c,client,execute):
    import ces_periods
    result=ces_periods.build(c,"weekly",execute=execute)
    return w.load(result["path"])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("command",choices=["attribute","quality","daily","weekly","run"]);p.add_argument("--config",required=True);p.add_argument("--run");p.add_argument("--execute",action="store_true")
    a=p.parse_args();c=w.config(a.config)
    w.need(c.get("notifications",{}).get("channel")=="github_mentions","NOTIFICATION_CHANNEL_NOT_CONFIGURED")
    client=Client(c);output={}
    if c.get('issue_tracking',{}).get('enabled'):
        import ces_tracking
        output['issue_tracking']=ces_tracking.sync(c,a.execute)
    if a.command in ("attribute","quality","daily","run"):
        w.need(a.run,"RUN_REQUIRED");run=Path(a.run).resolve()
        w.need(Path(c["output_root"]).resolve() in run.parents,"RUN_OUTSIDE_REPORT_ROOT")
        w.need(w.load(run/"run.json")["repository"]==c["repository_path"],"REPORT_REPOSITORY_MISMATCH")
        if a.command in ('quality','run'):
            import ces_issue_quality
            output['issue_quality']=ces_issue_quality.enrich(c,run,client,a.execute)
        if a.command=='quality':
            print(json.dumps(dict(status='completed',email_delivery_verified=False,**output),ensure_ascii=False));return
        if a.command in ("attribute","run"):origins=attributed(c,run,client,a.execute)
        else:origins=w.load(run/"attribution.json")["findings"]
        if a.command in ("daily","run"):
            rows=daily_reports(c,run,client,origins,a.execute);output["daily"]=[dict(recipient=x["core"]["recipient"],publication=x["publication"]) for x in rows]
    if a.command in ("weekly","run"):
        weekly=weekly_report(c,client,a.execute);output["weekly"]=weekly["publication"];output["weekly_recipients"]=client.maintainers()
        if a.run:
            run=Path(a.run).resolve()
            w.need(Path(c["output_root"]).resolve() in run.parents,"RUN_OUTSIDE_REPORT_ROOT")
            (run/"周报.md").write_text(weekly["core"]["markdown"],encoding="utf-8")
    print(json.dumps(dict(status="completed",email_delivery_verified=False,**output),ensure_ascii=False))
if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(json.dumps(dict(status="failed",error_type=type(exc).__name__,reason=str(exc) if isinstance(exc,RuntimeError) else "DETAILS_REDACTED"),ensure_ascii=False));sys.exit(1)

