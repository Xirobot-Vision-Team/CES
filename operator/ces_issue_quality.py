"""Source-bound deep Issue content and explicit personal-reminder routing."""
from pathlib import Path
import json,re
import ces_workflow as w
import ces_notifications as notifications

FIELDS=("problem","evidence","trigger","expected_actual","root_cause","impact","quality","optimization","recommendation","alternatives","verification","limitations")
LABELS=("问题与结论","代码证据与来源","触发条件","预期与实际行为","根因分析","影响范围","代码质量分析","优化机会与权衡","修改建议","替代方案","验证方法与验收标准","证据限制")
def details(c,run,proposal,origins):
    source=run/"issue-analysis.json"
    w.need(source.is_file(),"DEEP_ISSUE_ANALYSIS_REQUIRED")
    d=w.load(source);info=w.load(run/"run.json");checked=w.load(run/"validate.json")["data"]
    w.need(d["schema"]=="ces.deep_issue_analysis.v1" and d["packet_sha256"]==info["packet_sha256"] and
           d["draft_sha256"]==w.sha((run/"review-draft.json").read_bytes()),"DEEP_ANALYSIS_BINDING_MISMATCH")
    entry=next((x for x in d["issues"] if x["title"]==proposal["title"]),None)
    w.need(entry and set(entry["finding_ids"])==set(proposal["finding_ids"]),"DEEP_ANALYSIS_FINDING_SCOPE_MISMATCH")
    valid={f["id"] for f in checked["checked_findings"]}
    w.need(set(entry["finding_ids"])<=valid,"DEEP_ANALYSIS_UNVALIDATED_FINDING")
    for field in FIELDS:w.need(isinstance(entry.get(field),str) and 15<=len(entry[field])<=12000,"DEEP_ANALYSIS_SECTION_REQUIRED:"+field)
    people=sorted({o["author_login"] for f in proposal["finding_ids"] for o in origins[f] if o.get("author_login")})
    w.need(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}",x) for x in people),"REMINDER_LOGIN_INVALID")
    text=["<!-- ces-deep-analysis:start -->","## 个人处理提醒",
          " ".join("@"+p for p in people)+"：请复核下列代码问题/改进建议，确认影响后处理或说明不采用原因。",
          "提交来源定位不作为个人责任判定。",""]
    for field,label in zip(FIELDS,LABELS):text+=["### "+label,entry[field],""]
    text+=["<!-- ces-deep-analysis:end -->"]
    return "\n".join(text),people

def enrich(c,run,client,execute):
    import ces_reports as r
    origins=r.resolve_origins(c,run,client)
    results={x["title"]:x for x in w.load(run/"issue-results.json")}
    output=[]
    for p in w.load(run/"issue-proposals.json"):
        target=results.get(p["title"])
        if not target or not target.get("number"):continue
        section,people=details(c,run,p,origins)
        old=client.get(client.prefix+f"/issues/{target['number']}");body=old.get("body") or ""
        if "<!-- ces-deep-analysis:start -->" in body:
            updated=re.sub(r"<!-- ces-deep-analysis:start -->.*?<!-- ces-deep-analysis:end -->",lambda _:section,body,flags=re.S)
        else:updated=body+"\n\n"+section
        updated=notifications.message(c,updated,people)
        if updated==body:status="already_enriched"
        elif execute:_,status=client.write(client.prefix+f"/issues/{target['number']}",dict(body=updated),"PATCH")
        else:status="prepared_not_published"
        sender=client.account_login
        recipients=[dict(login=x,self_generated=(x==sender),personal_notification_verified=False,email_delivery_verified=False,
                         next_step="enable_email_for_own_updates_or_use_independent_sender" if x==sender else "recipient_participating_mentions_email_preference_required") for x in people]
        routing=notifications.route(c,people)
        recipients += [dict(login=x,role='cc',self_generated=x==sender,personal_notification_verified=False,email_delivery_verified=False) for x in routing['cc_recipients']]
        output.append(dict(number=target["number"],url=old["html_url"],status=status,sender=sender,recipients=recipients,primary_recipients=routing['primary_recipients'],cc_recipients=routing['cc_recipients'],
                           content_quality_sections=list(FIELDS),analysis_sha256=w.sha(section)))
    w.save(run/"issue-quality-and-reminders.json",dict(schema="ces.issue_quality_reminder.v1",issues=output))
    return output

