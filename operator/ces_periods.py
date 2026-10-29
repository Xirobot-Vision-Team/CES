"""Calendar summaries over immutable reports with optional bounded maintenance-commit exclusion."""
from __future__ import annotations
import argparse,calendar,json
from pathlib import Path
from datetime import date,datetime,timedelta
import ces_workflow as w
import ces_documents as d

LABEL={"weekly":"周报","monthly":"月总结","yearly":"年总结"}
CHILD={"weekly":"daily","monthly":"weekly","yearly":"monthly"}
def bounds(kind,as_of):
    start=as_of-timedelta(days=as_of.weekday()) if kind=="weekly" else as_of.replace(day=1) if kind=="monthly" else as_of.replace(month=1,day=1)
    return start,as_of
def choose_daily(c,as_of,start,end):
    root=Path(c["output_root"])/"reports/daily";latest={}
    for path in sorted(root.glob("*/*/*.json")):
        record=w.load(path);core=record.get("core",{})
        w.need(record.get("schema")=="ces.daily_report_record.v1" and record.get("core_sha256")==d.digest(core),"DAILY_SOURCE_HASH_INVALID")
        if core.get("repository_id")!=c["github"]["repository_id"] or not start.isoformat()<=core["date"]<=end.isoformat():continue
        key=(core["date"],core["recipient"])
        if key not in latest or core["generated_at"]>latest[key]["record"]["core"]["generated_at"]:
            latest[key]=dict(path=str(path),record=record)
    return list(latest.values())
def load_inputs(c,kind,as_of):
    start,end=bounds(kind,as_of);children=[];daily={}
    if kind=="weekly":
        for row in choose_daily(c,as_of,start,end):
            core=row["record"]["core"];children.append(dict(path=row["path"],schema=row["record"]["schema"],id=core["id"],core_sha256=row["record"]["core_sha256"],url=(row["record"].get("publication") or {}).get("url")))
            daily[(core["date"],core["recipient"])]=core
    else:
        latest={}
        for path in sorted((Path(c["output_root"])/"reports"/CHILD[kind]).glob("*/*.json")):
            record=w.load(path)
            if record.get("schema")!="ces.period_report_record.v1":continue
            core=record["core"];w.need(record["core_sha256"]==d.digest(core),"CHILD_SUMMARY_HASH_INVALID")
            if core["repository_id"]!=c["github"]["repository_id"]:continue
            in_period=[x for x in core["daily_records"] if start.isoformat()<=x["date"]<=end.isoformat()]
            if not in_period:continue
            key=core["period_start"]
            if key not in latest or core["generated_at"]>latest[key][1]["core"]["generated_at"]:latest[key]=(path,record,in_period)
        for path,record,records in latest.values():
            core=record["core"];children.append(dict(path=str(path),schema=record["schema"],id=core["id"],core_sha256=record["core_sha256"],url=(record.get("publication") or {}).get("url")))
            for row in records:
                key=(row["date"],row["recipient"])
                if key not in daily or row["generated_at"]>daily[key]["generated_at"]:daily[key]=row
    w.need(children,"NO_CHILD_REPORTS:"+CHILD[kind])
    w.need(len(children)<=512 and len(daily)<=4096,"REPORT_AGGREGATION_LIMIT")
    import ces_audit
    audit_cache={}
    records=[ces_audit.normalize_daily(c,row,audit_cache) for row in sorted(daily.values(),key=lambda x:(x["date"],x["recipient"]))]
    commits={x["sha"]:x for row in records for x in row["commits"]}
    findings={}
    for row in records:
        for f in row["findings"]:
            key=f.get("issue_url") or d.digest([f["path"],f["quote_sha256"],f["title"]])
            findings[key]=f
    days={x["date"] for x in records}
    missing=[(start+timedelta(days=n)).isoformat() for n in range((end-start).days+1) if (start+timedelta(days=n)).isoformat() not in days]
    context=dict(repository_id=c["github"]["repository_id"],kind=kind,period_start=start.isoformat(),as_of=end.isoformat(),
                 child_kind=CHILD[kind],children=sorted(children,key=lambda x:x["id"]),daily_records=records,
                 commits=sorted(commits.values(),key=lambda x:x["sha"]),findings=list(findings.values()),missing_dates=missing)
    if ces_audit.enabled(c):
        excluded={x['sha']:x for row in records for x in row.get('excluded_maintenance_commits',[])}
        context.update(audit_policy='exclude_verified_ces_document_publications_v1',excluded_maintenance_commits=sorted(excluded.values(),key=lambda x:x['sha']))
    import ces_tracking
    tracking=ces_tracking.for_report(c)
    if tracking:context['issue_tracking']=tracking
    if c.get('execution_policy',{}).get('build_before_analysis'):
        import ces_lifecycle
        buildpath=ces_lifecycle.home(c)/'last-preflight.json'
        if buildpath.exists():context['preanalysis_build']=w.load(buildpath)
    context["input_binding_sha256"]=d.digest(context)
    return context
def build(c,kind,as_of=None,execute=False,analysis_path=None):
    as_of=date.fromisoformat(as_of) if as_of else datetime.now(w.offset(c)).date()
    context=load_inputs(c,kind,as_of)
    cache=Path(c.get("cache_root",c["state_root"]))/"report-inputs"
    w.save(cache/(kind+"-"+context["period_start"]+".json"),context)
    reasoning=None
    if analysis_path:
        reasoning=w.load(analysis_path)
        w.need(reasoning.get("schema")=="ces.period_synthesis.v1" and reasoning.get("input_binding_sha256")==context["input_binding_sha256"],"PERIOD_SYNTHESIS_BINDING_MISMATCH")
        for field in ("achievements","risks","next_steps","knowledge_updates"):
            w.need(isinstance(reasoning.get(field),list) and len(reasoning[field])<=32 and all(isinstance(x,str) and 1<=len(x)<=4000 for x in reasoning[field]),"PERIOD_SYNTHESIS_FIELDS_INVALID")
    labels=LABEL[kind];records=context["daily_records"]
    counts={key:sum(f["severity"]==key for f in context["findings"]) for key in ("critical","high","medium","low","info")}
    lines=[f"# {labels} · {context['period_start']} 至 {context['as_of']}","",f"仓库：{c['github']['repository']}",
           f"来源：{len(context['children'])} 份{CHILD[kind]}记录，展开为 {len(records)} 份去重日报。",
           "复用已分析内容；汇总不重新分析业务源码，仅为排除CES维护提交核对有范围的Git提交/托管元数据。","",
           "## 综合概况","",f"- 去重提交：{len(context['commits'])}；去重问题/建议：{len(context['findings'])}。",
           "- 严重性分布："+", ".join(f"{key}={value}" for key,value in counts.items())+"。",
           f"- 缺少日报的日期：{len(context['missing_dates'])} 天；缺日报不表示没有工作。"]
    if context["missing_dates"]:lines+=["- 缺口样例："+", ".join(context["missing_dates"][:20])+("……" if len(context["missing_dates"])>20 else "")]
    if reasoning:
        for field,title in (("achievements","阶段进展与归纳"),("risks","风险与质量趋势"),("next_steps","下一阶段行动"),("knowledge_updates","知识与技术文档维护")):
            lines+=["","## "+title,""]+["- "+x for x in reasoning[field]]
    else:
        lines+=["","## 综合判断与行动","",
                "- 这是基于归档数据的结构化总结，尚未附加新的AI综合评述，不声称进行了新的深度推理。",
                "- 优先处理已保存的高/中等级问题；info级作为优化或维护建议，不混为已证明缺陷。",
                "- 优先补齐缺失日报与未审阅范围，再评价周期趋势；不把提交数量转为个人绩效。",
                "- 将影响架构、接口或运行约定的已确认变更整理进仓库知识章节；未经核验的推断保留待验证标记。"]
    lines+=["","## 关联代码问题与优化建议",""]
    severity={"critical":0,"high":1,"medium":2,"low":3,"info":4}
    for f in sorted(context["findings"],key=lambda x:severity[x["severity"]]):
        title=f"[{f['title']}]({f['issue_url']})" if f.get("issue_url") else f["title"]
        lines += [f"- [{f['severity']}] {title}", "  - 已有分析："+f["reasoning"],"  - 建议："+f["recommendation"]]
    lines+=["","## 来源与可追溯性",""]
    import ces_tracking
    lines+=ces_tracking.report_lines(context.get('issue_tracking'))
    import ces_audit
    lines+=ces_audit.lines(context.get('excluded_maintenance_commits',[]),[x for row in records for x in row.get('audit_filter_warnings',[])])
    for child in context["children"]:
        name=child["id"][:16]
        lines.append("- "+(f"[{name}]({child['url']})" if child.get("url") else name)+f"；内容哈希 {child['core_sha256']}")
    lines+=["","## 边界","",
            "- 汇总使用归档报告，并按审计策略核对提交元数据；前置构建结果另列，不代表运行测试、CI或硬件验证。",
            "- 来源于报告的观点仍保留原有置信度和限制，不提升为运行事实。",
            "- GitHub内的个人提醒/指派与邮件入箱是不同状态。"]
    payload=dict(input=context["input_binding_sha256"],synthesis_sha256=d.digest(reasoning) if reasoning else None)
    ident=d.digest(payload)
    core=dict(schema="ces.period_report.v1",id=ident,repository_id=c["github"]["repository_id"],kind=kind,
              period_start=context["period_start"],period_end=context["as_of"],generated_at=datetime.now(w.offset(c)).isoformat(),
              markdown="\n".join(lines)+"\n",daily_records=records,source_reports=context["children"],missing_dates=context["missing_dates"],
              commit_count=len(context["commits"]),finding_count=len(context["findings"]),input_binding_sha256=context["input_binding_sha256"],
              synthesis_mode="codex_reviewed" if reasoning else "structural_summary",source_code_reads=0,git_history_queries=None if ces_audit.enabled(c) else 0,ces_analysis_actions=0)
    if context.get('audit_policy'):
        core.update(audit_policy=context['audit_policy'],excluded_maintenance_commits=context['excluded_maintenance_commits'],git_history_scope='bounded publication metadata validation; exact query count not recorded')
    if context.get('issue_tracking'):core['issue_tracking']=context['issue_tracking']
    if context.get('preanalysis_build'):
        import ces_lifecycle
        core['preanalysis_build']=context['preanalysis_build']
        core['markdown']+='\n## 本次分析前的实际构建\n\n'+'\n'.join(ces_lifecycle.build_lines(c,receipt=context['preanalysis_build']['build']))+'\n'
    dest=Path(c["output_root"])/"reports"/kind/core["period_start"]/(ident+".json")
    record=dict(schema="ces.period_report_record.v1",core=core,core_sha256=d.digest(core),publication=None)
    if dest.exists():
        previous=w.load(dest);w.need(previous["core_sha256"]==d.digest(previous["core"]),"SAVED_PERIOD_REPORT_HASH_INVALID");record=previous
    if execute:
        import ces_reports
        client=ces_reports.Client(c)
        recipients=client.maintainers()
        record["publication"]=client.publish(f"{kind}:{c['github']['repository_id']}:{core['period_start']}",ident,
                                             f"[CES {labels}] {core['period_start']} 起",record["core"]["markdown"],recipients)
    w.save(dest,record)
    w.save(Path(c["output_root"])/"notifications"/(kind+"-latest.json"),dict(path=str(dest),publication=record["publication"],source_code_reads=0,ces_analysis_actions=0))
    return dict(status="report_generated",kind=kind,path=str(dest),id=ident,input_path=str(cache/(kind+"-"+context["period_start"]+".json")),
                input_binding_sha256=context["input_binding_sha256"],source_reports=len(context["children"]),daily_records=len(records),
                commits=len(context["commits"]),missing_days=len(context["missing_dates"]),synthesis_mode=record["core"]["synthesis_mode"],
                source_code_reads=0,ces_analysis_actions=0,publication=record["publication"])
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("kind",choices=list(LABEL));p.add_argument("--config",required=True);p.add_argument("--as-of");p.add_argument("--analysis");p.add_argument("--execute",action="store_true")
    a=p.parse_args();result=build(w.config(a.config),a.kind,a.as_of,a.execute,a.analysis)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=="__main__":main()

