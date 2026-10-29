"""Unified CES product entry: reports, deep Issues, repository knowledge and account reminders."""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
import ces_workflow as w
import ces_documents as docs
import ces_knowledge as knowledge
import ces_periods as periods
import ces_notifications as notifications

def notify(c,run,execute):
    import ces_reports
    client=ces_reports.Client(c)
    origins=ces_reports.resolve_origins(c,run,client)
    policy={x["title"]:x for x in w.load(run/"issue-proposals.json")}
    items=[]
    for result in w.load(run/"issue-results.json"):
        if result.get("number"):
            people=sorted({x["author_login"] for f in policy[result["title"]]["finding_ids"] for x in origins[f] if x.get("author_login")})
            items.append(dict(number=result["number"],recipients=people,kind="code_issue"))
    daily_path=run/"daily-report-records.json"
    if daily_path.exists():
        for record in w.load(daily_path)["records"]:
            publication=record.get("publication")
            if publication:items.append(dict(number=publication["number"],recipients=[record["recipient"]],kind="daily"))
    for kind in ("weekly","monthly","yearly"):
        path=Path(c["output_root"])/"notifications"/(kind+"-latest.json")
        if path.exists():
            publication=w.load(path).get("publication")
            if not publication:
                published=[]
                for archived in (Path(c['output_root'])/'reports'/kind).glob('*/*.json'):
                    record=w.load(archived)
                    if record.get('publication') and record.get('core',{}).get('repository_id')==c['github']['repository_id']:
                        published.append(record)
                if published:publication=max(published,key=lambda x:x['core']['generated_at'])['publication']
            if publication:items.append(dict(number=publication["number"],recipients=client.maintainers(),kind=kind))
    assignable={x["login"] for x in client.pages(client.prefix+"/assignees")}
    outcomes=[]
    for item in items:
        issue=client.get(client.prefix+f"/issues/{item['number']}")
        w.need("<!-- ces-" in (issue.get("body") or ""),"NOT_CES_OWNED_ISSUE")
        valid=sorted(set(item["recipients"]).intersection(assignable))
        unresolved=sorted(set(item["recipients"])-assignable)
        desired=sorted({x["login"] for x in issue["assignees"]}|set(valid))
        w.need(len(desired)<=10,"GITHUB_ASSIGNEE_LIMIT_REQUIRES_TEAM_ROUTE")
        existing={x["login"] for x in issue["assignees"]}
        status="already_assigned"
        if set(desired)!=existing:
            if execute:issue,status=client.write(client.prefix+f"/issues/{item['number']}",dict(assignees=desired),"PATCH")
            else:status="planned"
        observed_assignees={x['login'] for x in issue['assignees']}
        routing=notifications.route(c,item['recipients'])
        message_bodies=[issue.get('body') or '']
        if routing['cc_recipients']:
            message_bodies += [x.get('body') or '' for x in client.pages(client.prefix+f"/issues/{item['number']}/comments")]
        outcomes.append(dict(kind=item["kind"],number=item["number"],url=issue["html_url"],status=status,**routing,
                             cc_mentions_readback_verified=notifications.mentions_verified(message_bodies,routing['cc_recipients']),
                             assignees=[x["login"] for x in issue["assignees"]],unassignable=unresolved,
                             account_task_links={x:"https://github.com/issues/assigned?q=assignee%3A"+x for x in valid},
                             github_assignee_readback_verified=set(valid)<=observed_assignees,
                             personal_notification_inbox_verified=False,email_delivery_verified=False))
    receipt=dict(schema="ces.account_reminders.v1",delivery_channel="github_account_assignment_and_mentions",items=outcomes,
                 meets_requirement="account-visible assigned tasks and report mentions; not guaranteed personal email or bell delivery",
                 credential_account=client.account_login)
    w.save(Path(c["output_root"])/"notifications/account-reminders.json",receipt)
    return receipt
def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv in (['--version'],['version']):
        product=w.load(Path(__file__).resolve().parent.parent/'PRODUCT.json')
        print(json.dumps(dict(product='CES',operator_version=product['operator_version'],core_protocol_version=product['core_protocol_version'])));return
    if not argv or argv in (['--help'],['-h']):
        print('CES: source-bound repository analysis, reports, GitHub notifications and opt-in tests.\n\nCommands:\n  doctor                 Inspect external project configuration\n  prepare / complete     Collect and validate source-bound analysis\n  issue                  Publish validated, deduplicated code Issues\n  report daily|weekly|monthly|yearly|quality\n  knowledge prepare|publish|status\n  test prepare|register|owners|run|analyze|publish|status\n  track sync|status|history|prepare|review|test|transition\n  lifecycle preflight|pull|build|publish|status\n  audit / documents / notify\n\nUse <command> --help for options; --config always names an external profile.\nExecution/publication require independent authorization. --version shows versions.');return
    if argv and argv[0]=='test':
        import ces_testing
        sys.argv=[sys.argv[0]]+argv[1:];ces_testing.main();return
    if argv and argv[0]=='audit':
        import ces_audit
        sys.argv=[sys.argv[0]]+argv[1:];ces_audit.main();return
    if argv and argv[0]=='lifecycle':
        import ces_lifecycle
        sys.argv=[sys.argv[0]]+argv[1:];ces_lifecycle.main();return
    if argv and argv[0]=='track':
        import ces_tracking
        sys.argv=[sys.argv[0]]+argv[1:];ces_tracking.main();return
    if argv and argv[0] in ("prepare","complete","issue"):
        sys.argv=[sys.argv[0]]+argv;w.main();return
    if argv and argv[0]=="knowledge":
        sys.argv=[sys.argv[0]]+argv[1:];knowledge.main();return
    if argv and argv[0]=="report" and len(argv)>1 and argv[1] in ("weekly","monthly","yearly"):
        if '--config' in argv:
            config_path=argv[argv.index('--config')+1];cfg=w.config(config_path)
            if cfg.get('execution_policy',{}).get('build_before_analysis'):
                import ces_lifecycle
                if '--analysis' in argv:ces_lifecycle.resume_preflight(cfg)
                else:ces_lifecycle.preflight(cfg)
            if cfg.get('issue_tracking',{}).get('enabled'):
                import ces_tracking
                ces_tracking.sync(cfg,'--execute' in argv)
        sys.argv=[sys.argv[0]]+argv[1:];periods.main();return
    if argv and argv[0]=="report":
        import ces_reports
        sys.argv=[sys.argv[0]]+argv[1:];ces_reports.main();return
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="command",required=True)
    doctor=sub.add_parser("doctor");doctor.add_argument("--config",required=True)
    document=sub.add_parser("documents");document.add_argument("--config",required=True);document.add_argument("--execute",action="store_true")
    reminders=sub.add_parser("notify");reminders.add_argument("--config",required=True);reminders.add_argument("--run",required=True);reminders.add_argument("--execute",action="store_true")
    a=p.parse_args(argv);c=w.config(a.config)
    if a.command=="doctor":
        result=dict(product="CES",operator_version="1.8.0",core_protocol_version="1.0.0",
                    pillars=["日周月年总结","代码问题质量与优化分析","仓库知识与技术文档持续维护"],
                    source_repository=c["repository_path"],repository_documents=str(docs.root(c)),
                    reports_cache=str(Path(c["output_root"])/"reports"),knowledge_cache=str(knowledge.cache(c)),
                    notification_channel="GitHub account assigned tasks and mentions",
                    notification_cc_recipients=notifications.configured_cc(c),
                    project_testing=c.get('testing',dict(enabled=False)),
                    issue_tracking_enabled=c.get('issue_tracking',{}).get('enabled',False),
                    personal_email_required=False,automatic_scheduler_enabled=c.get("authorization",{}).get("schedule_enabled",False),
                    git_stage_default=c.get('repository_docs',{}).get('allow_git_stage',False),git_commit_default=c.get('repository_docs',{}).get('allow_git_commit',False),git_push_default=c.get('repository_docs',{}).get('allow_git_push',False),
                    build_before_analysis=c.get('execution_policy',{}).get('build_before_analysis',False),runtime_tests_enabled=c.get('execution_policy',{}).get('run_runtime_tests',False))
    elif a.command=="documents":
        result=docs.publish(c,docs.export_reports(c),a.execute)
        if a.execute:
            import ces_lifecycle
            result['git_publication']=ces_lifecycle.autocommit(c)
    else:
        run=Path(a.run).resolve();w.need(Path(c["output_root"]).resolve() in run.parents,"RUN_OUTSIDE_CONFIGURED_ROOT")
        result=notify(c,run,a.execute)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(json.dumps(dict(status="failed",error_type=type(exc).__name__,reason=str(exc) if isinstance(exc,RuntimeError) else "DETAILS_REDACTED"),ensure_ascii=False));sys.exit(1)

