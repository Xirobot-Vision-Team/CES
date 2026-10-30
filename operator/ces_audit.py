"""Exclude verified CES document publications from work audits, preserving human/mixed commits."""
from pathlib import Path
import argparse,copy,json,re
from datetime import datetime
import ces_workflow as w
import ces_documents as docs

def enabled(c):return c.get('audit',{}).get('exclude_ces_generated_documents',False) is True
def receipt_root(c):return Path(c.get('cache_root',c['state_root']))/'lifecycle/publications'
def classify(c,sha):
    if not enabled(c):return None
    w.need(re.fullmatch(r'[0-9a-f]{40}',sha or '') is not None,'AUDIT_COMMIT_INVALID')
    raw=w.git(c,'show','-s','--format=%P%n%B',sha);parent,_,message=raw.partition('\n')
    if re.fullmatch(r'[0-9a-f]{40}',parent) is None:return None # Keep merges and root commits.
    proof=None;path=receipt_root(c)/(sha+'.json')
    receipt=w.load(path) if path.is_file() else None
    if receipt and receipt.get('schema')=='ces.document_git_publish.v1' and receipt.get('repository_id')==c['github']['repository_id'] and receipt.get('commit')==sha and receipt.get('parent')==parent and receipt.get('status') in ('pushed_remote_verified','published_and_local_branch_synchronized'):
        proof='verified_publication_receipt'
    trailers=dict(re.findall(r'^(CES-Generated-By|CES-Repository-Id): ([^\r\n]+)$',message,re.M))
    if proof is None and trailers=={'CES-Generated-By':'CES','CES-Repository-Id':str(c['github']['repository_id'])}:proof='ces_commit_trailers'
    if proof is None:return None
    prefix=docs.relative(c.get('repository_docs',{}).get('relative_directory','docs/ces')).as_posix()
    changed=[x for x in w.git(c,'diff','--name-only','-z',parent,sha,'--').split('\0') if x]
    if not changed:return None
    external=[name for name in changed if not name.startswith(prefix+'/')]
    manifest_name=prefix+'/.ces-documents.json'
    manifest=json.loads(w.git(c,'show',sha+':'+manifest_name))
    if manifest.get('schema')!='ces.repository_documents.v1' or manifest.get('repository_id')!=c['github']['repository_id']:return None
    owned={prefix+'/'+docs.relative(name).as_posix() for name in manifest['files']}|{manifest_name}
    if external:
        import ces_readmes
        if prefix+'/'+ces_readmes.MANIFEST not in owned:return None
        if docs.text_hash(ces_readmes.blob(c,sha,prefix+'/'+ces_readmes.MANIFEST))!=manifest['files'][ces_readmes.MANIFEST]['sha256']:return None
        owned|=ces_readmes.audit_paths(c,sha,parent,external,prefix)
    if not set(changed)<=owned:return None
    if proof=='verified_publication_receipt' and set(receipt.get('paths',[]))!=set(changed):return None
    return dict(sha=sha,reason='ces_generated_managed_documents',proof=proof,paths=sorted(changed))

def filter_commits(c,rows,cache=None):
    if not enabled(c):return list(rows),[],[]
    cache={} if cache is None else cache;kept=[];excluded=[];warnings=[]
    for row in rows:
        sha=row['sha']
        try:
            if sha not in cache:cache[sha]=classify(c,sha)
            evidence=cache[sha]
        except Exception as exc:
            # Unavailable or inconsistent evidence must never silently hide a commit.
            evidence=None;warnings.append(dict(sha=sha,status='kept_unverified',error_type=type(exc).__name__))
        if evidence:excluded.append({**evidence,'subject':row.get('subject','')})
        else:kept.append(row)
    return kept,excluded,warnings

def normalize_daily(c,core,cache=None):
    row=copy.deepcopy(core);commits,excluded,warnings=filter_commits(c,row['commits'],cache)
    if not enabled(c):return row
    excluded_by_sha={x['sha']:x for x in row.get('excluded_maintenance_commits',[])}
    excluded_by_sha.update({x['sha']:x for x in excluded})
    removed=set(excluded_by_sha)
    row['commits']=commits
    row['findings']=[f for f in row.get('findings',[]) if not (f.get('origins') and all(o.get('commit') in removed for o in f['origins']))]
    row['excluded_maintenance_commits']=sorted(excluded_by_sha.values(),key=lambda x:x['sha'])
    row['audit_policy']='exclude_verified_ces_document_publications_v1'
    row['audit_filter_warnings']=warnings
    # This is a derived view; original report records/hashes remain immutable.
    row['audit_projection']=dict(source_report_id=core['id'],effective_commit_count=len(commits))
    return row

def lines(excluded,warnings=()):
    if not excluded and not warnings:return []
    result=['','## 审计排除项','',f'- 已排除{len(excluded)}次可核验的CES自动托管文档提交；不计工作提交、代码变更或新增问题。']
    for x in excluded[:10]:result.append('- '+x['sha'][:12]+'：'+w.md(x.get('subject',''))+'；'+x['proof']+'。')
    if len(excluded)>10:result.append('- 其余排除项保留在结构化审计输入中。')
    if warnings:result.append(f'- {len(warnings)}次提交的排除证据核验失败，保留在有效列表，不据此隐藏。')
    return result

def daily_markdown(c,core):
    if not enabled(c):return core['markdown']
    row=normalize_daily(c,core)
    if not row.get('excluded_maintenance_commits'):return core['markdown']
    result=['# 日报 · '+row['date']+' · 审计口径修正','',f"有效工作提交：{len(row['commits'])} 条。CES自动文档维护提交不计工作量。",'']
    for x in row['commits']:result.append('- ['+x['sha'][:12]+'](https://github.com/'+c['github']['repository']+'/commit/'+x['sha']+') '+w.md(x.get('subject','')))
    if not row['commits']:result.append('本报告范围内无有效工作提交；保留构建与已有问题状态，不把自动文档更新归为个人工作。')
    result+=['','## 已有代码分析资料','']
    for f in row.get('findings',[]):result+=['- '+f['title']+'：'+f.get('reasoning',''),'  建议：'+f.get('recommendation','')]
    if not row.get('findings'):result.append('- 无新增、可归属的有效工作Finding。')
    build=row.get('preanalysis_build',{}).get('build')
    if build:
        import ces_lifecycle
        result+=['','## 构建状态（不计提交工作量）','']+ces_lifecycle.build_lines(c,receipt=build)
    import ces_tracking
    result+=ces_tracking.report_lines(row.get('issue_tracking'))
    result+=lines(row['excluded_maintenance_commits'],row.get('audit_filter_warnings',[]))
    result+=['','## 来源与限制','', '- 原始归档ID：'+core['id']+'；保留原始归档，仅修正审计投影。',
             '- 统计区间：'+str(core.get('period_start',core['date']))+' 至 '+str(core.get('period_end',core['date']))+'。',
             '- 本修正不执行新的业务代码分析或运行测试，不使用旧文字中已排除的提交数量。']
    return '\n'.join(result)+'\n'

def period_markdown(c,core):
    if not enabled(c) or core.get('audit_policy')=='exclude_verified_ces_document_publications_v1':return core['markdown']
    rows=[normalize_daily(c,x) for x in core.get('daily_records',[])]
    excluded={x['sha']:x for row in rows for x in row.get('excluded_maintenance_commits',[])}
    if not excluded:return core['markdown']
    commits={x['sha']:x for row in rows for x in row['commits']}
    findings={f.get('issue_url') or w.sha(str(f)):f for row in rows for f in row.get('findings',[])}
    result=['# 周期报告 · 审计口径修正','',core['kind']+'：'+core['period_start']+' 至 '+core.get('period_end',''),'',
            f'有效工作提交：{len(commits)}；去重问题/建议：{len(findings)}。','',
            '原始报告归档保留。本投影仅更新CES自动文档提交排除口径，不冒称新的AI综合分析。','']
    for row in sorted(commits.values(),key=lambda x:x['sha']):result.append('- '+row['sha'][:12]+' '+w.md(row.get('subject','')))
    for f in findings.values():result+=['- '+f['title']+'：'+f.get('reasoning',''),'  建议：'+f.get('recommendation','')]
    result+=lines(sorted(excluded.values(),key=lambda x:x['sha']))
    result+=['','来源归档ID：'+core['id']+'。缺报日期和原始来源限制继续保留，缺报不表示没有工作。']
    return '\n'.join(result)+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True)
    args=p.parse_args();c=w.config(args.config);end=datetime.now(w.offset(c));start=end.replace(hour=0,minute=0,second=0,microsecond=0)
    kept,excluded,warnings=w.activity(c,start,end,True)
    print(json.dumps(dict(status='work_audit_ready',start=start.isoformat(),end=end.isoformat(),effective_commits=kept,
                         excluded_maintenance_commits=excluded,warnings=warnings,read_only=True),ensure_ascii=False,indent=2))

if __name__=='__main__':main()
