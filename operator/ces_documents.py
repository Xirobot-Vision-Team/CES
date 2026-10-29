"""CES repository-owned document publishing with tracked ownership and conflict checks."""
from __future__ import annotations
import json,os,re,hashlib
from pathlib import Path
from datetime import datetime,timezone
import ces_workflow as w

def canonical(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))
def digest(v):return w.sha(canonical(v))
def text_hash(raw):
    return w.sha(raw.decode('utf-8-sig').replace('\r\n','\n').replace('\r','\n'))
def unsafe(p):return p.is_symlink() or (hasattr(p,"is_junction") and p.is_junction())
def relative(value):
    w.need(isinstance(value,str) and value and "\\" not in value and not value.startswith("/") and ":" not in value,"DOC_PATH_INVALID")
    parts=value.split("/")
    w.need(all(re.fullmatch(r"[A-Za-z0-9_\-.\u4e00-\u9fff]+",x) and x not in (".","..",".git") for x in parts),"DOC_PATH_INVALID")
    return Path(*parts)
def root(c):
    repo=Path(c["repository_path"]).resolve()
    rel=relative(c.get("repository_docs",{}).get("relative_directory","docs/ces"))
    dest=repo/rel
    for parent in [dest,*dest.parents]:
        if parent==repo:break
        w.need(not unsafe(parent),"DOC_REPARSE_POINT_REFUSED")
    w.need(dest.resolve().is_relative_to(repo) and dest.resolve()!=repo,"DOC_ROOT_OUTSIDE_REPOSITORY")
    return dest
def publish(c,documents,execute=False):
    dest=root(c)
    w.need(documents and len(documents)<=256,"DOCUMENT_BATCH_LIMIT")
    manifest_path=dest/".ces-documents.json"
    if manifest_path.exists():
        w.need(not unsafe(manifest_path),"DOC_MANIFEST_UNSAFE")
        manifest=w.load(manifest_path)
        w.need(manifest.get("schema")=="ces.repository_documents.v1" and manifest["repository_id"]==c["github"]["repository_id"],"DOC_MANIFEST_REPOSITORY_MISMATCH")
    else:manifest=dict(schema="ces.repository_documents.v1",repository_id=c["github"]["repository_id"],files={})
    plan=[]
    for name,body in documents.items():
        w.need(name not in ('.ces-documents.json','.ces-publish.lock'),'DOC_RESERVED_METADATA_PATH')
        rel=relative(name);target=dest/rel
        w.need(isinstance(body,str) and 0<len(body.encode("utf-8"))<=1024*1024,"DOCUMENT_SIZE_LIMIT")
        for p in [target,*target.parents]:
            if p==dest:break
            w.need(not unsafe(p),"DOC_REPARSE_POINT_REFUSED")
        body=body.replace('\r\n','\n').replace('\r','\n')
        content=body if body.endswith("\n") else body+"\n"
        desired=w.sha(content)
        current=text_hash(target.read_bytes()) if target.is_file() else None
        owned=manifest["files"].get(rel.as_posix())
        if target.exists():
            w.need(target.is_file(),"DOC_TARGET_NOT_REGULAR")
            w.need(owned is not None and owned["sha256"]==current,"DOC_EXTERNALLY_MODIFIED_OR_NOT_OWNED:"+name)
        plan.append(dict(relative_path=rel.as_posix(),target=str(target),prior_sha256=current,sha256=desired,
                         action="unchanged" if current==desired else "create" if current is None else "update",content=content))
    if execute:
        w.need(c.get("repository_docs",{}).get("allow_write") is True,"REPOSITORY_DOC_WRITE_NOT_AUTHORIZED")
        if all(row['action']=='unchanged' for row in plan):
            return dict(status='already_current',root=str(dest),files=[{k:v for k,v in row.items() if k!='content'} for row in plan],git_stage_performed=False,git_commit_performed=False,git_push_performed=False)
        dest.mkdir(parents=True,exist_ok=True)
        lock=dest/".ces-publish.lock"
        fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            os.write(fd,str(os.getpid()).encode());os.close(fd);fd=-1
            # Detect content changes after planning before any writes.
            for row in plan:
                path=Path(row["target"])
                w.need((text_hash(path.read_bytes()) if path.is_file() else None)==row["prior_sha256"],"DOC_CHANGED_AFTER_PLAN")
            for row in plan:
                if row["action"]!="unchanged":
                    path=Path(row["target"]);path.parent.mkdir(parents=True,exist_ok=True)
                    temporary=path.with_name(path.name+".ces-new")
                    with temporary.open("x",encoding="utf-8",newline="") as f:f.write(row["content"]);f.flush();os.fsync(f.fileno())
                    os.replace(temporary,path)
                    manifest["files"][row["relative_path"]]=dict(sha256=row["sha256"],updated_at=datetime.now(timezone.utc).isoformat())
            temp=manifest_path.with_name(".ces-documents.new.json")
            with temp.open("x",encoding="utf-8",newline="") as f:
                json.dump(manifest,f,ensure_ascii=False,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
            os.replace(temp,manifest_path)
        finally:
            if fd!=-1:os.close(fd)
            lock.unlink(missing_ok=True)
    return dict(status="written_to_repository" if execute else "preview",root=str(dest),
                files=[{k:v for k,v in row.items() if k!="content"} for row in plan],
                git_stage_performed=False,git_commit_performed=False,git_push_performed=False,
                transactional_scope="per-file atomic replace with preflight conflict checks; interrupted batch may require repair")
def export_reports(c):
    """Copy only recorded reports, never arbitrary cache files, into repository docs."""
    import ces_audit
    archive=Path(c["output_root"])/"reports"
    docs={}
    for p in sorted(archive.glob("daily/*/*/*.json")):
        data=w.load(p);core=data["core"]
        w.need(data["core_sha256"]==digest(core),"REPORT_CORE_HASH_MISMATCH")
        if core["repository_id"]!=c["github"]["repository_id"]:continue
        name="reports/daily/"+core["date"]+"/"+core["recipient"]+".md"
        old=docs.get(name)
        if old is None or core["generated_at"]>old[0]:docs[name]=(core["generated_at"],ces_audit.daily_markdown(c,core))
    for kind in ("weekly","monthly","yearly"):
        for p in sorted(archive.glob(kind+"/*/*.json")):
            data=w.load(p);core=data["core"]
            if core.get("repository_id")!=c["github"]["repository_id"]:continue
            w.need(data.get("core_sha256")==digest(core),"SUMMARY_HASH_MISMATCH")
            label=core.get("period_start",core.get("week_start"))
            name="reports/"+kind+"/"+label+".md"
            if name not in docs or core["generated_at"]>docs[name][0]:docs[name]=(core["generated_at"],ces_audit.period_markdown(c,core))
    index=["# CES 文档系统","",
           "本目录是仓库内可读成品。缓存、凭据和发送账本在仓库外；提交到Git后可由GitHub供成员与AI查看。","",
           "## 项目知识与技术文档","",
           "- [知识索引](knowledge/README.md)","",
           "## 周期报告",""]
    for name in sorted(docs):index.append("- ["+name.removeprefix("reports/")+"]("+name+")")
    if c.get('testing',{}).get('enabled'):
        import ces_testing
        test_docs=ces_testing.export_reports(c)
        if test_docs:
            index+=['','## 测试审查报告','']
            for name,body in sorted(test_docs.items()):
                docs[name]=('',body);index.append('- ['+name.removeprefix('reports/tests/')+']('+name+')')
    index+=["","报告的代码结论来自已分析证据；周/月/年复用下级报告，不重新扫描全部源码。缺口不等于没有工作。"]
    import ces_tracking
    tracking=ces_tracking.for_report(c)
    if tracking:
        docs['issues/README.md']=('', '\n'.join(['# 当前问题与修复状态']+ces_tracking.report_lines(tracking))+'\n')
        index+=['','## 问题闭环','','- [问题与修复状态](issues/README.md)']
    latest=Path(c['output_root'])/'latest-run.json'
    if latest.exists():
        run=Path(w.load(latest)['run_directory']).resolve()
        w.need(Path(c['output_root']).resolve() in run.parents,'ANALYSIS_RUN_OUTSIDE_OUTPUT_ROOT')
        receipt_path=run/'report-receipt.json'
        if receipt_path.exists():
            receipt=w.load(receipt_path)
            for entry in receipt['reports']:
                path=Path(entry['path']).resolve()
                if path.name=='代码分析报告.md':
                    w.need(run in path.parents and w.sha(path.read_bytes())==entry['sha256'],'ANALYSIS_REPORT_HASH_MISMATCH')
                    docs['analysis/'+receipt['head']+'.md']=('',path.read_text(encoding='utf-8'))
                    index += ['', '## 最近代码分析', '', '- [代码分析报告](analysis/'+receipt['head']+'.md)']
    return {"README.md":"\n".join(index)+"\n",**{name:item[1] for name,item in docs.items()}}

