"""Repository-facing, source-bound knowledge documents; no legacy signature claims."""
from __future__ import annotations
import argparse,json,re,os
from pathlib import Path
from datetime import datetime,timezone
import ces_workflow as w
import ces_documents as d

def cache(c):return Path(c.get("cache_root",c["state_root"]))/"knowledge"
def source_path(path):
    # Source names follow Git paths, not the narrower generated-document filename policy.
    w.need(isinstance(path,str) and path and not path.startswith("/") and "\\" not in path and ":" not in path and
           not any(ord(x)<32 or ord(x)==127 for x in path) and
           all(x and x not in (".","..") and x.casefold()!=".git" for x in path.split("/")),"KNOWLEDGE_SOURCE_PATH_INVALID")
    return path
def tracked_source(c,path,head):
    source_path(path)
    names=w.git(c,"ls-files","--",":(literal)"+path).splitlines()
    w.need(names==[path],"KNOWLEDGE_SOURCE_NOT_TRACKED:"+path)
    content=w.git(c,"show",head+":"+path)
    w.need(0<len(content.encode("utf-8"))<=4*1024*1024,"KNOWLEDGE_SOURCE_LIMIT")
    return content
def prepare(c,selected_sources=None):
    cfg=c.get("knowledge",{})
    selected=cfg.get("sources",["README.md"]) if selected_sources is None else selected_sources
    w.need(isinstance(selected,list) and 1<=len(selected)<=64 and all(isinstance(x,str) for x in selected),"KNOWLEDGE_SOURCES_INVALID")
    w.need(len(set(selected))==len(selected),"KNOWLEDGE_SOURCES_INVALID")
    for path in selected:source_path(path)
    head=w.git(c,"rev-parse","HEAD")
    sources=[]
    for path in selected:
        content=tracked_source(c,path,head)
        sources.append(dict(path=path,content_sha256=w.sha(content),line_count=len(content.splitlines())))
    previous_path=cache(c)/"current.json"
    previous=w.load(previous_path) if previous_path.exists() else None
    old_sources={s["path"]:s["content_sha256"] for s in (previous or {}).get("sources",[])}
    changed=[s["path"] for s in sources if old_sources.get(s["path"])!=s["content_sha256"]]
    body=dict(schema="ces.knowledge_input.v1",repository_id=c["github"]["repository_id"],head=head,sources=sources,
              changed_selected_sources=changed,previous_snapshot=(previous or {}).get("snapshot_id"),
              mode="initial" if previous is None else "incremental",
              original_legacy_signed_save_used=False,
              source_scope="tracked immutable HEAD content, explicit configured or per-run source list; not whole repository knowledge")
    import ces_readmes
    body['readme_maintenance']=ces_readmes.discover(c,head,sources)
    body["binding_sha256"]=d.digest(body)
    path=cache(c)/"inputs"/(body["binding_sha256"]+".json")
    w.save(path,body);w.save(cache(c)/"latest-input.json",dict(path=str(path)))
    return dict(status="knowledge_input_ready" if changed else "knowledge_sources_unchanged",input=str(path),head=head,mode=body["mode"],changed_sources=changed,
                readme_maintenance=body['readme_maintenance'],
                next_step="Codex reads sources, old knowledge, and discovered README/descriptors; authors cited chapters and readmes updates or reasoned unchanged decisions. Missing README drafts remain visible gaps.")
def inspect_input(c,path):
    data=w.load(path);binding=data.pop("binding_sha256")
    w.need(data["schema"]=="ces.knowledge_input.v1" and data["repository_id"]==c["github"]["repository_id"] and d.digest(data)==binding,"KNOWLEDGE_INPUT_BINDING_INVALID")
    data["binding_sha256"]=binding
    w.need(w.git(c,"rev-parse","HEAD")==data["head"],"KNOWLEDGE_HEAD_CHANGED")
    return data
def chapter_index(c,chapters):
    """Retain links to untouched managed chapters during a partial knowledge update."""
    dest=d.root(c);manifest=dest/".ces-documents.json";links={}
    if manifest.exists():
        w.need(not d.unsafe(manifest),"DOC_MANIFEST_UNSAFE")
        data=w.load(manifest)
        w.need(data.get("schema")=="ces.repository_documents.v1" and data["repository_id"]==c["github"]["repository_id"],"DOC_MANIFEST_REPOSITORY_MISMATCH")
        for name in data["files"]:
            if name.startswith("knowledge/") and name.endswith(".md") and name!="knowledge/README.md":
                rel=d.relative(name.removeprefix("knowledge/")).as_posix();links[rel]=rel
        old=dest/"knowledge/README.md"
        if old.is_file():
            for p in [old,*old.parents]:
                if p==dest:break
                w.need(not d.unsafe(p),"DOC_REPARSE_POINT_REFUSED")
            owned=data["files"].get("knowledge/README.md")
            w.need(owned and owned["sha256"]==d.text_hash(old.read_bytes()),"DOC_EXTERNALLY_MODIFIED_OR_NOT_OWNED:knowledge/README.md")
            for title,rel in re.findall(r"^- \[([^\]\n]+)\]\(([^)\n]+)\)$",old.read_text(encoding="utf-8-sig"),re.M):
                if rel in links:links[rel]=title
    for chapter in chapters:links[chapter["path"]]=chapter.get("title",chapter["path"])
    return ["- ["+links[rel]+"]("+rel+")" for rel in sorted(links)]
def publish(c,input_path,draft_path,execute=False):
    # Serialize knowledge+README writes without locking ordinary source or touching the user's Git index.
    if not execute:return _publish(c,input_path,draft_path,False)
    lock=cache(c)/'publish.lock';lock.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    try:return _publish(c,input_path,draft_path,True)
    finally:lock.unlink(missing_ok=True)

def _publish(c,input_path,draft_path,execute=False):
    inp=inspect_input(c,input_path);draft=w.load(draft_path)
    w.need(draft.get("schema")=="ces.knowledge_draft.v1" and draft.get("input_binding_sha256")==inp["binding_sha256"],"KNOWLEDGE_DRAFT_SOURCE_MISMATCH")
    chapters=draft.get("chapters",[])
    w.need(isinstance(chapters,list) and 1<=len(chapters)<=32,"KNOWLEDGE_CHAPTER_LIMIT")
    sources={row["path"]:tracked_source(c,row["path"],inp["head"]) for row in inp["sources"]}
    for row in inp["sources"]:w.need(w.sha(sources[row["path"]])==row["content_sha256"],"KNOWLEDGE_SOURCE_DIGEST_MISMATCH")
    documents={};seen=set();citation_count=0
    for chapter in chapters:
        name=chapter["path"];rel=d.relative(name)
        w.need(name.endswith(".md") and name not in seen and name!="README.md","KNOWLEDGE_CHAPTER_PATH_INVALID")
        seen.add(name);body=chapter["markdown"];citations=chapter.get("citations",[])
        w.need(isinstance(body,str) and 50<=len(body.encode("utf-8"))<=256*1024 and citations,"KNOWLEDGE_CHAPTER_EVIDENCE_REQUIRED")
        refs=[]
        for ref in citations:
            path=ref["path"];w.need(path in sources,"KNOWLEDGE_UNAPPROVED_SOURCE")
            lines=sources[path].splitlines();start=ref["line_start"];end=ref["line_end"]
            w.need(type(start) is int and type(end) is int and 1<=start<=end<=len(lines) and end-start<100,"KNOWLEDGE_CITATION_RANGE_INVALID")
            quote=ref.get("quote","")
            w.need(isinstance(quote,str) and quote.strip() and quote in "\n".join(lines[start-1:end]),"KNOWLEDGE_CITATION_NOT_PRESENT")
            refs.append(f"- [{path}:L{start}-L{end}]({w.source_link(c,inp['head'],path)}#L{start}-L{end})")
            citation_count+=1
        front="<!-- CES managed knowledge; do not remove ownership metadata -->\n"
        meta=f"\n\n## 来源与维护\n\n- 源码提交：{inp['head']}\n- 输入绑定：{inp['binding_sha256']}\n- 范围：显式选择的已跟踪来源；不证明全库知识完整或架构语义正确。\n"
        documents["knowledge/"+rel.as_posix()]=front+body.rstrip()+meta+"\n"+"\n".join(refs)+"\n"
    index=["# 项目知识与技术文档","",draft.get("summary","按提交来源维护项目知识，变更后只复核受影响章节。"),"",
           f"本轮维护所选源码基线：{inp['head']}；各章保留自己的来源提交。","",
           "## 章节",""]
    index+=chapter_index(c,chapters)
    index+=["","## 持续维护规则","",
            "- 修改相关源码后，重新核对受影响章节与来源行，保留陈旧或未验证标记。",
            "- 区分源码观察、用户确认和待验证推断；不把AI分析直接当作运行事实。",
            "- 由CES跟踪文件哈希；成员修改过的文档不会被静默覆盖。",
            "- 成品位于仓库，Git提交/推送后在GitHub同步；缓存和版本历史位于仓库外。",
            "- 当前入口是通用操作层，不冒充旧版双签名KnowledgeSave协议。"]
    documents["knowledge/README.md"]="\n".join(index)+"\n"
    import ces_readmes
    readme,readme_manifest=ces_readmes.plan(c,inp,draft)
    if readme_manifest is not None:documents[ces_readmes.MANIFEST]=json.dumps(readme_manifest,ensure_ascii=False,indent=2)+'\n'
    # Validate all document ownership and README plans before the first write.
    d.publish(c,documents,False)
    if execute:
        w.need(not w.git(c,'diff','--cached','--name-only'),'STAGED_CHANGES_BLOCK_KNOWLEDGE_PUBLICATION')
        if c.get('repository_push',{}).get('allow') and c.get('repository_push',{}).get('automatic_after_document_write'):
            import ces_lifecycle
            w.need(w.git(c,'ls-remote','--exit-code','origin','refs/heads/'+ces_lifecycle.branch(c)).split()[0]==inp['head'],'KNOWLEDGE_REMOTE_ADVANCED_REVIEW_REQUIRED')
    w.need(w.git(c,'rev-parse','HEAD')==inp['head'],'KNOWLEDGE_HEAD_CHANGED')
    plan=d.publish(c,documents,execute)
    if execute and readme['updates']:
        w.save(cache(c)/'readme-plans'/(inp['binding_sha256']+'.json'),ces_readmes.summary(readme))
        ces_readmes.apply(c,readme)
    snapshot_id=d.digest(dict(input=inp["binding_sha256"],documents={k:w.sha(v) for k,v in documents.items()}))
    record=dict(schema="ces.knowledge_docset.v1",snapshot_id=snapshot_id,head=inp["head"],sources=inp["sources"],
                generated_at=datetime.now(timezone.utc).isoformat(),draft_sha256=w.sha(Path(draft_path).read_bytes()),
                citation_count=citation_count,documents=plan["files"],readme_maintenance=ces_readmes.summary(readme),repository_written=execute,legacy_signed_save_used=False)
    if execute:
        version_path=cache(c)/'versions'/(snapshot_id+'.json')
        if version_path.exists():
            previous=w.load(version_path)
            w.need(previous['snapshot_id']==snapshot_id and previous['draft_sha256']==record['draft_sha256'] and previous['sources']==record['sources'],'KNOWLEDGE_VERSION_CONFLICT')
            record=previous
        else:w.save(version_path,record)
        w.save(cache(c)/'current.json',record)
    result=dict(status=plan["status"],snapshot_id=snapshot_id,chapters=len(chapters),citations=citation_count,documents=plan["files"],readme_maintenance=ces_readmes.summary(readme))
    if execute:
        import ces_lifecycle
        result['git_publication']=ces_lifecycle.autocommit(c)
    return result
def status(c):
    path=cache(c)/"current.json"
    return dict(deployed=path.exists(),repository_document_root=str(d.root(c)/"knowledge"),cache=str(cache(c)),
                current=w.load(path) if path.exists() else None,legacy_signed_store_separate=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("command",choices=["prepare","publish","status"]);p.add_argument("--config",required=True);p.add_argument("--input");p.add_argument("--draft");p.add_argument("--sources-file",help="prepare only: UTF-8 JSON array of 1-64 tracked source paths for this batch; does not edit the profile");p.add_argument("--execute",action="store_true")
    a=p.parse_args();c=w.config(a.config)
    selected=None
    if a.sources_file:
        w.need(a.command=="prepare","SOURCE_BATCH_ONLY_FOR_PREPARE")
        path=Path(a.sources_file);w.need(path.is_file() and path.stat().st_size<=65536,"KNOWLEDGE_SOURCE_BATCH_FILE_INVALID")
        selected=w.load(path);w.need(isinstance(selected,list),"KNOWLEDGE_SOURCES_INVALID")
    result=prepare(c,selected) if a.command=="prepare" else status(c) if a.command=="status" else publish(c,a.input,a.draft,a.execute)
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=="__main__":main()

