"""Cumulative published knowledge sources; batches do not erase older coverage."""
from __future__ import annotations
from datetime import datetime,timezone
from pathlib import Path
import re
import ces_workflow as w

def load(home,repository_id):
    home=Path(home);paths=list((home/'versions').glob('*.json'))
    if (home/'current.json').is_file():paths.append(home/'current.json')
    rows={};warnings=[]
    for path in sorted(paths,key=lambda p:(p.name=='current.json',str(p))):
        try:
            w.need(not path.is_symlink() and not (hasattr(path,'is_junction') and path.is_junction()),'unsafe_record')
            row=w.load(path)
            w.need(row.get('schema')=='ces.knowledge_docset.v1' and row.get('repository_written') is True,'not_published_record')
            if row.get('repository_id',repository_id)!=repository_id:continue
            stamp=datetime.fromisoformat(row['generated_at'])
            w.need(stamp.tzinfo is not None,'timestamp_timezone_required')
            w.need(isinstance(row.get('sources'),list),'sources_required')
            w.need(isinstance(row.get('snapshot_id'),str) and row['snapshot_id'],'snapshot_id_required')
            for source in row['sources']:
                w.need(isinstance(source.get('path'),str) and isinstance(source.get('content_sha256'),str) and re.fullmatch('[0-9a-f]{64}',source['content_sha256']),'invalid_source')
            w.need(row.get('chapter_sources') is None or isinstance(row['chapter_sources'],dict),'invalid_chapter_bindings')
            w.need(isinstance(row.get('documents',[]),list) and all(isinstance(x,dict) and isinstance(x.get('relative_path',''),str) for x in row.get('documents',[])),'invalid_documents')
            if row['snapshot_id'] in rows and rows[row['snapshot_id']][1]!=row:
                warnings.append(dict(record=path.name,reason='conflicting_knowledge_snapshot_retained'));continue
            rows[row['snapshot_id']]=(stamp.astimezone(timezone.utc),row)
        except (ValueError,KeyError,TypeError,AttributeError,RuntimeError,OSError):
            warnings.append(dict(record=path.name,reason='unusable_knowledge_history_retained'))
    sources={};chapters={}
    for _,row in sorted(rows.values(),key=lambda pair:(pair[0],pair[1]['snapshot_id'])):
        observed={s['path']:s['content_sha256'] for s in row['sources']}
        sources.update(observed)
        specific=row.get('chapter_sources')
        if specific is not None:
            for name,bindings in specific.items():
                if not isinstance(name,str) or not isinstance(bindings,dict) or not bindings or not set(bindings)<=set(observed) or any(observed[p]!=h for p,h in bindings.items()):
                    warnings.append(dict(record=row['snapshot_id'],reason='unusable_chapter_bindings_retained'));continue
                chapters[name]=dict(sources=bindings,snapshot_id=row['snapshot_id'],binding_kind='chapter_citations')
        else:
            for doc in row.get('documents',[]):
                name=doc.get('relative_path','')
                if name.startswith('knowledge/') and name.endswith('.md') and name!='knowledge/README.md':
                    chapters[name.removeprefix('knowledge/')]=dict(sources=observed,snapshot_id=row['snapshot_id'],binding_kind='legacy_batch_scope')
    return dict(schema='ces.knowledge_inventory.v1',repository_id=repository_id,sources=sources,chapters=chapters,
                snapshots=len(rows),warnings=warnings,scope='published source observations; not proof of semantic or whole-repository coverage')

def stale(inventory,current):
    result=[]
    for name,row in sorted(inventory['chapters'].items()):
        changed=[path for path,digest in row['sources'].items() if path in current and current[path]!=digest]
        if changed:result.append(dict(path=name,changed_sources=sorted(changed),binding_kind=row['binding_kind'],snapshot_id=row['snapshot_id']))
    return result
