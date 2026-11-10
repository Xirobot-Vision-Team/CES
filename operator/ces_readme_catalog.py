"""Persistent README sections: repository inventory and project interface catalogs."""
from __future__ import annotations
import copy,re
import ces_workflow as w

CONTRACT='ces.readme_catalog.v1'
REQUIRED={
    'repository':('overview','components','build','usage','navigation'),
    'solution':('overview','components','build','usage'),
    'project':('overview','interfaces','usage','dependencies'),
}
JOURNAL=re.compile(r'本轮|本次|今日|昨日|本日|当日|用户更新|进一步更新|(?:日报|周总结|月总结)|^#{1,6}\s*\d{4}[-/]\d{1,2}[-/]\d{1,2}',re.M)

def contract(roles):
    return dict(schema=CONTRACT,required_sections=list(dict.fromkeys(k for role in roles for k in REQUIRED[role])),
                update_mode='merge_stable_sections',style='current reference documentation; no period narrative',
                interfaces='named signatures, purpose, parameters, returns and errors with source citations')

def text(value,reason,minimum=1):
    w.need(isinstance(value,str) and len(value.strip())>=minimum,reason);return value

def semantic(value):
    if isinstance(value,dict):return {k:semantic(v) for k,v in value.items() if k!='source_revision'}
    if isinstance(value,list):return [semantic(v) for v in value]
    return value

def merge(entry,item,owned):
    """Validate an incoming patch and retain every unmentioned section and citation."""
    previous=(owned or {}).get('sections',[])
    if not previous:
        text(entry.get('migration_reason'),'README_CATALOG_INITIAL_REVIEW_REQUIRED',20)
    patches=entry.get('sections')
    w.need(isinstance(patches,list) and 1<=len(patches)<=128,'README_CATALOG_SECTIONS_REQUIRED')
    order=[s['id'] for s in previous];sections={s['id']:copy.deepcopy(s) for s in previous};seen=set()
    for patch in patches:
        ident=patch.get('id')
        w.need(isinstance(ident,str) and re.fullmatch(r'[a-z][a-z0-9-]{0,79}',ident) and ident not in seen,'README_SECTION_ID_INVALID')
        seen.add(ident);action=patch.get('action','update')
        w.need(action in ('update','unchanged','remove'),'README_SECTION_ACTION_INVALID')
        if action=='unchanged':
            w.need(ident in sections,'README_SECTION_NOT_FOUND');continue
        if action=='remove':
            w.need(ident in sections,'README_SECTION_NOT_FOUND')
            text(patch.get('reasoning'),'README_SECTION_REMOVAL_REASON_REQUIRED',20)
            w.need(patch.get('citations'),'README_SECTION_REMOVAL_EVIDENCE_REQUIRED')
            del sections[ident];order.remove(ident);continue
        row={k:copy.deepcopy(v) for k,v in patch.items() if k not in ('action','reasoning')}
        text(row.get('title'),'README_SECTION_TITLE_REQUIRED')
        body=text(row.get('markdown'),'README_SECTION_CONTENT_REQUIRED',20)
        w.need(not JOURNAL.search(row['title']+'\n'+body),'README_PERIOD_NARRATIVE_REFUSED')
        w.need(not re.search(r'^#{1,2}\s',body,re.M),'README_SECTION_NESTED_HEADING_REFUSED')
        w.need(isinstance(row.get('citations'),list) and row['citations'],'README_SECTION_CITATIONS_REQUIRED')
        w.need(isinstance(row.get('knowledge_paths',[]),list),'README_SECTION_KNOWLEDGE_PATHS_INVALID')
        if ident=='interfaces':
            entries=row.get('entries')
            w.need(isinstance(entries,list) and entries,'README_INTERFACE_CATALOG_REQUIRED')
            prior_entries=sections.get(ident,{}).get('entries',[])
            api_order=[a['id'] for a in prior_entries];apis={a['id']:copy.deepcopy(a) for a in prior_entries}
            ids=set()
            for api in entries:
                key=text(api.get('id'),'README_INTERFACE_ID_REQUIRED')
                w.need(key not in ids,'README_INTERFACE_DUPLICATE');ids.add(key)
                api_action=api.get('action','update')
                w.need(api_action in ('update','unchanged','remove'),'README_INTERFACE_ACTION_INVALID')
                if api_action=='unchanged':
                    w.need(key in apis,'README_INTERFACE_NOT_FOUND');continue
                if api_action=='remove':
                    w.need(key in apis and api.get('citations'),'README_INTERFACE_REMOVAL_EVIDENCE_REQUIRED')
                    text(api.get('reasoning'),'README_INTERFACE_REMOVAL_REASON_REQUIRED',20)
                    del apis[key];api_order.remove(key);continue
                for field in ('signature','purpose','parameters','returns','errors'):
                    text(api.get(field),'README_INTERFACE_DETAIL_REQUIRED:'+field)
                w.need(api.get('citations'),'README_INTERFACE_CITATION_REQUIRED')
                if key not in apis:api_order.append(key)
                apis[key]={k:copy.deepcopy(v) for k,v in api.items() if k not in ('action','reasoning')}
            w.need(apis,'README_INTERFACE_CATALOG_REQUIRED');row['entries']=[apis[k] for k in api_order]
        if ident not in sections:order.append(ident)
        sections[ident]=row
    required=item['content_contract']['required_sections']
    w.need(set(required)<=set(sections),'README_REQUIRED_SECTION_MISSING')
    if 'components' in required:
        represented=sections['components'].get('descriptor_paths',[])
        actual={x['path'] for x in item.get('component_inventory',[])}
        w.need(isinstance(represented,list) and set(represented)==actual,'README_COMPONENT_INVENTORY_INCOMPLETE')
    # Stable required order; optional extension sections preserve their insertion order.
    order=[*required,*[i for i in order if i not in required]]
    return [sections[i] for i in order]

def render(sections):
    lines=[]
    for s in sections:
        lines+=['## '+s['title'],'',s['markdown'].rstrip(),'']
        for api in s.get('entries',[]):
            lines+=['### '+api['id'],'','```text',api['signature'],'```','',api['purpose'],'',
                    '- 参数：'+api['parameters'],'- 返回与输出：'+api['returns'],'- 错误与边界：'+api['errors'],'']
    return '\n'.join(lines).rstrip()
