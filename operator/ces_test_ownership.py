"""Explicit function/feature ownership and failure routing; never infer personal fault."""
import fnmatch
import ces_notifications as notifications
import ces_workflow as w

def mappings(value):
    w.need(isinstance(value,list) and len(value)<=256,'TEST_OWNERSHIP_LIST_INVALID')
    output=[];seen=set()
    for row in value:
        w.need(isinstance(row,dict) and set(row)<={'id','kind','name','developers','case_ids','case_patterns','source_paths'},'TEST_OWNERSHIP_FIELDS_INVALID')
        key=row.get('id');name=row.get('name')
        w.need(isinstance(key,str) and 0<len(key)<=200 and not any(ord(x)<32 for x in key) and key not in seen,'TEST_OWNERSHIP_ID_INVALID')
        seen.add(key)
        w.need(row.get('kind') in ('function','feature') and isinstance(name,str) and 0<len(name)<=300,'TEST_OWNERSHIP_SUBJECT_INVALID')
        developers=notifications.unique(row.get('developers',[]));w.need(developers,'TEST_OWNERSHIP_DEVELOPERS_REQUIRED')
        selectors={}
        for field in ('case_ids','case_patterns','source_paths'):
            values=row.get(field,[])
            w.need(isinstance(values,list) and len(values)<=128 and all(isinstance(x,str) and 0<len(x)<=1000 and not any(ord(ch)<32 for ch in x) for x in values),'TEST_OWNERSHIP_SELECTOR_INVALID')
            selectors[field]=sorted(set(values))
        w.need(selectors['case_ids'] or selectors['case_patterns'],'TEST_OWNERSHIP_CASE_MAPPING_REQUIRED')
        for path in selectors['source_paths']:
            w.need(not path.startswith('/') and ':' not in path and '\\' not in path and all(part not in ('','..','.') for part in path.split('/')),'TEST_OWNERSHIP_SOURCE_PATH_INVALID')
        output.append(dict(id=key,kind=row['kind'],name=name,developers=developers,**selectors))
    return sorted(output,key=lambda row:row['id'])

def resolve(normalized,registered):
    selected=mappings(registered);matches=[];unmapped=[];developers={}
    # A changed-source run cannot be used for function-specific attribution.
    if normalized['summary'].get('source_stable') is False:
        return dict(developers=[],matches=[],unmapped_problem_cases=[],status='source_invalidated_no_developer_attribution')
    for case in normalized['cases']:
        if case['status'] not in ('failed','error'):continue
        subjects=[]
        for row in selected:
            exact=case['id'] in row['case_ids']
            patterns=[pattern for pattern in row['case_patterns'] if fnmatch.fnmatchcase(case['id'],pattern)]
            if exact or patterns:
                subjects.append(dict(id=row['id'],kind=row['kind'],name=row['name'],developers=row['developers'],source_paths=row['source_paths'],matched_by='exact_case_id' if exact else 'registered_case_pattern',patterns=patterns))
                for user in row['developers']:developers.setdefault(user.casefold(),user)
        if subjects:matches.append(dict(case_id=case['id'],case_status=case['status'],subjects=subjects))
        else:unmapped.append(case['id'])
    return dict(developers=notifications.unique(list(developers.values())),matches=matches,unmapped_problem_cases=sorted(unmapped),status='explicit_registration_matches',basis='user-registered case-to-function/feature mapping; not root-cause proof or personal responsibility')
