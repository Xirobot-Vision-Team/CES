"""Bounded, conservative normalization of configured test result protocols."""
import csv,io,json,math,re
import xml.etree.ElementTree as ET

FORMATS={'junit_xml','trx_xml','json','json_lines','csv','console_regex'}
STATUSES={'passed','failed','error','skipped'}
MAX_BYTES=8*1024*1024
MAX_CASES=10000

def need(ok,reason):
    if not ok:raise RuntimeError(reason)

def text(value,limit=12000):return str(value or '')[:limit]

def case(identity,status,message='',seconds=None):
    need(isinstance(identity,str) and 0<len(identity)<=1000,'TEST_CASE_ID_INVALID')
    need(status in STATUSES,'TEST_CASE_STATUS_UNKNOWN')
    if seconds is not None:
        seconds=float(seconds);need(math.isfinite(seconds) and seconds>=0,'TEST_DURATION_INVALID')
    return dict(id=identity,status=status,message=text(message),duration_seconds=seconds)

def field(obj,path,default=None):
    if path=='':return obj
    for name in path.split('.'):
        if not isinstance(obj,dict) or name not in obj:return default
        obj=obj[name]
    return obj

def mapped(rows,mapping):
    need(isinstance(rows,list) and len(rows)<=MAX_CASES,'TEST_CASE_ARRAY_INVALID')
    states=mapping.get('statuses',{x:x for x in STATUSES})
    need(isinstance(states,dict) and set(states.values())<=STATUSES,'TEST_STATUS_MAPPING_INVALID')
    result=[]
    for row in rows:
        need(isinstance(row,dict),'TEST_CASE_OBJECT_REQUIRED')
        raw=field(row,mapping.get('status','status'))
        if type(raw) in (bool,int):raw=json.dumps(raw)
        need(isinstance(raw,str) and raw in states,'TEST_CASE_STATUS_UNKNOWN')
        identity=field(row,mapping.get('id','id'))
        if type(identity) is int:identity=str(identity)
        result.append(case(identity,states[raw],field(row,mapping.get('message','message'),''),field(row,mapping.get('duration','duration_seconds'))))
    return result

def local(tag):return tag.rsplit('}',1)[-1]

def xml(raw):
    need(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),'TEST_XML_DTD_FORBIDDEN')
    class BoundedTree(ET.TreeBuilder):
        def __init__(self):super().__init__();self.depth=0;self.nodes=0
        def doctype(self,*args):raise RuntimeError('TEST_XML_DTD_FORBIDDEN')
        def start(self,tag,attrs):
            self.depth+=1;self.nodes+=1
            need(self.depth<=128 and self.nodes<=100000,'TEST_XML_STRUCTURE_LIMIT')
            return super().start(tag,attrs)
        def end(self,tag):
            value=super().end(tag);self.depth-=1;return value
    return ET.fromstring(raw,parser=ET.XMLParser(target=BoundedTree()))

def junit(raw):
    root=xml(raw);need(local(root.tag) in ('testsuite','testsuites'),'TEST_JUNIT_ROOT_INVALID')
    result=[]
    for item in root.iter():
        if local(item.tag)!='testcase':continue
        need(len(result)<MAX_CASES,'TEST_CASE_LIMIT')
        statuses=[local(x.tag) for x in item if local(x.tag) in ('failure','error','skipped')]
        need(len(statuses)<=1,'TEST_JUNIT_CONFLICTING_OUTCOMES')
        status={'failure':'failed','error':'error','skipped':'skipped'}.get(statuses[0] if statuses else '','passed')
        name=item.get('name');need(bool(name),'TEST_CASE_ID_INVALID')
        identity=(item.get('classname')+'::' if item.get('classname') else '')+name
        message='\n'.join(' '.join((x.get('message',''),x.text or '')) for x in item if local(x.tag) in ('failure','error','skipped'))
        result.append(case(identity,status,message,item.get('time')))
    # Validate declared totals at every suite level, avoiding nested-suite double counting.
    for suite in root.iter():
        if local(suite.tag) not in ('testsuite','testsuites'):continue
        items=[x for x in suite.iter() if local(x.tag)=='testcase']
        totals=dict(tests=len(items),failures=sum(any(local(y.tag)=='failure' for y in x) for x in items),errors=sum(any(local(y.tag)=='error' for y in x) for x in items),skipped=sum(any(local(y.tag)=='skipped' for y in x) for x in items))
        for key,count in totals.items():
            if suite.get(key) is not None:need(int(suite.get(key))==count,'TEST_DECLARED_COUNT_MISMATCH')
    return result

def trx(raw):
    root=xml(raw);need(local(root.tag)=='TestRun','TEST_TRX_ROOT_INVALID')
    states={'Passed':'passed','Failed':'failed','Error':'error','Timeout':'error','Aborted':'error','NotExecuted':'skipped','Inconclusive':'skipped'}
    result=[]
    for item in root.iter():
        if local(item.tag)!='UnitTestResult':continue
        need(len(result)<MAX_CASES,'TEST_CASE_LIMIT')
        status=item.get('outcome');need(status in states,'TEST_CASE_STATUS_UNKNOWN')
        duration=item.get('duration');seconds=None
        if duration:
            match=re.fullmatch(r'(\d+):(\d{2}):(\d{2}(?:\.\d+)?)',duration)
            need(match is not None,'TEST_DURATION_INVALID')
            seconds=int(match[1])*3600+int(match[2])*60+float(match[3])
        result.append(case(item.get('testId') or item.get('testName'),states[status],'\n'.join(x.text or '' for x in item.iter() if local(x.tag) in ('Message','StackTrace')),seconds))
    for counter in root.iter():
        if local(counter.tag)=='Counters':
            for key,count in (('total',len(result)),('passed',sum(x['status']=='passed' for x in result)),('failed',sum(x['status']=='failed' for x in result))):
                if counter.get(key) is not None:need(int(counter.get(key))==count,'TEST_DECLARED_COUNT_MISMATCH')
    return result

def parse(raw,spec):
    need(isinstance(raw,bytes) and len(raw)<=MAX_BYTES,'TEST_RESULT_SIZE_LIMIT')
    fmt=spec['format'];need(fmt in FORMATS,'TEST_FORMAT_UNSUPPORTED')
    mapping=spec.get('mapping',{})
    if fmt=='junit_xml':rows=junit(raw)
    elif fmt=='trx_xml':rows=trx(raw)
    else:
        content=raw.decode('utf-8-sig')
        if fmt=='json':
            data=json.loads(content);rows=mapped(field(data,mapping.get('cases','tests')),mapping)
            if 'total' in mapping:
                declared=field(data,mapping['total'])
                need(type(declared) is int and declared==len(rows),'TEST_DECLARED_COUNT_MISMATCH')
        elif fmt=='json_lines':rows=mapped([json.loads(line) for line in content.splitlines() if line.strip()],mapping)
        elif fmt=='csv':rows=mapped(list(csv.DictReader(io.StringIO(content))),mapping)
        else:
            pattern=spec.get('pattern','');need(0<len(pattern)<=1000,'TEST_CONSOLE_PATTERN_REQUIRED')
            regex=re.compile(pattern);need({'id','status'}<=set(regex.groupindex),'TEST_CONSOLE_GROUPS_REQUIRED')
            matches=[]
            for line in content.splitlines():
                need(len(line)<=65536,'TEST_CONSOLE_LINE_LIMIT')
                match=regex.fullmatch(line)
                if match:matches.append(match.groupdict())
            rows=mapped(matches,mapping)
    need(len(rows)<=MAX_CASES,'TEST_CASE_LIMIT')
    need(len({x['id'] for x in rows})==len(rows),'TEST_DUPLICATE_CASE_ID')
    return rows

def summarize(cases,exit_code,timed_out=False,errors=(),required=(),source_stable=True):
    counts={x:sum(row['status']==x for row in cases) for x in sorted(STATUSES)}
    missing=sorted(set(required)-{x['id'] for x in cases})
    if not source_stable:status='invalidated'
    elif timed_out:status='timed_out'
    elif errors or missing or not cases:status='inconclusive'
    elif counts['failed'] or counts['error']:status='failed'
    elif exit_code!=0:status='execution_error'
    elif not counts['passed']:status='inconclusive'
    else:status='passed'
    return dict(status=status,total=len(cases),counts=counts,missing_required_cases=missing,parse_errors=list(errors),exit_code=exit_code,timed_out=timed_out,source_stable=source_stable)
