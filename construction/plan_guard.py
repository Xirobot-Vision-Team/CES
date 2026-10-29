#!/usr/bin/env python3
"""Static CES replan gate. Checks plan/provenance only; NEVER runs native CES tests."""
from __future__ import annotations
import json
from pathlib import Path
import re
import hashlib
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent

def jread(p):
    return json.loads(p.read_text(encoding='utf-8'))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def check_plan(plan, progress, active):
    errors=[]
    rounds=plan.get('rounds',[])
    if len(rounds)!=100: errors.append(f'expected 100 rounds, got {len(rounds)}')
    if len(plan.get('phases',[]))!=10: errors.append('expected 10 phases')
    phase_ids=[p['id'] for p in plan.get('phases',[])]
    if len(set(phase_ids))!=len(phase_ids): errors.append('duplicate phase IDs')
    seen= set()
    valid={'PLANNED','BLOCKED','IMPLEMENTED_PENDING_FINAL_ACCEPTANCE'}
    for i,rd in enumerate(rounds):
        n=151+i; label=f'EC-{n:03}'
        if rd.get('round')!=n or rd.get('ec')!=label: errors.append(f'bad round sequence at index {i}')
        if rd.get('phase') != 'ABCDEFGHIJ'[i//10]: errors.append(f'wrong phase for {label}')
        if rd.get('status') not in valid: errors.append(f'bad status for {label}')
        if not all(str(rd.get(x,'')).strip() for x in ('title','scope','exit_gate')): errors.append(f'incomplete plan entry {label}')
        if label in seen: errors.append(f'duplicate {label}')
        seen.add(label)
        deps=rd.get('depends_on',[])
        if not deps: errors.append(f'missing dependencies in {label}')
        for dep in deps:
            m=re.fullmatch(r'EC-(\d{3})(?: .*\))?',str(dep))
            if m and int(m.group(1))>=n: errors.append(f'forward dependency in {label}: {dep}')
        if n>151 and f'EC-{n-1:03}' not in deps: errors.append(f'{label} misses previous-round dependency')
    for p in plan.get('phases',[]):
        if p.get('count')!=10: errors.append('bad phase count')
    if progress.get('plan_revision')!=plan.get('plan_revision'): errors.append('plan revision mismatch')
    if active.get('next_ec')!=progress.get('next_ec'): errors.append('active next_ec mismatch')
    if active.get('completed_ec')!=progress.get('last_completed_ec'):
        errors.append('active completed_ec mismatch with progress')
    if progress.get('last_completed_ec')=='EC-150' and (active.get('version')!='V4.60' or active.get('build')!='R150'):
        errors.append('planning-only revision must not bump R150 release')
    try:
        last=int(progress['last_completed_ec'].removeprefix('EC-'))
        nxt=int(progress['next_ec'].removeprefix('EC-'))
        if nxt!=last+1: errors.append('noncontiguous progress last/next')
        if not 150<=last<=250: errors.append('last_completed out of range')
        if progress.get('completed_replan_rounds')!=last-150: errors.append('completed_replan_rounds mismatches progress')
        for rd in rounds:
            if rd['round']<=last and rd['status']!='IMPLEMENTED_PENDING_FINAL_ACCEPTANCE': errors.append(f'completed {rd["ec"]} not marked implemented')
            if rd['round']>last and rd['status']=='IMPLEMENTED_PENDING_FINAL_ACCEPTANCE': errors.append(f'future {rd["ec"]} marked implemented')
        if nxt==251 and progress.get('final_acceptance')=='NOT_STARTED':
            # Legal state: EC250 completed, user has not yet begun acceptance.
            pass
    except (ValueError, KeyError, TypeError) as exc: errors.append(f'invalid progress: {exc}')
    return errors

def check_history(root):
    errors=[]
    m=jread(root/'construction/LEGACY_RELOCATIONS.json')
    mapping=m.get('relocations',[])
    if len(mapping)!=156: errors.append(f'expected 156 archived items, got {len(mapping)}')
    old_ec=[r for r in mapping if re.fullmatch(r'EC-\d{3}\.md',r.get('from',''))]
    if len(old_ec)!=149: errors.append('expected original 149 EC records')
    for r in mapping:
        p=root/r['to']
        if not p.is_file(): errors.append(f'missing archived file {r["to"]}')
        elif p.stat().st_size!=r['bytes'] or sha(p)!=r['sha256']:
            errors.append(f'archived content changed: {r["to"]}')
        # Activity entrypoints are intentionally replaced after old bytes were archived.
        if r['from'].startswith('EC-') and (root/r['from']).exists():
            errors.append(f'old EC log still in active root {r["from"]}')
    if (root/'history/legacy-rounds/EC-001.md').exists(): errors.append('EC-001 was not in original; cannot synthesize')
    return errors

def check_structure(root):
    errors=[]
    required=['SKILL.md','README.md','BUILD_STATE.json','CHANGELOG.md','agents/openai.yaml','construction/LEGACY_PLAN.json','construction/NEXT_ROUND.md','construction/ROUND_TEMPLATE.md','construction/CAPABILITY_MATRIX.json','construction/TRACEABILITY.md','construction/DEVIATION_AUDIT.md','construction/LEGACY_PROJECT_STATE.json','construction/SOURCE_BASELINE.json','references/non-code-edit-policy.md','scripts/ces.ps1']
    for path in required:
        if not (root/path).is_file(): errors.append(f'missing {path}')
    scripts=list((root/'scripts').glob('*.ps1'))
    tests=list((root/'tests').glob('*.Smoke.ps1'))
    if len(scripts)<124: errors.append(f'original PowerShell modules missing: {len(scripts)}')
    if len(tests)<15: errors.append(f'original Smoke scripts missing: {len(tests)}')
    source=(root/'scripts/ces.ps1')
    if source.exists():
        text=source.read_text(encoding='utf-8-sig')
        mods=re.findall(r"Join-Path\s+\$PSScriptRoot\s+'([^']+\.ps1)'",text)
        for name in mods:
            if not (root/'scripts'/name).is_file(): errors.append('broken module import '+name)
        if len(set(mods))!=len(mods): errors.append('repeated module import')
        if 'NOT_IMPLEMENTED' not in text: errors.append('missing unimplemented-action safety gate')
    front=(root/'SKILL.md').read_text(encoding='utf-8')
    if not front.startswith('---\n') or 'name: ces' not in front[:80]: errors.append('bad SKILL.md frontmatter')
    if 'EC-151' not in front or 'EC-250' not in front: errors.append('SKILL.md lacks active 100-round routing')
    for p in [root/'SKILL.md',root/'README.md',root/'CHANGELOG.md']+sorted((root/'references').glob('*.md'))+sorted((root/'construction').glob('*.md')):
        content=p.read_text(encoding='utf-8')
        for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',content):
            link=link.strip().split('#',1)[0].strip('<>')
            if not link or re.match(r'^(?:https?:|mailto:|data:)',link,re.I): continue
            if not (p.parent/link).exists(): errors.append(f'dead markdown link: {p.relative_to(root)} -> {link}')
    # Plan-ready capability count remains grounded in existing CLI Action set.
    caps=jread(root/'construction/CAPABILITY_MATRIX.json')['actions']
    names=[c['name'] for c in caps]
    if len(names)!=len(set(names)): errors.append('duplicate capability matrix entries')
    allowed_caps={'IMPLEMENTED_UNVERIFIED','IMPLEMENTED_PENDING_FINAL_ACCEPTANCE','NOT_IMPLEMENTED','BLOCKED'}
    for c in caps:
        if c.get('status') not in allowed_caps: errors.append('invalid capability status for '+c['name'])
    progress=jread(root/'construction/LEGACY_PROJECT_STATE.json')
    active=jread(root/'BUILD_STATE.json')
    last=int(progress['last_completed_ec'].removeprefix('EC-'))
    if last==150 and sum(c['status']=='IMPLEMENTED_UNVERIFIED' for c in caps)!=8:
        # 7 action families, with Collect split into two mode entries.
        errors.append('unexpected baseline mode-level action count in matrix')
    if last>=250 or progress.get('final_acceptance')!='NOT_STARTED':
        missing=[c['name'] for c in caps if c['status'] in ('NOT_IMPLEMENTED','BLOCKED')]
        if missing: errors.append('cannot claim full feature-completion/acceptance: '+', '.join(missing))
    plan=jread(root/'construction/LEGACY_PLAN.json')
    for rd in plan['rounds']:
        ec=rd['ec']
        ecfile=root/f'{ec}.md'
        if rd['status']=='IMPLEMENTED_PENDING_FINAL_ACCEPTANCE' and not ecfile.is_file():
            errors.append('missing completed round report '+ec)
    current_ec_files=list(root.glob('EC-*.md'))
    plan_ids={x['ec'] for x in plan['rounds']}
    for ecfile in current_ec_files:
        if ecfile.stem not in plan_ids: errors.append('unplanned EC file in active root '+ecfile.name)
    baseline=set(jread(root/'construction/SOURCE_BASELINE.json')['fingerprints'])
    newly_added=[p for p in (root/'scripts').glob('codeprofileretentionendpoint*interaction.ps1') if str(p.relative_to(root)) not in baseline]
    if newly_added and active.get('advanced_codesequence_scope_override')!='EXPLICIT_USER_APPROVAL':
        errors.append('unapproved CodeShow k-extension/source: '+', '.join(p.name for p in newly_added))
    return errors

def main(root=ROOT):
    active=jread(root/'BUILD_STATE.json')
    plan=jread(root/'construction/LEGACY_PLAN.json')
    progress=jread(root/'construction/LEGACY_PROJECT_STATE.json')
    errors=check_plan(plan,progress,active)+check_history(root)+check_structure(root)
    if errors:
        print('PLAN GUARD FAILED',len(errors))
        for e in errors[:100]: print(' -',e)
        return 1
    print(f'PLAN GUARD PASS: 100 EC slots (151..250), 10 phases, no gaps; progress {progress["last_completed_ec"]} -> {progress["next_ec"]}')
    print('ARCHIVE PASS: 156 original documents byte-preserved (149 EC logs + 7 oversized docs)')
    print('SOURCE STRUCTURE PASS: 124 original PS modules and 15 original Smoke suites present; imports/link references consistent')
    print('IMPORTANT: This is only a planning/provenance STATIC gate; no pwsh CLI, Smoke, Windows/Git, or performance acceptance ran.')
    return 0

if __name__=='__main__':
    sys.exit(main())
