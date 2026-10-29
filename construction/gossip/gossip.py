#!/usr/bin/env python3
"""EC354: offline signed cross-log gossip of EC353 *verified originals*.

All historical EC353->EC337 verification is re-executed on every invocation.
Only whole-SHA-pinned, explicitly furnished canonical originals are read;
Ed25519 self-signed actors, asserted UTC and gossip cannot establish real-world
independence, global log visibility or external custody. No writer or network.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from key_registry import registry as reg352
from transparency import transparency as parent353

RESULT_SCHEMA='ces.ec354.offline_signed_cross_log_gossip_unresolved.v1'
DENIAL_SCHEMA='ces.ec354.offline_signed_cross_log_gossip_denial.v1'
HANDOFF_SCHEMA='ces.ec354.unsigned_cross_log_gossip_handoff.v1'
BUNDLE_SCHEMA='ces.ec354.pinned_cross_log_gossip_bundle.v1'
AUDITOR_SCHEMA='ces.ec354.self_signed_external_gossip_auditor_reference.v1'
CHALLENGE_SCHEMA='ces.ec354.signed_gossip_challenge.v1'
REPLY_SCHEMA='ces.ec354.signed_gossip_reply.v1'
AUDITOR_DOMAIN=b'CES/EC354/GossipAuditorReference/v1\x00'
CHALLENGE_DOMAIN=b'CES/EC354/GossipChallenge/v1\x00'
REPLY_DOMAIN=b'CES/EC354/GossipReply/v1\x00'
GENESIS='GENESIS'
MAX_BUNDLE=100_000
MAX_ORIGINAL=12_000
MAX_AUDITORS=4
MAX_CHALLENGES=8
MAX_REPLIES=12
MAX_CHAIN=3
MAX_VALIDITY=timedelta(days=366)
MAX_FRESHNESS=timedelta(days=7)
NONCE_RE=re.compile(r'[0-9a-f]{32}\Z')
ORG_RE=re.compile(r'[A-Za-z0-9][A-Za-z0-9 .,_()&/-]{2,119}\Z')
OUTCOMES=(
    'ec353_parent_signed_transparency_unresolved',
    'ec354_two_independent_gossip_auditor_roles_not_furnished',
    'ec354_reciprocal_two_log_signed_gossip_coverage_incomplete',
    'ec354_signed_challenge_forks_or_responder_equivocation_visible',
    'ec354_verified_same_log_split_view_or_branch_unresolved',
    'ec354_reply_missing_or_signed_unavailable_or_unfurnished_view',
    'ec354_clock_or_organization_independence_claim_unresolved',
    'ec354_matching_offline_gossip_real_external_independence_unproven',
)
NEGATIVES=(
    'self_signed_gossip_auditor_keys_prove_real_outside_organization',
    'two_auditor_names_prove_physical_or_legal_independence',
    'signed_gossip_proves_global_log_head_or_hidden_fork_absence',
    'reply_about_unfurnished_checkpoint_is_a_verified_log_checkpoint',
    'gossip_claimed_utc_is_a_trusted_external_clock',
    'cross_log_matching_roots_mean_different_logs_must_share_a_tree',
    'gossip_repairs_parent_ec353_or_ec352_authority_or_missing_proofs',
    'gossip_issues_private_signatures_or_reads_secret_keys',
    'gossip_fetches_urls_or_writes_provider_cas_worm_remote_storage',
    'ec317_ec318_production_custody_and_final_acceptance_proven',
)


def need(condition,code,status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC354_'+code,status)


def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()


def _sha(v):
    return parent353._sha(v)


def _utc(v):
    return parent353._utc(v)


def _obj(raw,role):
    return parent353.strict_json(raw,'EC354_'+role)


def _fields(doc,keys,role):
    need(type(doc) is dict and set(doc)==keys,role+'_FIELDS_MUST_BE_EXACT')


def _verify(public,doc,field,domain,role):
    signature=doc[field]
    need(type(signature) is str and parent353.SIG_RE.fullmatch(signature) is not None,
         role+'_SIGNATURE_FORMAT')
    need(type(public) is bytes and len(public)==32,role+'_PUBKEY_BYTES')
    body={k:v for k,v in doc.items() if k!=field}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(signature),domain+canonical.canonical(body))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise errors.AnchorError('EC354_'+role+'_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _read_pin(pin,role,pins):
    _fields(pin,{'path','sha256'},role+'_PIN')
    need(type(pin['path']) is str and _sha(pin['sha256']),role+'_PIN_FORMAT')
    need(pin['path'] not in pins,'DUPLICATE_GOSSIP_ORIGINAL_PATH','permission_denied')
    data=tsa._read_pinned(pin['path'],pin['sha256'],
                          MAX_BUNDLE if role=='BUNDLE' else MAX_ORIGINAL,role,{})
    pins[pin['path']]=(pin['sha256'],MAX_BUNDLE if role=='BUNDLE' else MAX_ORIGINAL)
    return data


def _catalog(parent_inputs,parent):
    """Reopen EC353 original bundle after full parent replay; never infer SHAs."""
    pubpath=parent_inputs['publication_bundle_file']
    pubsha=parent_inputs['expected_publication_bundle_sha256']
    raw=tsa._read_pinned(pubpath,pubsha,parent353.MAX_BUNDLE,'EC354_EC353_BUNDLE',{})
    doc=_obj(raw,'PARENT_BUNDLE')
    _fields(doc,{'schema','logs'},'PARENT_BUNDLE')
    need(doc['schema']==parent353.BUNDLE_SCHEMA and type(doc['logs']) is list,
         'PARENT_BUNDLE_SCHEMA')
    excluded=set(reg352._all_parent_files({
        k:v for k,v in parent_inputs.items() if k not in
        ('publication_bundle_file','expected_publication_bundle_sha256','publication_evaluation_utc')}))
    excluded.add(pubpath)
    publication_pins={pubpath:(pubsha,parent353.MAX_BUNDLE)}
    known={};roles=set(parent_inputs['authority_key_shas']+parent_inputs['registry_signer_key_shas']+
                       parent_inputs['registry_root_key_shas'])
    orgs=[]
    for item in doc['logs']:
        _fields(item,{'log_id','log_reference','log_public_key','witness_reference',
                      'witness_public_key','checkpoints','inclusions'},'PARENT_LOG')
        log_id=item['log_id']
        for field in ('log_reference','log_public_key','witness_reference','witness_public_key'):
            pin=item[field]
            _fields(pin,{'path','sha256'},'PARENT_'+field.upper())
            excluded.add(pin['path'])
            publication_pins[pin['path']]=(pin['sha256'],
                32 if field.endswith('_key') else parent353.MAX_REFERENCE)
        roles.update((item['log_public_key']['sha256'],item['witness_public_key']['sha256']))
        for field,org in (('log_reference','claimed_log_organization'),
                          ('witness_reference','claimed_witness_organization')):
            ref=_obj(tsa._read_pinned(item[field]['path'],item[field]['sha256'],
                                      parent353.MAX_REFERENCE,'EC354_'+field,{}),field)
            orgs.append(ref[org])
        for entry in item['checkpoints']:
            for field in ('checkpoint','witness_statement','consistency_proof'):
                pin=entry[field]
                if pin is None:continue
                excluded.add(pin['path'])
                publication_pins[pin['path']]=(pin['sha256'],
                    parent353.MAX_PROOF if field=='consistency_proof' else
                    parent353.MAX_CHECKPOINT if field=='checkpoint' else
                    parent353.MAX_WITNESS)
            pin=entry['checkpoint']
            cp=_obj(tsa._read_pinned(pin['path'],pin['sha256'],
                                    parent353.MAX_CHECKPOINT,'EC354_CP',{}),'CP')
            need(cp['schema']==parent353.CHECKPOINT_SCHEMA and cp['log_id']==log_id,
                 'PARENT_CHECKPOINT_BINDING','permission_denied')
            key=(log_id,pin['sha256'])
            need(key not in known,'DUPLICATE_PARENT_CHECKPOINT')
            known[key]={'log_id':log_id,'checkpoint_sha256':pin['sha256'],
                        'tree_size':cp['tree_size'],
                        'root_hash_sha256':cp['root_hash_sha256'],
                        'previous_checkpoint_sha256':cp['previous_checkpoint_original_sha256'],
                        'checkpoint_claimed_issued_utc':cp['issued_utc'],
                        'log_reference_original_sha256':cp['log_reference_original_sha256']}
        for pin in item['inclusions']:
            excluded.add(pin['path'])
            publication_pins[pin['path']]=(pin['sha256'],parent353.MAX_PROOF)
    # For each checkpoint above, the parent has already verified the exact raw
    # log and witness signatures and merkle proofs; assert no catalog drift.
    for log in parent['log_evidence']:
        from_catalog=sorted(cp_sha for (lid,cp_sha) in known if lid==log['id'])
        need(from_catalog==log['verified_signed_and_witnessed_checkpoint_original_shas'],
             'PARENT_VERIFIED_CHECKPOINT_CATALOG_MISMATCH','permission_denied')
    for p,h in zip(parent_inputs['registry_root_reference_files'],
                   parent_inputs['registry_root_reference_shas'],strict=True):
        doc=_obj(tsa._read_pinned(p,h,reg352.MAX_ROOT_BYTES,'EC354_REGROOT',{}),'REGROOT')
        orgs.append(doc['claimed_issuer_organization'])
    return known,excluded,roles,orgs,publication_pins


def _auditor(raw,key,keypin,refsha,evaluation):
    doc=_obj(raw,'AUDITOR_REF')
    _fields(doc,{'schema','auditor_id','auditor_public_key_original_sha256',
                 'claimed_auditor_organization','claimed_auditor_directory_uri',
                 'valid_from_utc','valid_until_utc','signature_ed25519_hex'},'AUDITOR_REF')
    need(doc['schema']==AUDITOR_SCHEMA and parent353._ident(doc['auditor_id']) and
         doc['auditor_public_key_original_sha256']==keypin and
         type(doc['claimed_auditor_organization']) is str and
         ORG_RE.fullmatch(doc['claimed_auditor_organization']) is not None and
         type(doc['claimed_auditor_directory_uri']) is str and
         reg352.HTTPS_RE.fullmatch(doc['claimed_auditor_directory_uri']) is not None,
         'AUDITOR_REFERENCE_ID_OR_SOURCE_FORMAT','permission_denied')
    frm=_utc(doc['valid_from_utc']);to=_utc(doc['valid_until_utc'])
    need(frm<=evaluation<=to and to>frm and to-frm<=MAX_VALIDITY,
         'AUDITOR_REFERENCE_WINDOW_INVALID','permission_denied')
    _verify(key,doc,'signature_ed25519_hex',AUDITOR_DOMAIN,'AUDITOR_REFERENCE')
    return {'id':doc['auditor_id'],'public_key':key,'key_sha':keypin,'ref_sha':refsha,
            'organization':doc['claimed_auditor_organization'],'from':frm,'until':to}


def _read_challenge(raw,auditors,known,pubsha,evaluation):
    d=_obj(raw,'CHALLENGE')
    _fields(d,{'schema','challenge_id','challenger_auditor_id','responder_auditor_id',
               'challenger_reference_original_sha256','responder_reference_original_sha256',
               'parent_publication_bundle_original_sha256','log_id',
               'log_reference_original_sha256','checkpoint_original_sha256',
               'tree_size','root_hash_sha256','previous_challenge_original_sha256',
               'nonce_hex','issued_utc','signature_ed25519_hex'},'CHALLENGE')
    need(type(d['challenger_auditor_id']) is str and
         type(d['responder_auditor_id']) is str,
         'CHALLENGE_AUDITOR_IDS_MUST_BE_STRINGS')
    origin=auditors.get(d['challenger_auditor_id']);target=auditors.get(d['responder_auditor_id'])
    need(d['schema']==CHALLENGE_SCHEMA and parent353._ident(d['challenge_id']) and
         origin is not None and target is not None and origin is not target and
         d['challenger_reference_original_sha256']==origin['ref_sha'] and
         d['responder_reference_original_sha256']==target['ref_sha'] and
         d['parent_publication_bundle_original_sha256']==pubsha and
         type(d['nonce_hex']) is str and NONCE_RE.fullmatch(d['nonce_hex']) is not None and
         (d['previous_challenge_original_sha256']==GENESIS or
          _sha(d['previous_challenge_original_sha256'])),
         'CHALLENGE_ROLE_PARENT_NONCE_INVALID','permission_denied')
    need(type(d['log_id']) is str and type(d['tree_size']) is int and
         type(d['root_hash_sha256']) is str and
         type(d['checkpoint_original_sha256']) is str,
         'CHALLENGE_CHECKPOINT_TYPES')
    cp=known.get((d['log_id'],d['checkpoint_original_sha256']))
    need(cp is not None and cp['tree_size']==d['tree_size'] and
         cp['root_hash_sha256']==d['root_hash_sha256'] and
         d['log_reference_original_sha256']==cp['log_reference_original_sha256'],
         'CHALLENGE_MUST_BIND_WITNESSED_EC353_CHECKPOINT','permission_denied')
    issued=_utc(d['issued_utc'])
    need(origin['from']<=issued<=origin['until'] and
         target['from']<=issued<=target['until'] and
         _utc(cp['checkpoint_claimed_issued_utc'])<=issued<=evaluation,
         'CHALLENGE_CLAIMED_TIME_INVALID','permission_denied')
    _verify(origin['public_key'],d,'signature_ed25519_hex',CHALLENGE_DOMAIN,'CHALLENGE')
    return d,issued


def _read_reply(raw,challenge,auditors,known,evaluation):
    d=_obj(raw,'REPLY')
    _fields(d,{'schema','challenge_original_sha256','responder_auditor_id',
               'responder_reference_original_sha256','log_id','response_kind',
               'checkpoint_original_sha256','tree_size','root_hash_sha256',
               'responded_utc','signature_ed25519_hex'},'REPLY')
    actor=auditors[challenge['responder_auditor_id']]
    need(d['schema']==REPLY_SCHEMA and
         d['challenge_original_sha256']==challenge['_sha'] and
         d['responder_auditor_id']==actor['id'] and
         d['responder_reference_original_sha256']==actor['ref_sha'] and
         d['log_id']==challenge['log_id'] and
         d['response_kind'] in ('checkpoint_view','unavailable_claim'),
         'REPLY_CHALLENGE_OR_ACTOR_BINDING_INVALID','permission_denied')
    if d['response_kind']=='unavailable_claim':
        need(all(d[k] is None for k in ('checkpoint_original_sha256','tree_size',
                                        'root_hash_sha256')),
             'UNAVAILABLE_CLAIM_MUST_NOT_SMUGGLE_CHECKPOINT')
        state='signed_unavailable_claim'
    else:
        need(_sha(d['checkpoint_original_sha256']) and
             type(d['tree_size']) is int and 1<=d['tree_size']<=parent353.MAX_LOG_LEAVES and
             _sha(d['root_hash_sha256']),
             'REPLY_VIEW_SHA_SIZE_ROOT_INVALID')
        cp=known.get((d['log_id'],d['checkpoint_original_sha256']))
        if cp is None:state='signed_unfurnished_checkpoint_claim'
        else:
            need(cp['tree_size']==d['tree_size'] and
                 cp['root_hash_sha256']==d['root_hash_sha256'],
                 'REPLY_FURNISHED_CHECKPOINT_METADATA_MISMATCH','permission_denied')
            state='verified_ec353_signed_witnessed_checkpoint_view'
    when=_utc(d['responded_utc']);origin=_utc(challenge['issued_utc'])
    need(origin<=when<=evaluation and actor['from']<=when<=actor['until'],
         'REPLY_CLAIMED_TIME_INVALID','permission_denied')
    _verify(actor['public_key'],d,'signature_ed25519_hex',REPLY_DOMAIN,'REPLY')
    return d,when,state


def _same_branch(a,b,known):
    """A *verified* ancestry relationship in the original EC353 checkpoint graph.

    This only speaks to supplied signed predecessors, never a global log head.
    """
    def ancestors(cp):
        seen=set()
        while cp is not None and cp['checkpoint_sha256'] not in seen:
            seen.add(cp['checkpoint_sha256'])
            parent=cp['previous_checkpoint_sha256']
            cp=known.get((cp['log_id'],parent))
        return seen
    return a['checkpoint_sha256'] in ancestors(b) or b['checkpoint_sha256'] in ancestors(a)


def _compare(challenge,reply,known,consistent_log_ids):
    if reply is None:return 'no_signed_reply'
    if reply['response_kind']=='unavailable_claim':return 'signed_unavailable_claim'
    cp=known.get((reply['log_id'],reply['checkpoint_original_sha256']))
    if cp is None:return 'signed_unfurnished_claim_not_verified_log_view'
    origin=known[(challenge['log_id'],challenge['checkpoint_original_sha256'])]
    if cp['tree_size']==origin['tree_size']:
        return ('matching_signed_tree_root' if cp['root_hash_sha256']==origin['root_hash_sha256']
                else 'verified_same_log_same_size_conflicting_roots')
    return ('verified_signed_ancestor_descendant_view' if
            challenge['log_id'] in consistent_log_ids and _same_branch(origin,cp,known)
            else 'two_verified_checkpoint_branches_without_proved_ancestry')


def _run(*,gossip_evaluation_utc:str, gossip_bundle_file:str,
         expected_gossip_bundle_sha256:str, **parent_inputs):
    evaluation=_utc(gossip_evaluation_utc)
    need(evaluation>=_utc(parent_inputs['publication_evaluation_utc']),
         'GOSSIP_EVALUATION_PRECEDES_PARENT','permission_denied')
    parent=parent353.audit(**parent_inputs)  # actual EC353->EC337 raw signed replay
    need(parent.get('parent_actual_signed_originals_replayed') is True and
         parent.get('exit_code')==2,'EC353_REPLAY_REQUIRED','permission_denied')
    known,excluded,roles,organizations,publication_pins=_catalog(parent_inputs,parent)
    consistent_log_ids={log['id'] for log in parent['log_evidence']
                        if not log['split_view'] and not log['append_only_unresolved']}
    need(gossip_bundle_file not in excluded,
         'GOSSIP_BUNDLE_PATH_ALIASES_ANCESTOR','permission_denied')
    pins={};bundle=_obj(_read_pin({'path':gossip_bundle_file,
                                   'sha256':expected_gossip_bundle_sha256},
                                  'BUNDLE',pins),'BUNDLE')
    _fields(bundle,{'schema','auditors','exchanges'},'BUNDLE')
    need(bundle['schema']==BUNDLE_SCHEMA and type(bundle['auditors']) is list and
         0<=len(bundle['auditors'])<=MAX_AUDITORS and
         type(bundle['exchanges']) is list and
         len(bundle['exchanges'])<=MAX_CHALLENGES,
         'BUNDLE_SCHEMA_OR_BOUNDS_INVALID')
    auditors={};reported=[]
    for item in bundle['auditors']:
        _fields(item,{'auditor_id','auditor_reference','auditor_public_key'},
                'AUDITOR_MANIFEST')
        key=_read_pin(item['auditor_public_key'],'AUDITOR_KEY',pins)
        keysha=item['auditor_public_key']['sha256']
        need(len(key)==32 and keysha not in roles,'AUDITOR_KEY_ROLE_REUSE',
             'permission_denied')
        roles.add(keysha)
        refpin=item['auditor_reference']
        doc=_auditor(_read_pin(refpin,'AUDITOR_REFERENCE',pins),key,keysha,
                     refpin['sha256'],evaluation)
        need(item['auditor_id']==doc['id'] and doc['id'] not in auditors,
             'AUDITOR_ID_DUPLICATED_OR_MISMATCHED')
        auditors[doc['id']]=doc
        reported.append({'auditor_id':doc['id'],'key_sha256':keysha,
                         'reference_original_sha256':doc['ref_sha'],
                         'claimed_organization':doc['organization']})
    need(list(auditors)==sorted(auditors),'AUDITOR_IDS_NOT_STRICT_SORTED')
    claims=Counter(name.strip().casefold() for name in
                   [*organizations,*(r['organization'] for r in auditors.values())])
    independent_claims=len(auditors)>=2 and all(
        claims[doc['organization'].strip().casefold()]==1 for doc in auditors.values())
    challenges={};seen_ids=set();seen_nonces=set();seen_reply_shas=set()
    exchanges=[];total_replies=0
    for entry in bundle['exchanges']:
        _fields(entry,{'challenge','replies'},'EXCHANGE_MANIFEST')
        need(type(entry['replies']) is list and len(entry['replies'])<=2,
             'MAX_TWO_SIGNED_REPLIES_PER_CHALLENGE')
        pin=entry['challenge'];raw=_read_pin(pin,'CHALLENGE',pins)
        body,issued=_read_challenge(raw,auditors,known,
                                    parent_inputs['expected_publication_bundle_sha256'],
                                    evaluation)
        chsha=pin['sha256']
        need(body['challenge_id'] not in seen_ids and body['nonce_hex'] not in seen_nonces,
             'CHALLENGE_ID_OR_NONCE_REPLAY','permission_denied')
        seen_ids.add(body['challenge_id']);seen_nonces.add(body['nonce_hex'])
        need(chsha not in challenges,'DUPLICATE_CHALLENGE')
        body['_sha']=chsha
        pair=(body['challenger_auditor_id'],body['responder_auditor_id'],body['log_id'])
        challenges[chsha]={'body':body,'issued':issued,'pair':pair,'reply_shas':[]}
        replies=[]
        for replypin in entry['replies']:
            rraw=_read_pin(replypin,'REPLY',pins)
            need(replypin['sha256'] not in seen_reply_shas,
                 'DUPLICATE_SIGNED_REPLY_ORIGINAL_SHA','permission_denied')
            seen_reply_shas.add(replypin['sha256'])
            rd,when,state=_read_reply(rraw,body,auditors,known,evaluation)
            replies.append({'reply_original_sha256':replypin['sha256'],
                            'view_state':state,'relationship':_compare(
                                body,rd,known,consistent_log_ids),
                            'response_kind':rd['response_kind'],
                            'checkpoint_original_sha256':rd['checkpoint_original_sha256'],
                            'tree_size':rd['tree_size'],
                            'root_hash_sha256':rd['root_hash_sha256'],
                            'responded_utc_claim':rd['responded_utc']})
            challenges[chsha]['reply_shas'].append(replypin['sha256'])
        total_replies+=len(replies)
        exchanges.append({'challenge_original_sha256':chsha,
                          'challenge_id':body['challenge_id'],
                          'challenger_id':pair[0],'responder_id':pair[1],
                          'log_id':pair[2],
                          'challenged_checkpoint_original_sha256':body['checkpoint_original_sha256'],
                          'challenged_tree_size':body['tree_size'],
                          'challenged_root_hash_sha256':body['root_hash_sha256'],
                          'previous_challenge_original_sha256':body['previous_challenge_original_sha256'],
                          'claimed_issued_utc':body['issued_utc'],
                          'replies':replies})
    need(total_replies<=MAX_REPLIES,'TOTAL_REPLY_COUNT_EXCEEDED')
    graph_parents=Counter();chains=defaultdict(list)
    for chsha,c in challenges.items():
        parent_sha=c['body']['previous_challenge_original_sha256']
        if parent_sha!=GENESIS:
            prior=challenges.get(parent_sha)
            need(prior is not None and prior['pair']==c['pair'] and
                 prior['issued']<=c['issued'] and parent_sha!=chsha,
                 'CHALLENGE_PREDECESSOR_SHA_PAIR_OR_TIME_INVALID','permission_denied')
        graph_parents[(c['pair'],parent_sha)]+=1
        chains[c['pair']].append(chsha)
    for chsha,c in challenges.items():
        count=0;seen=set();cur=chsha
        while cur!=GENESIS:
            need(cur in challenges and cur not in seen,'CHALLENGE_HISTORY_CYCLE',
                 'permission_denied')
            seen.add(cur);count+=1
            cur=challenges[cur]['body']['previous_challenge_original_sha256']
        need(count<=MAX_CHAIN,'CHALLENGE_HISTORY_TOO_LONG')
    fork=any(n>1 for n in graph_parents.values())
    reply_conflict=False;view_conflict=False;unavailable=False;stale=False
    full_coverage=set();observers=defaultdict(set)
    # Compare across *all* independent signed observations, not just a single
    # challenge/reply pair. Same-size disagreement within ONE log is distinct
    # from ordinary different roots of TWO different log trees.
    verified_views=defaultdict(list)
    for e in exchanges:
        reps=e['replies']
        verified_views[(e['log_id'],e['challenged_tree_size'])].append(
            (e['challenger_id'],e['challenged_root_hash_sha256'],
             e['challenged_checkpoint_original_sha256']))
        for r in reps:
            if r['view_state']=='verified_ec353_signed_witnessed_checkpoint_view':
                verified_views[(e['log_id'],r['tree_size'])].append(
                    (e['responder_id'],r['root_hash_sha256'],
                     r['checkpoint_original_sha256']))
        if not reps:unavailable=True
        # Multiple valid signatures about incompatible roots, missing original
        # or explicit unavailability are all retained, never last-write-wins.
        if len(reps)==2 and (reps[0]['response_kind'],reps[0]['checkpoint_original_sha256'],
                             reps[0]['tree_size'],reps[0]['root_hash_sha256']) != (
                                 reps[1]['response_kind'],reps[1]['checkpoint_original_sha256'],
                                 reps[1]['tree_size'],reps[1]['root_hash_sha256']):
            reply_conflict=True
        if any(r['relationship'] in ('verified_same_log_same_size_conflicting_roots',
                                    'two_verified_checkpoint_branches_without_proved_ancestry')
               for r in reps):view_conflict=True
        if any(r['relationship'] in ('signed_unavailable_claim',
                                    'signed_unfurnished_claim_not_verified_log_view')
               for r in reps):unavailable=True
        if any(r['relationship'] in ('matching_signed_tree_root',
                                    'verified_signed_ancestor_descendant_view') for r in reps):
            full_coverage.add(e['log_id'])
            observers[e['log_id']].update((e['challenger_id'],e['responder_id']))
        if evaluation-_utc(e['claimed_issued_utc'])>MAX_FRESHNESS or any(
                evaluation-_utc(r['responded_utc_claim'])>MAX_FRESHNESS for r in reps):
            stale=True
    same_size_comparisons=[]
    for (log_id,size),observations in sorted(verified_views.items()):
        actors=sorted({actor for actor,_,_ in observations})
        roots=sorted({root for _,root,_ in observations})
        conflict=len(actors)>=2 and len(roots)>1
        if conflict:view_conflict=True
        same_size_comparisons.append({
            'log_id':log_id,'tree_size':size,'signed_auditor_ids':actors,
            'verified_signed_checkpoint_original_shas':sorted({c for _,_,c in observations}),
            'verified_root_hashes_sha256':roots,
            'comparison':('conflicting_verified_roots' if conflict else
                          'matching_verified_roots' if len(actors)>=2 else
                          'single_auditor_uncompared')})
    need(not set(pins).intersection(excluded),'GOSSIP_PATH_ALIASES_PARENT_OR_PUBLICATION',
         'permission_denied')
    tsa._check_late(pins)  # all EC354 source bytes reread after decisions
    tsa._check_late(publication_pins) # also recheck original EC353 manifest/proofs
    requirements=sorted(l['id'] for l in parent['log_evidence'])
    covered=sorted(log for log in full_coverage if len(observers[log])>=2)
    coverage_complete=len(requirements)==2 and covered==requirements
    parent_good=all(r['outcome']==parent353.OUTCOMES[-1] for r in parent['channel_evidence'])
    if not parent_good:outcome=OUTCOMES[0]
    elif len(auditors)<2:outcome=OUTCOMES[1]
    elif fork or reply_conflict:outcome=OUTCOMES[3]
    elif view_conflict:outcome=OUTCOMES[4]
    elif unavailable:outcome=OUTCOMES[5]
    elif not coverage_complete:outcome=OUTCOMES[2]
    elif stale or not independent_claims:outcome=OUTCOMES[6]
    else:outcome=OUTCOMES[7]
    rows=[{'tsa_channel_id':r['tsa_channel_id'],'parent_ec353_outcome':r['outcome'],
           'outcome':outcome if r['outcome']==parent353.OUTCOMES[-1] else OUTCOMES[0]}
          for r in parent['channel_evidence']]
    counts={k:sum(r['outcome']==k for r in rows) for k in OUTCOMES}
    return {'schema':RESULT_SCHEMA,'command':'audit-cross-log-gossip',
            'status':next(k for k in OUTCOMES if counts[k])+'_unresolved',
            'exit_code':2,'case_id':parent['case_id'],
            'actual_ec353_through_ec337_original_signatures_replayed':True,
            'parent_ec353_canonical_result_sha256':sha(canonical.canonical(parent)),
            'parent_publication_bundle_original_sha256':parent_inputs['expected_publication_bundle_sha256'],
            'gossip_bundle_original_sha256':expected_gossip_bundle_sha256,
            'gossip_evaluation_utc_as_caller_claim':gossip_evaluation_utc,
            'furnished_auditor_count':len(auditors),'auditor_evidence':reported,
            'verified_parent_checkpoint_count':len(known),
            'gossip_exchanges':exchanges,'signed_challenge_count':len(challenges),
            'signed_reply_count':total_replies,
            'covered_log_ids_with_two_signed_actors':covered,
            'required_parent_log_ids':requirements,
            'same_log_same_size_verified_root_comparisons':same_size_comparisons,
            'signed_challenge_fork_visible':fork,
            'signed_responder_equivocation_visible':reply_conflict,
            'verified_same_log_branch_conflict_visible':view_conflict,
            'missing_unavailable_or_unfurnished_replies_visible':unavailable,
            'stale_claimed_gossip_time_visible':stale,
            'claimed_auditor_organization_names_distinct':independent_claims,
            'channel_evidence':rows,'outcome_counts':counts,
            'real_auditor_identity_physical_independence_utc_and_global_heads_unproven':True,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}


def audit(*,gossip_evaluation_utc:str,gossip_bundle_file:str,
          expected_gossip_bundle_sha256:str,**parent_inputs):
    return _run(gossip_evaluation_utc=gossip_evaluation_utc,
                gossip_bundle_file=gossip_bundle_file,
                expected_gossip_bundle_sha256=expected_gossip_bundle_sha256,
                **parent_inputs)


def checklist(**parent_inputs):
    parent=parent353.audit(**parent_inputs)
    known,_,_,_,_=_catalog(parent_inputs,parent)
    return {'schema':HANDOFF_SCHEMA,'command':'derive-gossip-handoff',
            'status':'external_signed_cross_log_gossip_originals_needed',
            'exit_code':2,'case_id':parent['case_id'],
            'actual_ec353_through_ec337_original_signatures_replayed':True,
            'parent_ec353_canonical_result_sha256':sha(canonical.canonical(parent)),
            'parent_publication_bundle_original_sha256':parent_inputs['expected_publication_bundle_sha256'],
            'verified_witnessed_checkpoint_inventory':[known[k] for k in sorted(known)],
            'requires_two_auditor_roles_and_both_log_gossip':True,
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}
