#!/usr/bin/env python3
"""EC355: offline original-byte disclosure of EC354 *signed unfurnished* views.

Every invocation replays EC354->EC353->EC337 signed originals. New requests and
receipts use separately domain-separated Ed25519 signatures by the previously
verified, caller-pinned EC354 auditors. An alleged copy is not a furnished log
view unless its actual SHA-pinned checkpoint AND its separately signed EC353
witness are reopened and cryptographically verified against the same log keys.
No signing keys, URLs, mutable log operations or remote writers are used here.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
import hashlib

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as transparency
from gossip import gossip as gossip

RESULT_SCHEMA = 'ces.ec355.offline_signed_checkpoint_disclosure_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec355.offline_signed_checkpoint_disclosure_denial.v1'
HANDOFF_SCHEMA = 'ces.ec355.unsigned_checkpoint_disclosure_handoff.v1'
BUNDLE_SCHEMA = 'ces.ec355.pinned_checkpoint_disclosure_bundle.v1'
REQUEST_SCHEMA = 'ces.ec355.signed_checkpoint_disclosure_request.v1'
RECEIPT_SCHEMA = 'ces.ec355.signed_checkpoint_disclosure_receipt.v1'
REQUEST_DOMAIN = b'CES/EC355/CheckpointDisclosureRequest/v1\x00'
RECEIPT_DOMAIN = b'CES/EC355/CheckpointDisclosureReceipt/v1\x00'
GENESIS = 'GENESIS'
MAX_BUNDLE = 100_000
MAX_REQUESTS = 24
MAX_RECEIPTS = 36
MAX_ROUNDS = 2
MAX_PER_REQUEST = 2
MAX_OPEN_CLAIMS = 12
MAX_FRESHNESS = timedelta(days=7)
OUTCOMES = (
    'ec355_parent_signed_gossip_or_transparency_coverage_unresolved',
    'ec355_no_signed_unfurnished_view_to_disclose',
    'ec355_two_target_disclosure_request_coverage_incomplete',
    'ec355_signed_request_fork_or_receipt_equivocation_preserved',
    'ec355_no_complete_furnished_checkpoint_witness_originals',
    'ec355_verified_same_log_root_conflict_or_append_only_unproven',
    'ec355_only_one_auditor_has_verified_furnished_originals',
    'ec355_matching_two_signed_original_byte_handoffs_external_custody_unproven',
)
NEGATIVES = (
    'disclosure_creates_a_log_or_witness_signature',
    'disclosure_claimed_copies_prove_physical_separate_custody',
    'two_auditor_signatures_prove_institutional_identity_or_independence',
    'signed_offer_or_unavailable_claim_proves_checkpoint_original_exists',
    'checkpoint_and_witness_signatures_prove_global_head_or_all_hidden_forks',
    'log_signature_without_witness_proves_independent_publication',
    'unsigned_or_wrong_branch_consistency_is_append_only_proof',
    'claimed_disclosure_time_proves_external_utc_or_tsa_qualification',
    'disclosure_repairs_ec354_ec353_or_ec352_earlier_coverage_gaps',
    'disclosure_fetches_remote_urls_or_writes_provider_cas_worm',
    'ec317_ec318_production_and_final_user_acceptance_proven',
)


def need(ok, name, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC355_'+name, status)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _obj(raw, label):
    return transparency.strict_json(raw, 'EC355_'+label)


def _fields(doc, fields, label):
    need(type(doc) is dict and set(doc)==set(fields), label+'_FIELDS_MUST_BE_EXACT')


def _pin(pin, label, cap, pins, oldpaths):
    _fields(pin, ('path', 'sha256'), label+'_PIN')
    need(type(pin['path']) is str and transparency._sha(pin['sha256']),
         label+'_PIN_INVALID')
    path = pin['path']
    need(path not in pins and path not in oldpaths,
         'NEW_ORIGINAL_PATH_ALIASES_OLD_OR_ANOTHER_ROLE', 'permission_denied')
    raw = tsa._read_pinned(path, pin['sha256'], cap, 'EC355_'+label, {})
    pins[path] = (pin['sha256'], cap)
    return raw


def _old_pin(pin, cap, oldpins):
    # Old signatures/role/path uniqueness were already audited by EC354;
    # record every input for *additional* post-decision whole-original reread.
    path, h = pin['path'], pin['sha256']
    if path in oldpins:
        need(oldpins[path][0]==h, 'OLD_PIN_SHA_CONTRADICTION', 'permission_denied')
        oldpins[path]=(h,max(cap,oldpins[path][1]))
    else:
        oldpins[path]=(h,cap)
    return tsa._read_pinned(path,h,cap,'EC355_INHERITED_ORIGINAL',{})


def _claimed_views(parent):
    found={}
    for ex in parent['gossip_exchanges']:
        for reply in ex['replies']:
            if reply['view_state'] != 'signed_unfurnished_checkpoint_claim':
                continue
            h=reply['reply_original_sha256']
            need(h not in found, 'DUPLICATE_PARENT_UNFURNISHED_REPLY')
            found[h]={
                'gossip_reply_original_sha256':h,
                'gossip_challenge_original_sha256':ex['challenge_original_sha256'],
                'log_id':ex['log_id'],
                'claimed_checkpoint_original_sha256':reply['checkpoint_original_sha256'],
                'claimed_tree_size':reply['tree_size'],
                'claimed_root_hash_sha256':reply['root_hash_sha256'],
                'challenger_auditor_id':ex['challenger_id'],
                'original_responder_auditor_id':ex['responder_id'],
                'gossip_reply_utc_claim':reply['responded_utc_claim'],
                'parent_challenged_checkpoint_original_sha256':ex['challenged_checkpoint_original_sha256'],
                'parent_challenged_tree_size':ex['challenged_tree_size'],
                'parent_challenged_root_hash_sha256':ex['challenged_root_hash_sha256'],
            }
    need(len(found)<=MAX_OPEN_CLAIMS, 'TOO_MANY_UNFURNISHED_CLAIMS')
    return found


def _sources(inputs, parent, evaluation):
    """Reopen each actual EC353/EC354 role source, never trust a report-only key."""
    oldpins={};oldpaths=set(gossip.reg352._all_parent_files({
        k:v for k,v in inputs.items() if k not in (
            'publication_bundle_file','expected_publication_bundle_sha256',
            'publication_evaluation_utc','gossip_evaluation_utc',
            'gossip_bundle_file','expected_gossip_bundle_sha256')}))
    pp={'path':inputs['publication_bundle_file'],
        'sha256':inputs['expected_publication_bundle_sha256']}
    pdoc=_obj(_old_pin(pp,transparency.MAX_BUNDLE,oldpins),'PUBLICATION_BUNDLE')
    _fields(pdoc,{'schema','logs'},'PUBLICATION_BUNDLE')
    need(pdoc['schema']==transparency.BUNDLE_SCHEMA,'PARENT_PUBLICATION_SCHEMA')
    logs={};known={}
    for item in pdoc['logs']:
        logid=item['log_id']
        lk=_old_pin(item['log_public_key'],32,oldpins)
        wk=_old_pin(item['witness_public_key'],32,oldpins)
        lrpin=item['log_reference'];wrpin=item['witness_reference']
        logref=transparency._ref(_old_pin(lrpin,transparency.MAX_REFERENCE,oldpins),
             lk,item['log_public_key']['sha256'],logid,
             transparency._utc(inputs['publication_evaluation_utc']),is_witness=False)
        witref=transparency._ref(_old_pin(wrpin,transparency.MAX_REFERENCE,oldpins),
             wk,item['witness_public_key']['sha256'],logid,
             transparency._utc(inputs['publication_evaluation_utc']),is_witness=True)
        logs[logid]={'id':logid,'log_ref_sha':lrpin['sha256'],
            'log_ref':logref,'log_key':lk,'witness_ref_sha':wrpin['sha256'],
            'witness_ref':witref,'witness_key':wk}
        for entry in item['checkpoints']:
            cp_pin=entry['checkpoint']
            cp=_obj(_old_pin(cp_pin,transparency.MAX_CHECKPOINT,oldpins),'OLD_CHECKPOINT')
            known[(logid,cp_pin['sha256'])]={
                'sha256':cp_pin['sha256'],'size':cp['tree_size'],
                'root':bytes.fromhex(cp['root_hash_sha256']),
                'issued_utc':cp['issued_utc']}
            _old_pin(entry['witness_statement'],transparency.MAX_WITNESS,oldpins)
            if entry['consistency_proof'] is not None:
                _old_pin(entry['consistency_proof'],transparency.MAX_PROOF,oldpins)
        for pin in item['inclusions']:_old_pin(pin,transparency.MAX_PROOF,oldpins)
    need(set(logs)==set(parent['required_parent_log_ids']),
         'PARENT_AUDITED_LOG_IDS_CHANGED','permission_denied')
    gp={'path':inputs['gossip_bundle_file'],'sha256':inputs['expected_gossip_bundle_sha256']}
    gdoc=_obj(_old_pin(gp,gossip.MAX_BUNDLE,oldpins),'GOSSIP_BUNDLE')
    _fields(gdoc,{'schema','auditors','exchanges'},'GOSSIP_BUNDLE')
    need(gdoc['schema']==gossip.BUNDLE_SCHEMA,'PARENT_GOSSIP_SCHEMA')
    auditors={}
    for row in gdoc['auditors']:
        keypin=row['auditor_public_key'];refpin=row['auditor_reference']
        key=_old_pin(keypin,32,oldpins)
        ref=_obj(_old_pin(refpin,gossip.MAX_ORIGINAL,oldpins),'AUDITOR_REFERENCE')
        auditor_id=row['auditor_id']
        auditors[auditor_id]={'id':auditor_id,'key':key,'reference_sha':refpin['sha256'],
            'from':transparency._utc(ref['valid_from_utc']),
            'until':transparency._utc(ref['valid_until_utc'])}
    need({x['auditor_id']:x['reference_original_sha256'] for x in parent['auditor_evidence']}
         =={id:a['reference_sha'] for id,a in auditors.items()},
         'AUDITOR_REPLAY_IDENTITIES_CHANGED','permission_denied')
    for exchange in gdoc['exchanges']:
        _old_pin(exchange['challenge'],gossip.MAX_ORIGINAL,oldpins)
        for reply in exchange['replies']:
            _old_pin(reply,gossip.MAX_ORIGINAL,oldpins)
    oldpaths.update(oldpins)
    return logs,known,auditors,oldpaths,oldpins


def _verify(actor, body, field, domain, label):
    gossip._verify(actor['key'],body,field,domain,'EC355_'+label)


def _request(raw, sha, claim, auditors, inputs, evaluation):
    d=_obj(raw,'REQUEST')
    _fields(d,{'schema','request_id','parent_gossip_bundle_original_sha256',
        'gossip_challenge_original_sha256','gossip_reply_original_sha256',
        'log_id','claimed_checkpoint_original_sha256','claimed_tree_size',
        'claimed_root_hash_sha256','requester_auditor_id',
        'requester_reference_original_sha256','requested_auditor_id',
        'requested_reference_original_sha256','requested_role',
        'previous_request_original_sha256','nonce_hex','issued_utc',
        'signature_ed25519_hex'},'REQUEST')
    requester=auditors.get(d['requester_auditor_id'])
    target=auditors.get(d['requested_auditor_id'])
    role=d['requested_role']
    need(d['schema']==REQUEST_SCHEMA and gossip.parent353._ident(d['request_id']) and
         requester is not None and target is not None and requester is not target and
         d['requester_auditor_id']==claim['challenger_auditor_id'] and
         d['requester_reference_original_sha256']==requester['reference_sha'] and
         d['requested_reference_original_sha256']==target['reference_sha'] and
         d['parent_gossip_bundle_original_sha256']==inputs['expected_gossip_bundle_sha256'] and
         d['gossip_challenge_original_sha256']==claim['gossip_challenge_original_sha256'] and
         d['gossip_reply_original_sha256']==claim['gossip_reply_original_sha256'] and
         d['log_id']==claim['log_id'] and
         d['claimed_checkpoint_original_sha256']==claim['claimed_checkpoint_original_sha256'] and
         type(d['claimed_tree_size']) is int and
         d['claimed_tree_size']==claim['claimed_tree_size'] and
         d['claimed_root_hash_sha256']==claim['claimed_root_hash_sha256'] and
         role in ('original_responder','independent_peer') and
         ((role=='original_responder' and target['id']==claim['original_responder_auditor_id']) or
          (role=='independent_peer' and target['id'] not in (
                claim['original_responder_auditor_id'],claim['challenger_auditor_id']))) and
         (d['previous_request_original_sha256']==GENESIS or
          transparency._sha(d['previous_request_original_sha256'])) and
         type(d['nonce_hex']) is str and gossip.NONCE_RE.fullmatch(d['nonce_hex']) is not None,
         'REQUEST_SIGNED_PARENT_CLAIM_AND_TWO_TARGET_BINDING_INVALID', 'permission_denied')
    when=transparency._utc(d['issued_utc'])
    need(transparency._utc(claim['gossip_reply_utc_claim'])<=when<=evaluation and
         requester['from']<=when<=requester['until'] and
         target['from']<=when<=target['until'],
         'REQUEST_CLAIMED_TIME_OUTSIDE_SIGNERS_VALIDITY','permission_denied')
    _verify(requester,d,'signature_ed25519_hex',REQUEST_DOMAIN,'REQUEST')
    return d,when


def _receipt(raw,request,claim,actors,evaluation):
    d=_obj(raw,'RECEIPT')
    _fields(d,{'schema','request_original_sha256','gossip_reply_original_sha256',
        'respondent_auditor_id','respondent_reference_original_sha256','log_id',
        'response_kind','checkpoint_original_sha256','witness_original_sha256',
        'claimed_checkpoint_length','claimed_witness_length','responded_utc',
        'signature_ed25519_hex'},'RECEIPT')
    actor=actors[request['requested_auditor_id']]
    kind=d['response_kind']
    need(d['schema']==RECEIPT_SCHEMA and
         d['request_original_sha256']==request['_sha'] and
         d['gossip_reply_original_sha256']==claim['gossip_reply_original_sha256'] and
         d['respondent_auditor_id']==actor['id'] and
         d['respondent_reference_original_sha256']==actor['reference_sha'] and
         d['log_id']==claim['log_id'] and
         kind in ('furnished_originals','offer_only','unavailable_claim'),
         'RECEIPT_REQUEST_ROLE_OR_KIND_BINDING_INVALID','permission_denied')
    if kind=='furnished_originals':
        need(d['checkpoint_original_sha256']==claim['claimed_checkpoint_original_sha256'] and
             transparency._sha(d['witness_original_sha256']) and
             type(d['claimed_checkpoint_length']) is int and
             1<=d['claimed_checkpoint_length']<=transparency.MAX_CHECKPOINT and
             type(d['claimed_witness_length']) is int and
             1<=d['claimed_witness_length']<=transparency.MAX_WITNESS,
             'RECEIPT_FURNISHED_SHA_OR_LENGTH_INVALID','permission_denied')
    else:
        need(d['checkpoint_original_sha256']==claim['claimed_checkpoint_original_sha256'] and
             all(d[k] is None for k in ('witness_original_sha256',
                                        'claimed_checkpoint_length','claimed_witness_length')),
             'RECEIPT_NONFURNISHED_MUST_NOT_ASSERT_MEASURED_ORIGINALS',
             'permission_denied')
    when=transparency._utc(d['responded_utc'])
    need(transparency._utc(request['issued_utc'])<=when<=evaluation and
         actor['from']<=when<=actor['until'],
         'RECEIPT_CLAIMED_TIME_OUTSIDE_SIGNER_VALIDITY','permission_denied')
    _verify(actor,d,'signature_ed25519_hex',RECEIPT_DOMAIN,'RECEIPT')
    return d,when


def _furnished(doc,manifest,claim,request,logs,known,evaluation,pins,oldpaths):
    cp_pin=manifest['checkpoint'];w_pin=manifest['witness_statement']
    need(type(cp_pin) is dict and type(w_pin) is dict,
         'FURNISHED_REQUIRES_TWO_INDEPENDENT_PINNED_FILES')
    cp_raw=_pin(cp_pin,'FURNISHED_CHECKPOINT',transparency.MAX_CHECKPOINT,pins,oldpaths)
    w_raw=_pin(w_pin,'FURNISHED_WITNESS',transparency.MAX_WITNESS,pins,oldpaths)
    need(cp_pin['sha256']==doc['checkpoint_original_sha256'] and
         w_pin['sha256']==doc['witness_original_sha256'] and
         len(cp_raw)==doc['claimed_checkpoint_length'] and
         len(w_raw)==doc['claimed_witness_length'],
         'FURNISHED_RECEIPT_WHOLE_BYTE_SHA_OR_LENGTH_DIFFER','permission_denied')
    log=logs[claim['log_id']]
    cp=transparency._checkpoint(cp_raw,log,evaluation)
    w=transparency._witness(w_raw,cp,log,evaluation)
    need(cp['sha256']==claim['claimed_checkpoint_original_sha256'] and
         cp['size']==claim['claimed_tree_size'] and
         cp['body']['root_hash_sha256']==claim['claimed_root_hash_sha256'],
         'FURNISHED_SIGNED_LOG_VIEW_DIFFERS_FROM_EC354_CLAIM',
         'permission_denied')
    consistency_pin=manifest['consistency_proof']
    ancestry='verified_signed_checkpoint_witness_but_append_only_unproven'
    prior_sha=claim['parent_challenged_checkpoint_original_sha256']
    prior=known[(claim['log_id'],prior_sha)]
    if cp['size']==prior['size']:
        need(consistency_pin is None,'SAME_SIZE_CONSISTENCY_PROOF_UNEXPECTED')
        ancestry=('verified_matching_same_size_root' if cp['root']==prior['root'] else
                  'verified_same_log_same_size_conflicting_roots')
    elif consistency_pin is not None:
        need(cp['size']>prior['size'] and
             cp['body']['previous_checkpoint_original_sha256']==prior_sha,
             'CONSISTENCY_CLAIM_NOT_DIRECT_CHILD_OF_CHALLENGED_PARENT',
             'permission_denied')
        proof=_pin(consistency_pin,'FURNISHED_CONSISTENCY',
                   transparency.MAX_PROOF,pins,oldpaths)
        need(transparency._parse_consistency(proof,claim['log_id'],prior,cp),
             'FURNISHED_RFC6962_CONSISTENCY_PROOF_INVALID','permission_denied')
        ancestry='verified_rfc6962_append_only_relative_to_challenged_parent'
    # No consistency proof is NOT a failure of the checkpoint's two actual
    # signatures. It is a failure to establish append-only ancestry.
    return {'checkpoint_original_sha256':cp['sha256'],
            'checkpoint_length':len(cp_raw),
            'witness_original_sha256':w['sha256'],
            'witness_length':len(w_raw),
            'witnessed_utc_as_self_claim':_obj(w_raw,'WITNESS')['witnessed_utc'],
            'claimed_time_order_anomaly':cp['issued'] > transparency._utc(
                claim['gossip_reply_utc_claim']),
            'relation_to_verified_ec353_challenge':ancestry}


def _replay(inputs):
    result=gossip.audit(**inputs)  # NOT a cached previous JSON result
    need(result.get('actual_ec353_through_ec337_original_signatures_replayed') is True and
         result.get('exit_code')==2 and result.get('schema')==gossip.RESULT_SCHEMA,
         'ACTUAL_EC354_THROUGH_EC337_SIGNED_REPLAY_REQUIRED','permission_denied')
    return result


def checklist(**gossip_inputs):
    parent=_replay(gossip_inputs)
    claims=_claimed_views(parent)
    return {'schema':HANDOFF_SCHEMA,'command':'derive-disclosure-handoff',
            'status':'per_claim_separate_signed_original_byte_disclosure_needed',
            'exit_code':2,'case_id':parent['case_id'],
            'actual_ec354_through_ec337_original_signatures_replayed':True,
            'parent_ec354_canonical_result_sha256':digest(canonical.canonical(parent)),
            'parent_gossip_bundle_original_sha256':gossip_inputs['expected_gossip_bundle_sha256'],
            'signed_unfurnished_view_inventory':[claims[k] for k in sorted(claims)],
            'requires_separate_original_responder_and_third_auditor_request':True,
            'offline_unresolved_exit_code':2, **{k:False for k in NEGATIVES}}


def audit(*,checkpoint_disclosure_evaluation_utc,checkpoint_disclosure_bundle_file,
          expected_checkpoint_disclosure_bundle_sha256,**gossip_inputs):
    evaluation=transparency._utc(checkpoint_disclosure_evaluation_utc)
    need(evaluation>=transparency._utc(gossip_inputs['gossip_evaluation_utc']),
         'EVALUATION_EARLIER_THAN_EC354','permission_denied')
    parent=_replay(gossip_inputs)
    claims=_claimed_views(parent)
    logs,known,actors,oldpaths,oldpins=_sources(gossip_inputs,parent,evaluation)
    pins={}
    manifest=_obj(_pin({'path':checkpoint_disclosure_bundle_file,
                        'sha256':expected_checkpoint_disclosure_bundle_sha256},
                       'BUNDLE',MAX_BUNDLE,pins,oldpaths),'BUNDLE')
    _fields(manifest,{'schema','requests'},'BUNDLE')
    need(manifest['schema']==BUNDLE_SCHEMA and type(manifest['requests']) is list and
         len(manifest['requests'])<=MAX_REQUESTS,'BUNDLE_SCHEMA_OR_BOUNDS_INVALID')
    seen_ids=set();seen_nonces=set();requests={};counts=Counter()
    output=defaultdict(list);total_receipts=0
    for entry in manifest['requests']:
        _fields(entry,{'request','responses'},'REQUEST_MANIFEST')
        need(type(entry['responses']) is list and
             len(entry['responses'])<=MAX_PER_REQUEST,
             'RESPONSE_MANIFEST_BOUNDS_INVALID')
        pin=entry['request'];raw=_pin(pin,'DISCLOSURE_REQUEST',12_000,pins,oldpaths)
        reqdoc=_obj(raw,'REQUEST')
        claim=claims.get(reqdoc.get('gossip_reply_original_sha256'))
        need(claim is not None,'REQUEST_MUST_SELECT_SIGNED_UNFURNISHED_GOSSIP_REPLY',
             'permission_denied')
        r,when=_request(raw,pin['sha256'],claim,actors,gossip_inputs,evaluation)
        need(r['request_id'] not in seen_ids and r['nonce_hex'] not in seen_nonces,
             'REQUEST_ID_OR_NONCE_REPLAY','permission_denied')
        seen_ids.add(r['request_id']);seen_nonces.add(r['nonce_hex'])
        sha=pin['sha256'];r['_sha']=sha
        chainkey=(claim['gossip_reply_original_sha256'],r['requested_role'],
                  r['requested_auditor_id'])
        counts[chainkey]+=1
        need(counts[chainkey]<=MAX_ROUNDS,'TOO_MANY_REQUEST_ROUNDS')
        requests[sha]={'body':r,'when':when,'chain':chainkey}
        rows=[]
        for item in entry['responses']:
            _fields(item,{'receipt','checkpoint','witness_statement','consistency_proof'},
                    'RESPONSE_MANIFEST')
            recv_pin=item['receipt']
            recv_raw=_pin(recv_pin,'DISCLOSURE_RECEIPT',12_000,pins,oldpaths)
            rd,responded=_receipt(recv_raw,r,claim,actors,evaluation)
            original=None
            if rd['response_kind']=='furnished_originals':
                need(type(item['checkpoint']) is dict and
                     type(item['witness_statement']) is dict,
                     'RECEIPT_FURNISHED_REQUIRES_ORIGINALS')
                original=_furnished(rd,item,claim,r,logs,known,evaluation,pins,oldpaths)
                need(transparency._utc(original['witnessed_utc_as_self_claim'])<=responded,
                     'RECEIPT_CLAIMED_BEFORE_WITNESS_ORIGINAL','permission_denied')
            else:
                need(all(item[k] is None for k in (
                    'checkpoint','witness_statement','consistency_proof')),
                    'OFFERS_CANNOT_SMUGGLE_UNVERIFIED_FILES','permission_denied')
            rows.append({'receipt_original_sha256':recv_pin['sha256'],
                'respondent_auditor_id':rd['respondent_auditor_id'],
                'response_kind':rd['response_kind'],
                'responded_utc_as_claim':rd['responded_utc'],
                'verified_furnished_original':original})
        total_receipts+=len(rows)
        output[claim['gossip_reply_original_sha256']].append({
            'request_original_sha256':sha,'requested_role':r['requested_role'],
            'requested_auditor_id':r['requested_auditor_id'],
            'previous_request_original_sha256':r['previous_request_original_sha256'],
            'issued_utc_as_claim':r['issued_utc'],'signed_responses':rows})
    need(total_receipts<=MAX_RECEIPTS,'TOO_MANY_RECEIPTS')
    forks=False;equivocation=False
    parent_counts=Counter()
    for entry in requests.values():
        r=entry['body'];previous=r['previous_request_original_sha256']
        key=entry['chain']
        if previous!=GENESIS:
            prior=requests.get(previous)
            need(prior is not None and prior['chain']==key and
                 prior['when']<=entry['when'],
                 'REQUEST_SHA_PREDECESSOR_CHAIN_INVALID','permission_denied')
        parent_counts[(key,previous)]+=1
        visited=set();cur=r['_sha']
        while cur!=GENESIS:
            need(cur in requests and cur not in visited and
                 requests[cur]['chain']==key,
                 'REQUEST_SHA_HISTORY_CYCLE_OR_ROLE_CHANGE','permission_denied')
            visited.add(cur)
            need(len(visited)<=MAX_ROUNDS,'REQUEST_SHA_HISTORY_TOO_DEEP')
            cur=requests[cur]['body']['previous_request_original_sha256']
    forks=any(x>1 for x in parent_counts.values())
    detail=[];coverage_ok=True;any_actual=False;all_two=True;branch_issue=False;unanswered=False
    stale_claimed_time=False
    for claimsha,claim in sorted(claims.items()):
        rows=output[claimsha];role_requests={k:[r for r in rows if r['requested_role']==k]
                       for k in ('original_responder','independent_peer')}
        coverage=all(bool(role_requests[k]) for k in role_requests)
        coverage_ok &= coverage
        if not coverage:unanswered=True
        furnished={};total_signed=0
        for role,reqrows in role_requests.items():
            valid=[]
            for row in reqrows:
                signed=row['signed_responses']
                if evaluation-transparency._utc(row['issued_utc_as_claim'])>MAX_FRESHNESS:
                    stale_claimed_time=True
                total_signed+=len(signed)
                if not signed:unanswered=True
                if len(signed)==2 and any((x['response_kind'],x['verified_furnished_original'])!=
                        (signed[0]['response_kind'],signed[0]['verified_furnished_original'])
                        for x in signed[1:]):
                    equivocation=True
                for response in signed:
                    if evaluation-transparency._utc(response['responded_utc_as_claim'])>MAX_FRESHNESS:
                        stale_claimed_time=True
                    original=response['verified_furnished_original']
                    if original is None:
                        unanswered=True
                    else:
                        any_actual=True
                        if (original['relation_to_verified_ec353_challenge'] in (
                            'verified_same_log_same_size_conflicting_roots',
                            'verified_signed_checkpoint_witness_but_append_only_unproven') or
                            original['claimed_time_order_anomaly']):
                            branch_issue=True
                        valid.append(original)
            furnished[role]=valid
        if not furnished['original_responder'] or not furnished['independent_peer']:
            all_two=False
        detail.append({**claim,'disclosure_requests':rows,
            'both_roles_separately_requested':coverage,
            'valid_original_responder_byte_handoffs':len(furnished['original_responder']),
            'valid_independent_peer_byte_handoffs':len(furnished['independent_peer']),
            'same_original_observed_by_both_signed_roles':bool(
                furnished['original_responder'] and furnished['independent_peer'] and
                set(v['checkpoint_original_sha256'] for v in furnished['original_responder']) &
                set(v['checkpoint_original_sha256'] for v in furnished['independent_peer'])),
            'total_signed_receipt_count':total_signed})
    # All source bytes re-read after verifying signatures and graph decisions.
    need(not set(pins).intersection(oldpaths),'NEW_INPUT_ALIASES_PARENT','permission_denied')
    tsa._check_late(pins);tsa._check_late(oldpins)
    parent_good=len(parent['required_parent_log_ids'])==2 and all(
        row['parent_ec353_outcome']==transparency.OUTCOMES[-1]
        for row in parent['channel_evidence'])
    if not parent_good:outcome=OUTCOMES[0]
    elif not claims:outcome=OUTCOMES[1]
    elif not coverage_ok:outcome=OUTCOMES[2]
    elif forks or equivocation:outcome=OUTCOMES[3]
    elif not any_actual:outcome=OUTCOMES[4]
    elif branch_issue or stale_claimed_time:outcome=OUTCOMES[5]
    elif not all_two:outcome=OUTCOMES[6]
    else:outcome=OUTCOMES[7]
    rows=[{'tsa_channel_id':row['tsa_channel_id'],
           'parent_ec354_outcome':row['outcome'],'outcome':outcome}
          for row in parent['channel_evidence']]
    outcomes={k:sum(r['outcome']==k for r in rows) for k in OUTCOMES}
    return {'schema':RESULT_SCHEMA,'command':'audit-checkpoint-disclosures',
            'status':outcome+'_unresolved','exit_code':2,'case_id':parent['case_id'],
            'actual_ec354_through_ec337_original_signatures_replayed':True,
            'parent_ec354_canonical_result_sha256':digest(canonical.canonical(parent)),
            'parent_gossip_bundle_original_sha256':gossip_inputs['expected_gossip_bundle_sha256'],
            'disclosure_bundle_original_sha256':expected_checkpoint_disclosure_bundle_sha256,
            'checkpoint_disclosure_evaluation_utc_as_caller_claim':checkpoint_disclosure_evaluation_utc,
            'signed_unfurnished_view_count':len(claims),
            'signed_request_count':len(requests),'signed_receipt_count':total_receipts,
            'disclosure_claim_evidence':detail,
            'request_sha_predecessor_forks_visible':forks,
            'signed_receipt_equivocation_visible':equivocation,
            'any_two_target_requests_missing':not coverage_ok,
            'any_signed_offer_unavailable_or_no_response':unanswered,
            'any_genuine_new_signed_log_and_witness_pair_verified':any_actual,
            'verified_same_log_conflict_or_unproved_ancestry_visible':branch_issue,
            'stale_claimed_disclosure_time_visible':stale_claimed_time,
            'both_roles_furnished_same_original_for_all_claims':bool(claims) and all_two,
            'channel_evidence':rows,'outcome_counts':outcomes,
            'physical_external_identity_custody_utc_global_heads_unproven':True,
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}
