#!/usr/bin/env python3
"""EC363: real offline source-publication history and disclosure challenges.

Each call replays the EC362->EC337 original signature chain. No source key,
challenger key, signed UTC or local copy certifies an official public publisher,
independent physical custody or the absence of undisclosed signed histories.
All accepted audits are read-only, exit-2 and unresolved.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
import os
import re

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from publication_custody import custody as previous

parent = previous.parent
consistency = previous.previous
SLOTS = previous.SLOTS
ROLES = previous.COPY_ROLES
RESULT_SCHEMA = 'ces.ec363.offline_signed_publication_history_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec363.offline_signed_publication_history_denial.v1'
HANDOFF_SCHEMA = 'ces.ec363.unsigned_publication_history_handoff.v1'
BUNDLE_SCHEMA = 'ces.ec363.pinned_signed_source_history_bundle.v1'
CHALLENGE_SCHEMA = 'ces.ec363.signed_historical_copy_challenge.v1'
RESPONSE_SCHEMA = 'ces.ec363.signed_historical_copy_disclosure.v1'
CHALLENGE_DOMAIN = b'CES/EC363/HistoricalCopyChallenge/v1\x00'
RESPONSE_DOMAIN = b'CES/EC363/HistoricalCopyDisclosure/v1\x00'
MAX_BUNDLE = 48_000
MAX_HISTORY = 4
MAX_CHALLENGES = 16
MAX_CHALLENGE_BYTES = 8_000
MAX_RESPONSE_BYTES = 10_000
MAX_WINDOW = timedelta(days=3)
MAX_CLOCK_LAG = timedelta(days=7)
BOUNDED_INT = 2**31-1
BUNDLE_FIELDS = {'schema','source_slot','parent_ec362_canonical_result_sha256',
    'custodian_public_key_original_sha256','challenger_public_key_original_sha256',
    'historical_manifest_originals','signed_challenge_originals',
    'signed_disclosure_response_originals'}
CHALLENGE_FIELDS = {'schema','source_slot','claimed_source_id',
    'challenger_public_key_original_sha256','custodian_public_key_original_sha256',
    'parent_ec362_canonical_result_sha256',
    'parent_ec361_canonical_result_sha256','target_manifest_original_sha256',
    'target_publication_sequence','requested_copy_role','requested_copy_sha256',
    'nonce_hex','issued_utc','expires_utc','signature_challenger_ed25519_hex'}
RESPONSE_FIELDS = {'schema','source_slot','claimed_source_id',
    'custodian_public_key_original_sha256','parent_ec362_canonical_result_sha256',
    'challenge_original_sha256','target_manifest_original_sha256',
    'requested_copy_role','requested_copy_sha256','response_kind',
    'disclosed_copy','responded_utc','expires_utc',
    'signature_custodian_ed25519_hex'}
NEW_OPTIONAL = tuple(k for slot in SLOTS for k in (
    f'source_{slot}_history_bundle_file',
    f'expected_source_{slot}_history_bundle_sha256',
    f'source_{slot}_challenger_public_key_file',
    f'expected_source_{slot}_challenger_public_key_sha256',
    f'minimum_source_{slot}_retained_publication_sequence',
    f'expected_source_{slot}_retained_manifest_sha256',
    f'minimum_source_{slot}_retained_directory_tree_size'))
NEW_REPEATS = tuple((f'source_{slot}_{role}_shas',
                     f'--source-{slot}-{role.replace("_", "-")}-sha256')
    for slot in SLOTS for role in ('historical_manifest','challenge','response'))
NEW_REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
OUTCOMES = (
    'ec363_parent_ec362_published_originals_not_locally_coherent',
    'ec363_pinned_history_or_disclosure_challenges_incomplete',
    'ec363_source_or_challenger_signer_role_collision',
    'ec363_same_sequence_genuinely_signed_source_equivocation',
    'ec363_caller_retained_source_sequence_or_head_regression',
    'ec363_signed_copy_disclosed_with_wrong_original_sha',
    'ec363_signed_unavailability_missing_reply_or_retroactive_withdrawal',
    'ec363_real_directory_signed_history_fork_visible',
    'ec363_signed_claimed_clock_outside_evaluation_window',
    'ec363_bounded_signed_history_and_copies_locally_reconciled_external_trust_unproven',
)
NEGATIVES = (
    'self_signed_source_history_proves_official_public_archive',
    'separately_pinned_challengers_prove_real_legal_independence',
    'disclosure_response_without_original_bytes_proves_availability',
    'signed_withdrawal_erases_past_publication_or_revocation_obligations',
    'retained_local_sequence_and_head_prove_no_hidden_fork',
    'historical_source_or_response_utc_is_trusted_timestamp',
    'source_signature_substitutes_for_directory_checkpoint_true_signature',
    'new_history_repairs_ec362_or_any_parent_signature_failure',
    'auditor_fetches_network_or_ambient_system_trust',
    'auditor_generates_private_keys_signatures_or_remote_cas_worm_writes',
    'old_powershell_deep_mock_or_final_human_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC363_'+code,status)


def exact(doc,fields,role):
    need(type(doc) is dict and set(doc)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return previous.sha(raw)


def _source(inputs,slot):
    return {'bundle_file':inputs.get(f'source_{slot}_history_bundle_file'),
        'bundle_sha':inputs.get(f'expected_source_{slot}_history_bundle_sha256'),
        'challenger_file':inputs.get(f'source_{slot}_challenger_public_key_file'),
        'challenger_sha':inputs.get(f'expected_source_{slot}_challenger_public_key_sha256'),
        'floor':inputs.get(f'minimum_source_{slot}_retained_publication_sequence'),
        'retained_manifest_sha':inputs.get(f'expected_source_{slot}_retained_manifest_sha256'),
        'tree_floor':inputs.get(f'minimum_source_{slot}_retained_directory_tree_size'),
        **{role+'_shas':inputs.get(f'source_{slot}_{role}_shas',[])
           for role in ('historical_manifest','challenge','response')}}


def _collect_refs(doc,paths):
    if type(doc) is dict:
        if set(doc)=={'path','sha256'} and type(doc['path']) is str and tr._sha(doc['sha256']):
            paths.add(doc['path'])
        for value in doc.values():_collect_refs(value,paths)
    elif type(doc) is list:
        for value in doc:_collect_refs(value,paths)


def _parent_material(inputs,prior):
    """Independently reopen the current true EC362 source roles/bytes, collect
    inherited nested originals and roles for physical/cryptographic separation.
    This does not replace the completed parent.audit signature verification.
    """
    inherited=parent.previous.parent.parent.prior._inherited
    oldpins,oldpaths,old_keys=parent.parent_boundary(inputs)
    oldpaths=set(oldpaths); old_keys=set(old_keys)
    for k,v in inputs.items():
        if k.endswith('_file') and type(v) is str:oldpaths.add(v)
        elif k.endswith('_files') and type(v) is list:
            oldpaths.update(x for x in v if type(x) is str)
        if k.endswith('_public_key_sha256') and tr._sha(v):old_keys.add(v)
    # The nested EC360/361 originals were already authenticated by parent.
    for fname,hashname,cap in (
        ('distribution_bundle_file','expected_distribution_bundle_sha256',
         parent.previous.MAX_BUNDLE),
        ('authority_bundle_file','expected_authority_bundle_sha256',parent.MAX_BUNDLE),
        ('consistency_bundle_file','expected_consistency_bundle_sha256',
         consistency.MAX_BUNDLE)):
        f,h=inputs.get(fname),inputs.get(hashname)
        if f is None or h is None:continue
        raw=inherited({'path':f,'sha256':h},'EC363_PARENT_'+fname,cap,oldpins)
        _collect_refs(tr.strict_json(raw,'EC363_PARENT_'+fname),oldpaths)
    current={};publics={}
    for slot in SLOTS:
        src=previous._source_args(inputs,slot)
        if src['key_file'] is None or src['manifest_file'] is None:continue
        key=inherited({'path':src['key_file'],'sha256':src['key_sha']},
            'EC363_PARENT_CUSTODIAN_'+slot,32,oldpins)
        need(len(key)==32,'PARENT_CUSTODIAN_KEY_NOT_ED25519','permission_denied')
        raw=inherited({'path':src['manifest_file'],'sha256':src['manifest_sha']},
            'EC363_PARENT_PUBLICATION_'+slot,previous.MAX_MANIFEST,oldpins)
        doc=tr.strict_json(raw,'EC363_PARENT_PUBLICATION_'+slot)
        exact(doc,previous.MANIFEST_FIELDS,'PARENT_PUBLICATION_'+slot)
        review=next((r for r in prior['signed_publication_source_reviews']
                    if r['slot']==slot),None)
        need(review is not None and
             review['signed_manifest_original_sha256']==src['manifest_sha'] and
             review['custodian_public_key_sha256']==src['key_sha'] and
             doc['parent_ec361_canonical_result_sha256']==
                prior['parent_ec361_canonical_result_sha256'],
             'ACTUAL_EC362_SIGNED_SOURCE_ROLE_NOT_REPLAYED','permission_denied')
        for role,ref in doc['copies'].items():
            inherited(ref,'EC363_PARENT_COPY_'+slot+'_'+role,
                      previous.COPY_CAPS[role],oldpins)
        _collect_refs(doc,oldpaths)
        oldpaths.update((src['key_file'],src['manifest_file']))
        old_keys.add(src['key_sha'])
        current[slot]=(src['manifest_sha'],doc)
        publics[slot]=key
    return oldpins,oldpaths,old_keys,current,publics


def _manifest(raw,slot,ref,source,prior,base):
    d=tr.strict_json(raw,'EC363_HISTORICAL_MANIFEST_'+slot)
    exact(d,previous.MANIFEST_FIELDS,'HISTORICAL_MANIFEST')
    need(d['schema']==previous.MANIFEST_SCHEMA and d['source_slot']==slot and
         d['custodian_public_key_original_sha256']==source['custodian_public_key_original_sha256'] and
         d['claimed_source_id']==base['claimed_source_id'] and
         d['directory_id']==base['directory_id'] and
         d['parent_ec361_canonical_result_sha256']==prior['parent_ec361_canonical_result_sha256'] and
         d['parent_ec360_canonical_result_sha256']==prior['parent_ec360_canonical_result_sha256'] and
         d['parent_directory_checkpoint_original_sha256']==
            base['parent_directory_checkpoint_original_sha256'],
         'HISTORY_SOURCE_IDENTITY_OR_ACTUAL_PARENT_BINDING_MISMATCH','permission_denied')
    need(type(d['publication_sequence']) is int and
         0<=d['publication_sequence']<=BOUNDED_INT and
         tr._sha(d['advertised_checkpoint_original_sha256']) and
         tr._sha(d['advertised_root_sha256']) and
         type(d['advertised_tree_size']) is int and
         1<=d['advertised_tree_size']<=parent.MAX_DIRECTORY_LEAVES,
         'HISTORICAL_PUBLISHED_SEQUENCE_OR_HEAD_INVALID','permission_denied')
    exact(d['copies'],ROLES,'HISTORICAL_COPY_ROLES')
    for role,copy in d['copies'].items():
        exact(copy,('path','sha256'),'HISTORICAL_'+role)
        path=copy['path']
        need(type(path) is str and os.path.isabs(path) and
             os.path.normpath(path)==path and not path.startswith('//') and
             '\\' not in path and '\x00' not in path and len(path)<=4000 and
             tr._sha(copy['sha256']),
             'HISTORICAL_COPY_PIN_MALFORMED')
    need(len({x['path'] for x in d['copies'].values()})==len(ROLES),
         'HISTORICAL_COPY_ROLES_CANNOT_USE_SAME_ORIGINAL_PATH',
         'permission_denied')
    need(d['advertised_checkpoint_original_sha256']==d['copies']['checkpoint']['sha256'],
         'HISTORICAL_HEAD_NOT_THE_ADVERTISED_COPY','permission_denied')
    start,end=parent.window(d['issued_utc'],d['expires_utc'],previous.MAX_SPAN,
                            'EC363_HISTORICAL_MANIFEST')
    parent.sig(d,'signature_custodian_ed25519_hex',source['custodian_pub'],
               previous.DOMAIN,'EC363_HISTORICAL_MANIFEST')
    return d,start,end


def _challenge(raw,slot,source,prior,by_sha,now):
    d=tr.strict_json(raw,'EC363_CHALLENGE_'+slot)
    exact(d,CHALLENGE_FIELDS,'CHALLENGE')
    target=by_sha.get(d['target_manifest_original_sha256'])
    need(d['schema']==CHALLENGE_SCHEMA and d['source_slot']==slot and
         d['claimed_source_id']==source['source_id'] and
         d['challenger_public_key_original_sha256']==source['challenger_sha'] and
         d['custodian_public_key_original_sha256']==source['custodian_sha'] and
         d['parent_ec362_canonical_result_sha256']==source['parent_sha'] and
         d['parent_ec361_canonical_result_sha256']==prior['parent_ec361_canonical_result_sha256'] and
         target is not None and
         type(d['target_publication_sequence']) is int and
         d['target_publication_sequence']==target['publication_sequence'] and
         d['requested_copy_role'] in ROLES and
         d['requested_copy_sha256']==target['copies'][d['requested_copy_role']]['sha256'] and
         type(d['nonce_hex']) is str and
         re.fullmatch('[0-9a-f]{64}',d['nonce_hex']) is not None and
         d['nonce_hex']!='0'*64,
         'SIGNED_CHALLENGE_MUST_BIND_ACTUAL_HISTORICAL_COPY_AND_PARENT',
         'permission_denied')
    start,end=parent.window(d['issued_utc'],d['expires_utc'],MAX_WINDOW,
                            'EC363_SIGNED_CHALLENGE')
    manifest_issued=tr._utc(target['issued_utc'])
    parent.sig(d,'signature_challenger_ed25519_hex',source['challenger_pub'],
               CHALLENGE_DOMAIN,'EC363_TRUE_CHALLENGER')
    return d,(parent.utc_untrusted(now,start,end,MAX_CLOCK_LAG) or
              start<manifest_issued)


def _response(raw,slot,source,challenge_by_sha,now):
    d=tr.strict_json(raw,'EC363_RESPONSE_'+slot)
    exact(d,RESPONSE_FIELDS,'DISCLOSURE_RESPONSE')
    requested=challenge_by_sha.get(d['challenge_original_sha256'])
    need(d['schema']==RESPONSE_SCHEMA and d['source_slot']==slot and
         d['claimed_source_id']==source['source_id'] and
         d['custodian_public_key_original_sha256']==source['custodian_sha'] and
         d['parent_ec362_canonical_result_sha256']==source['parent_sha'] and
         requested is not None and
         d['target_manifest_original_sha256']==requested['target_manifest_original_sha256'] and
         d['requested_copy_role']==requested['requested_copy_role'] and
         d['requested_copy_sha256']==requested['requested_copy_sha256'] and
         d['response_kind'] in ('disclosed','unavailable','withdrawn'),
         'SIGNED_RESPONSE_REFERENCE_OR_ROLE_NOT_A_REAL_REQUEST',
         'permission_denied')
    ref=d['disclosed_copy']
    if d['response_kind']=='disclosed':
        exact(ref,('path','sha256'),'DISCLOSED_ORIGINAL')
        need(type(ref['path']) is str and tr._sha(ref['sha256']),
             'DISCLOSED_ORIGINAL_REF_INVALID')
    else:
        need(ref is None,'NON_DISCLOSING_RESPONSE_CANNOT_CARRY_COPIES',
             'permission_denied')
    start,end=parent.window(d['responded_utc'],d['expires_utc'],MAX_WINDOW,
                            'EC363_SIGNED_RESPONSE')
    parent.sig(d,'signature_custodian_ed25519_hex',source['custodian_pub'],
               RESPONSE_DOMAIN,'EC363_TRUE_DISCLOSURE')
    need(start>=tr._utc(requested['issued_utc']),
         'RESPONSE_CANNOT_PREDATE_REQUEST_EVEN_AS_SELF_CLAIM','permission_denied')
    return d,parent.utc_untrusted(now,start,end,MAX_CLOCK_LAG)


def _validate_disclosed_copy(raw,role,slot,manifest,prior,inputs,now,oldpins):
    # A source-signed receipt does not turn ordinary JSON into a directory or
    # observer signature. Revalidate each supplied cryptographic role.
    if role=='checkpoint':
        keyfile=inputs.get('directory_public_key_file')
        keysha=inputs.get('expected_directory_public_key_sha256')
        need(keyfile is not None and keysha is not None,
             'PARENT_DIRECTORY_SIGNER_ABSENT','permission_denied')
        inherited=parent.previous.parent.parent.prior._inherited
        pub=inherited({'path':keyfile,'sha256':keysha},
            'EC363_DIRECTORY_SIGNER',32,oldpins)
        cp,stale=consistency.signed_checkpoint(
            raw,pub,keysha,manifest['directory_id'],now)
        need(cp['tree_size']==manifest['advertised_tree_size'] and
             cp['root_sha256']==manifest['advertised_root_sha256'] and
             sha(raw)==manifest['advertised_checkpoint_original_sha256'],
             'TRUE_SIGNED_DIRECTORY_CHECKPOINT_DIFFERS_FROM_SOURCE_CLAIM',
             'permission_denied')
        return cp,stale
    obj=tr.strict_json(raw,'EC363_DISCLOSED_'+role)
    if role=='consistency_bundle':
        exact(obj,consistency.BUNDLE_FIELDS,'DISCLOSED_CONSISTENCY_BUNDLE')
        need(obj['schema']==consistency.BUNDLE_SCHEMA,
             'DISCLOSED_CONSISTENCY_SCHEMA_INVALID','permission_denied')
        # Deliberately no append-only success claim for an old copied bundle.
        return None,False
    obs_slot=role.removeprefix('observer_').removesuffix('_receipt')
    exact(obj,consistency.OBSERVER_FIELDS,'DISCLOSED_OBSERVER')
    need(obj['schema']==consistency.OBSERVER_SCHEMA and obj['slot']==obs_slot and
         obj['parent_ec360_canonical_result_sha256']==
           prior['parent_ec360_canonical_result_sha256'] and
         obj['parent_directory_checkpoint_original_sha256']==
           manifest['parent_directory_checkpoint_original_sha256'] and
         obj['observed_checkpoint_original_sha256']==
           manifest['advertised_checkpoint_original_sha256'] and
         obj['observed_tree_size']==manifest['advertised_tree_size'] and
         obj['observed_root_sha256']==manifest['advertised_root_sha256'] and
         obj['directory_id']==manifest['directory_id'] and
         obj['directory_public_key_original_sha256']==
             inputs.get('expected_directory_public_key_sha256'),
         'DISCLOSED_OBSERVER_NOT_BOUND_TO_TRUE_HISTORICAL_HEAD',
         'permission_denied')
    keyfile=inputs.get('observer_'+obs_slot+'_public_key_file')
    keysha=inputs.get('expected_observer_'+obs_slot+'_public_key_sha256')
    need(keyfile is not None and keysha is not None and
         obj['observer_public_key_original_sha256']==keysha,
         'DISCLOSED_OBSERVER_SIGNER_ROLE_MISMATCH','permission_denied')
    inherited=parent.previous.parent.parent.prior._inherited
    pub=inherited({'path':keyfile,'sha256':keysha},
                  'EC363_PARENT_OBSERVER_'+obs_slot,32,oldpins)
    parent.sig(obj,'signature_observer_ed25519_hex',pub,
               consistency.OBSERVER_DOMAIN,'EC363_DISCLOSED_OBSERVER_'+obs_slot)
    first,last=parent.window(obj['observed_utc'],obj['expires_utc'],
                             consistency.MAX_OBSERVER_SPAN,
                             'EC363_DISCLOSED_OBSERVER')
    return None,parent.utc_untrusted(now,first,last,consistency.MAX_LAG)


def checklist(**publication_inputs):
    prior=previous.audit(**publication_inputs)
    need(prior['schema']==previous.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec361_through_ec337_signed_originals_replayed'] is True,
         'ACTUAL_EC362_THROUGH_EC337_CRYPTO_PARENT_REQUIRED','permission_denied')
    return {'schema':HANDOFF_SCHEMA,'command':'derive-publication-history-handoff',
        'status':'caller_held_history_challenger_and_signed_disclosure_originals_required_unresolved',
        'exit_code':2,'case_id':prior['case_id'],
        'actual_ec362_through_ec337_signed_originals_replayed':True,
        'parent_ec362_canonical_result_sha256':sha(canonical.canonical(prior)),
        'required_new_external_material':[
          'two separate caller-SHA-pinned history bundles and Ed25519 challenger public keys',
          'per-source historical EC362 manifest originals each with a separate caller SHA pin',
          'per-request challenger-signed challenges and source-signed responses with caller SHA pins',
          'disclosed raw copies compared to each historical signed advertised copy SHA',
          'caller-retained minimum source sequence, signed history head SHA and directory tree floor'],
        'official_source_legal_custody_historical_utc_global_forks_unproven':True,
        'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,history_evaluation_utc,**inputs):
    parent_inputs={k:v for k,v in inputs.items()
                   if k not in NEW_OPTIONAL and k not in NEW_REPEAT_NAMES}
    now=tr._utc(history_evaluation_utc)
    need(now>=tr._utc(parent_inputs['publication_copy_evaluation_utc']),
         'EVALUATION_BEFORE_REAL_EC362_PARENT','permission_denied')
    for slot in SLOTS:
        cfg=_source(inputs,slot)
        for label in ('bundle','challenger'):
            parent.outer_pin(cfg[label+'_file'],cfg[label+'_sha'],
                             'EC363_'+slot.upper()+'_'+label.upper())
        need(cfg['floor'] is None or
             (type(cfg['floor']) is int and 0<=cfg['floor']<=BOUNDED_INT),
             'RETAINED_SOURCE_SEQUENCE_FLOOR_INVALID')
        need(cfg['tree_floor'] is None or
             (type(cfg['tree_floor']) is int and
              1<=cfg['tree_floor']<=parent.MAX_DIRECTORY_LEAVES),
             'RETAINED_TREE_FLOOR_INVALID')
        need(cfg['retained_manifest_sha'] is None or
             tr._sha(cfg['retained_manifest_sha']),
             'RETAINED_HEAD_SHA_INVALID')
        for typ,limit in (('historical_manifest',MAX_HISTORY),
                          ('challenge',MAX_CHALLENGES),('response',MAX_CHALLENGES)):
            pins=cfg[typ+'_shas']
            need(type(pins) is list and len(pins)<=limit and
                 all(tr._sha(s) for s in pins) and len(pins)==len(set(pins)),
                 'CALLER_HELD_'+typ.upper()+'_SHAS_INVALID')
    prior=previous.audit(**parent_inputs)  # truly replays original EC362..337.
    need(prior['schema']==previous.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec361_through_ec337_signed_originals_replayed'] is True,
         'TRUE_EC362_THROUGH_EC337_SIGNED_PARENT_REQUIRED','permission_denied')
    parent_sha=sha(canonical.canonical(prior))
    oldpins,oldpaths,known_keys,current,source_pubs=_parent_material(parent_inputs,prior)
    newpins={};categories={};new_keys=set();nonces=set()
    flags={'missing':False,'role':False,'equivocation':False,'rollback':False,
           'mismatch':False,'undisclosed':False,'withdrawn':False,
           'directory_fork':False,'clock':False}
    reviews=[]
    for slot in SLOTS:
        cfg=_source(inputs,slot)
        if (cfg['bundle_file'] is None or cfg['challenger_file'] is None or
            slot not in current):
            flags['missing']=True
            continue
        old_sha,base=current[slot]
        signer_pub=source_pubs[slot]
        signer_sha=base['custodian_public_key_original_sha256']
        challenger_pub=parent.key_file(cfg['challenger_file'],cfg['challenger_sha'],
           'EC363_CHALLENGER_'+slot,newpins,oldpaths,categories,new_keys)
        if cfg['challenger_sha'] in known_keys or cfg['challenger_sha']==signer_sha:
            flags['role']=True
        bundle_raw=parent.load({'path':cfg['bundle_file'],'sha256':cfg['bundle_sha']},
           'EC363_HISTORY_BUNDLE_'+slot,MAX_BUNDLE,newpins,oldpaths,categories,
           'ec363_history_bundle_'+slot)
        bundle=tr.strict_json(bundle_raw,'EC363_BUNDLE_'+slot)
        exact(bundle,BUNDLE_FIELDS,'HISTORY_BUNDLE')
        need(bundle['schema']==BUNDLE_SCHEMA and bundle['source_slot']==slot and
             bundle['parent_ec362_canonical_result_sha256']==parent_sha and
             bundle['custodian_public_key_original_sha256']==signer_sha and
             bundle['challenger_public_key_original_sha256']==cfg['challenger_sha'],
             'HISTORY_BUNDLE_CURRENT_PARENT_OR_ROLE_BINDING_INVALID',
             'permission_denied')
        refs={
            'historical_manifest':bundle['historical_manifest_originals'],
            'challenge':bundle['signed_challenge_originals'],
            'response':bundle['signed_disclosure_response_originals']}
        for typ,cap in (('historical_manifest',MAX_HISTORY),
                        ('challenge',MAX_CHALLENGES),('response',MAX_CHALLENGES)):
            seq=refs[typ]
            need(type(seq) is list and len(seq)<=cap,
                 'HISTORY_'+typ.upper()+'_COUNT_OUT_OF_BOUNDS')
            for ref in seq:exact(ref,('path','sha256'),'HISTORY_'+typ.upper()+'_REF')
            seen=[x['sha256'] for x in seq]
            need(all(tr._sha(v) for v in seen) and len(set(seen))==len(seen),
                 'HISTORY_'+typ.upper()+'_SHA_DUPLICATE_OR_INVALID')
            held=cfg[typ+'_shas']
            if len(held)!=len(seq):flags['missing']=True
            for i,ref in enumerate(seq):
                if i>=len(held):flags['missing']=True
                elif ref['sha256']!=held[i]:flags['mismatch']=True
        source={'source_id':base['claimed_source_id'],
            'custodian_pub':signer_pub,'custodian_sha':signer_sha,
            'custodian_public_key_original_sha256':signer_sha,
            'challenger_pub':challenger_pub,'challenger_sha':cfg['challenger_sha'],
            'parent_sha':parent_sha}
        by_sha={}
        for i,ref in enumerate(refs['historical_manifest']):
            need(ref['sha256']!=old_sha,
                 'CURRENT_SOURCE_MANIFEST_IS_NOT_A_HISTORICAL_ORIGINAL')
            raw=parent.load(ref,'EC363_HISTORICAL_'+slot+'_'+str(i),
                previous.MAX_MANIFEST,newpins,oldpaths,categories,
                'historical_manifest_'+slot+'_'+str(i))
            doc,start,_=_manifest(raw,slot,ref,source,prior,base)
            by_sha[ref['sha256']]=doc
            if start>now:flags['clock']=True
        seq_to_shas=defaultdict(set)
        verified_heads={(base['advertised_tree_size'],base['advertised_root_sha256'])}
        for h,d in [(old_sha,base),*by_sha.items()]:
            seq_to_shas[d['publication_sequence']].add(h)
        if any(len(v)>1 for v in seq_to_shas.values()):flags['equivocation']=True
        if cfg['floor'] is None or cfg['retained_manifest_sha'] is None or cfg['tree_floor'] is None:
            flags['missing']=True
        if cfg['floor'] is not None and base['publication_sequence']<cfg['floor']:
            flags['rollback']=True
        if cfg['tree_floor'] is not None and base['advertised_tree_size']<cfg['tree_floor']:
            flags['rollback']=True
        if cfg['retained_manifest_sha'] is not None:
            head=({old_sha:base,**by_sha}).get(cfg['retained_manifest_sha'])
            if head is None or head['publication_sequence']>base['publication_sequence']:
                flags['rollback']=True
        if any(d['publication_sequence']>base['publication_sequence'] or
               d['advertised_tree_size']>base['advertised_tree_size']
               for d in by_sha.values()):flags['rollback']=True
        # This is a bounded caller-visible history, NOT proof of all preceding
        # sequence numbers or an outside-global journal. Gaps within the
        # presented retained interval are never silently treated as continuous.
        span=sorted(seq_to_shas)
        if not by_sha or any(y!=x+1 for x,y in zip(span,span[1:])):
            flags['missing']=True
        challenges={};challenge_by_pair={};response_map=defaultdict(list)
        for i,ref in enumerate(refs['challenge']):
            raw=parent.load(ref,'EC363_CHALLENGE_'+slot+'_'+str(i),
                MAX_CHALLENGE_BYTES,newpins,oldpaths,categories,
                'ec363_challenge_'+slot+'_'+str(i))
            d,stale=_challenge(raw,slot,source,prior,by_sha,now)
            if stale:flags['clock']=True
            nonce=d['nonce_hex']
            if nonce in nonces:flags['equivocation']=True
            nonces.add(nonce)
            pair=(d['target_manifest_original_sha256'],d['requested_copy_role'])
            if pair in challenge_by_pair:flags['equivocation']=True
            challenge_by_pair[pair]=ref['sha256']
            challenges[ref['sha256']]=d
        for i,ref in enumerate(refs['response']):
            raw=parent.load(ref,'EC363_RESPONSE_'+slot+'_'+str(i),
                MAX_RESPONSE_BYTES,newpins,oldpaths,categories,
                'ec363_response_'+slot+'_'+str(i))
            d,stale=_response(raw,slot,source,challenges,now)
            if stale:flags['clock']=True
            response_map[d['challenge_original_sha256']].append((ref['sha256'],d))
        covered=0; disclosed=0;unavailable=0;withdrawn=0
        for manifest_sha,manifest in by_sha.items():
            for role in ROLES:
                challenger_sha=challenge_by_pair.get((manifest_sha,role))
                if challenger_sha is None:
                    flags['missing']=True
                    continue
                covered+=1
                replies=response_map.get(challenger_sha,[])
                if not replies:
                    flags['undisclosed']=True
                    continue
                if len(replies)!=1:
                    # The source really signed more than one response to the
                    # *same* exact challenge; never elect a convenient branch.
                    flags['equivocation']=True
                    continue
                _,response=replies[0]
                kind=response['response_kind']
                if kind=='withdrawn':
                    flags['withdrawn']=True;withdrawn+=1;continue
                if kind=='unavailable':
                    flags['undisclosed']=True;unavailable+=1;continue
                copyref=response['disclosed_copy']
                raw=parent.load(copyref,'EC363_DISCLOSED_COPY_'+slot+'_'+str(disclosed),
                   previous.COPY_CAPS[role],newpins,oldpaths,categories,
                   'ec363_copy_'+slot+'_'+manifest_sha+'_'+role)
                if copyref['sha256']!=response['requested_copy_sha256']:
                    flags['mismatch']=True
                    continue
                signed_head,stale=_validate_disclosed_copy(
                    raw,role,slot,manifest,prior,parent_inputs,now,oldpins)
                if stale:flags['clock']=True
                if signed_head is not None:
                    verified_heads.add((signed_head['tree_size'],signed_head['root_sha256']))
                disclosed+=1
        # Same-size different roots here come from actually verified genuine
        # directory signatures, not merely a source custodian's signed claim.
        roots=defaultdict(set)
        for size,root in verified_heads:roots[size].add(root)
        if any(len(v)>1 for v in roots.values()):flags['directory_fork']=True
        rows=len(by_sha)*len(ROLES)
        reviews.append({'slot':slot,
          'custodian_public_key_sha256':signer_sha,
          'challenger_public_key_sha256':cfg['challenger_sha'],
          'history_bundle_original_sha256':cfg['bundle_sha'],
          'current_ec362_manifest_sha256':old_sha,
          'current_signed_sequence':base['publication_sequence'],
          'caller_retained_minimum_sequence':cfg['floor'],
          'caller_retained_manifest_sha256':cfg['retained_manifest_sha'],
          'caller_retained_minimum_tree_size':cfg['tree_floor'],
          'historical_manifests_checked':len(by_sha),
          'signed_challenges_checked':len(challenges),
          'signed_responses_checked':len(refs['response']),
          'historical_copy_roles_total':rows,
          'historical_copy_roles_challenged':covered,
          'historical_originals_disclosed_and_rechecked':disclosed,
          'explicit_signed_unavailable_responses':unavailable,
          'explicit_signed_withdrawal_responses':withdrawn,
          'all_history_roles_disclosed_and_rechecked':bool(rows and rows==covered==disclosed)})
        if not rows or rows!=covered or rows!=disclosed:flags['missing']=True
    if len({r['challenger_public_key_sha256'] for r in reviews})!=len(reviews):
        flags['role']=True
    # Re-read and inspect all actual source originals and check late inode
    # independence. This is necessarily not an atomic filesystem snapshot.
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    parent.previous.parent.parent._late_identity_check(newpins,oldpaths)
    locally=(prior['two_offline_signed_publication_copies_locally_coherent'] and
             len(reviews)==2 and not any(flags.values()) and
             all(r['all_history_roles_disclosed_and_rechecked'] for r in reviews))
    if not prior['two_offline_signed_publication_copies_locally_coherent']:
        outcome=OUTCOMES[0]
    elif flags['equivocation']:outcome=OUTCOMES[3]
    elif flags['rollback']:outcome=OUTCOMES[4]
    elif flags['role']:outcome=OUTCOMES[2]
    elif flags['mismatch']:outcome=OUTCOMES[5]
    elif flags['withdrawn'] or flags['undisclosed']:outcome=OUTCOMES[6]
    elif flags['directory_fork']:outcome=OUTCOMES[7]
    elif flags['clock']:outcome=OUTCOMES[8]
    elif flags['missing']:outcome=OUTCOMES[1]
    else:outcome=OUTCOMES[9]
    evidence=[{'tsa_channel_id':row['tsa_channel_id'],
      'parent_ec362_outcome':row['outcome'],'outcome':outcome}
      for row in prior['channel_evidence']]
    return {'schema':RESULT_SCHEMA,'command':'audit-publication-history',
      'status':outcome+'_unresolved','exit_code':2,'case_id':prior['case_id'],
      'actual_ec362_through_ec337_signed_originals_replayed':True,
      'parent_ec362_canonical_result_sha256':parent_sha,
      'parent_ec361_canonical_result_sha256':prior['parent_ec361_canonical_result_sha256'],
      'history_evaluation_utc_as_caller_claim':history_evaluation_utc,
      'parent_ec362_locally_coherent':prior['two_offline_signed_publication_copies_locally_coherent'],
      'source_history_reviews':reviews,'histories_cryptographically_reviewed':len(reviews),
      'external_history_challenges_or_retained_pins_missing':flags['missing'],
      'challenger_or_source_signer_role_collision':flags['role'],
      'genuinely_signed_same_sequence_or_challenge_equivocation':flags['equivocation'],
      'caller_retained_source_sequence_or_head_regression':flags['rollback'],
      'disclosed_original_does_not_match_challenged_sha':flags['mismatch'],
      'signed_disclosure_missing_or_explicitly_unavailable':flags['undisclosed'],
      'signed_retroactive_withdrawal_visible':flags['withdrawn'],
      'independently_verified_directory_signed_history_fork':flags['directory_fork'],
      'signed_historical_claimed_clock_anomaly':flags['clock'],
      'bounded_signed_history_and_disclosures_locally_coherent':locally,
      'official_archive_identity_physical_custody_and_global_latest_unproven':True,
      'channel_evidence':evidence,
      'outcome_counts':{o:sum(x['outcome']==o for x in evidence) for o in OUTCOMES},
      'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}
