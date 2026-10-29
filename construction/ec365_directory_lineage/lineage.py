#!/usr/bin/env python3
"""EC365: verify an old+new directory-signed, externally SHA-pinned key handoff.

The full EC364 auditor must run first, genuinely replaying each historical EC362
window, current EC363 and all inherited EC337+ signed originals. EC364 does not
approve a changed directory key; this layer verifies the exceptional cross-key
edge *without* masking its other unresolved defects. A dual-signed event binds
both observed endpoint key bytes, source manifests, signed checkpoints and the
actual RFC6962 proof. Caller-retained per-epoch pins are a separate input.

No private signer, network lookup, physical-world authority, trustworthy UTC,
claim of a global log head, or remote CAS/WORM writer exists in this module.
All lawful reports (including locally reconciled ones) exit 2 / unresolved.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec360_authority_directory import authority as authority
from ec361_directory_consistency import consistency
from ec362_publication_custody import custody
from ec364_cross_epoch import continuity as parent

RESULT_SCHEMA='ces.ec365.offline_directory_authority_lineage_unresolved.v1'
DENIAL_SCHEMA='ces.ec365.offline_directory_authority_lineage_denial.v1'
HANDOFF_SCHEMA='ces.ec365.unsigned_directory_authority_lineage_handoff.v1'
BUNDLE_SCHEMA='ces.ec365.pinned_directory_authority_handoffs.v1'
EVENT_SCHEMA='ces.ec365.dual_signed_directory_authority_handoff.v1'
EVENT_DOMAIN=b'CES/EC365/DualSignedDirectoryAuthorityHandoff/v1\x00'
BUNDLE_FIELDS={'schema','parent_ec364_canonical_result_sha256',
               'claimed_directory_lineage_id','signed_directory_handoffs'}
EVENT_FIELDS={'schema','claimed_directory_lineage_id','from_epoch_index',
 'to_epoch_index','event_kind','from_root_generation','to_root_generation',
 'from_directory_public_key_original_sha256','to_directory_public_key_original_sha256',
 'from_parent_ec361_canonical_result_sha256','to_parent_ec361_canonical_result_sha256',
 'from_checkpoint_original_sha256','to_checkpoint_original_sha256',
 'from_tree_size','to_tree_size','from_merkle_root_sha256','to_merkle_root_sha256',
 'from_source_a_manifest_original_sha256','from_source_b_manifest_original_sha256',
 'to_source_a_manifest_original_sha256','to_source_b_manifest_original_sha256',
 'cross_epoch_consistency_proof_canonical_sha256','issued_utc','expires_utc',
 'signature_old_directory_ed25519_hex','signature_new_directory_ed25519_hex'}
MAX_BUNDLE=16_000
MAX_EVENT=9_000
MAX_EVENTS=5    # up to 2 expected, plus 3 caller-exposed authentic forks
MAX_EPOCHS=3
MAX_SPAN=timedelta(days=7)
NEW_OPTIONAL=('directory_authority_bundle_file',
 'expected_directory_authority_bundle_sha256',
 'minimum_retained_directory_root_generation',
 'expected_retained_initial_directory_root_sha256',
 'expected_retained_current_directory_root_sha256',
 'minimum_retained_latest_directory_tree_size')
NEW_REPEATS=(
 ('epoch_directory_root_shas','--epoch-directory-root-sha256'),
 ('epoch_source_a_manifest_shas','--epoch-source-a-manifest-sha256'),
 ('epoch_source_b_manifest_shas','--epoch-source-b-manifest-sha256'),
 ('epoch_signed_checkpoint_shas','--epoch-signed-checkpoint-sha256'),
 ('signed_directory_handoff_shas','--signed-directory-handoff-sha256'),
)
NEW_REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
FLAGS=(
 'parent_ec364_non_directory_defect_visible',
 'separately_retained_epoch_or_root_rollback',
 'directory_handoff_missing_or_unpinned',
 'genuine_double_signed_directory_handoff_fork',
 'directory_key_lineage_or_role_collision',
 'genuinely_signed_checkpoint_fork_visible',
 'cross_root_rfc6962_proof_missing_or_invalid',
 'signed_directory_terminal_retirement_visible',
 'directory_claimed_utc_timeline_anomaly',
 'no_actual_directory_root_change_demonstrated',
)
OUTCOMES=(
 'ec365_inherited_nondirectory_parent_defect_unresolved',
 'ec365_retained_root_or_source_originals_regressed',
 'ec365_signed_directory_handoff_missing_or_unpinned',
 'ec365_contradictory_genuine_directory_delegations',
 'ec365_directory_root_lineage_or_signer_role_collision',
 'ec365_actual_signed_directory_checkpoint_fork',
 'ec365_cross_root_rfc6962_append_proof_missing_or_invalid',
 'ec365_signed_terminal_directory_retirement',
 'ec365_signed_directory_timeline_claim_conflict',
 'ec365_no_actual_directory_signer_rotation',
 'ec365_cross_root_double_signed_delegation_locally_reconciled_external_authority_unproven',
)
NEGATIVES=(
 'self_signed_new_root_proves_authorized_directory_rotation',
 'source_custodian_rotation_authorizes_directory_key_rotation',
 'dual_ed25519_signatures_prove_legal_authority_or_independent_institutions',
 'locally_consistent_rfc6962_proof_establishes_global_complete_log',
 'claimed_directory_handoff_utc_is_a_trusted_timestamp',
 'valid_handoff_resolves_inherited_ec364_signed_source_or_fork_defects',
 'caller_pinned_directory_roots_are_official_public_trust_anchors',
 'retired_directory_key_can_silently_sign_a_later_epoch',
 'missing_real_signed_handoff_is_inferred_from_a_favorable_parent_result',
 'network_or_os_key_store_authority_was_queried',
 'private_keys_generated_or_remote_provider_cas_worm_updated',
 'native_powershell_old_mock_or_final_human_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC365_'+code,status)


def exact(d,fields,role):
    need(type(d) is dict and set(d)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(b):return parent.sha(b)


def _pinlists(inputs):
    for key in NEW_REPEAT_NAMES:
        values=inputs.get(key,[])
        cap=MAX_EVENTS if key=='signed_directory_handoff_shas' else MAX_EPOCHS
        valid=(type(values) is list and len(values)<=cap and
               all(tr._sha(x) for x in values))
        if key=='signed_directory_handoff_shas' and valid:
            valid=len(values)==len(set(values))
        need(valid,'EXTERNALLY_RETAINED_'+key.upper()+'_INVALID')


def _parent_inputs(inputs):
    return {k:v for k,v in inputs.items() if k not in NEW_OPTIONAL and
            k not in NEW_REPEAT_NAMES}


def _read_original(ref,role,cap,pins):
    parent.ref_check(ref,role)
    return parent._raw_ref(ref,'EC365_'+role,cap,pins)


def _reopen_epoch(index, args, row, now, pins):
    """Re-open endpoints of the *just independently replayed* EC364 evidence.

    The parent is the source of the authenticated original and canonical-result
    binding; SHA-pinned manifests, their Ed25519 signatures, directory key and
    both actual copied directory-checkpoint signatures are verified again.
    """
    need(row['epoch_index']==index,'PARENT_EPOCH_ROW_INDEX_MISMATCH','permission_denied')
    keyref={'path':args.get('directory_public_key_file'),
            'sha256':args.get('expected_directory_public_key_sha256')}
    key=_read_original(keyref,'WINDOW_'+str(index)+'_DIRKEY',32,pins)
    need(len(key)==32 and sha(key)==row['directory_signer_sha256'],
         'REPLAYED_DIRECTORY_ROOT_KEY_MISMATCH','permission_denied')
    sources={}
    for slot in parent.SLOTS:
        ref={'path':args.get('source_'+slot+'_publication_manifest_file'),
             'sha256':args.get('expected_source_'+slot+'_publication_manifest_sha256')}
        raw=_read_original(ref,'WINDOW_'+str(index)+'_MANIFEST_'+slot,
                           custody.MAX_MANIFEST,pins)
        m=tr.strict_json(raw,'EC365_SIGNED_PUBLISHED_'+slot)
        exact(m,custody.MANIFEST_FIELDS,'REPLAYED_PUBLISHER_MANIFEST')
        need(m['schema']==custody.MANIFEST_SCHEMA and m['source_slot']==slot and
             row['source_'+slot+'_manifest_sha256']==ref['sha256'] and
             m['parent_ec361_canonical_result_sha256']==row['parent_ec361_result_sha256'] and
             m['custodian_public_key_original_sha256']==
               args['expected_source_'+slot+'_custody_public_key_sha256'],
             'PARENT_REPLAY_SIGNED_MANIFEST_ENDPOINT_MISMATCH','permission_denied')
        custodian=_read_original({'path':args['source_'+slot+'_custody_public_key_file'],
             'sha256':args['expected_source_'+slot+'_custody_public_key_sha256']},
             'WINDOW_'+str(index)+'_CUSTODIAN_'+slot,32,pins)
        need(len(custodian)==32,'CUSTODIAN_KEY_LENGTH_INVALID','permission_denied')
        authority.sig(m,'signature_custodian_ed25519_hex',custodian,
                      custody.DOMAIN,'EC365_WINDOW_MANIFEST_'+slot)
        cpr=m['copies']['checkpoint']
        cpraw=_read_original(cpr,'WINDOW_'+str(index)+'_CHECKPOINT_'+slot,
                             custody.COPY_CAPS['checkpoint'],pins)
        cp,_=consistency.signed_checkpoint(cpraw,key,keyref['sha256'],
                                             m['directory_id'],now)
        need(cp['directory_public_key_original_sha256']==keyref['sha256'] and
             cp['tree_size']==row['signed_tree_size'] and
             cp['root_sha256']==row['signed_root_sha256'] and
             sha(cpraw)==m['advertised_checkpoint_original_sha256'] and
             m['advertised_tree_size']==cp['tree_size'] and
             m['advertised_root_sha256']==cp['root_sha256'],
             'REPLAYED_SIGNED_CHECKPOINT_ENDPOINT_MISMATCH','permission_denied')
        sources[slot]={'manifest_sha':ref['sha256'], 'manifest':m,
                       'checkpoint_sha':cpr['sha256'],'checkpoint':cp}
    return {'index':index,'key_sha':keyref['sha256'],'pub':key,
            'ec361_sha':row['parent_ec361_result_sha256'],
            'sources':sources,'directory_id':sources['a']['manifest']['directory_id'],
            'cp_sha':sources['a']['checkpoint_sha'],
            'cp':sources['a']['checkpoint']}


def _verified_endpoints(parent_inputs, replay, now, pins, oldpaths):
    """No fake parent-success JSON; `replay` comes from parent.audit right now."""
    raw=_read_original({'path':parent_inputs.get('cross_epoch_bundle_file'),
          'sha256':parent_inputs.get('expected_cross_epoch_bundle_sha256')},
          'TRUE_EC364_BUNDLE',parent.MAX_BUNDLE,pins)
    d=tr.strict_json(raw,'EC365_PARENT_CROSS_EPOCH_BUNDLE')
    exact(d,parent.BUNDLE_FIELDS,'PARENT_CROSS_EPOCH_BUNDLE')
    need(d['schema']==parent.BUNDLE_SCHEMA and
         d['current_ec363_canonical_result_sha256']==
             replay['parent_ec363_canonical_result_sha256'],
         'PARENT_CROSS_EPOCH_BUNDLE_BINDING_MISMATCH','permission_denied')
    live=parent._ec362_inputs(parent._parent_inputs({k:v for k,v in
          parent_inputs.items() if k!='cross_epoch_evaluation_utc'}))
    inputs=[]
    for index,ref in enumerate(d['historical_parent_snapshots']):
        raw=_read_original(ref,'HISTORICAL_REPLAY_INPUTS_'+str(index),
                           parent.MAX_SNAPSHOT,pins)
        snapshot=tr.strict_json(raw,'EC365_PARENT_HISTORICAL_SNAPSHOT')
        exact(snapshot,parent.SNAPSHOT_FIELDS,'PARENT_HISTORICAL_INPUT_SNAPSHOT')
        need(snapshot['schema']==parent.SNAPSHOT_SCHEMA and
             snapshot['epoch_index']==index and
             type(snapshot['ec362_audit_inputs']) is dict and
             set(snapshot['ec362_audit_inputs'])==set(live),
             'EC364_ACTUAL_HISTORICAL_SNAPSHOT_CHANGED','permission_denied')
        inputs.append(snapshot['ec362_audit_inputs'])
        oldpaths.add(ref['path'])
    inputs.append(live)
    need(len(inputs)==len(replay['epoch_reviews']) and len(inputs)<=MAX_EPOCHS,
         'EC364_TRUE_EPOCH_COUNT_MISMATCH','permission_denied')
    for values in inputs:
        oldpaths.update(v for k,v in values.items() if
                        k.endswith('_file') and type(v) is str)
    return ([_reopen_epoch(i,args,row,now,pins) for i,(args,row) in enumerate(
             zip(inputs,replay['epoch_reviews']))],d,inputs)


def _check_signed_handoff(d,left,right,proof,lineage,from_generation,now):
    exact(d,EVENT_FIELDS,'DUAL_SIGNED_DIRECTORY_HANDOFF')
    edge=left['index']
    need(d['schema']==EVENT_SCHEMA and
         d['claimed_directory_lineage_id']==lineage==left['directory_id']==
             right['directory_id'] and
         type(d['from_epoch_index']) is int and d['from_epoch_index']==edge and
         type(d['to_epoch_index']) is int and d['to_epoch_index']==edge+1 and
         d['event_kind'] in ('carry','delegate_and_retire','terminal_retirement') and
         d['from_directory_public_key_original_sha256']==left['key_sha'] and
         d['to_directory_public_key_original_sha256']==right['key_sha'] and
         d['from_parent_ec361_canonical_result_sha256']==left['ec361_sha'] and
         d['to_parent_ec361_canonical_result_sha256']==right['ec361_sha'] and
         d['from_checkpoint_original_sha256']==left['cp_sha'] and
         d['to_checkpoint_original_sha256']==right['cp_sha'] and
         d['from_tree_size']==left['cp']['tree_size'] and
         d['to_tree_size']==right['cp']['tree_size'] and
         d['from_merkle_root_sha256']==left['cp']['root_sha256'] and
         d['to_merkle_root_sha256']==right['cp']['root_sha256'] and
         all(d[side+'_source_'+slot+'_manifest_original_sha256']==
             ep['sources'][slot]['manifest_sha'] for side,ep in
             (('from',left),('to',right)) for slot in parent.SLOTS) and
         d['cross_epoch_consistency_proof_canonical_sha256']==
             sha(canonical.canonical(proof)),
         'HANDOFF_NOT_BOUND_TO_TRUE_PUBLISHED_ENDPOINT_AND_RFC6962_PROOF',
         'permission_denied')
    sigfields=('signature_old_directory_ed25519_hex',
               'signature_new_directory_ed25519_hex')
    need(all(type(d[k]) is str and tr.SIG_RE.fullmatch(d[k]) for k in sigfields),
         'DIRECTORY_HANDOFF_SIGNATURE_FORMAT_INVALID','permission_denied')
    message=EVENT_DOMAIN+canonical.canonical({k:v for k,v in d.items()
                                                if k not in sigfields})
    for role,pub,field in (('OLD',left['pub'],sigfields[0]),
                            ('NEW',right['pub'],sigfields[1])):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(
                bytes.fromhex(d[field]),message)
        except (InvalidSignature,ValueError,TypeError) as exc:
            raise errors.AnchorError('EC365_'+role+'_DIRECTORY_TRUE_SIGNATURE_INVALID',
                                     'permission_denied') from exc
    a,b=authority.window(d['issued_utc'],d['expires_utc'],MAX_SPAN,
                           'EC365_DIRECTORY_HANDOFF')
    clock=(authority.utc_untrusted(now,a,b,MAX_SPAN) or
           a<tr._utc(left['cp']['issued_utc']) or
           a>tr._utc(right['sources']['a']['manifest']['issued_utc']))
    action=d['event_kind']
    changed=left['key_sha']!=right['key_sha']
    proper_kind=((action=='carry' and not changed) or
                 (action=='delegate_and_retire' and changed) or
                 action=='terminal_retirement')
    correct_generation=(type(d['from_root_generation']) is int and
       type(d['to_root_generation']) is int and
       d['from_root_generation']==from_generation and
       d['to_root_generation']==from_generation+int(changed))
    return {'clock':clock,'role_bad':not proper_kind or not correct_generation,
            'terminal':action=='terminal_retirement',
            'generation':from_generation+int(changed),
            'event_kind':action,'changed':changed}


def _proofs(epochs,bundle):
    paths={};valid=0;invalid=False
    all_proofs=bundle['directory_window_proofs']
    need(type(all_proofs) is list and len(all_proofs)<=MAX_EPOCHS-1,
         'PARENT_DIRECTORY_PROOFS_COUNT_INVALID')
    for item in all_proofs:
        exact(item,parent.PROOF_FIELDS,'PARENT_SIGNED_CHECKPOINT_PROOF')
        edge=item['from_epoch_index'];to=item['to_epoch_index']
        need(type(edge) is int and type(to) is int and
             0<=edge<len(epochs)-1 and to==edge+1 and edge not in paths,
             'DIRECTORY_PROOFS_MUST_BE_DISTINCT_ADJACENT_EDGES')
        paths[edge]=item
    for index,(left,right) in enumerate(zip(epochs,epochs[1:])):
        item=paths.get(index)
        if item is None:invalid=True;continue
        hashes=item['audit_path_sha256']
        need(type(hashes) is list and len(hashes)<=parent.MAX_PATH and
             all(tr._sha(x) for x in hashes),
             'RFC6962_DIRECT_PROOF_PATH_FORMAT_INVALID')
        if (item['older_checkpoint_original_sha256']!=left['cp_sha'] or
            item['newer_checkpoint_original_sha256']!=right['cp_sha'] or
            left['cp']['tree_size']>=right['cp']['tree_size'] or
            left['ec361_sha']==right['ec361_sha'] or
            not tr.verify_consistency(left['cp']['tree_size'],
                right['cp']['tree_size'],
                bytes.fromhex(left['cp']['root_sha256']),
                bytes.fromhex(right['cp']['root_sha256']),
                [bytes.fromhex(v) for v in hashes])):
            invalid=True
        else:valid+=1
    if len(paths)!=len(epochs)-1:invalid=True
    return paths,valid,invalid


def checklist(**cross_epoch_inputs):
    replay=parent.audit(**cross_epoch_inputs)
    need(replay['schema']==parent.RESULT_SCHEMA and replay['exit_code']==2 and
         replay['actual_ec363_through_ec337_signed_originals_replayed'] is True,
         'INDEPENDENT_EC364_TO_EC337_TRUE_REPLAY_REQUIRED','permission_denied')
    return {'schema':HANDOFF_SCHEMA,'command':'derive-directory-authority-handoff',
      'status':'caller_retained_old_and_new_directory_root_delegations_required_unresolved',
      'exit_code':2,'case_id':replay['case_id'],
      'actual_ec364_through_ec337_signed_originals_replayed':True,
      'parent_ec364_canonical_result_sha256':sha(canonical.canonical(replay)),
      'required_external_material':[
        'a separately caller-SHA-pinned directory key original per genuinely replayed EC364 epoch, including OLD and NEW roots',
        'independent per-epoch source-a/source-b manifest and both-sources agreed directory checkpoint SHA pins',
        'old-and-new-directory-key Ed25519 jointly signed, SHA-pinned bound handoff originals; never self-authorizing',
        'RFC6962 proof bound inside BOTH signatures to exact independently reverified directory-signed endpoint checkpoints',
        'caller independently retained oldest/current roots, generation floor and latest signed tree size'],
      'real_world_public_directory_authority_trusted_utc_global_log_and_custody_unproven':True,
      'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,directory_lineage_evaluation_utc,**inputs):
    now=tr._utc(directory_lineage_evaluation_utc)
    cross_inputs=_parent_inputs(inputs)
    need(now>=tr._utc(cross_inputs['cross_epoch_evaluation_utc']),
         'EVALUATION_PRECEDES_ACTUAL_EC364_PARENT','permission_denied')
    _pinlists(inputs)
    authority.outer_pin(inputs.get('directory_authority_bundle_file'),
                        inputs.get('expected_directory_authority_bundle_sha256'),
                        'EC365_DIRECTORY_AUTHORITY_BUNDLE')
    for key in ('expected_retained_initial_directory_root_sha256',
                'expected_retained_current_directory_root_sha256'):
        need(inputs.get(key) is None or tr._sha(inputs[key]),
             'RETAINED_ROOT_SHA_FORMAT_INVALID')
    generation_floor=inputs.get('minimum_retained_directory_root_generation')
    tree_floor=inputs.get('minimum_retained_latest_directory_tree_size')
    need(generation_floor is None or (type(generation_floor) is int and
         1<=generation_floor<=MAX_EPOCHS-1),
         'RETAINED_ROOT_GENERATION_FLOOR_INVALID')
    need(tree_floor is None or (type(tree_floor) is int and 1<=tree_floor<=64),
         'RETAINED_NEWEST_TREE_FLOOR_INVALID')
    replay=parent.audit(**cross_inputs)   # actual current EC363 + all earlier EC362..337
    need(replay['schema']==parent.RESULT_SCHEMA and replay['exit_code']==2 and
         replay['actual_ec363_through_ec337_signed_originals_replayed'] is True,
         'TRUE_EC364_PARENT_CRYPTO_REPLAY_REQUIRED','permission_denied')
    replay_sha=sha(canonical.canonical(replay))
    parentpins={};newpins={};oldpaths={v for k,v in cross_inputs.items()
                       if k.endswith('_file') and type(v) is str}
    epochs,parent_bundle,epoch_args=_verified_endpoints(
        cross_inputs,replay,now,parentpins,oldpaths)
    oldpaths.update(parentpins)
    edges,verified_proofs,invalid_proofs=_proofs(epochs,parent_bundle)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=(not replay['parent_ec363_locally_coherent'] or
      any(not r['parent_locally_coherent'] for r in replay['epoch_reviews']) or
      any(replay[name] for name,_ in parent.FLAG_MAP
          if name!='cross_window_consistency_proof_missing_or_invalid'))
    # Directory signer changes are the single deliberately unresolved EC364
    # case that can be resolved locally here, not a blanket EC364 PASS override.
    if len(epochs)<2:flags[FLAGS[0]]=True
    flags[FLAGS[6]]=invalid_proofs
    declared=(('epoch_directory_root_shas','key_sha'),
      ('epoch_source_a_manifest_shas','a'),('epoch_source_b_manifest_shas','b'),
      ('epoch_signed_checkpoint_shas','cp_sha'))
    for key,attribute in declared:
        values=inputs.get(key,[])
        actual=[e['sources'][attribute]['manifest_sha'] if attribute in parent.SLOTS
                else e[attribute] for e in epochs]
        if len(values)!=len(actual) or values!=actual:
            flags[FLAGS[1]]=True
    if (inputs.get('expected_retained_initial_directory_root_sha256')!=
           epochs[0]['key_sha'] or
        inputs.get('expected_retained_current_directory_root_sha256')!=
           epochs[-1]['key_sha'] or
        tree_floor is None or epochs[-1]['cp']['tree_size']<tree_floor or
        generation_floor is None):flags[FLAGS[1]]=True
    by_size=defaultdict(set)
    for e in epochs:
        for slot in parent.SLOTS:
            cp=e['sources'][slot]['checkpoint']
            by_size[cp['tree_size']].add(cp['root_sha256'])
    if any(len(roots)>1 for roots in by_size.values()):flags[FLAGS[5]]=True
    root_seen=defaultdict(list)
    for e in epochs:root_seen[e['key_sha']].append(e['index'])
    if any(indices!=list(range(indices[0],indices[-1]+1)) for indices in
           root_seen.values()):flags[FLAGS[4]]=True   # reanimated retired signer
    # Root signer cannot be recycled from a different previously replayed
    # role merely because it is *new* in the directory-key position. Include
    # all directly pinned public/root/observer/issuer/challenger roles from
    # every historic EC362 argument snapshot, not just source custodians.
    other_role_keys={row['source_'+s+'_custodian_key_sha256']
                     for row in replay['epoch_reviews'] for s in parent.SLOTS}
    for args in epoch_args:
        for field,value in args.items():
            if field=='expected_directory_public_key_sha256':continue
            if ('public_key' not in field and '_root_key_' not in field and
                'signer_key' not in field):continue
            if tr._sha(value):other_role_keys.add(value)
            elif type(value) is list:
                other_role_keys.update(v for v in value if tr._sha(v))
    if any(k in other_role_keys for k in root_seen):flags[FLAGS[4]]=True
    if any(e['directory_id']!=epochs[0]['directory_id'] or
           e['sources']['a']['manifest']['directory_id']!=
           e['sources']['b']['manifest']['directory_id'] for e in epochs):
        flags[FLAGS[4]]=True
    if not any(l['key_sha']!=r['key_sha'] for l,r in zip(epochs,epochs[1:])):
        flags[FLAGS[9]]=True
    bundle=None;reviews=[];verified_signatures=0
    path=inputs.get('directory_authority_bundle_file')
    categories={}
    if path is None:
        flags[FLAGS[2]]=True
    else:
        raw=authority.load({'path':path,
             'sha256':inputs['expected_directory_authority_bundle_sha256']},
             'EC365_DIRECTORY_AUTHORITY_BUNDLE',MAX_BUNDLE,newpins,oldpaths,
             categories,'ec365_signed_handoff_bundle')
        bundle=tr.strict_json(raw,'EC365_DIRECTORY_AUTHORITY_BUNDLE')
        exact(bundle,BUNDLE_FIELDS,'DIRECTORY_AUTHORITY_HANDOFF_BUNDLE')
        need(bundle['schema']==BUNDLE_SCHEMA and
             bundle['parent_ec364_canonical_result_sha256']==replay_sha and
             type(bundle['claimed_directory_lineage_id']) is str and
             bundle['claimed_directory_lineage_id']==epochs[0]['directory_id'],
             'DIRECTORY_AUTHORITY_BUNDLE_PARENT_OR_ID_MISMATCH',
             'permission_denied')
        refs=bundle['signed_directory_handoffs']
        need(type(refs) is list and len(refs)<=MAX_EVENTS,
             'SIGNED_DIRECTORY_HANDOFF_COUNT_INVALID')
        for ref in refs:parent.ref_check(ref,'AUTHORITY_SIGNED_HANDOFF_REF')
        if len(refs)!=len(inputs.get('signed_directory_handoff_shas',[])):
            flags[FLAGS[2]]=True
        for i,ref in enumerate(refs):
            if i>=len(inputs.get('signed_directory_handoff_shas',[])):
                flags[FLAGS[2]]=True
            elif ref['sha256']!=inputs['signed_directory_handoff_shas'][i]:
                flags[FLAGS[1]]=True
        seen=defaultdict(list)
        # In the presence of contradictory valid signed handoffs, ALL events
        # must be signature checked before raising a visible fork flag.
        for i,ref in enumerate(refs):
            eventraw=authority.load(ref,'EC365_TRUE_SIGNED_HANDOFF_'+str(i),
                    MAX_EVENT,newpins,oldpaths,categories,
                    'ec365_directory_handoff_'+str(i))
            doc=tr.strict_json(eventraw,'EC365_DIRECTORY_AUTHORITY_HANDOFF')
            exact(doc,EVENT_FIELDS,'DIRECTORY_HANDOFF_ORIGINAL')
            edge=doc['from_epoch_index']
            need(type(edge) is int and 0<=edge<len(epochs)-1,
                 'HANDOFF_EDGE_MUST_BE_ADJACENT_REPLAYED_EPOCHS',
                 'permission_denied')
            proof=edges.get(edge)
            need(proof is not None,'SIGNED_HANDOFF_REQUIRES_PRESENTED_RFC6962_EDGE',
                 'permission_denied')
            # Derive expected generation from actual observed signer *changes*,
            # not from unsigned or signed generation claims in the event.
            generation=sum(epochs[j]['key_sha']!=epochs[j+1]['key_sha']
                           for j in range(edge))
            v=_check_signed_handoff(doc,epochs[edge],epochs[edge+1],proof,
                   bundle['claimed_directory_lineage_id'],generation,now)
            verified_signatures+=1
            if v['clock']:flags[FLAGS[8]]=True
            if v['role_bad']:flags[FLAGS[4]]=True
            if v['terminal']:flags[FLAGS[7]]=True
            seen[edge].append(ref['sha256'])
            reviews.append({'from_epoch_index':edge,'to_epoch_index':edge+1,
              'handoff_original_sha256':ref['sha256'], 'event_kind':v['event_kind'],
              'from_root_sha256':epochs[edge]['key_sha'],
              'to_root_sha256':epochs[edge+1]['key_sha'],
              'from_root_generation':generation,
              'to_root_generation':v['generation'],
              'true_old_and_new_directory_signatures_verified':True,
              'signed_kind_and_generation_match_actual_replay':not v['role_bad'],
              'signed_claimed_clock_anomaly':v['clock']})
        if any(len(seen[i])!=1 for i in range(len(epochs)-1)):
            flags[FLAGS[2]]=True
        if any(len(v)>1 for v in seen.values()):flags[FLAGS[3]]=True
    true_generation=sum(epochs[i]['key_sha']!=epochs[i+1]['key_sha']
                        for i in range(len(epochs)-1))
    if generation_floor is not None and true_generation<generation_floor:
        flags[FLAGS[1]]=True
    tsa._check_late(parentpins)
    tsa._check_late(newpins)
    if bundle is not None:
        parent.history.parent.previous.parent.parent._late_identity_check(
            newpins,oldpaths)
    local=(len(epochs)>=2 and verified_proofs==len(epochs)-1 and
           verified_signatures==len(epochs)-1 and not any(flags.values()))
    winner=next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                OUTCOMES[-1])
    # No trusted key bootstrap or latest completeness even after local success.
    evidence=[{'tsa_channel_id':row['tsa_channel_id'],
       'parent_ec364_outcome':row['outcome'], 'outcome':winner}
       for row in replay['channel_evidence']]
    return {'schema':RESULT_SCHEMA,'command':'audit-directory-authority',
      'status':winner+'_unresolved','exit_code':2,'case_id':replay['case_id'],
      'actual_ec364_through_ec337_signed_originals_replayed':True,
      'parent_ec364_canonical_result_sha256':replay_sha,
      'parent_ec364_locally_coherent':
          replay['locally_coherent_cross_epoch_signed_publication'],
      'directory_lineage_evaluation_utc_as_caller_claim':directory_lineage_evaluation_utc,
      'directory_authority_bundle_original_sha256':
          inputs.get('expected_directory_authority_bundle_sha256'),
      'caller_minimum_retained_root_generation':generation_floor,
      'caller_minimum_retained_latest_tree_size':tree_floor,
      'true_directory_root_generation':true_generation,
      'retained_initial_root_sha256':inputs.get('expected_retained_initial_directory_root_sha256'),
      'retained_current_root_sha256':inputs.get('expected_retained_current_directory_root_sha256'),
      'epoch_lineage_reviews':[{'epoch_index':e['index'],
           'actual_directory_key_original_sha256':e['key_sha'],
           'signed_checkpoint_original_sha256':e['cp_sha'],
           'signed_tree_size':e['cp']['tree_size'],
           'signed_merkle_root_sha256':e['cp']['root_sha256'],
           'signed_claimed_directory_id':e['directory_id'],
           'true_parent_ec361_canonical_result_sha256':e['ec361_sha'],
           'source_a_manifest_original_sha256':e['sources']['a']['manifest_sha'],
           'source_b_manifest_original_sha256':e['sources']['b']['manifest_sha']}
             for e in epochs],
      'signed_directory_handoff_reviews':reviews,
      'true_signed_directory_handoff_originals_verified':verified_signatures,
      'actual_cross_root_rfc6962_proofs_verified':verified_proofs,
      **flags,
      'locally_authorized_directory_signer_transition':local,
      'official_identity_legal_independence_physical_custody_trusted_utc_and_global_head_unproven':True,
      'channel_evidence':evidence,
      'outcome_counts':{o:sum(row['outcome']==o for row in evidence)
                        for o in OUTCOMES},
      'offline_unresolved_exit_code':2,
      **{k:False for k in NEGATIVES}}
