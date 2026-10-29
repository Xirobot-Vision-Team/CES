#!/usr/bin/env python3
"""EC366 read-only, two independently SHA-pinned institution root-provenance views.

Each evaluation actually invokes EC365's entire EC364..EC337 replay. Caller-
retained keys and their signed status/attestation histories are *additional*
evidence, not trust anchors acquired from a bundle or evidence of real legal
independence. Genuine conflicting signatures remain visible. Checkpoints first
verified by EC365 can be compared to newly presented genuine directory-signed
checkpoints; unsupported claims are never upgraded to verified split views.

No private key, network fetch, OS authority lookup, provider/CAS/WORM writer,
or external official identity attestation is created by this verifier.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from authority_directory import authority
from directory_consistency import consistency
from cross_epoch import continuity as historic
from directory_lineage import lineage as parent

RESULT_SCHEMA='ces.ec366.offline_two_institution_root_provenance_unresolved.v1'
DENIAL_SCHEMA='ces.ec366.offline_two_institution_root_provenance_denial.v1'
HANDOFF_SCHEMA='ces.ec366.unsigned_root_provenance_handoff.v1'
BUNDLE_SCHEMA='ces.ec366.two_institution_root_provenance_bundle.v1'
STATUS_SCHEMA='ces.ec366.institution_root_status.v1'
ATTEST_SCHEMA='ces.ec366.institution_signed_root_provenance.v1'
STATUS_DOMAIN=b'CES/EC366/InstitutionRootStatus/v1\x00'
ATTEST_DOMAIN=b'CES/EC366/InstitutionRootProvenance/v1\x00'
MAX_BUNDLE=18_000
MAX_STATUS=5_000
MAX_ATTEST=11_000
MAX_ORIGINAL_CP=5_000
MAX_EVENTS_PER_ROLE=4
MAX_EXTRA_CP=4
MAX_SPAN=timedelta(days=7)
ROLES=('origin_registry','independent_archive')
BUNDLE_FIELDS={'schema','parent_ec365_canonical_result_sha256',
 'claimed_directory_lineage_id','institutions','additional_signed_checkpoints'}
INSTITUTION_FIELDS={'claimed_institution_id','claimed_institution_role',
 'institution_public_key_original_sha256','signed_status_events','signed_provenance_attestations'}
STATUS_FIELDS={'schema','claimed_institution_id','claimed_institution_role',
 'institution_public_key_original_sha256','parent_ec365_canonical_result_sha256',
 'sequence','previous_status_original_sha256','action',
 'successor_public_key_original_sha256','issued_utc','expires_utc',
 'signature_institution_ed25519_hex'}
ATTEST_FIELDS={'schema','claimed_institution_id','claimed_institution_role',
 'institution_public_key_original_sha256','parent_ec365_canonical_result_sha256',
 'institution_status_original_sha256','sequence','previous_attestation_original_sha256',
 'directory_lineage_id','attestation_kind','directory_root_generation',
 'epoch_signed_directory_observations','signed_directory_handoff_original_shas',
 'observed_checkpoint_original_sha256','observed_tree_size',
 'observed_merkle_root_sha256','issued_utc','expires_utc',
 'signature_institution_ed25519_hex'}
EXTRA_CP_FIELDS={'signer_epoch_index','original'}
OBSERVATION_FIELDS={'epoch_index','directory_root_public_key_original_sha256',
 'directory_checkpoint_original_sha256','signed_tree_size','signed_merkle_root_sha256',
 'parent_ec361_canonical_result_sha256','source_a_manifest_original_sha256',
 'source_b_manifest_original_sha256'}
NEW_REQUIRED=('root_provenance_evaluation_utc',)
NEW_OPTIONAL=(
 'root_provenance_bundle_file','expected_root_provenance_bundle_sha256',
 'minimum_retained_origin_registry_sequence',
 'minimum_retained_independent_archive_sequence',
 'expected_retained_origin_registry_status_head_sha256',
 'expected_retained_independent_archive_status_head_sha256',
 'expected_retained_origin_registry_attestation_head_sha256',
 'expected_retained_independent_archive_attestation_head_sha256',
)
NEW_REPEATS=(
 ('institution_root_public_key_files','--institution-root-public-key-file'),
 ('institution_root_public_key_shas','--institution-root-public-key-sha256'),
 ('institution_claimed_ids','--institution-claimed-id'),
 ('signed_institution_status_shas','--signed-institution-status-sha256'),
 ('signed_institution_attestation_shas','--signed-institution-attestation-sha256'),
 ('additional_signed_checkpoint_shas','--additional-signed-checkpoint-sha256'),
)
NEW_REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
FLAGS=(
 'inherited_ec365_directory_lineage_defect_visible',
 'institution_root_or_signing_role_alias_visible',
 'independent_institution_head_or_sequence_rollback_visible',
 'genuine_institution_status_history_fork_or_gap_visible',
 'signed_institution_root_revocation_or_rotation_visible',
 'two_current_root_provenance_corroborations_missing',
 'genuine_signed_institution_provenance_fork_or_dispute_visible',
 'signed_institution_provenance_contradicts_actual_directory_originals',
 'genuine_directory_signed_checkpoint_split_view_visible',
 'institution_self_claimed_utc_anomaly_visible',
 'extra_signed_checkpoint_not_proven_append_only_to_replayed_log',
)
OUTCOMES=(
 'ec366_inherited_ec365_directory_lineage_unresolved',
 'ec366_claimed_institution_root_or_prior_signer_role_collision',
 'ec366_independently_retained_institution_status_or_attestation_rollback',
 'ec366_authentically_signed_institution_status_fork_or_gap',
 'ec366_institution_root_signed_revocation_or_rotation_terminal',
 'ec366_two_active_institution_root_corroborations_not_demonstrated',
 'ec366_authentically_signed_provenance_fork_dispute_or_withdrawal',
 'ec366_signed_institution_claim_conflicts_with_original_directory_proofs',
 'ec366_genuine_signed_directory_checkpoint_same_size_split_view',
 'ec366_institution_signed_clock_cannot_be_trusted',
 'ec366_extra_signed_checkpoint_append_only_not_reverified',
 'ec366_two_separately_pinned_institution_provenance_views_locally_correlated_official_provenance_unproven',
)
NEGATIVES=(
 'two_caller_pinned_public_keys_prove_legally_independent_institutions',
 'institution_self_claimed_name_or_role_proves_official_registration',
 'two_valid_signatures_establish_government_sovereignty_or_root_ownership',
 'institution_status_renewal_proves_historical_trusted_utc',
 'signed_external_provenance_repairs_parent_ec365_fork_or_failed_handoff',
 'signed_extra_checkpoint_without_append_proof_establishes_global_latest',
 'signed_but_unverified_checkpoint_claim_is_true_directory_fork',
 'root_revocation_or_signed_dispute_can_be_silently_ignored',
 'unseen_global_split_views_or_hidden_forks_have_been_excluded',
 'network_or_os_trust_store_was_queried_or_authenticated',
 'private_signer_or_remote_provider_cas_worm_writer_used',
 'native_powershell_or_old_mock_or_final_human_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC366_'+code,status)


def exact(obj,fields,role):
    need(type(obj) is dict and set(obj)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _parent_inputs(inputs):
    return {k:v for k,v in inputs.items() if k not in NEW_REQUIRED and
            k not in NEW_OPTIONAL and k not in NEW_REPEAT_NAMES}


def _validate_new_inputs(inputs):
    authority.outer_pin(inputs.get('root_provenance_bundle_file'),
                        inputs.get('expected_root_provenance_bundle_sha256'),
                        'EC366_ROOT_PROVENANCE_BUNDLE')
    for role in ROLES:
        for typ in ('status','attestation'):
            k='expected_retained_'+role+'_'+typ+'_head_sha256'
            need(inputs.get(k) is None or tr._sha(inputs[k]),
                 'RETAINED_'+typ.upper()+'_HEAD_PIN_INVALID')
        floor=inputs.get('minimum_retained_'+role+'_sequence')
        need(floor is None or (type(floor) is int and 1<=floor<=8),
             'INDEPENDENT_SEQUENCE_FLOOR_INVALID')
    keys=inputs.get('institution_root_public_key_files',[])
    hashes=inputs.get('institution_root_public_key_shas',[])
    ids=inputs.get('institution_claimed_ids',[])
    need(type(keys) is list and len(keys)==2 and all(type(v) is str for v in keys)
         and type(hashes) is list and len(hashes)==2 and all(tr._sha(v) for v in hashes)
         and len(set(hashes))==2 and type(ids) is list and len(ids)==2 and
         all(tr._ident(v) for v in ids) and len(set(ids))==2,
         'TWO_DISTINCT_EXTERNALLY_PINNED_INSTITUTIONS_REQUIRED')
    for k,cap in (('signed_institution_status_shas',8),
                  ('signed_institution_attestation_shas',8),
                  ('additional_signed_checkpoint_shas',MAX_EXTRA_CP)):
        v=inputs.get(k,[])
        need(type(v) is list and len(v)<=cap and
             all(tr._sha(s) for s in v) and len(set(v))==len(v),
             'EXTERNAL_'+k.upper()+'_INVALID')


def _load(ref,role,cap,pins,oldpaths,categories,category):
    return authority.load(ref,'EC366_'+role,cap,pins,oldpaths,categories,category)


def _sig(doc,pub,domain,role):
    # Strict, domain-separated actual Ed25519; never a supplied 'signature_valid'.
    authority.sig(doc,'signature_institution_ed25519_hex',pub,domain,
                  'EC366_'+role)


def _claimed_clock(doc,now):
    first,last=authority.window(doc['issued_utc'],doc['expires_utc'],MAX_SPAN,
                                'EC366_SIGNED_INSTITUTION_CLAIM')
    return authority.utc_untrusted(now,first,last,MAX_SPAN)


def _check_status_shape(doc):
    exact(doc,STATUS_FIELDS,'SIGNED_INSTITUTION_STATUS')
    need(doc['schema']==STATUS_SCHEMA and
         type(doc['sequence']) is int and 0<=doc['sequence']<=8 and
         doc['action'] in ('activate','renew','revoke','rotate') and
         (doc['previous_status_original_sha256'] is None or
          tr._sha(doc['previous_status_original_sha256'])) and
         (doc['successor_public_key_original_sha256'] is None or
          tr._sha(doc['successor_public_key_original_sha256'])),
         'SIGNED_STATUS_SCHEMA_OR_FIELDS_INVALID')


def _check_attestation_shape(doc,maximum_epochs):
    exact(doc,ATTEST_FIELDS,'SIGNED_INSTITUTION_PROVENANCE')
    need(doc['schema']==ATTEST_SCHEMA and
         type(doc['sequence']) is int and 1<=doc['sequence']<=8 and
         (doc['previous_attestation_original_sha256'] is None or
          tr._sha(doc['previous_attestation_original_sha256'])) and
         tr._sha(doc['institution_status_original_sha256']) and
         doc['attestation_kind'] in ('corroborate','dispute','withdraw') and
         type(doc['directory_root_generation']) is int and
         0<=doc['directory_root_generation']<=2 and
         type(doc['epoch_signed_directory_observations']) is list and
         1<=len(doc['epoch_signed_directory_observations'])<=maximum_epochs and
         type(doc['signed_directory_handoff_original_shas']) is list and
         len(doc['signed_directory_handoff_original_shas'])<=5 and
         all(tr._sha(x) for x in doc['signed_directory_handoff_original_shas']) and
         tr._sha(doc['observed_checkpoint_original_sha256']) and
         type(doc['observed_tree_size']) is int and 1<=doc['observed_tree_size']<=64 and
         tr._sha(doc['observed_merkle_root_sha256']),
         'SIGNED_PROVENANCE_FIELDS_INVALID')
    for row in doc['epoch_signed_directory_observations']:
        exact(row,OBSERVATION_FIELDS,'SIGNED_EPOCH_OBSERVATION')
        need(type(row['epoch_index']) is int and
             0<=row['epoch_index']<maximum_epochs and
             type(row['signed_tree_size']) is int and
             1<=row['signed_tree_size']<=64 and
             all(tr._sha(v) for k,v in row.items() if k.endswith('sha256')),
             'SIGNED_EPOCH_OBSERVATION_FORMAT_INVALID')


def _parents_for_signed_checkpoint(parent_inputs, parent_result, pins):
    """Reopen old/new caller SHA-pinned signer key originals from the real EC364 snapshots.

    EC365 already checked every one against the signed publications and
    Ed25519 checkpoint. This second read is only for an *additional* checkpoint.
    """
    cross_inputs=parent._parent_inputs(parent_inputs)
    bundle_ref={'path':cross_inputs.get('cross_epoch_bundle_file'),
                'sha256':cross_inputs.get('expected_cross_epoch_bundle_sha256')}
    data=tr.strict_json(parent._read_original(bundle_ref,'PARENT_364_BUNDLE',
                                                  historic.MAX_BUNDLE,pins),
                         'EC366_PARENT_364_BUNDLE')
    exact(data,historic.BUNDLE_FIELDS,'REPLAYED_EC364_BUNDLE')
    live=historic._ec362_inputs(historic._parent_inputs({k:v for k,v in
                    cross_inputs.items() if k!='cross_epoch_evaluation_utc'}))
    args=[]
    for i,ref in enumerate(data['historical_parent_snapshots']):
        raw=parent._read_original(ref,'PARENT_364_WINDOW_'+str(i),
                                  historic.MAX_SNAPSHOT,pins)
        snapshot=tr.strict_json(raw,'EC366_REPLAYED_PARENT_SNAPSHOT')
        exact(snapshot,historic.SNAPSHOT_FIELDS,'PARENT_364_SNAPSHOT')
        need(snapshot['schema']==historic.SNAPSHOT_SCHEMA and
             snapshot['epoch_index']==i and
             type(snapshot['ec362_audit_inputs']) is dict and
             set(snapshot['ec362_audit_inputs'])==set(live),
             'REPLAYED_PARENT_EPOCH_INPUTS_MISMATCH','permission_denied')
        args.append(snapshot['ec362_audit_inputs'])
    args.append(live)
    reviews=parent_result['epoch_lineage_reviews']
    need(len(args)==len(reviews),'REPLAYED_PARENT_ROOT_COUNT_MISMATCH',
         'permission_denied')
    keys=[]
    for i,epoch in enumerate(args):
        ref={'path':epoch['directory_public_key_file'],
             'sha256':epoch['expected_directory_public_key_sha256']}
        pub=parent._read_original(ref,'REPLAYED_DIRECTORY_KEY_'+str(i),32,pins)
        need(len(pub)==32 and ref['sha256']==reviews[i][
             'actual_directory_key_original_sha256'],
             'DIRECTORY_SIGNER_NOT_THE_REPLAYED_EC365_SIGNER','permission_denied')
        keys.append(pub)
    return keys,args


def _external_checkpoints(bundle, prior, now, keys, newpins,
                          oldpaths,categories,inputs,flags):
    extra=bundle['additional_signed_checkpoints']
    need(type(extra) is list and len(extra)<=MAX_EXTRA_CP,
         'ADDITIONAL_CHECKPOINT_REFS_BOUNDS_INVALID')
    reviews=prior['epoch_lineage_reviews']
    result={r['signed_checkpoint_original_sha256']:{'tree_size':r['signed_tree_size'],
        'root_sha256':r['signed_merkle_root_sha256'],
        'signer_epoch_index':r['epoch_index'], 'is_replayed_parent':True}
        for r in reviews}
    extras=[];signed_pairs=defaultdict(set)
    for i,r in enumerate(reviews):
        signed_pairs[(r['actual_directory_key_original_sha256'],
                      r['signed_tree_size'])].add(r['signed_merkle_root_sha256'])
    for index,row in enumerate(extra):
        exact(row,EXTRA_CP_FIELDS,'ADDITIONAL_SIGNED_CHECKPOINT')
        e=row['signer_epoch_index']
        need(type(e) is int and 0<=e<len(reviews),
             'ADDITIONAL_SIGNED_CHECKPOINT_EPOCH_INVALID')
        ref=row['original'];historic.ref_check(ref,'ADDITIONAL_CP_REF')
        need(ref['sha256'] not in result,
             'DUPLICATE_PARENT_OR_ALTERNATE_CHECKPOINT_INVALID')
        raw=_load(ref,'ALT_SIGNED_CHECKPOINT_'+str(index),MAX_ORIGINAL_CP,
                  newpins,oldpaths,categories,'ec366_new_signed_cp_'+str(index))
        cp,stale=consistency.signed_checkpoint(raw,keys[e],
                       reviews[e]['actual_directory_key_original_sha256'],
                       reviews[e]['signed_claimed_directory_id'],now)
        if stale:flags[FLAGS[9]]=True
        need(cp['directory_public_key_original_sha256']==reviews[e][
                 'actual_directory_key_original_sha256'],
             'NEW_CP_SIGNED_BY_DIFFERENT_DIRECTORY_ROLE','permission_denied')
        key=(reviews[e]['actual_directory_key_original_sha256'],cp['tree_size'])
        signed_pairs[key].add(cp['root_sha256'])
        entry={'tree_size':cp['tree_size'],'root_sha256':cp['root_sha256'],
               'signer_epoch_index':e,'is_replayed_parent':False}
        result[ref['sha256']]=entry
        extras.append({'original_sha256':ref['sha256'],
                       'actual_directory_signature_verified':True,
                       'signer_epoch_index':e,
                       'signed_tree_size':cp['tree_size'],
                       'signed_merkle_root_sha256':cp['root_sha256']})
        if (cp['tree_size']!=reviews[e]['signed_tree_size'] or
            cp['root_sha256']!=reviews[e]['signed_merkle_root_sha256']):
            # A larger signed tree without a genuine RFC6962 path is *not*
            # automatically a proven ancestor of the EC365 replayed tree.
            if cp['tree_size']!=reviews[e]['signed_tree_size']:
                flags[FLAGS[10]]=True
    if any(len(roots)>1 for roots in signed_pairs.values()):
        flags[FLAGS[8]]=True
    if len(extra)!=len(inputs['additional_signed_checkpoint_shas']) or any(
        extra[i]['original']['sha256']!=pin for i,pin in enumerate(
                       inputs['additional_signed_checkpoint_shas'])):
        flags[FLAGS[2]]=True
    return result,extras


def _claimed_observations(prior):
    return [{'epoch_index':r['epoch_index'],
             'directory_root_public_key_original_sha256':r['actual_directory_key_original_sha256'],
             'directory_checkpoint_original_sha256':r['signed_checkpoint_original_sha256'],
             'signed_tree_size':r['signed_tree_size'],
             'signed_merkle_root_sha256':r['signed_merkle_root_sha256'],
             'parent_ec361_canonical_result_sha256':r['true_parent_ec361_canonical_result_sha256'],
             'source_a_manifest_original_sha256':r['source_a_manifest_original_sha256'],
             'source_b_manifest_original_sha256':r['source_b_manifest_original_sha256']}
            for r in prior['epoch_lineage_reviews']]


def _history(items,*,kind,role,inputs,flags):
    """Analyze all *verified signed* originals, never silently pick a branch."""
    if not items:
        flags[FLAGS[5]]=True
        return None,False
    by_sha={r['sha']:r for r in items}
    seqfield='sequence'
    previous='previous_status_original_sha256' if kind=='status' else \
             'previous_attestation_original_sha256'
    children=defaultdict(list)
    for row in items:
        doc=row['document'];seq=doc[seqfield];prev=doc[previous]
        children[prev].append(row['sha'])
        if seq==(0 if kind=='status' else 1):
            if prev is not None or (kind=='status' and doc['action']!='activate'):
                flags[FLAGS[3 if kind=='status' else 6]]=True
        elif prev not in by_sha or (prev in by_sha and
             by_sha[prev]['document'][seqfield]!=seq-1):
            flags[FLAGS[3 if kind=='status' else 6]]=True
    for siblings in children.values():
        if len(siblings)>1:flags[FLAGS[3 if kind=='status' else 6]]=True
    max_sequence=max(r['document']['sequence'] for r in items)
    leaves=[r for r in items if r['sha'] not in children]
    if len(leaves)!=1 or leaves[0]['document']['sequence']!=max_sequence:
        flags[FLAGS[3 if kind=='status' else 6]]=True
    selected=leaves[0] if len(leaves)==1 else None
    key='expected_retained_'+role+'_'+('status' if kind=='status' else 'attestation')+'_head_sha256'
    retained=inputs.get(key)
    if selected is None or retained is None or selected['sha']!=retained:
        flags[FLAGS[2]]=True
    floor=inputs.get('minimum_retained_'+role+'_sequence')
    if kind=='attestation' and (floor is None or max_sequence<floor):
        flags[FLAGS[2]]=True
    if len(by_sha)!=len(items):flags[FLAGS[3 if kind=='status' else 6]]=True
    return selected,selected is not None and selected['sha']==retained


def checklist(**parent_inputs):
    prior=parent.audit(**parent_inputs)
    need(prior['schema']==parent.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec364_through_ec337_signed_originals_replayed'] is True,
         'TRUE_EC365_THROUGH_EC337_PARENT_REQUIRED','permission_denied')
    return {'schema':HANDOFF_SCHEMA,
      'command':'derive-root-provenance-handoff',
      'status':'independently_retained_institution_status_and_provenance_originals_required_unresolved',
      'exit_code':2,'case_id':prior['case_id'],
      'actual_ec365_through_ec337_signed_originals_replayed':True,
      'parent_ec365_canonical_result_sha256':sha(canonical.canonical(prior)),
      'required_external_material':[
        'two externally caller-SHA-pinned distinct institution public-key originals and independent claimed institution IDs',
        'two role-separated Ed25519-signed institutional status histories with retained caller SHA heads',
        'root-signed canonical provenance attestations binding ALL genuine EC365 epoch roots, checkpoints, sources, generation and co-signed handoff hashes',
        'independent retained per-institution provenance SHA heads and minimum sequence floors',
        'optional extra genuinely directory-signed checkpoint originals for visible split-view comparison'],
      'real_legal_identity_physical_independence_official_root_ownership_trusted_utc_global_latest_unproven':True,
      'offline_unresolved_exit_code':2,
      **{k:False for k in NEGATIVES}}


def audit(*,root_provenance_evaluation_utc,**inputs):
    now=tr._utc(root_provenance_evaluation_utc)
    _validate_new_inputs(inputs)
    parent_inputs=_parent_inputs(inputs)
    need(now>=tr._utc(parent_inputs['directory_lineage_evaluation_utc']),
         'EVALUATION_PRECEDES_TRUE_EC365_PARENT','permission_denied')
    # This is the real EC365 verifier, not an injected JSON verdict or marker.
    prior=parent.audit(**parent_inputs)
    need(prior['schema']==parent.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec364_through_ec337_signed_originals_replayed'] is True,
         'SIGNED_EC365_TO_EC337_PARENT_NOT_REPLAYED','permission_denied')
    prior_sha=sha(canonical.canonical(prior))
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not prior['locally_authorized_directory_signer_transition']
    roots=prior['epoch_lineage_reviews']
    true_directory_id=roots[0]['signed_claimed_directory_id']
    true_generation=prior['true_directory_root_generation']
    original_handoffs=[r['handoff_original_sha256']
                       for r in prior['signed_directory_handoff_reviews']]
    expected_observations=_claimed_observations(prior)
    inherited_paths={v for k,v in parent_inputs.items() if k.endswith('_file')
                     and type(v) is str}
    oldpins={};newpins={};categories={}
    institution_roots=[]
    for i,role in enumerate(ROLES):
        ref={'path':inputs['institution_root_public_key_files'][i],
             'sha256':inputs['institution_root_public_key_shas'][i]}
        raw=_load(ref,'INSTITUTION_ROOT_'+role,32,newpins,
                  inherited_paths,categories,'ec366_institution_root_'+role)
        need(len(raw)==32,'INSTITUTION_KEY_MUST_BE_ED25519_32_BYTES',
             'permission_denied')
        institution_roots.append(raw)
    # Inspect true current and all signed historical role-key SHA pins, not
    # merely the source custodians in the latest EC365 input snapshot.
    collision_roles=set()
    for k,v in parent_inputs.items():
        if 'public_key' in k or 'signer_key' in k or 'root_key' in k:
            if tr._sha(v):collision_roles.add(v)
            elif type(v) is list:collision_roles.update(x for x in v if tr._sha(x))
    collision_roles.update(r['actual_directory_key_original_sha256'] for r in roots)
    # EC364's historic snapshot inputs contain older role keys which are not
    # visible in today's flat CLI arguments. Reopen them after EC365's true
    # replay instead of letting an 'institution' reuse an old custodian key.
    epoch_keys,epoch_args=_parents_for_signed_checkpoint(parent_inputs,prior,oldpins)
    for epoch in epoch_args:
        for k,v in epoch.items():
            if 'public_key' in k or 'signer_key' in k or 'root_key' in k:
                if tr._sha(v):collision_roles.add(v)
                elif type(v) is list:
                    collision_roles.update(x for x in v if tr._sha(x))
    if any(k in collision_roles for k in inputs['institution_root_public_key_shas']):
        flags[FLAGS[1]]=True
    if institution_roots[0]==institution_roots[1]:flags[FLAGS[1]]=True
    bundle_ref={'path':inputs.get('root_provenance_bundle_file'),
                'sha256':inputs.get('expected_root_provenance_bundle_sha256')}
    reviewed=[];extra_reviews=[]
    verified_status=0;verified_attest=0;active_count=0
    if bundle_ref['path'] is None:
        flags[FLAGS[5]]=True
    else:
        raw=_load(bundle_ref,'PROVENANCE_BUNDLE',MAX_BUNDLE,newpins,
                  inherited_paths,categories,'ec366_new_provenance_bundle')
        bundle=tr.strict_json(raw,'EC366_PROVENANCE_BUNDLE')
        exact(bundle,BUNDLE_FIELDS,'TWO_INSTITUTION_PROVENANCE_BUNDLE')
        need(bundle['schema']==BUNDLE_SCHEMA and
             bundle['parent_ec365_canonical_result_sha256']==prior_sha and
             bundle['claimed_directory_lineage_id']==true_directory_id and
             type(bundle['institutions']) is list and len(bundle['institutions'])==2,
             'PROVENANCE_BUNDLE_PARENT_OR_DIRECTORY_BINDING_INVALID',
             'permission_denied')
        for i,item in enumerate(bundle['institutions']):
            exact(item,INSTITUTION_FIELDS,'INSTITUTION_PROVENANCE_ENTRY')
            need(item['claimed_institution_role']==ROLES[i] and
                 item['claimed_institution_id']==inputs['institution_claimed_ids'][i] and
                 item['institution_public_key_original_sha256']==
                    inputs['institution_root_public_key_shas'][i],
                 'INSTITUTION_ROLE_ROOT_OR_EXTERNALLY_RETAINED_ID_SWAPPED',
                 'permission_denied')
            for kind,key in (('STATUS','signed_status_events'),
                             ('ATTESTATION','signed_provenance_attestations')):
                refs=item[key]
                need(type(refs) is list and len(refs)<=MAX_EVENTS_PER_ROLE,
                     'BOUNDED_'+kind+'_REFS_REQUIRED')
                for ref in refs:historic.ref_check(ref,'EC366_'+kind+'_REF')
        # The bundle is not permitted to substitute its own roots/heads/pins.
        for section,external in (
            ('signed_status_events','signed_institution_status_shas'),
            ('signed_provenance_attestations','signed_institution_attestation_shas')):
            actual=[r['sha256'] for inst in bundle['institutions'] for r in inst[section]]
            if actual!=inputs[external]:flags[FLAGS[2]]=True
        cpmap,extra_reviews=_external_checkpoints(bundle,prior,now,epoch_keys,
                           newpins,inherited_paths,categories,inputs,flags)
        for i,inst in enumerate(bundle['institutions']):
            role=ROLES[i];pub=institution_roots[i]
            rows=[];atts=[]
            for j,ref in enumerate(inst['signed_status_events']):
                raw=_load(ref,'SIGNED_STATUS_'+role+'_'+str(j),MAX_STATUS,
                         newpins,inherited_paths,categories,
                         'ec366_signed_status_'+role+'_'+str(j))
                d=tr.strict_json(raw,'EC366_SIGNED_STATUS')
                _check_status_shape(d)
                need(d['claimed_institution_id']==inst['claimed_institution_id'] and
                     d['claimed_institution_role']==role and
                     d['institution_public_key_original_sha256']==
                       inst['institution_public_key_original_sha256'],
                     'SIGNED_INSTITUTION_STATUS_ROOT_IDENTITY_MISMATCH',
                     'permission_denied')
                _sig(d,pub,STATUS_DOMAIN,'ROOT_STATUS')
                verified_status+=1
                if d['parent_ec365_canonical_result_sha256']!=prior_sha:
                    flags[FLAGS[7]]=True
                if d['action'] in ('revoke','rotate'):
                    flags[FLAGS[4]]=True
                if ((d['action']=='rotate') !=
                     (d['successor_public_key_original_sha256'] is not None)):
                    flags[FLAGS[3]]=True
                if d['successor_public_key_original_sha256'] in (
                       inst['institution_public_key_original_sha256'],
                       *inputs['institution_root_public_key_shas']):
                    if d['action']=='rotate':flags[FLAGS[1]]=True
                clock=_claimed_clock(d,now)
                if clock:flags[FLAGS[9]]=True
                rows.append({'sha':ref['sha256'],'document':d,'clock':clock})
            status_head,status_retained=_history(rows,kind='status',role=role,
                                                  inputs=inputs,flags=flags)
            if status_head is None or status_head['document']['action'] not in (
                         'activate','renew'):
                flags[FLAGS[5]]=True
            status_docs={r['sha']:r['document'] for r in rows}
            for j,ref in enumerate(inst['signed_provenance_attestations']):
                raw=_load(ref,'SIGNED_ATTESTATION_'+role+'_'+str(j),MAX_ATTEST,
                    newpins,inherited_paths,categories,
                    'ec366_signed_attestation_'+role+'_'+str(j))
                d=tr.strict_json(raw,'EC366_SIGNED_ROOT_PROVENANCE')
                _check_attestation_shape(d,len(roots))
                need(d['claimed_institution_id']==inst['claimed_institution_id'] and
                     d['claimed_institution_role']==role and
                     d['institution_public_key_original_sha256']==
                         inst['institution_public_key_original_sha256'],
                     'SIGNED_PROVENANCE_INSTITUTION_KEY_OR_ROLE_MISMATCH',
                     'permission_denied')
                _sig(d,pub,ATTEST_DOMAIN,'ROOT_PROVENANCE')
                verified_attest+=1
                if d['attestation_kind'] in ('dispute','withdraw'):
                    flags[FLAGS[6]]=True
                matches=(d['parent_ec365_canonical_result_sha256']==prior_sha and
                         d['directory_lineage_id']==true_directory_id and
                         d['directory_root_generation']==true_generation and
                         d['epoch_signed_directory_observations']==expected_observations and
                         d['signed_directory_handoff_original_shas']==original_handoffs)
                observed=cpmap.get(d['observed_checkpoint_original_sha256'])
                checkpoint_ok=(observed is not None and
                    observed['tree_size']==d['observed_tree_size'] and
                    observed['root_sha256']==d['observed_merkle_root_sha256'])
                if not matches or not checkpoint_ok:
                    flags[FLAGS[7]]=True
                status_valid=(d['institution_status_original_sha256'] in status_docs
                     and status_docs[d['institution_status_original_sha256']]['action']
                         in ('activate','renew'))
                if not status_valid:flags[FLAGS[5]]=True
                clock=_claimed_clock(d,now)
                if clock:flags[FLAGS[9]]=True
                atts.append({'sha':ref['sha256'],'document':d,'clock':clock,
                             'matches':matches,'checkpoint_verified':checkpoint_ok,
                             'status_valid':status_valid})
            att_head,att_retained=_history(atts,kind='attestation',role=role,
                                           inputs=inputs,flags=flags)
            corroborated=(status_retained and att_retained and
                status_head is not None and att_head is not None and
                status_head['document']['action'] in ('activate','renew') and
                att_head['document']['attestation_kind']=='corroborate' and
                att_head['document']['institution_status_original_sha256']==
                    status_head['sha'] and att_head['matches'] and
                att_head['checkpoint_verified'] and
                att_head['document']['observed_checkpoint_original_sha256']==
                    roots[-1]['signed_checkpoint_original_sha256'] and
                not att_head['clock'] and
                not status_head['clock'] and
                not flags[FLAGS[4]] and not flags[FLAGS[3]] and
                not flags[FLAGS[6]])
            if corroborated:active_count+=1
            else:flags[FLAGS[5]]=True
            reviewed.append({'claimed_institution_role':role,
              'claimed_institution_id_as_caller_pin':inst['claimed_institution_id'],
              'public_key_original_sha256':inst['institution_public_key_original_sha256'],
              'signed_root_status_originals_verified':len(rows),
              'signed_root_provenance_originals_verified':len(atts),
              'retained_status_head_sha256':inputs.get(
                  'expected_retained_'+role+'_status_head_sha256'),
              'retained_attestation_head_sha256':inputs.get(
                  'expected_retained_'+role+'_attestation_head_sha256'),
              'actual_status_head_sha256':status_head['sha'] if status_head else None,
              'actual_attestation_head_sha256':att_head['sha'] if att_head else None,
              'status_head_action':status_head['document']['action'] if status_head else None,
              'latest_signed_attestation_kind':att_head['document'][
                  'attestation_kind'] if att_head else None,
              'current_corroboration_locally_verified':corroborated})
    if active_count!=2:flags[FLAGS[5]]=True
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    if bundle_ref['path'] is not None:
        parent.parent.history.parent.previous.parent.parent._late_identity_check(
           newpins,inherited_paths)
    local=(active_count==2 and verified_status>=2 and verified_attest>=2 and
           not any(flags.values()))
    winner=next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])
    evidence=[{'tsa_channel_id':r['tsa_channel_id'],
               'parent_ec365_outcome':r['outcome'],
               'outcome':winner} for r in prior['channel_evidence']]
    return {'schema':RESULT_SCHEMA,'command':'audit-root-provenance',
      'status':winner+'_unresolved','exit_code':2,'case_id':prior['case_id'],
      'actual_ec365_through_ec337_signed_originals_replayed':True,
      'parent_ec365_canonical_result_sha256':prior_sha,
      'parent_ec365_locally_authorized_directory_transition':prior[
          'locally_authorized_directory_signer_transition'],
      'root_provenance_evaluation_utc_as_caller_claim':root_provenance_evaluation_utc,
      'root_provenance_bundle_original_sha256':inputs.get(
          'expected_root_provenance_bundle_sha256'),
      'actual_directory_root_generation':true_generation,
      'actual_epoch_directory_original_reviews':roots,
      'actual_signed_directory_handoff_original_shas':original_handoffs,
      'true_verified_institution_status_signatures':verified_status,
      'true_verified_institution_provenance_signatures':verified_attest,
      'two_institution_original_reviews':reviewed,
      'extra_genuine_directory_signed_checkpoint_reviews':extra_reviews,
      'number_of_currently_corroborating_institution_roles':active_count,
      **flags,
      'locally_two_institutions_correlate_on_same_real_directory_lineage':local,
      'real_official_identity_legal_independence_physical_custody_trusted_utc_global_head_and_hidden_fork_absence_unproven':True,
      'channel_evidence':evidence,
      'outcome_counts':{o:sum(x['outcome']==o for x in evidence) for o in OUTCOMES},
      'offline_unresolved_exit_code':2,
      **{k:False for k in NEGATIVES}}
