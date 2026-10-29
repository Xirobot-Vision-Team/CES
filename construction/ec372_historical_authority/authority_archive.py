#!/usr/bin/env python3
"""EC372 receiver-only signed historical authority & revocation custody slice.

Replays the *real* EC371 -> EC370 -> EC369 receiver chain on each call. Reopens
receiver copies of historical EC362 custody manifests and exact EC360 root-
authorized delegations, independent witness origin claims and revocation
snapshot chains. Every verification uses unchanged EC360 signing domains.

An issuer or EC359 ancestry mentioned inside these originals remains a signed
CLAIM until the corresponding original old parent history is separately replayed.
No source/sender original path is opened. Every lawful result stays unresolved.
"""
from __future__ import annotations

from collections import defaultdict

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec360_authority_directory import authority
from ec362_publication_custody import custody
from ec370_publication_accountability import accountability as current
from ec371_historical_archive import archive as prior

RESULT_SCHEMA = 'ces.ec372.receiver_historical_authority_revocation_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec372.receiver_historical_authority_revocation_denial.v1'
DERIVE_SCHEMA = 'ces.ec372.unsigned_historical_authority_inventory_unresolved.v1'
BUNDLE_SCHEMA = 'ces.ec372.receiver_historical_authority_originals.v1'
INVENTORY_SCHEMA = 'ces.ec372.receiver_verified_authority_snapshot_sha_inventory.v1'
MAX_BUNDLE = 48_000
MAX_EPOCHS = prior.MAX_EPOCHS
MAX_SNAPSHOTS = authority.MAX_SNAPSHOTS
MAX_CUSTODIANS = 2
NEW_SCALARS = ('historical_authority_bundle_file',
               'expected_historical_authority_bundle_sha256')
AUDIT_ONLY = ('expected_retained_historical_authority_inventory_sha256',)
NEW_REPEATS = (
 ('historical_authority_a_root_shas', '--historical-authority-a-root-sha256'),
 ('historical_authority_b_root_shas', '--historical-authority-b-root-sha256'),
 ('historical_authority_a_head_shas', '--historical-authority-a-head-sha256'),
 ('historical_authority_b_head_shas', '--historical-authority-b-head-sha256'),
 ('minimum_authority_a_revocation_sequences', '--minimum-authority-a-revocation-sequence'),
 ('minimum_authority_b_revocation_sequences', '--minimum-authority-b-revocation-sequence'),
 ('minimum_authority_a_publication_sequences', '--minimum-authority-a-publication-sequence'),
 ('minimum_authority_b_publication_sequences', '--minimum-authority-b-publication-sequence'),
)
NEW_REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
BUNDLE_FIELDS = {'schema', 'parent_ec371_canonical_result_sha256',
 'historical_directory_archive_original_sha256', 'claimed_directory_lineage_id',
 'epochs'}
EPOCH_FIELDS = {'epoch_index', 'source_a', 'source_b'}
SOURCE_FIELDS = {'authority_root_public_key_original',
 'origin_witness_public_key_original', 'issuer_public_key_original',
 'root_signed_delegation_original', 'witness_signed_origin_original',
 'root_signed_revocation_snapshot_originals', 'selected_revocation_head_sha256',
 'source_manifest_original_sha256', 'source_custodian_key_original_sha256',
 'signed_parent_ec360_canonical_result_sha256'}
FLAGS = (
 'inherited_ec371_directory_custody_or_current_receiver_dispute_unresolved',
 'external_authority_inventory_root_head_or_sequence_floor_mismatch',
 'historical_root_signed_issuer_revoked_or_inventory_coverage_gap',
 'historical_root_signed_revocation_fork_or_regression',
 'historical_scope_or_witnessed_jurisdiction_exclusion',
 'historical_authority_role_collision_or_unproven_cross_epoch_rotation',
 'historical_source_custody_sequence_or_ancestor_claim_disagreement',
 'historical_authority_signature_clock_claim_untrusted',
 'historical_authority_originals_only_partially_recover_ec365_to_ec337',
)
OUTCOMES = (
 'ec372_inherited_receiver_directory_publication_dispute',
 'ec372_outside_authority_inventory_or_rollback_floor_disagrees',
 'ec372_genuine_root_signed_issuer_revoked_or_not_listed',
 'ec372_signed_revocation_fork_or_history_regression',
 'ec372_delegation_excludes_scope_or_witnessed_jurisdiction',
 'ec372_signer_collision_or_unproved_authority_rotation',
 'ec372_source_publication_sequence_or_ancestor_conflict',
 'ec372_signed_time_claim_untrusted',
 'ec372_partial_old_root_and_source_authority_originals_only',
)
NEGATIVES = (
 'actual_ec365_to_ec337_complete_original_parent_replay_performed',
 'actual_ec360_to_ec359_authority_parent_result_regenerated',
 'signed_ec359_issuer_and_owner_ancestry_fully_authenticated',
 'signed_delegations_revocations_directory_inclusion_proofs_replayed',
 'source_manifest_unopened_sender_or_other_old_copy_roles_verified',
 'historical_root_signed_inventory_proves_global_complete_revocation',
 'caller_pinned_roots_witnesses_or_issuers_are_official_legal_roles',
 'claimed_utc_or_physical_custody_is_independently_trusted',
 'inherited_ec371_or_ec370_disputes_revocations_repaired',
 'sender_origin_path_required_opened_or_restored',
 'new_signatures_private_keys_network_provider_cas_worm_or_powershell_used',
 'old_deep_mock_removed_or_final_user_acceptance_proven',
)


def need(value, code, status='invalid_input'):
    if value is not True:
        raise errors.AnchorError('EC372_' + code, status)


def exact(value, keys, role):
    need(type(value) is dict and set(value)==set(keys),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return current.digest(raw)


def _inputs(opts, derive):
    parent_keys=(*current.prior.SCALARS, *current.prior.REPEAT_NAMES,
                 *current.NEW_SCALARS, *current.NEW_REPEAT_NAMES,
                 *prior.NEW_SCALARS, *prior.REPEAT_NAMES, *prior.AUDIT_ONLY)
    expected=set(parent_keys)|set(NEW_SCALARS)|set(NEW_REPEAT_NAMES)
    if not derive:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'EXACT_PARENT_AND_NEW_INPUTS_REQUIRED')
    parent={k:opts[k] for k in parent_keys}
    prior._input_check(parent,False)
    authority.outer_pin(opts['historical_authority_bundle_file'],
                        opts['expected_historical_authority_bundle_sha256'],
                        'EC372_AUTHORITY_ARCHIVE')
    need(opts['historical_authority_bundle_file'] is not None and
         opts['expected_historical_authority_bundle_sha256'] is not None,
         'INDEPENDENT_RECEIVER_SHA_PIN_REQUIRED')
    if not derive:need(tr._sha(opts[AUDIT_ONLY[0]]),
         'EXTERNAL_CANONICAL_AUTHORITY_INVENTORY_PIN_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    for name in NEW_REPEAT_NAMES:
        data=opts[name]
        need(type(data) is list and len(data)==n,
             name.upper()+'_ONE_ENTRY_PER_HISTORIC_EPOCH_REQUIRED')
        if name.endswith('_shas'):
            need(all(tr._sha(s) for s in data),
                 name.upper()+'_SHA256_LIST_INVALID')
        else:
            cap=MAX_SNAPSHOTS-1 if 'revocation' in name else custody.MAX_SEQUENCE
            need(all(type(x) is int and 0<=x<=cap for x in data),
                 name.upper()+'_BOUNDED_SEQUENCE_FLOOR_REQUIRED')
    return parent


def _read(ref, role, cap, pins, categories, forbidden):
    prior.lineage.parent.ref_check(ref,'EC372_'+role)
    need(ref['path'] not in forbidden,
         'REF_ALIASES_SENDER_OR_OLDER_SOURCE_ORIGINAL_PATH','permission_denied')
    return current._read(ref,'ec372_'+role,cap,pins,categories,forbidden)


def _historical_custody(parent_opts, read, forbidden):
    """Reopen exact signed source manifests, not their four sender path labels.

    The EC371 audit just independently validated each signature and SHA. This
    function binds newly supplied EC360 originals to those reopened signed
    source bytes and builds a denylist of *all* protected origin labels.
    """
    detached=tr.strict_json(read({'path':parent_opts['detached_bundle_file'],
             'sha256':parent_opts['expected_detached_bundle_sha256']},
             'detached_receiver_bundle',current.prior.MAX_BUNDLE),
             'EC372_REOPEN_CURRENT_DETACHED_BUNDLE')
    current.prior.exact(detached,current.prior.BUNDLE_FIELDS,'CURRENT_DETACHED')
    sm=tr.strict_json(read(detached['signed_copy_map_original'],
             'signed_source_map',current.prior.MAX_MAP),
             'EC372_REOPEN_CURRENT_RECEIVER_SOURCE_MAP')
    current.prior.exact(sm,current.prior.MAP_FIELDS,'CURRENT_SOURCE_MAP')
    forbidden.update(x['source_original']['path'] for x in sm['originals'])
    raw=read({'path':parent_opts['historical_archive_bundle_file'],
              'sha256':parent_opts['expected_historical_archive_bundle_sha256']},
              'ec371_historical_archive',prior.MAX_BUNDLE)
    b=tr.strict_json(raw,'EC372_REOPEN_HISTORICAL_DIRECTORY_ARCHIVE')
    exact(b,prior.BUNDLE_FIELDS,'EC371_BUNDLE')
    need(b['schema']==prior.BUNDLE_SCHEMA,
         'HISTORICAL_PARENT_BUNDLE_SCHEMA_INVALID','permission_denied')
    manifests=[]
    for i,epoch in enumerate(b['epochs']):
        exact(epoch,prior.EPOCH_FIELDS,'EC371_REOPEN_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i,
             'EC371_REOPEN_EPOCH_NOT_CONTIGUOUS')
        slots={}
        for slot in ('a','b'):
            ref=epoch['source_'+slot+'_manifest_original']
            m=tr.strict_json(read(ref,'historic_manifest_'+slot+'_'+str(i),
                                  custody.MAX_MANIFEST),
                             'EC372_REOPEN_REAL_SIGNED_MANIFEST')
            exact(m,custody.MANIFEST_FIELDS,'EC371_SIGNED_SOURCE_MANIFEST')
            need(m['schema']==custody.MANIFEST_SCHEMA and
                 m['source_slot']==slot and
                 m['directory_id']==b['claimed_directory_lineage_id'] and
                 m['advertised_checkpoint_original_sha256']==epoch[
                       'signed_directory_checkpoint_original']['sha256'] and
                 ref['sha256']==parent_opts[
                       'historical_source_'+slot+'_manifest_shas'][i],
                 'REOPENED_MANIFEST_DIFFERS_FROM_EC371_TRUE_ORIGINAL',
                 'permission_denied')
            for copyref in m['copies'].values():
                prior.lineage.parent.ref_check(copyref,'EC372_OLD_UNOPENED_SOURCE')
                forbidden.add(copyref['path'])
            slots[slot]={'manifest':m,'manifest_sha':ref['sha256'],
                         'custodian_sha':epoch[
                         'source_'+slot+'_custodian_public_key_original']['sha256']}
        manifests.append(slots)
    return b,manifests


def _source(i,slot,row,signed,opts,now,read,forbidden,used,seen_roots):
    exact(row,SOURCE_FIELDS,'AUTHORITY_'+slot.upper()+'_EPOCH')
    m=signed['manifest']
    need(row['source_manifest_original_sha256']==signed['manifest_sha'] and
         row['source_custodian_key_original_sha256']==signed['custodian_sha'] and
         row['signed_parent_ec360_canonical_result_sha256']==m[
                    'parent_ec360_canonical_result_sha256'],
         'AUTHORITY_SNAPSHOT_NOT_BOUND_TO_VERIFIED_SIGNED_EC362_SOURCE',
         'permission_denied')
    def open_key(name):
        ref=row[name]
        raw=read(ref,slot+'_'+name,32)
        need(len(raw)==32,name.upper()+'_32_BYTE_ED25519_KEY_REQUIRED',
             'permission_denied')
        return raw,ref['sha256']
    root,rsha=open_key('authority_root_public_key_original')
    witness,wsha=open_key('origin_witness_public_key_original')
    issuer,isha=open_key('issuer_public_key_original')
    need(rsha==opts['historical_authority_'+slot+'_root_shas'][i],
         'EXTERNAL_AUTHORITY_ROOT_SHA_MISMATCH','permission_denied')
    # The issuer's original public key is possession evidence only: EC359 old
    # owner/issuer signatures are NOT thereby reconstructed.
    keys=(rsha,wsha,isha)
    need(len(set(keys))==3 and not set(keys).intersection(used),
         'OLD_AUTHORITY_WITNESS_ISSUER_COLLIDES_WITH_OTHER_SIGNER_ROLE',
         'permission_denied')
    for key,kind in ((rsha,'root'),(wsha,'witness'),(isha,'issuer')):
        old=seen_roots.get(key)
        need(old is None or old==(slot,kind),
             'CROSS_SLOT_OR_CROSS_ROLE_ED25519_REUSE_DENIED','permission_denied')
        seen_roots[key]=(slot,kind)
    dref=row['root_signed_delegation_original']
    delegation=tr.strict_json(read(dref,slot+'_delegation',
                                   authority.MAX_ORIGINAL),'EC372_REAL_DELEGATION')
    exact(delegation,authority.DELEGATION_FIELDS,'ROOT_SIGNED_DELEGATION')
    need(delegation['schema']==authority.DELEGATION_SCHEMA and
         delegation['slot']==slot and
         tr._ident(delegation['authority_id']) and
         delegation['root_public_key_original_sha256']==rsha and
         delegation['issuer_public_key_original_sha256']==isha and
         tr._ident(delegation['issuer_id_as_signed_claim']) and
         tr._sha(delegation['owner_public_key_original_sha256']) and
         tr._sha(delegation['parent_owner_head_event_sha256']) and
         tr._sha(delegation['parent_distribution_head_original_sha256']) and
         tr._sha(delegation['parent_ec359_canonical_result_sha256']),
         'REAL_DELEGATION_CLAIM_AND_ORIGINAL_KEY_BINDING_INVALID',
         'permission_denied')
    authority.sorted_ids(delegation['authorized_scopes'],'DELEGATED_SCOPE')
    authority.sorted_ids(delegation['authorized_jurisdictions'],'DELEGATED_JURISDICTION')
    authority.sig(delegation,'signature_root_ed25519_hex',root,
                  authority.DELEGATION_DOMAIN,'EC372_REAL_DELEGATION')
    ds,de=authority.window(delegation['valid_from_utc'],delegation['expires_utc'],
                           authority.MAX_AUTH_SPAN,'EC372_DELEGATION')
    oref=row['witness_signed_origin_original']
    origin=tr.strict_json(read(oref,slot+'_origin',
                               authority.MAX_ORIGINAL),'EC372_REAL_WITNESS_ORIGIN')
    exact(origin,authority.ORIGIN_FIELDS,'WITNESSED_AUTHORITY_ORIGIN')
    need(origin['schema']==authority.ORIGIN_SCHEMA and
         origin['slot']==slot and origin['authority_id']==delegation['authority_id'] and
         tr._ident(origin['claimed_jurisdiction']) and
         tr._ident(origin['origin_reference_id']) and
         origin['root_public_key_original_sha256']==rsha and
         origin['delegation_original_sha256']==dref['sha256'] and
         origin['origin_witness_public_key_original_sha256']==wsha,
         'WITNESS_ORIGIN_NOT_BOUND_TO_REAL_DELEGATION',
         'permission_denied')
    authority.sig(origin,'signature_witness_ed25519_hex',witness,
                  authority.ORIGIN_DOMAIN,'EC372_REAL_ORIGIN_WITNESS')
    os,oe=authority.window(origin['observed_utc'],origin['expires_utc'],
                           authority.MAX_ORIGIN_SPAN,'EC372_ORIGIN')
    # A root-signed revoked key makes ALL known competing copies adverse;
    # no observer can choose a favorable branch to conceal the revocation.
    refs=row['root_signed_revocation_snapshot_originals']
    need(type(refs) is list and len(refs)<=MAX_SNAPSHOTS,
         'BOUNDED_HISTORICAL_REVOCATION_ORIGINALS_REQUIRED')
    records={};snapshot_refs=[];clocks=[]
    for j,ref in enumerate(refs):
        raw=read(ref,slot+'_snapshot_'+ref['sha256'],authority.MAX_ORIGINAL)
        digest=sha(raw)
        need(digest not in records,'DUPLICATE_REVOCATION_ORIGINAL_SHA_DENIED',
             'permission_denied')
        checked=authority.validate_snapshot(raw,root,slot,rsha,dref['sha256'],
                                            delegation['authority_id'])
        records[digest]=checked;snapshot_refs.append(digest)
        clocks.append(authority.utc_untrusted(now,checked[1],checked[2],
                                              authority.MAX_EVALUATION_LAG))
    selected=row['selected_revocation_head_sha256']
    need(selected is None or tr._sha(selected),
         'SELECTED_REVOCATION_HEAD_SHA_OR_EXPLICIT_NULL_REQUIRED')
    if selected is not None:
        need(selected in records,'SELECTED_SIGNED_SNAPSHOT_NOT_FURNISHED',
             'permission_denied')
    floor=opts['minimum_authority_'+slot+'_revocation_sequences'][i]
    history=authority.snapshot_history(records,selected,floor,now,isha)
    publication_floor=opts['minimum_authority_'+slot+'_publication_sequences'][i]
    pubseq=m['publication_sequence']
    need(type(pubseq) is int and 0<=pubseq<=custody.MAX_SEQUENCE,
         'EC371_SIGNED_PUBLISHER_SEQUENCE_INVALID','permission_denied')
    head_disagrees=(selected!=opts['historical_authority_'+slot+'_head_shas'][i])
    scope_missing=(authority.TARGET_SCOPE not in delegation['authorized_scopes'] or
                   origin['claimed_jurisdiction'] not in delegation['authorized_jurisdictions'])
    return {'slot':slot,'epoch_index':i,'root_sha':rsha,'witness_sha':wsha,
            'issuer_sha':isha,'authority_id':delegation['authority_id'],
            'delegation_sha':dref['sha256'],'origin_sha':oref['sha256'],
            'snapshot_shas':snapshot_refs,'selected_head':selected,
            'selected_sequence':history['selected_sequence'],
            'signed_source_manifest_sha':signed['manifest_sha'],
            'signed_source_publication_sequence':pubseq,
            'parent_ec360_claim_sha':m['parent_ec360_canonical_result_sha256'],
            'parent_ec359_claim_sha':delegation['parent_ec359_canonical_result_sha256'],
            'signed_witness_claimed_jurisdiction':origin['claimed_jurisdiction'],
            'revoked':history['revoked'],'coverage':history['coverage_missing'],
            'fork':history['fork'],'rollback':history['rollback'] or head_disagrees or
                        history['missing'],
            'scope_missing':scope_missing,
            'publication_rollback':pubseq<publication_floor,
            'clock':bool(authority.utc_untrusted(now,ds,de,authority.MAX_EVALUATION_LAG) or
                    authority.utc_untrusted(now,os,oe,authority.MAX_EVALUATION_LAG) or
                    history['stale'] or any(clocks))}


def _engine(derive,**opts):
    previous=_inputs(opts,derive)
    # Not a cached or synthetic "parent PASS" JSON; each call replays EC371.
    inherited=prior.audit(**previous)
    need(inherited['schema']==prior.RESULT_SCHEMA and
         inherited['exit_code']==2 and
         inherited['sender_origin_path_required_or_read'] is False,
         'REAL_EC371_RECEIVER_SIGNED_PARENT_REQUIRED','unavailable')
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set()
    def read(ref,role,cap):return _read(ref,role,cap,pins,categories,forbidden)
    hb,manifest=_historical_custody(previous,read,forbidden)
    need(hb['claimed_directory_lineage_id']==opts[
           'claimed_historical_directory_lineage_id'],
         'EC371_SIGNED_LINEAGE_DIFFERENT','permission_denied')
    need(not set(pins).intersection(forbidden),
         'PARENT_MANIFEST_REOPEN_ALIASES_SENDER_ORIGINAL',
         'permission_denied')
    bref={'path':opts['historical_authority_bundle_file'],
          'sha256':opts['expected_historical_authority_bundle_sha256']}
    doc=tr.strict_json(read(bref,'historical_authority_bundle',MAX_BUNDLE),
                       'EC372_RECEIVER_AUTHORITY_BUNDLE')
    exact(doc,BUNDLE_FIELDS,'HISTORICAL_AUTHORITY_BUNDLE')
    # Explicit parent SHA check; the actual parent digest is recomputed above.
    need(doc['schema']==BUNDLE_SCHEMA and
         doc['parent_ec371_canonical_result_sha256']==sha(canonical.canonical(inherited)) and
         doc['historical_directory_archive_original_sha256']==opts[
                           'expected_historical_archive_bundle_sha256'] and
         doc['claimed_directory_lineage_id']==opts[
                           'claimed_historical_directory_lineage_id'],
         'HISTORIC_AUTHORITY_ARCHIVE_PARENT_BINDING_INVALID',
         'permission_denied')
    epochs=doc['epochs']
    need(type(epochs) is list and len(epochs)==len(manifest) and
         1<=len(epochs)<=MAX_EPOCHS,
         'EXACT_HISTORICAL_AUTHORITY_EPOCH_COVERAGE_REQUIRED')
    used=set(opts['institution_root_public_key_shas']+
             opts['witness_public_key_shas']+
             [opts['expected_sender_public_key_sha256'],
              opts['expected_receiver_public_key_sha256'],
              opts['expected_publisher_public_key_sha256'],
              opts['expected_publication_observer_public_key_sha256'],
              *opts['historical_directory_root_shas']])
    for epoch in hb['epochs']:
        used.update(epoch['source_'+slot+'_custodian_public_key_original']['sha256']
                    for slot in ('a','b'))
    seen_roots={};reviews=[]
    for i,row in enumerate(epochs):
        exact(row,EPOCH_FIELDS,'AUTHORITY_EPOCH')
        need(type(row['epoch_index']) is int and row['epoch_index']==i,
             'AUTHORITY_EPOCH_INDEX_NOT_CONTIGUOUS')
        for slot in ('a','b'):
            reviews.append(_source(i,slot,row['source_'+slot],manifest[i][slot],
                                   opts,now,read,forbidden,used,seen_roots))
    need(not set(pins).intersection(forbidden),
         'NEW_AUTHORITY_READ_ALIASES_SIGNED_SENDER_PATH','permission_denied')
    tsa._check_late(pins)
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=not inherited[
               'local_pinned_historical_directory_signature_and_proof_consistency']
    flags[FLAGS[1]]=any(r['rollback'] for r in reviews)
    flags[FLAGS[2]]=any(r['revoked'] or r['coverage'] for r in reviews)
    flags[FLAGS[3]]=any(r['fork'] for r in reviews)
    flags[FLAGS[4]]=any(r['scope_missing'] for r in reviews)
    flags[FLAGS[6]]=any(r['publication_rollback'] for r in reviews)
    flags[FLAGS[7]]=any(r['clock'] for r in reviews)
    # Cross-epoch identity / root rotation is NOT authorized by a new
    # self-signed claim. Require a separately authenticated historical
    # authority handoff in a future EC; flag any new root / delegation / issuer.
    for slot in ('a','b'):
        sequence=[r for r in reviews if r['slot']==slot]
        for old,new in zip(sequence,sequence[1:]):
            if (old['root_sha']!=new['root_sha'] or
                old['authority_id']!=new['authority_id'] or
                old['issuer_sha']!=new['issuer_sha'] or
                old['witness_sha']!=new['witness_sha'] or
                old['delegation_sha']!=new['delegation_sha']):
                flags[FLAGS[5]]=True
            else:
                if (old['selected_head'] is None or
                    old['selected_head'] not in new['snapshot_shas'] or
                    new['selected_sequence'] is None or
                    old['selected_sequence'] is None or
                    new['selected_sequence']<=old['selected_sequence']):
                    flags[FLAGS[3]]=True
            if new['signed_source_publication_sequence']<=old[
                                             'signed_source_publication_sequence']:
                flags[FLAGS[6]]=True
            if old['parent_ec360_claim_sha']!=new['parent_ec360_claim_sha']:
                # Different claims, with no original EC360 parent result replay.
                flags[FLAGS[6]]=True
    for i in range(len(epochs)):
        a=reviews[2*i];b=reviews[2*i+1]
        if a['root_sha']==b['root_sha'] or a['witness_sha']==b['witness_sha'] or (
             a['authority_id']==b['authority_id']):
            flags[FLAGS[5]]=True
        if a['parent_ec360_claim_sha']!=b['parent_ec360_claim_sha']:
            flags[FLAGS[6]]=True
    flags[FLAGS[8]]=True  # No recovered slice upgrades the absent old parents.
    inventory={'schema':INVENTORY_SCHEMA,
        'verified_live_ec371_canonical_result_sha256':sha(canonical.canonical(inherited)),
        'ec371_historical_archive_original_sha256':opts[
                            'expected_historical_archive_bundle_sha256'],
        'historical_authority_bundle_original_sha256':bref['sha256'],
        'claimed_historical_directory_lineage_id':opts[
                            'claimed_historical_directory_lineage_id'],
        'source_authority_originals':[{k:r[k] for k in (
            'slot','epoch_index','root_sha','witness_sha','issuer_sha',
            'authority_id','delegation_sha','origin_sha','snapshot_shas',
            'selected_head','selected_sequence','signed_source_manifest_sha',
            'signed_source_publication_sequence','parent_ec360_claim_sha',
            'parent_ec359_claim_sha','revoked','coverage','fork','rollback')}
            for r in reviews]}
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:-1])
    status=(next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                   OUTCOMES[-1])+'_unresolved')
    result={'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
         'command':'derive-historical-authority-inventory' if derive else
                   'audit-historical-authority-archive',
         'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
         'historical_authority_bundle_original_sha256':bref['sha256'],
         'verified_live_parent_ec371_canonical_result_sha256':sha(
              canonical.canonical(inherited)),
         'receiver_verified_historical_authority_inventory_sha256':digest,
         'verified_original_root_signed_delegation_count':len(reviews),
         'verified_original_witness_signed_origin_count':len(reviews),
         'verified_original_root_signed_revocation_snapshot_count':sum(
                     len(r['snapshot_shas']) for r in reviews),
         'replayed_historical_ec362_signed_source_manifest_count':len(reviews),
         'historical_authority_source_epoch_review_count':len(reviews),
         'historical_authority_source_epoch_reviews':[{k:r[k] for k in (
               'epoch_index','slot','root_sha','issuer_sha','selected_head',
               'selected_sequence','signed_source_manifest_sha','revoked',
               'coverage','fork','rollback','scope_missing',
               'publication_rollback','clock')} for r in reviews],
         'local_pinned_historical_authority_slice_consistent':bool(local),
         'sender_origin_path_required_or_read':False,
         'ec365_to_ec337_full_parent_original_replay_performed':False,
         **flags, **{x:False for x in NEGATIVES}}
    if derive:
        result['unsigned_verified_historical_authority_inventory']=inventory
        result['caller_external_inventory_pin_created_or_certified']=False
    return result


def audit(**opts):return _engine(False,**opts)


def derive_inventory(**opts):return _engine(True,**opts)
