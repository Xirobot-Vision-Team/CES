#!/usr/bin/env python3
"""EC362: offline, read-only, cross-source verification of directory evidence copies.

No local distribution claim establishes a public service, legal independence,
physical custody, historical trusted time, or global latest directory state.
All parent EC361..337 true cryptographic evidence is replayed on EACH call.
"""
from __future__ import annotations

from datetime import timedelta

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from directory_consistency import consistency as previous

parent = previous.parent
RESULT_SCHEMA = 'ces.ec362.offline_directory_publication_custody_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec362.offline_directory_publication_custody_denial.v1'
HANDOFF_SCHEMA = 'ces.ec362.unsigned_directory_publication_custody_handoff.v1'
MANIFEST_SCHEMA = 'ces.ec362.signed_offline_directory_publication_copy.v1'
DOMAIN = b'CES/EC362/OfflineDirectoryPublicationCustody/v1\x00'
MAX_MANIFEST = 12_000
MAX_SEQUENCE = 2**31 - 1
MAX_SPAN = timedelta(days=7)
MAX_LAG = timedelta(days=7)
SLOTS = ('a', 'b')
COPY_ROLES = ('checkpoint', 'consistency_bundle', 'observer_a_receipt',
              'observer_b_receipt')
COPY_CAPS = {'checkpoint':parent.MAX_ORIGINAL,
             'consistency_bundle':previous.MAX_BUNDLE,
             'observer_a_receipt':parent.MAX_ORIGINAL,
             'observer_b_receipt':parent.MAX_ORIGINAL}
MANIFEST_FIELDS = {'schema','source_slot','claimed_source_id',
    'custodian_public_key_original_sha256','directory_id',
    'parent_ec361_canonical_result_sha256',
    'parent_ec360_canonical_result_sha256',
    'parent_directory_checkpoint_original_sha256',
    'advertised_checkpoint_original_sha256','advertised_tree_size',
    'advertised_root_sha256','publication_sequence','issued_utc','expires_utc',
    'copies','signature_custodian_ed25519_hex'}
NEW_KEYS = ('publication_copy_evaluation_utc',
    'source_a_custody_public_key_file','expected_source_a_custody_public_key_sha256',
    'source_a_publication_manifest_file','expected_source_a_publication_manifest_sha256',
    'expected_source_a_checkpoint_copy_sha256',
    'expected_source_a_consistency_bundle_copy_sha256',
    'expected_source_a_observer_a_receipt_copy_sha256',
    'expected_source_a_observer_b_receipt_copy_sha256',
    'minimum_source_a_publication_sequence',
    'source_b_custody_public_key_file','expected_source_b_custody_public_key_sha256',
    'source_b_publication_manifest_file','expected_source_b_publication_manifest_sha256',
    'expected_source_b_checkpoint_copy_sha256',
    'expected_source_b_consistency_bundle_copy_sha256',
    'expected_source_b_observer_a_receipt_copy_sha256',
    'expected_source_b_observer_b_receipt_copy_sha256',
    'minimum_source_b_publication_sequence')
OUTCOMES = (
    'ec362_ec361_parent_not_locally_coherent',
    'ec362_independent_sources_or_caller_copy_pins_missing',
    'ec362_signed_publication_source_identity_or_role_collision',
    'ec362_source_copy_external_sha_pin_or_original_bytes_mismatch',
    'ec362_independently_shown_signed_directory_head_conflict',
    'ec362_source_publication_sequence_or_signed_head_rollback',
    'ec362_source_signed_publication_time_claim_outside_window',
    'ec362_two_locally_signed_publication_copies_agree_public_custody_unproven',
)
NEGATIVES = (
    'local_publication_copy_signatures_prove_official_distribution',
    'two_distinct_custodian_keys_prove_real_independent_entities',
    'offline_source_manifest_proves_physical_separate_custody',
    'copied_directory_checkpoint_proves_globally_latest_public_head',
    'signed_publication_utc_is_trusted_historical_time',
    'two_locally_agreeing_copies_exclude_hidden_signed_forks',
    'copied_proofs_repair_parent_ec361_or_earlier_evidence',
    'auditor_fetches_online_sources_or_ambient_os_trust_store',
    'auditor_creates_private_keys_signatures_or_provider_cas_worm_writes',
    'native_powershell_deep_mock_or_final_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC362_'+code,status)


def exact(obj,fields,role):
    need(type(obj) is dict and set(obj)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return previous.sha(raw)


def _source_args(inputs,slot):
    prefix='source_'+slot+'_'
    return {
        'key_file':inputs.get(prefix+'custody_public_key_file'),
        'key_sha':inputs.get('expected_'+prefix+'custody_public_key_sha256'),
        'manifest_file':inputs.get(prefix+'publication_manifest_file'),
        'manifest_sha':inputs.get('expected_'+prefix+'publication_manifest_sha256'),
        'floor':inputs.get('minimum_'+prefix+'publication_sequence'),
        'external_copy_pins':{
            role:inputs.get('expected_'+prefix+role+'_copy_sha256')
            for role in COPY_ROLES},
    }


def _parent_evidence(parent_inputs,prior):
    """Reopen EC361 original bundle + all actual receipts/checkpoints, not a
    summarized JSON's self-declared success flags. Preserve paths and SHA for
    late checks and prohibit new role and same-inode aliasing.
    """
    inherited=parent.previous.parent.parent.prior._inherited
    # The inherited boundary collects earlier EC357..359 nested role paths,
    # signer keys and original SHA pins (not just CLI file arguments).
    oldpins, oldpaths, old_role_shas = parent.parent_boundary(parent_inputs)
    oldpaths=set(oldpaths);old_role_shas=set(old_role_shas)
    for key,val in parent_inputs.items():
        if (key.endswith('_file') and type(val) is str) or (
            key.endswith('_files') and type(val) is list):
            oldpaths.update(val if type(val) is list else [val])
        if key.endswith('_public_key_sha256') and tr._sha(val):
            old_role_shas.add(val)
    # EC360 has its own nested delegation/revocation refs and additional key
    # originals; all were verified by parent.audit, but reject using their
    # physical paths/inodes as a purported independent publication source.
    def collect_refs(item, role=''):
        if type(item) is dict:
            if set(item)=={'path','sha256'} and type(item['path']) is str and tr._sha(item['sha256']):
                oldpaths.add(item['path'])
                if 'public_key' in role or role.endswith('_key'):
                    old_role_shas.add(item['sha256'])
            for key,value in item.items():collect_refs(value,key)
        elif type(item) is list:
            for value in item:collect_refs(value,role)
    for key,sha_key,cap in (
        ('authority_bundle_file','expected_authority_bundle_sha256',parent.MAX_BUNDLE),
        ('distribution_bundle_file','expected_distribution_bundle_sha256',
         parent.previous.MAX_BUNDLE)):
        file=parent_inputs.get(key);digest=parent_inputs.get(sha_key)
        if file is None or digest is None:continue
        raw=inherited({'path':file,'sha256':digest},
                      'EC362_OLD_'+key.upper(),cap,oldpins)
        oldpaths.add(file)
        collect_refs(tr.strict_json(raw,'EC362_OLD_'+key.upper()))
    # Pick out the required previous scope files directly: EC361 has already
    # authenticated their bytes, but this read records their new late boundary.
    bundle_path=parent_inputs.get('consistency_bundle_file')
    bundle_sha=parent_inputs.get('expected_consistency_bundle_sha256')
    head_sha=parent_inputs.get('expected_latest_consistent_directory_checkpoint_sha256')
    anchor_sha=prior['parent_directory_checkpoint_original_sha256']
    refs={}; receipt_shas={}
    cp=None; cp_raw=None
    if bundle_path is not None and bundle_sha is not None:
        raw=inherited({'path':bundle_path,'sha256':bundle_sha},
                      'EC362_PARENT_CONSISTENCY_BUNDLE',previous.MAX_BUNDLE,oldpins)
        doc=tr.strict_json(raw,'EC362_PARENT_CONSISTENCY_BUNDLE')
        exact(doc,previous.BUNDLE_FIELDS,'PARENT_CONSISTENCY_BUNDLE')
        need(doc['schema']==previous.BUNDLE_SCHEMA,
             'PARENT_CONSISTENCY_BUNDLE_SCHEMA_INVALID','permission_denied')
        oldpaths.add(bundle_path)
        refs['consistency_bundle']=bundle_sha
        for ref in doc['checkpoint_originals']:
            exact(ref,('path','sha256'),'PARENT_CHECKPOINT_REF')
            oldpaths.add(ref['path'])
            if ref['sha256']==head_sha:
                cp_raw=inherited(ref,'EC362_PARENT_SELECTED_CHECKPOINT',
                                 parent.MAX_ORIGINAL,oldpins)
        for ref in doc['observer_receipt_originals']:
            exact(ref,('path','sha256'),'PARENT_OBSERVER_REF')
            oldpaths.add(ref['path'])
            obs_raw=inherited(ref,'EC362_PARENT_OBSERVER',
                              parent.MAX_ORIGINAL,oldpins)
            obj=tr.strict_json(obs_raw,'EC362_PARENT_OBSERVER')
            need(type(obj) is dict and obj.get('slot') in SLOTS,
                 'PARENT_OBSERVER_SLOT_INVALID','permission_denied')
            need(obj['slot'] not in receipt_shas,
                 'DUPLICATED_PARENT_OBSERVER_SLOT','permission_denied')
            receipt_shas[obj['slot']]=ref['sha256']
    if cp_raw is None and head_sha is not None and head_sha==anchor_sha:
        path=parent_inputs.get('directory_checkpoint_file')
        pin=parent_inputs.get('expected_directory_checkpoint_sha256')
        if path is not None and pin is not None:
            cp_raw=inherited({'path':path,'sha256':pin},
                   'EC362_PARENT_ANCHOR_CHECKPOINT',parent.MAX_ORIGINAL,oldpins)
            oldpaths.add(path)
    if cp_raw is not None:
        cp=tr.strict_json(cp_raw,'EC362_PARENT_SELECTED_DIRECTORY')
        exact(cp,parent.DIRECTORY_FIELDS,'PARENT_SELECTED_DIRECTORY')
        refs['checkpoint']=sha(cp_raw)
    for slot in SLOTS:
        if slot in receipt_shas:refs['observer_'+slot+'_receipt']=receipt_shas[slot]
    # Original ancestor anchors and signed-role key SHAs must remain distinct.
    # Every role with a direct caller-held public key SHA is included; the
    # previous auditors independently police roles nested in old manifests.
    for role in ('directory','observer_a','observer_b','authority_a_root',
                 'authority_b_root','origin_a_witness','origin_b_witness'):
        d=parent_inputs.get('expected_'+role+'_public_key_sha256')
        if tr._sha(d):old_role_shas.add(d)
    return refs,cp,oldpins,oldpaths,old_role_shas


def checklist(**consistency_inputs):
    prior=previous.audit(**consistency_inputs)
    need(prior['schema']==previous.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec360_through_ec337_signed_originals_replayed'] is True,
         'GENUINE_EC361_THROUGH_EC337_REPLAY_REQUIRED','permission_denied')
    return {'schema':HANDOFF_SCHEMA,
        'command':'derive-directory-publication-custody-handoff',
        'status':'independent_caller_sha_pinned_signed_publication_copies_required_unresolved',
        'exit_code':2,'case_id':prior['case_id'],
        'actual_ec361_through_ec337_signed_originals_replayed':True,
        'parent_ec361_canonical_result_sha256':sha(canonical.canonical(prior)),
        'caller_saved_selected_signed_checkpoint_sha256':
            prior['expected_latest_checkpoint_sha256_as_caller_pin'],
        'required_chain_external_inputs':[
            'two distinct caller-pinned Ed25519 custodian public keys and signed source manifests',
            'each signed source binds an independent path and exact SHA for four actual copies',
            'caller holds separately per-source exact SHA for each of the four copied originals',
            'caller-retained minimum publication sequences for both source roles',
            'all signed source checkpoints are checked for forks, rollback and divergence'],
        'legal_custody_public_dissemination_utc_and_global_latest_not_proven':True,
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES}}


def audit(*,publication_copy_evaluation_utc,**inputs):
    # Every call audits genuine upstream originals; never accepts cached or
    # caller-generated parent result JSON as a proof substitute.
    prev_inputs={k:v for k,v in inputs.items() if k not in NEW_KEYS}
    now=tr._utc(publication_copy_evaluation_utc)
    need(now>=tr._utc(prev_inputs['consistency_evaluation_utc']),
         'EVALUATION_MUST_NOT_PRECEDE_EC361_PARENT','permission_denied')
    for slot in SLOTS:
        cfg=_source_args(inputs,slot)
        for label in ('key','manifest'):
            parent.outer_pin(cfg[label+'_file'],cfg[label+'_sha'],
                             'EC362_'+slot.upper()+'_'+label.upper())
        if cfg['floor'] is not None:
            need(type(cfg['floor']) is int and 0<=cfg['floor']<=MAX_SEQUENCE,
                 'CALLER_HELD_PUBLICATION_FLOOR_OUT_OF_BOUNDS')
        for val in cfg['external_copy_pins'].values():
            need(val is None or tr._sha(val),
                 'EXTERNAL_PER_SOURCE_COPY_SHA_MUST_BE_LOWERCASE_SHA256')
    prior=previous.audit(**prev_inputs)
    need(prior['schema']==previous.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec360_through_ec337_signed_originals_replayed'] is True,
         'TRUE_EC361_THROUGH_EC337_CRYPTOGRAPHIC_REPLAY_REQUIRED',
         'permission_denied')
    parent_sha=sha(canonical.canonical(prior))
    expected,selected,oldpins,oldpaths,seen_keys=_parent_evidence(prev_inputs,prior)
    parent_good=prior['locally_coherent_signed_directory_evolution_and_gossip'] is True
    saved_head=prior['expected_latest_checkpoint_sha256_as_caller_pin']
    minimum=prior['minimum_tree_size_as_caller_pin']
    newpins={};categories={};reviews=[]
    flags={'missing':False,'identities':False,'copies':False,
           'conflicts':False,'rollback':False,'time':False}
    names=set();key_shas=set();advertised={}
    if len(expected)!=len(COPY_ROLES) or selected is None or not tr._sha(saved_head):
        flags['missing']=True
    if selected is not None:
        directory_id=selected['directory_id']
        directory_key_sha=selected['directory_public_key_original_sha256']
    else:
        directory_id=None;directory_key_sha=None
    # The trusted extent is only caller-held key bytes; an Ed25519 signature
    # never attests its key is a real public authority or independent operator.
    directory_pub=None
    if prev_inputs.get('directory_public_key_file') and directory_key_sha:
        keypin={'path':prev_inputs['directory_public_key_file'],
                'sha256':prev_inputs['expected_directory_public_key_sha256']}
        inherited=parent.previous.parent.parent.prior._inherited
        directory_pub=inherited(keypin,'EC362_PARENT_DIRECTORY_PUBLIC_KEY',32,oldpins)
        need(len(directory_pub)==32 and sha(directory_pub)==directory_key_sha,
             'DIRECTORY_SIGNER_NOT_TRUE_EC361_ROLE','permission_denied')
    for slot in SLOTS:
        cfg=_source_args(inputs,slot)
        has_manifest=cfg['manifest_file'] is not None
        has_key=cfg['key_file'] is not None
        has_any=has_manifest or has_key or cfg['floor'] is not None or any(
            v is not None for v in cfg['external_copy_pins'].values())
        if not has_manifest or not has_key:
            flags['missing']=True
            need(not (has_manifest and not has_key),
                 'PRESENTED_SIGNED_SOURCE_REQUIRES_EXTERNAL_CUSTODIAN_KEY',
                 'permission_denied')
            if has_any:continue
            continue
        # A source role has exactly one SHA-pinned key and one SHA-pinned
        # signed manifest. Each source's four actual copies use NEW inodes.
        pub=parent.key_file(cfg['key_file'],cfg['key_sha'],'SOURCE_'+slot.upper(),
                            newpins,oldpaths,categories,seen_keys)
        key_shas.add(cfg['key_sha'])
        raw=parent.load({'path':cfg['manifest_file'],'sha256':cfg['manifest_sha']},
                        'SIGNED_PUBLICATION_SOURCE_'+slot.upper(),MAX_MANIFEST,
                        newpins,oldpaths,categories,'signed_manifest_'+slot)
        doc=tr.strict_json(raw,'EC362_SIGNED_PUBLICATION_'+slot)
        exact(doc,MANIFEST_FIELDS,'PUBLICATION_SOURCE_'+slot.upper())
        need(doc['schema']==MANIFEST_SCHEMA and doc['source_slot']==slot and
             tr._ident(doc['claimed_source_id']) and
             doc['custodian_public_key_original_sha256']==cfg['key_sha'] and
             doc['parent_ec361_canonical_result_sha256']==parent_sha and
             doc['parent_ec360_canonical_result_sha256']==
                prior['parent_ec360_canonical_result_sha256'] and
             doc['parent_directory_checkpoint_original_sha256']==
                prior['parent_directory_checkpoint_original_sha256'] and
             doc['directory_id']==directory_id,
             'SOURCE_MANIFEST_ROLE_PARENT_OR_DIRECTORY_BINDING_INVALID',
             'permission_denied')
        need(type(doc['publication_sequence']) is int and
             0<=doc['publication_sequence']<=MAX_SEQUENCE and
             tr._sha(doc['advertised_checkpoint_original_sha256']) and
             tr._sha(doc['advertised_root_sha256']) and
             type(doc['advertised_tree_size']) is int and
             1<=doc['advertised_tree_size']<=parent.MAX_DIRECTORY_LEAVES,
             'SOURCE_SEQUENCE_OR_SIGNED_HEAD_SHAPE_INVALID','permission_denied')
        issued,expires=parent.window(doc['issued_utc'],doc['expires_utc'],
                                     MAX_SPAN,'EC362_SOURCE_'+slot.upper())
        parent.sig(doc,'signature_custodian_ed25519_hex',pub,DOMAIN,
                   'EC362_SOURCE_'+slot.upper())
        exact(doc['copies'],COPY_ROLES,'SOURCE_COPY_ROLES')
        if doc['claimed_source_id'] in names:flags['identities']=True
        names.add(doc['claimed_source_id'])
        if cfg['floor'] is None:flags['missing']=True
        elif doc['publication_sequence']<cfg['floor']:flags['rollback']=True
        if parent.utc_untrusted(now,issued,expires,MAX_LAG):flags['time']=True
        copies={};match={};local_external=True
        for role in COPY_ROLES:
            ref=doc['copies'][role]
            exact(ref,('path','sha256'),'COPY_'+role.upper())
            actual=parent.load(ref,'OFFLINE_SOURCE_'+slot.upper()+'_'+role.upper(),
                          COPY_CAPS[role],newpins,oldpaths,categories,
                          'independent_copy_'+slot+'_'+role)
            copies[role]=actual
            ext=cfg['external_copy_pins'][role]
            if ext is None:
                flags['missing']=True;local_external=False
            elif ext!=ref['sha256']:
                flags['copies']=True;local_external=False
            match[role]=(expected.get(role)==ref['sha256'])
            if not match[role]:flags['copies']=True
        need(directory_pub is not None and selected is not None,
             'SIGNED_SOURCE_CANNOT_BE_AUTHENTICATED_WITHOUT_PARENT_DIRECTORY_KEY',
             'permission_denied')
        checkpoint,stale=previous.signed_checkpoint(
            copies['checkpoint'],directory_pub,directory_key_sha,directory_id,now)
        cp_sha=sha(copies['checkpoint'])
        need(doc['advertised_checkpoint_original_sha256']==cp_sha and
             doc['advertised_tree_size']==checkpoint['tree_size'] and
             doc['advertised_root_sha256']==checkpoint['root_sha256'],
             'SOURCE_SIGNED_HEAD_MUST_EQUAL_COPIED_REAL_DIRECTORY_SIGNATURE',
             'permission_denied')
        if stale:flags['time']=True
        advertised[slot]=(cp_sha,checkpoint)
        if cp_sha!=saved_head:
            flags['conflicts']=True
            if minimum is not None and checkpoint['tree_size']<minimum:
                flags['rollback']=True
            if checkpoint['tree_size']>selected['tree_size'] or (
                checkpoint['tree_size']<selected['tree_size']):
                flags['rollback']=True
        # Even a conflicting copy must be parsable; it cannot lend verification
        # to a parent Merkle proof unless its exact original is the true parent.
        proof=tr.strict_json(copies['consistency_bundle'],
                             'EC362_SOURCE_'+slot.upper()+'_CONSISTENCY_COPY')
        exact(proof,previous.BUNDLE_FIELDS,'COPIED_CONSISTENCY_BUNDLE')
        need(proof['schema']==previous.BUNDLE_SCHEMA,
             'COPIED_CONSISTENCY_BUNDLE_SCHEMA_INVALID','permission_denied')
        for observer_slot in SLOTS:
            obs=tr.strict_json(copies['observer_'+observer_slot+'_receipt'],
                               'EC362_SOURCE_'+slot.upper()+'_OBSERVER_COPY')
            exact(obs,previous.OBSERVER_FIELDS,'COPIED_OBSERVER_RECEIPT')
            need(obs['schema']==previous.OBSERVER_SCHEMA and obs['slot']==observer_slot,
                 'COPIED_OBSERVER_ROLE_INVALID','permission_denied')
            # Different original, even when genuinely signed, cannot be claimed
            # as the parent's exact observer receipt. Verify signature for any
            # alternate receipt and make its actual head disagreement visible.
            if not match['observer_'+observer_slot+'_receipt']:
                keypath=prev_inputs.get('observer_'+observer_slot+'_public_key_file')
                keysha=prev_inputs.get('expected_observer_'+observer_slot+
                                        '_public_key_sha256')
                need(keypath is not None and keysha is not None,
                     'OBSERVER_COPY_HAS_NO_PARENT_SIGNER','permission_denied')
                inherited=parent.previous.parent.parent.prior._inherited
                observer_pub=inherited({'path':keypath,'sha256':keysha},
                                'EC362_PRIOR_OBSERVER_'+observer_slot,32,oldpins)
                checkpoint_map={cp_sha:checkpoint,saved_head:selected}
                # Include the genuine EC360 anchor if a distinct observer
                # still points to it, but that is NOT a local current head.
                previous.signed_observer(copies['observer_'+observer_slot+'_receipt'],
                      observer_pub,keysha,observer_slot,
                      prior['parent_ec360_canonical_result_sha256'],
                      prior['parent_directory_checkpoint_original_sha256'],
                      checkpoint_map,now)
        reviews.append({
            'slot':slot,'claimed_source_id_unverified':doc['claimed_source_id'],
            'custodian_public_key_sha256':cfg['key_sha'],
            'signed_manifest_original_sha256':cfg['manifest_sha'],
            'manifest_sequence_as_signed_claim':doc['publication_sequence'],
            'minimum_sequence_as_caller_pin':cfg['floor'],
            'advertised_checkpoint_sha256':cp_sha,
            'advertised_tree_size_as_signed_claim':checkpoint['tree_size'],
            'advertised_root_sha256_as_signed_claim':checkpoint['root_sha256'],
            'copies_exactly_match_parent_original_sha':match,
            'all_four_copy_shas_separately_caller_pinned':local_external,
            'signed_clock_anomaly':bool(stale or
                parent.utc_untrusted(now,issued,expires,MAX_LAG)),
        })
    # A separately signed, visible same-size fork is NOT explained away by an
    # agreeing source. A larger signed head makes the saved head look stale.
    if len(advertised)==2:
        a,b=(advertised[s] for s in SLOTS)
        if a[0]!=b[0]:flags['conflicts']=True
        if a[1]['tree_size']==b[1]['tree_size'] and (
             a[1]['root_sha256']!=b[1]['root_sha256']):flags['conflicts']=True
        if saved_head not in (a[0],b[0]) or any(
            cp['tree_size']>selected['tree_size'] for _,cp in advertised.values()):
            flags['rollback']=True
    if len(key_shas)!=len(reviews):flags['identities']=True
    # Re-read actual parent and child bytes at exit. Recheck inode and symlink
    # ancestry independently; cannot become an atomic filesystem snapshot.
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    parent.previous.parent.parent._late_identity_check(newpins,oldpaths)
    coherent=(parent_good and len(reviews)==2 and len(key_shas)==2 and
              len(names)==2 and not any(flags.values()))
    if not parent_good:outcome=OUTCOMES[0]
    elif flags['missing']:outcome=OUTCOMES[1]
    elif flags['identities']:outcome=OUTCOMES[2]
    elif flags['copies']:outcome=OUTCOMES[3]
    elif flags['conflicts']:outcome=OUTCOMES[4]
    elif flags['rollback']:outcome=OUTCOMES[5]
    elif flags['time']:outcome=OUTCOMES[6]
    else:outcome=OUTCOMES[7]
    evidence=[{'tsa_channel_id':r['tsa_channel_id'],
      'parent_ec361_outcome':r['outcome'],'outcome':outcome}
      for r in prior['channel_evidence']]
    return {'schema':RESULT_SCHEMA,'command':'audit-directory-publication-custody',
      'status':outcome+'_unresolved','exit_code':2,'case_id':prior['case_id'],
      'actual_ec361_through_ec337_signed_originals_replayed':True,
      'parent_ec361_canonical_result_sha256':parent_sha,
      'parent_ec360_canonical_result_sha256':
          prior['parent_ec360_canonical_result_sha256'],
      'parent_selected_checkpoint_original_sha256':saved_head,
      'parent_consistency_bundle_original_sha256':
          prior['consistency_bundle_original_sha256'],
      'publication_copy_evaluation_utc_as_caller_claim':publication_copy_evaluation_utc,
      'signed_publication_source_reviews':reviews,
      'signed_source_count':len(reviews),
      'ec361_parent_locally_coherent':parent_good,
      'external_sources_or_copy_pins_missing':flags['missing'],
      'publication_source_identity_or_role_collision':flags['identities'],
      'original_copies_or_caller_sha_pins_mismatch':flags['copies'],
      'independently_presented_signed_checkpoint_conflict':flags['conflicts'],
      'caller_publication_floor_or_newer_head_rollback':flags['rollback'],
      'source_signed_utc_claim_stale_or_future':flags['time'],
      'both_distinct_custodian_signatures_verified_locally':
          len(reviews)==2 and len(key_shas)==2,
      'each_four_original_copies_exactly_agree_with_parent':
          len(reviews)==2 and all(all(r['copies_exactly_match_parent_original_sha'].values())
                                  for r in reviews),
      'two_offline_signed_publication_copies_locally_coherent':coherent,
      'public_custody_official_dissemination_and_global_latest_unproven':True,
      'channel_evidence':evidence,
      'outcome_counts':{o:sum(r['outcome']==o for r in evidence) for o in OUTCOMES},
      'offline_unresolved_exit_code':2,
      **{key:False for key in NEGATIVES}}
