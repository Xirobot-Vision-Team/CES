#!/usr/bin/env python3
"""EC371 receiver-held EC360/362/365 REAL signed directory original replay.

Every call also replays the live EC370 -> EC369 detached receiver chain. The
historical material is a NEW, separately caller-SHA-pinned receiver archive:
no sender-origin path is opened, no cached audit JSON is substituted and no
missing EC365..EC337 evidence is invented. Real directory checkpoints, two
real custodian-signed source manifests per epoch and dual-directory-key-signed
EC365 rotation events are verified against exact receiver-held bytes and
caller-retained SHA streams. RFC6962 consistency is checked on the signed
checkpoint roots, not trusted because it is included in an archive JSON.

This is PARTIAL historical cryptographic recovery, not a replay of the EC365
canonical result or the entire EC365..337 ancestry. All lawful results exit 2.
"""
from __future__ import annotations

from collections import defaultdict

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec360_authority_directory import authority
from ec362_publication_custody import custody
from ec364_cross_epoch import continuity
from ec365_directory_lineage import lineage
from ec370_publication_accountability import accountability as prior

RESULT_SCHEMA='ces.ec371.receiver_historical_directory_originals_unresolved.v1'
DENIAL_SCHEMA='ces.ec371.receiver_historical_directory_originals_denial.v1'
BUNDLE_SCHEMA='ces.ec371.receiver_historical_directory_archive.v1'
INVENTORY_SCHEMA='ces.ec371.receiver_historical_directory_verified_sha_inventory.v1'
DERIVE_SCHEMA='ces.ec371.unsigned_receiver_historical_inventory_unresolved.v1'
MAX_EPOCHS=3
MAX_COMPETING=4
MAX_BUNDLE=48_000
MAX_PROOF_NODES=64
NEW_SCALARS=(
 'historical_archive_bundle_file','expected_historical_archive_bundle_sha256',
 'claimed_historical_directory_lineage_id',
 'expected_retained_historical_checkpoint_head_sha256',
 'minimum_retained_historical_tree_size',
 'minimum_retained_historical_root_generation',
)
NEW_REPEATS=(
 ('historical_directory_root_shas','--historical-directory-root-sha256'),
 ('historical_signed_checkpoint_shas','--historical-signed-checkpoint-sha256'),
 ('historical_source_a_manifest_shas','--historical-source-a-manifest-sha256'),
 ('historical_source_b_manifest_shas','--historical-source-b-manifest-sha256'),
 ('historical_dual_handoff_shas','--historical-dual-handoff-sha256'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
AUDIT_ONLY=('expected_retained_historical_inventory_sha256',)
BUNDLE_FIELDS={'schema','parent_ec370_canonical_result_sha256',
 'parent_ec365_canonical_result_sha256','claimed_directory_lineage_id',
 'epochs','transitions','competing_signed_checkpoints',
 'competing_signed_source_manifests','competing_signed_handoffs'}
EPOCH_FIELDS={'epoch_index','directory_public_key_original',
 'signed_directory_checkpoint_original','source_a_manifest_original',
 'source_b_manifest_original','source_a_custodian_public_key_original',
 'source_b_custodian_public_key_original'}
TRANSITION_FIELDS={'signed_directory_handoff_original',
                   'rfc6962_consistency_proof'}
COMPETING_CP_FIELDS={'epoch_index','signed_directory_checkpoint_original'}
COMPETING_SOURCE_FIELDS={'epoch_index','source_slot','signed_source_manifest_original'}
COMPETING_HANDOFF_FIELDS={'edge_index','signed_directory_handoff_original'}
FLAGS=(
 'inherited_detached_publication_signatures_or_disclosures_unresolved',
 'historical_archive_independent_pins_or_floor_mismatch',
 'historical_signed_directory_checkpoint_fork_or_newer_head_visible',
 'historical_source_signed_publication_fork_or_newer_manifest_visible',
 'historical_rfc6962_append_only_proof_missing_or_invalid',
 'historical_double_signed_directory_handoff_missing_or_fork_visible',
 'historical_signed_directory_retirement_or_role_conflict_visible',
 'historical_source_publication_head_or_clock_anomaly_visible',
 'historical_archive_only_partially_recovers_ec365_to_ec337',
)
OUTCOMES=(
 'ec371_inherited_detached_publication_has_unresolved_dispute',
 'ec371_independently_retained_historical_originals_or_floors_mismatch',
 'ec371_genuine_historical_signed_directory_fork_or_new_head',
 'ec371_genuine_historical_signed_source_manifest_fork_or_newer_head',
 'ec371_historical_signed_directory_rfc6962_proof_missing_or_invalid',
 'ec371_genuine_historical_dual_handoff_missing_or_conflicting',
 'ec371_directory_retirement_or_signer_lineage_conflict',
 'ec371_historical_source_publication_or_clock_conflict',
 'ec371_historical_directory_origins_only_partially_recovered',
)
NEGATIVES=(
 'full_ec365_to_ec337_historical_parent_audit_replayed',
 'archive_canonical_sha_matches_the_actual_ec365_result_bytes',
 'old_ec361_to_ec337_parent_directories_and_revocations_replayed',
 'source_manifest_unopened_other_copy_roles_verified',
 'historical_copies_prove_globally_complete_directory_or_absence_of_hidden_forks',
 'caller_pinned_directory_keys_are_official_legal_authorities',
 'signed_self_claimed_utc_is_trusted_timestamp',
 'new_archive_repairs_ec370_ec369_signed_withholding_revocation_or_dispute',
 'sender_original_source_paths_opened_or_restored',
 'new_signatures_private_keys_network_remote_provider_cas_worm_or_powershell_used',
 'old_ec317_ec318_deep_mock_removed_or_final_acceptance_proven',
)


def need(condition,code,status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC371_'+code,status)


def exact(doc,fields,role):
    need(type(doc) is dict and set(doc)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return prior.digest(raw)


def _input_check(opts,derive):
    expected=set(prior.NEW_SCALARS)|set(prior.NEW_REPEAT_NAMES)|set(prior.prior.SCALARS)|set(prior.prior.REPEAT_NAMES)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'EXACT_EC370_AND_HISTORICAL_INPUTS_REQUIRED')
    inherited={key:opts[key] for key in (*prior.prior.SCALARS,
                    *prior.prior.REPEAT_NAMES,*prior.NEW_SCALARS,
                    *prior.NEW_REPEAT_NAMES)}
    prior._inputs(inherited)
    authority.outer_pin(opts['historical_archive_bundle_file'],
                        opts['expected_historical_archive_bundle_sha256'],
                        'EC371_HISTORICAL_ARCHIVE_BUNDLE')
    need(opts['historical_archive_bundle_file'] is not None and
         opts['expected_historical_archive_bundle_sha256'] is not None,
         'CALLER_PINNED_RECEIVER_ARCHIVE_REQUIRED')
    need(tr._ident(opts['claimed_historical_directory_lineage_id']),
         'STRICT_HISTORICAL_DIRECTORY_LINEAGE_ID_REQUIRED')
    need(tr._sha(opts['expected_retained_historical_checkpoint_head_sha256']),
         'CALLER_RETAINED_SIGNED_DIRECTORY_HEAD_REQUIRED')
    for key in AUDIT_ONLY:
        if not derive:need(tr._sha(opts[key]),'CALLER_RETAINED_CANONICAL_INVENTORY_REQUIRED')
    for name,high in (('minimum_retained_historical_tree_size',64),
                      ('minimum_retained_historical_root_generation',2)):
        value=opts[name]
        need(type(value) is int and 0<=value<=high,
             name.upper()+'_OUT_OF_BOUNDS')
    for name in REPEAT_NAMES:
        seq=opts[name]
        cap=MAX_EPOCHS-1 if name=='historical_dual_handoff_shas' else MAX_EPOCHS
        minimum=0 if name=='historical_dual_handoff_shas' else 1
        need(type(seq) is list and minimum<=len(seq)<=cap and
             all(tr._sha(v) for v in seq),
             name.upper()+'_BOUNDED_SHA_LIST_INVALID')
        if name=='historical_dual_handoff_shas':
            need(len(seq)==len(set(seq)), 'DUPLICATED_SIGNED_HANDOFF_SHA_DENIED')
    return inherited


def _read(ref,role,limit,pins,categories,forbidden):
    lineage.parent.ref_check(ref,'EC371_'+role+'_REFERENCE')
    need(ref['path'] not in forbidden,'ARCHIVE_REF_ALIASES_HISTORICAL_SOURCE_PATH',
         'permission_denied')
    # Inherited no-symlink, no special files, SHA + inode/late identity reader.
    return prior._read(ref,'ec371_'+role,limit,pins,categories,forbidden)


def _root_and_sources(i,refrow,opts,now,read,unopened_source_labels,used_roles):
    exact(refrow,EPOCH_FIELDS,'HISTORICAL_EPOCH')
    need(type(refrow['epoch_index']) is int and refrow['epoch_index']==i,
         'HISTORICAL_EPOCH_INDEX_NOT_CONTIGUOUS')
    root_ref=refrow['directory_public_key_original']
    root=read(root_ref,'directory_root_'+str(i),32)
    need(len(root)==32,'DIRECTORY_ED25519_KEY_MUST_BE_32_BYTES','permission_denied')
    need(root_ref['sha256'] not in used_roles,
         'HISTORICAL_DIRECTORY_ROOT_REUSES_INHERITED_SIGNER_KEY',
         'permission_denied')
    need(root_ref['sha256']==opts['historical_directory_root_shas'][i],
         'EXTERNAL_DIRECTORY_ROOT_SHA_MISMATCH','permission_denied')
    cp_ref=refrow['signed_directory_checkpoint_original']
    cpraw=read(cp_ref,'directory_checkpoint_'+str(i),authority.MAX_ORIGINAL)
    need(cp_ref['sha256']==opts['historical_signed_checkpoint_shas'][i],
         'EXTERNAL_SIGNED_CHECKPOINT_SHA_MISMATCH','permission_denied')
    cp,clock=authority.directory_checkpoint(cpraw,root,root_ref['sha256'],now)
    need(cp['directory_id']==opts['claimed_historical_directory_lineage_id'],
         'SIGNED_CHECKPOINT_DIRECTORY_ID_CONFLICT','permission_denied')
    sources={};anomaly=clock
    for slot in ('a','b'):
        manifest_ref=refrow['source_'+slot+'_manifest_original']
        manifest=tr.strict_json(read(manifest_ref,'manifest_'+slot+'_'+str(i),
                                   custody.MAX_MANIFEST),
                                 'EC371_REAL_SIGNED_SOURCE_'+slot)
        exact(manifest,custody.MANIFEST_FIELDS,'SOURCE_MANIFEST')
        need(manifest_ref['sha256']==opts['historical_source_'+slot+'_manifest_shas'][i],
             'EXTERNAL_SOURCE_MANIFEST_SHA_MISMATCH','permission_denied')
        keyref=refrow['source_'+slot+'_custodian_public_key_original']
        key=read(keyref,'custodian_'+slot+'_'+str(i),32)
        need(len(key)==32 and keyref['sha256']!=root_ref['sha256'],
             'CUSTODIAN_DIRECTORY_ROLE_KEY_COLLISION','permission_denied')
        need(manifest['schema']==custody.MANIFEST_SCHEMA and
             manifest['source_slot']==slot and
             tr._ident(manifest['claimed_source_id']) and
             manifest['custodian_public_key_original_sha256']==keyref['sha256'] and
             manifest['directory_id']==cp['directory_id'] and
             tr._sha(manifest['parent_ec361_canonical_result_sha256']) and
             tr._sha(manifest['parent_ec360_canonical_result_sha256']) and
             tr._sha(manifest['parent_directory_checkpoint_original_sha256']) and
             tr._sha(manifest['advertised_checkpoint_original_sha256']) and
             manifest['advertised_checkpoint_original_sha256']==cp_ref['sha256'] and
             type(manifest['advertised_tree_size']) is int and
             manifest['advertised_tree_size']==cp['tree_size'] and
             manifest['advertised_root_sha256']==cp['root_sha256'] and
             type(manifest['publication_sequence']) is int and
             0<=manifest['publication_sequence']<=custody.MAX_SEQUENCE,
             'SIGNED_HISTORICAL_SOURCE_MANIFEST_ENDPOINT_MISMATCH',
             'permission_denied')
        # These four old path labels are ONLY data from the signature. No I/O
        # on them. Even the checkpoint is verified from a distinct receiver ref.
        copies=manifest['copies']
        need(type(copies) is dict and set(copies)==set(custody.COPY_ROLES),
             'HISTORICAL_MANIFEST_FOUR_COPY_ROLES_REQUIRED')
        for role,ref in copies.items():
            lineage.parent.ref_check(ref,'EC371_SIGNED_HISTORICAL_'+role)
            unopened_source_labels.add(ref['path'])
        need(copies['checkpoint']['sha256']==cp_ref['sha256'],
             'SIGNED_ORIGINAL_CHECKPOINT_SHA_DIFFERS_FROM_RECEIVER_COPY',
             'permission_denied')
        authority.sig(manifest,'signature_custodian_ed25519_hex',key,
                      custody.DOMAIN,'EC371_REAL_CUSTODIAN_'+slot)
        start,end=authority.window(manifest['issued_utc'],manifest['expires_utc'],
                                   custody.MAX_SPAN,'EC371_SOURCE_MANIFEST')
        anomaly|=authority.utc_untrusted(now,start,end,custody.MAX_LAG)
        need(keyref['sha256'] not in used_roles and
             manifest['claimed_source_id'] not in used_roles,
             'HISTORICAL_CUSTODIAN_ROLE_DUPLICATE','permission_denied')
        # Only inherited roles are forbidden here. Later all historic epochs
        # are compared by role so a legitimate carry key can be reused.
        # Do not insert the new historical role into the inherited set.
        sources[slot]={'manifest_sha':manifest_ref['sha256'],
                       'manifest':manifest,'pub':key,'key_sha':keyref['sha256']}
    need(sources['a']['manifest']['parent_ec361_canonical_result_sha256']==
         sources['b']['manifest']['parent_ec361_canonical_result_sha256'],
         'TWO_SIGNED_MANIFESTS_DISAGREE_PARENT_EC361','permission_denied')
    need(sources['a']['manifest']['claimed_source_id']!=
         sources['b']['manifest']['claimed_source_id'],
         'DUAL_SOURCE_IDENTITIES_NOT_DISTINCT','permission_denied')
    if (sources['a']['manifest']['parent_ec360_canonical_result_sha256']!=
        sources['b']['manifest']['parent_ec360_canonical_result_sha256'] or
        sources['a']['manifest']['parent_directory_checkpoint_original_sha256']!=
        sources['b']['manifest']['parent_directory_checkpoint_original_sha256']):
        anomaly=True  # genuine source-signed divergent historic ancestor claim
    return {'index':i,'key_sha':root_ref['sha256'],'pub':root,
            'ec361_sha':sources['a']['manifest']['parent_ec361_canonical_result_sha256'],
            'directory_id':cp['directory_id'],'cp_sha':cp_ref['sha256'],
            'cp':cp,'sources':sources,'clock_anomaly':bool(anomaly)}


def _manifest(opts,parent,eps,edges,verified_proofs,competing_cp,competing_sources,competing_handoffs):
    return {
      'schema':INVENTORY_SCHEMA,
      'parent_ec370_canonical_result_sha256':sha(canonical.canonical(parent)),
      'claimed_parent_ec365_canonical_result_sha256':opts[
          'expected_parent_ec365_canonical_result_sha256'],
      'historical_archive_bundle_original_sha256':opts[
          'expected_historical_archive_bundle_sha256'],
      'historical_directory_lineage_id':opts['claimed_historical_directory_lineage_id'],
      'directory_root_original_sha256_stream':[e['key_sha'] for e in eps],
      'directory_checkpoint_original_sha256_stream':[e['cp_sha'] for e in eps],
      'source_a_manifest_original_sha256_stream':[e['sources']['a']['manifest_sha'] for e in eps],
      'source_b_manifest_original_sha256_stream':[e['sources']['b']['manifest_sha'] for e in eps],
      'dual_directory_handoff_original_sha256_stream':edges,
      'verified_rfc6962_append_edge_count':verified_proofs,
      'genuinely_signed_competing_checkpoint_original_sha256_stream':competing_cp,
      'genuinely_signed_competing_source_manifest_sha256_stream':competing_sources,
      'genuinely_dual_signed_competing_handoff_original_sha256_stream':competing_handoffs,
    }


def _engine(derive,**opts):
    inherited=_input_check(opts,derive)
    # Mandatory TRUE live EC370, not a favorable cached response document.
    parent=prior.audit(**inherited)
    need(parent['schema']==prior.RESULT_SCHEMA and parent['exit_code']==2,
         'ACTUAL_EC370_PARENT_AUDIT_REQUIRED','unavailable')
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set();historical_labels=set()
    def read(ref,role,cap):return _read(ref,role,cap,pins,categories,forbidden)
    # The source labels are untrusted historical metadata and NEVER opened.
    dref={'path':opts['detached_bundle_file'],
          'sha256':opts['expected_detached_bundle_sha256']}
    detached=tr.strict_json(read(dref,'ec369_detached_bundle',prior.prior.MAX_BUNDLE),
                            'EC371_REOPEN_EC369_DETACHED')
    prior.prior.exact(detached,prior.prior.BUNDLE_FIELDS,'EC371_EC369_BUNDLE')
    m=tr.strict_json(read(detached['signed_copy_map_original'],
                          'ec369_signed_map',prior.prior.MAX_MAP),
                     'EC371_REOPEN_EC369_SIGNED_MAP')
    prior.prior.exact(m,prior.prior.MAP_FIELDS,'EC371_SIGNED_SOURCE_MAP')
    forbidden.update(row['source_original']['path'] for row in m['originals'])
    need(not set(pins).intersection(forbidden),
         'PARENT_OR_ARCHIVE_READ_ALIASES_MISSING_SENDER_ORIGINAL',
         'permission_denied')
    bref={'path':opts['historical_archive_bundle_file'],
          'sha256':opts['expected_historical_archive_bundle_sha256']}
    b=tr.strict_json(read(bref,'archive_bundle',MAX_BUNDLE),
                     'EC371_HISTORICAL_ARCHIVE')
    exact(b,BUNDLE_FIELDS,'RECEIVER_HISTORICAL_ARCHIVE')
    need(b['schema']==BUNDLE_SCHEMA and
         b['claimed_directory_lineage_id']==opts['claimed_historical_directory_lineage_id'] and
         b['parent_ec370_canonical_result_sha256']==sha(canonical.canonical(parent)) and
         b['parent_ec365_canonical_result_sha256']==opts[
             'expected_parent_ec365_canonical_result_sha256'] and
         m['parent_ec365_canonical_result_sha256']==b[
             'parent_ec365_canonical_result_sha256'],
         'RECEIVER_ARCHIVE_NOT_BOUND_TO_ACTUAL_DETACHED_PARENT_DIGEST',
         'permission_denied')
    rows=b['epochs']
    need(type(rows) is list and 1<=len(rows)<=MAX_EPOCHS,
         'HISTORICAL_ARCHIVE_EPOCHS_MUST_BE_ONE_TO_THREE')
    for stream in ('historical_directory_root_shas',
                   'historical_signed_checkpoint_shas',
                   'historical_source_a_manifest_shas',
                   'historical_source_b_manifest_shas'):
        need(len(opts[stream])==len(rows),stream.upper()+'_LENGTH_MISMATCH')
    need(type(b['transitions']) is list and len(b['transitions'])==len(rows)-1,
         'HISTORICAL_ARCHIVE_ADJACENT_EDGES_REQUIRED')
    need(type(b['competing_signed_checkpoints']) is list and
         len(b['competing_signed_checkpoints'])<=MAX_COMPETING and
         type(b['competing_signed_handoffs']) is list and
         len(b['competing_signed_handoffs'])<=MAX_COMPETING and
         type(b['competing_signed_source_manifests']) is list and
         len(b['competing_signed_source_manifests'])<=MAX_COMPETING,
         'BOUNDED_COMPETING_SIGNED_ORIGINALS_REQUIRED')
    used_roles=set(opts['institution_root_public_key_shas']+
                   opts['witness_public_key_shas']+
                   [opts['expected_sender_public_key_sha256'],
                    opts['expected_receiver_public_key_sha256'],
                    opts['expected_publisher_public_key_sha256'],
                    opts['expected_publication_observer_public_key_sha256'],
                    *opts['institution_claimed_ids'],*opts['witness_claimed_ids'],
                    opts['claimed_sender_id'],opts['claimed_receiver_id'],
                    opts['claimed_publisher_id'],opts['claimed_publication_observer_id']])
    eps=[_root_and_sources(i,r,opts,now,read,historical_labels,used_roles)
         for i,r in enumerate(rows)]
    # Original source paths from old manifests were NEVER opened. Signed path
    # labels can be identical to copied source paths only if separately read
    # by an auditor elsewhere: reject any alias in THIS receiver archive.
    need(not set(pins).intersection(historical_labels|forbidden),
         'ARCHIVE_READ_PATH_ALIASES_HISTORICAL_SENDER_LABEL',
         'permission_denied')
    # A historical custodian may keep the SAME key across adjacent epochs,
    # but neither slot may borrow the other's key, a directory root or an
    # inherited EC369/370 signing role. Root keys never become custodians.
    root_keys=set(e['key_sha'] for e in eps)
    source_role_keys={}
    source_role_ids={}
    source_claim_by_key={}
    for e in eps:
        for slot in ('a','b'):
            key=e['sources'][slot]['key_sha']
            need(key not in root_keys and (key not in source_role_keys or
                 source_role_keys[key]==slot),
                 'HISTORICAL_ROOT_OR_OTHER_SOURCE_CUSTODIAN_KEY_COLLISION',
                 'permission_denied')
            source_role_keys[key]=slot
            ident=e['sources'][slot]['manifest']['claimed_source_id']
            need(ident not in source_role_ids or source_role_ids[ident]==slot,
                 'HISTORICAL_SOURCE_CLAIMED_ID_REUSED_BY_OTHER_ROLE',
                 'permission_denied')
            source_role_ids[ident]=slot
            if key in source_claim_by_key and source_claim_by_key[key]!=ident:
                need(False,'SAME_HISTORICAL_KEY_CLAIMS_TWO_SOURCE_IDENTITIES',
                     'permission_denied')
            source_claim_by_key[key]=ident
    need(len(set((e['key_sha'],e['cp_sha'],e['sources']['a']['manifest_sha'],
                  e['sources']['b']['manifest_sha']) for e in eps))==len(eps),
         'DUPLICATE_HISTORICAL_EPOCH_INVENTORY_DENIED')
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=not parent['locally_two_party_publication_and_full_inventory_consistent']
    flags[FLAGS[7]]=any(e['clock_anomaly'] for e in eps)
    flags[FLAGS[8]]=True   # Full EC365..337 history is NEVER re-audited here.
    roots=[e['key_sha'] for e in eps];history_generation=0
    for i,e in enumerate(eps):
        if i and roots[i] in roots[:i] and roots[i]!=roots[i-1]:
            flags[FLAGS[6]]=True  # retired root reanimated
        if i and e['cp']['tree_size']<eps[i-1]['cp']['tree_size']:
            flags[FLAGS[2]]=True
        if i and (e['sources']['a']['manifest']['publication_sequence']<=
                  eps[i-1]['sources']['a']['manifest']['publication_sequence'] or
                  e['sources']['b']['manifest']['publication_sequence']<=
                  eps[i-1]['sources']['b']['manifest']['publication_sequence']):
            flags[FLAGS[7]]=True
    actual_handoffs=[];verified_proofs=0
    for i,entry in enumerate(b['transitions']):
        if entry is None:
            flags[FLAGS[5]]=True
            continue
        exact(entry,TRANSITION_FIELDS,'HISTORICAL_DUAL_HANDOFF_TRANSITION')
        ref=entry['signed_directory_handoff_original']
        doc=tr.strict_json(read(ref,'handoff_'+str(i),lineage.MAX_EVENT),
                           'EC371_REAL_OLD_NEW_DUAL_HANDOFF')
        proof=entry['rfc6962_consistency_proof']
        exact(proof,continuity.PROOF_FIELDS,'HISTORICAL_RFC6962_EDGE')
        left,right=eps[i:i+2]
        correct_proof=(type(proof['from_epoch_index']) is int and
          proof['from_epoch_index']==i and type(proof['to_epoch_index']) is int and
          proof['to_epoch_index']==i+1 and
          proof['older_checkpoint_original_sha256']==left['cp_sha'] and
          proof['newer_checkpoint_original_sha256']==right['cp_sha'] and
          type(proof['audit_path_sha256']) is list and
          len(proof['audit_path_sha256'])<=MAX_PROOF_NODES and
          all(tr._sha(x) for x in proof['audit_path_sha256']))
        need(correct_proof,'RFC6962_PROOF_FORMAT_OR_CHECKPOINT_BINDING_INVALID',
             'permission_denied')
        # Verify old+new REAL signatures using inherited precise EC365 wire,
        # original signed SHA pairs and SHA of exact claimed RFC6962 proof.
        edge=lineage._check_signed_handoff(doc,left,right,proof,
             opts['claimed_historical_directory_lineage_id'],history_generation,now)
        actual_handoffs.append(ref['sha256'])
        if edge['role_bad'] or edge['terminal']:
            flags[FLAGS[6]]=True
        if edge['clock']:flags[FLAGS[7]]=True
        if not tr.verify_consistency(left['cp']['tree_size'],
             right['cp']['tree_size'],bytes.fromhex(left['cp']['root_sha256']),
             bytes.fromhex(right['cp']['root_sha256']),
             [bytes.fromhex(s) for s in proof['audit_path_sha256']]):
            flags[FLAGS[4]]=True
        else:verified_proofs+=1
        history_generation=edge['generation']
    if len(actual_handoffs)!=len(rows)-1 or len(rows)<2:
        flags[FLAGS[5]]=True
    if opts['historical_dual_handoff_shas']!=actual_handoffs:
        flags[FLAGS[1]]=True
    if (roots[-1]!=roots[0] and history_generation==0) or (
         roots[-1]==roots[0] and history_generation>0):flags[FLAGS[6]]=True
    if (eps[-1]['cp_sha']!=opts['expected_retained_historical_checkpoint_head_sha256'] or
        eps[-1]['cp']['tree_size']<opts['minimum_retained_historical_tree_size'] or
        history_generation<opts['minimum_retained_historical_root_generation']):
        flags[FLAGS[1]]=True
    competing_cp=[]; competing_source=[]; competing_handoff=[]
    for entry in b['competing_signed_checkpoints']:
        exact(entry,COMPETING_CP_FIELDS,'COMPETING_DIRECTORY_CHECKPOINT')
        i=entry['epoch_index'];need(type(i) is int and 0<=i<len(eps),
                                   'COMPETING_CHECKPOINT_EPOCH_OUT_OF_RANGE')
        ref=entry['signed_directory_checkpoint_original']
        need(ref['sha256'] not in competing_cp and
             ref['sha256'] not in opts['historical_signed_checkpoint_shas'],
             'COMPETING_CHECKPOINT_DUPLICATES_SELECTED_OR_EACH_OTHER')
        d,_=authority.directory_checkpoint(read(ref,'competing_checkpoint',
                    authority.MAX_ORIGINAL),eps[i]['pub'],eps[i]['key_sha'],now)
        need(d['directory_id']==eps[i]['directory_id'],
             'COMPETING_SIGNED_CHECKPOINT_DIRECTORY_MISMATCH','permission_denied')
        competing_cp.append(ref['sha256'])
        # Every separately genuine competing signed original remains visible;
        # a later tree or same-size different Merkle root is a split/rollback
        # signal, but even an earlier distinct signature cannot be discarded.
        flags[FLAGS[2]]=True
    for entry in b['competing_signed_source_manifests']:
        exact(entry,COMPETING_SOURCE_FIELDS,'COMPETING_SOURCE_MANIFEST')
        i=entry['epoch_index'];slot=entry['source_slot']
        need(type(i) is int and 0<=i<len(eps) and slot in ('a','b'),
             'COMPETING_SOURCE_EPOCH_OR_SLOT_INVALID')
        ref=entry['signed_source_manifest_original']
        need(ref['sha256'] not in competing_source and
             ref['sha256'] not in [e['sources'][side]['manifest_sha']
                    for e in eps for side in ('a','b')],
             'COMPETING_SOURCE_ORIGINAL_DUPLICATE_OR_SELECTED')
        actual=tr.strict_json(read(ref,'competing_source_manifest',custody.MAX_MANIFEST),
                              'EC371_COMPETING_TRUE_SOURCE_MANIFEST')
        exact(actual,custody.MANIFEST_FIELDS,'COMPETING_SOURCE_MANIFEST')
        src=eps[i]['sources'][slot]
        need(actual['schema']==custody.MANIFEST_SCHEMA and
             actual['source_slot']==slot and
             actual['claimed_source_id']==src['manifest']['claimed_source_id'] and
             actual['directory_id']==eps[i]['directory_id'] and
             actual['custodian_public_key_original_sha256']==src['key_sha'] and
             actual['parent_ec361_canonical_result_sha256']==eps[i]['ec361_sha'],
             'COMPETING_SIGNED_SOURCE_NOT_SAME_HISTORICAL_ORIGIN',
             'permission_denied')
        authority.sig(actual,'signature_custodian_ed25519_hex',src['pub'],
                      custody.DOMAIN,'EC371_COMPETING_REAL_SOURCE_'+slot)
        original_copies=actual['copies']
        need(type(original_copies) is dict and
             set(original_copies)==set(custody.COPY_ROLES),
             'COMPETING_SOURCE_COPY_ROLES_REQUIRED')
        for role,src_ref in original_copies.items():
            lineage.parent.ref_check(src_ref,'EC371_COMPETING_'+role)
            historical_labels.add(src_ref['path'])
        competing_source.append(ref['sha256'])
        flags[FLAGS[3]]=True
    for entry in b['competing_signed_handoffs']:
        exact(entry,COMPETING_HANDOFF_FIELDS,'COMPETING_DIRECTORY_HANDOFF')
        i=entry['edge_index'];need(type(i) is int and 0<=i<len(eps)-1,
                                   'COMPETING_DUAL_HANDOFF_EDGE_OUT_OF_RANGE')
        need(b['transitions'][i] is not None,
             'COMPETING_HANDOFF_WITHOUT_SELECTED_AUTHENTIC_EDGE')
        ref=entry['signed_directory_handoff_original']
        need(ref['sha256'] not in competing_handoff and
             ref['sha256'] not in actual_handoffs,
             'COMPETING_HANDOFF_DUPLICATES_SELECTED_OR_EACH_OTHER')
        d=tr.strict_json(read(ref,'competing_handoff',lineage.MAX_EVENT),
                         'EC371_COMPETING_TRUE_DUAL_HANDOFF')
        p=b['transitions'][i]['rfc6962_consistency_proof']
        info=lineage._check_signed_handoff(d,eps[i],eps[i+1],p,
                opts['claimed_historical_directory_lineage_id'],
                sum(eps[j]['key_sha']!=eps[j+1]['key_sha'] for j in range(i)),now)
        if info['clock']:flags[FLAGS[7]]=True
        competing_handoff.append(ref['sha256'])
        flags[FLAGS[5]]=True
    need(not set(pins).intersection(historical_labels|forbidden),
         'HISTORICAL_COPIED_READ_ALIASES_ORIGIN_SOURCE_PATH',
         'permission_denied')
    tsa._check_late(pins)
    # Canonical inventory is computed ONLY from bytes actually reopened and
    # independently signature checked here, never accepted as a signed truth.
    inventory=_manifest(opts,parent,eps,actual_handoffs,verified_proofs,
                        competing_cp,competing_source,competing_handoff)
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts['expected_retained_historical_inventory_sha256']:
        flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:-1])
    status=(next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                  OUTCOMES[-1])+'_unresolved')
    result={
        'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
        'command':'derive-historical-directory-inventory' if derive else 'audit-historical-directory-archive',
        'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
        'historical_archive_bundle_original_sha256':bref['sha256'],
        'verified_live_parent_ec370_result_canonical_sha256':sha(canonical.canonical(parent)),
        'claimed_parent_ec365_canonical_result_sha256':b['parent_ec365_canonical_result_sha256'],
        'receiver_verified_historical_inventory_canonical_sha256':digest,
        'original_directory_root_sha256_stream':roots,
        'original_signed_checkpoint_sha256_stream':[e['cp_sha'] for e in eps],
        'true_verified_directory_checkpoint_ed25519_count':len(eps)+len(competing_cp),
        'true_verified_source_custodian_ed25519_count':2*len(eps),
        'true_verified_old_new_dual_handoff_pair_count':len(actual_handoffs)+len(competing_handoff),
        'true_verified_rfc6962_directory_append_edges':verified_proofs,
        'genuinely_signed_competing_directory_checkpoints':len(competing_cp),
        'genuinely_signed_competing_source_manifests':len(competing_source),
        'genuinely_dual_signed_competing_handoffs':len(competing_handoff),
        'last_historical_tree_size':eps[-1]['cp']['tree_size'],
        'last_historical_root_generation':history_generation,
        'local_pinned_historical_directory_signature_and_proof_consistency':bool(local),
        'inherited_ec370_locally_two_party_publication_consistent':bool(
            parent['locally_two_party_publication_and_full_inventory_consistent']),
        'sender_origin_path_required_or_read':False,
        'ec365_to_ec337_full_parent_original_replay_performed':False,
        **flags,**{x:False for x in NEGATIVES},
    }
    if derive:
        result['unsigned_verified_historical_inventory']=inventory
        result['external_inventory_pin_created_or_certified']=False
    return result


def audit(**opts):return _engine(False,**opts)


def derive_inventory(**opts):return _engine(True,**opts)
