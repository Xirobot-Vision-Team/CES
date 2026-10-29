#!/usr/bin/env python3
"""EC381: receiver-only reconstruction of original EC349 channel authority.

Replays genuine EC349 directory/root, receipt ancestors/visible siblings and
signed time witnesses against *the actual* EC380 -> EC369 audit, not a caller
report. Optional exact EC348 sources can be replayed (never synthesized).
Signatures and local SHA custody are not institutional independence or UTC.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import os

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from hold_receipts import timeline as old343
from external_custody import custody as old348
from dual_channel_anchor import anchor as old349
from tsa_timestamp import timestamp as old350
from transparency import transparency as old353
from historical_authority import authority_archive as p372
from historical_disclosure import disclosure_archive as p376
from historical_source import source_archive as p379
from historical_timestamp import timestamp_archive as previous

RESULT_SCHEMA = 'ces.ec381.receiver_original_ec349_directory_receipts_witnesses_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec381.unsigned_original_ec349_directory_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec381.receiver_original_ec349_authority_denial.v1'
BUNDLE_SCHEMA = 'ces.ec381.receiver_old_ec349_channel_original_archive.v1'
INVENTORY_SCHEMA = 'ces.ec381.receiver_verified_old_ec349_channel_original_inventory.v1'
MAX_BUNDLE = 110_000
MAX_SIGNED = 300_000
MAX_RECEIPTS = old349.MAX_RECEIPTS
MAX_TIMES = old349.MAX_TIMES
NEW_SCALARS = ('historical_ec349_channel_archive_bundle_file',
               'expected_historical_ec349_channel_archive_bundle_sha256')
AUDIT_ONLY = ('expected_retained_historical_ec349_channel_inventory_sha256',)
NEW_REPEATS = (
 ('historical_ec349_authority_inventory_shas','--historical-ec349-authority-inventory-sha256'),
 ('historical_ec349_witness_inventory_shas','--historical-ec349-witness-inventory-sha256'),
 ('minimum_historical_ec349_signed_receipt_counts','--minimum-historical-ec349-signed-receipt-count'),
 ('minimum_historical_ec349_signed_witness_counts','--minimum-historical-ec349-signed-witness-count'),
)
REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS = (*previous.PARENT_SCALARS,*previous.NEW_SCALARS,*previous.AUDIT_ONLY)
PARENT_REPEATS = (*previous.PARENT_REPEATS,*previous.REPEAT_NAMES)
BUNDLE_FIELDS = {'schema','parent_ec380_canonical_result_sha256',
 'ec380_historical_timestamp_archive_original_sha256',
 'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS = {'epoch_index','channels'}
CHANNEL_FIELDS = {'tsa_channel_id','channel_root_public_key_original',
 'signed_channel_directory_original','signed_receipt_predecessor_originals',
 'signed_receipt_sibling_originals','signed_time_witness_originals',
 'ec348_replay_inputs_original'}
FLAGS = (
 'inherited_live_ec380_through_ec369_signed_original_dispute',
 'outside_retained_ec349_authority_or_witness_inventory_floor_disagrees',
 'old_ec349_authenticated_timestamp_channel_directory_or_receipt_missing',
 'original_ec349_visible_receipt_predecessor_gap_fork_or_revocation',
 'original_ec349_signed_time_witness_absent_stale_or_disagrees',
 'original_ec348_keeper_custody_sources_not_replayed_or_disagree',
 'old_ec349_cross_epoch_directory_receipt_or_witness_rollback',
 'old_ec349_through_ec337_full_canonical_original_history_not_rebuilt',
 'external_independent_authority_trusted_utc_global_fork_census_not_proven',
)
OUTCOMES = (
 'ec381_inherited_authentic_historical_timestamp_dispute',
 'ec381_outside_retained_authority_witness_evidence_floor_disagrees',
 'ec381_signed_channel_authority_or_timestamp_receipt_missing',
 'ec381_visible_receipt_ancestry_fork_revocation_or_expiry',
 'ec381_signed_witness_absent_or_clock_claim_mismatch',
 'ec381_old_keeper_original_canonical_replay_missing_or_conflicting',
 'ec381_signed_channel_ancestry_epoch_rollback',
 'ec381_historic_ec349_through_ec337_canonical_history_incomplete',
 'ec381_outside_independence_clock_and_fork_census_unproven',
)
NEGATIVES = (
 'old_ec349_complete_two_channel_canonical_parent_audit_replayed',
 'all_old_ec349_to_ec337_original_signed_parents_reconstructed',
 'ec348_keeper_claim_alone_proves_physical_offsite_custody',
 'ec349_directory_public_key_proves_lawful_institutional_issuer',
 'self_signed_time_witness_claim_proves_calibrated_global_utc',
 'rfc3161_gen_time_proves_receipt_physically_delivered',
 'locally_visible_signed_heads_prove_absence_of_hidden_forks',
 'claimed_independent_organizations_prove_distinct_private_key_control',
 'old_ec353_sender_origin_path_used_as_receiver_original',
 'caller_unsigned_history_report_substituted_for_original_signed_receipts',
 'network_private_signer_remote_provider_cas_or_worm_invoked',
 'native_powershell_or_legacy_business_code_written',
 'historic_ec366_to_ec337_mock_removed_or_final_acceptance_granted',
)
KEEPER_HEAD_FIELDS = {'custodian_id','subject_receiver_id','signed_receipt_count',
 'signed_head_original_raw_sha256s','multiple_signed_heads_are_unresolved_forks',
 'latest_single_head_kind','latest_head_entire_history_caller_sha_pins_present',
 'signed_keeper_ancestry_has_self_reported_expiry_gap',
 'latest_single_head_ledger_original_raw_sha256','outcome'}
KEEPER_ORIGINAL_FIELDS = {'whole_original_raw_sha256','independently_furnished_sha_pin_present'}


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC381_'+code,status)


def exact(doc,fields,label):
    need(type(doc) is dict and set(doc)==set(fields),label+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return previous.sha(raw)


def _inputs(opts,derive):
    keys=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:keys.update(AUDIT_ONLY)
    need(set(opts)==keys,'EXACT_PARENT_AND_HISTORIC_EC349_INPUTS_REQUIRED')
    parent={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    previous._inputs(parent,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC381_RECEIVER_CHANNEL_ARCHIVE')
    if not derive:need(old353._sha(opts[AUDIT_ONLY[0]]),
                       'EXTERNAL_RETAINED_EC349_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORIC_EPOCH_COUNT_INVALID')
    for key in REPEAT_NAMES:
        arr=opts[key]
        need(type(arr) is list and len(arr)==n,
             key.upper()+'_ONE_ENTRY_PER_EPOCH_REQUIRED')
        if key.startswith('minimum_'):
            cap=MAX_RECEIPTS if 'receipt' in key else MAX_TIMES
            need(all(type(v) is int and 0<=v<=cap for v in arr),
                 key.upper()+'_COUNT_FLOOR_INVALID')
        else:
            need(all(old353._sha(v) for v in arr),key.upper()+'_SHA_INVALID')
    return parent


def _parent(parent,n):
    need(type(parent) is dict and parent.get('schema')==previous.RESULT_SCHEMA and
         parent.get('exit_code')==2 and
         parent.get('sender_origin_path_required_or_read') is False and
         parent.get('ec349_through_ec337_full_historical_parent_replay_performed') is False and
         type(parent.get('historical_timestamp_epoch_reviews')) is list and
         len(parent['historical_timestamp_epoch_reviews'])==n,
         'REAL_EC380_THROUGH_EC369_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(parent))


def _signed(ref,role,read,fields,schema,domain,key):
    doc=old353.strict_json(read(ref,role,MAX_SIGNED),'EC381_'+role.upper())
    exact(doc,{'schema','claim','signature_ed25519'},'OLD_EC349_SIGNED_'+role.upper())
    need(doc['schema']==schema,'OLD_EC349_SIGNED_SCHEMA_CHANGED','permission_denied')
    exact(doc['claim'],fields,'OLD_EC349_'+role.upper()+'_CLAIM')
    old343._signed(doc,schema,domain,key,'EC381_ACTUAL_'+role.upper())
    return doc['claim'],doc['signature_ed25519']


def _keeper_shape(claim):
    heads=claim['keeper_visible_heads']
    originals=claim['keeper_signed_originals']
    need(type(heads) is list and 1<=len(heads)<=old348.MAX_KEEPERS and
         type(originals) is list and len(originals)<=old348.MAX_RECEIPTS,
         'BOUNDED_EC348_KEEPER_CLAIMS_REQUIRED','permission_denied')
    for row in heads:
        exact(row,KEEPER_HEAD_FIELDS,'EC348_KEEPER_HEAD')
        need(old353._ident(row['custodian_id']) and
             old353._ident(row['subject_receiver_id']) and
             type(row['signed_receipt_count']) is int and
             0<=row['signed_receipt_count']<=old348.MAX_VERSIONS*2 and
             type(row['signed_head_original_raw_sha256s']) is list and
             len(row['signed_head_original_raw_sha256s'])<=2 and
             all(old353._sha(s) for s in row['signed_head_original_raw_sha256s']) and
             type(row['multiple_signed_heads_are_unresolved_forks']) is bool and
             type(row['latest_head_entire_history_caller_sha_pins_present']) is bool and
             type(row['signed_keeper_ancestry_has_self_reported_expiry_gap']) is bool and
             (row['latest_single_head_ledger_original_raw_sha256'] is None or
              old353._sha(row['latest_single_head_ledger_original_raw_sha256'])) and
             (row['latest_single_head_kind'] is None or
              row['latest_single_head_kind'] in old348.KINDS) and
             row['outcome'] in old348.OUTCOMES,
             'EC348_SIGNED_KEEPER_HEAD_SHAPE_INVALID','permission_denied')
    need([r['custodian_id'] for r in heads]==sorted(set(r['custodian_id'] for r in heads)),
         'KEEPER_HEADS_NOT_CANONICALLY_SORTED','permission_denied')
    for row in originals:
        exact(row,KEEPER_ORIGINAL_FIELDS,'EC348_KEEPER_ORIGINAL')
        need(old353._sha(row['whole_original_raw_sha256']) and
             type(row['independently_furnished_sha_pin_present']) is bool,
             'SIGNED_KEEPER_ORIGINAL_PIN_CLAIM_INVALID','permission_denied')


def _ec348_original(ref,read,forbidden):
    """Optional *real* EC348 replay; prohibit following sender/aliased paths.

    This is never a surrogate signed receipt. A missing source returns None;
    a supplied but broken full replay rejects. Legacy paths are read-only.
    """
    if ref is None:return None
    data=old353.strict_json(read(ref,'ec348_full_source_input_original',MAX_SIGNED),
                            'EC381_GENUINE_EC348_INPUTS')
    keys=old348.PARENT_KEYS|{'external_evaluation_utc','keeper_directory_file',
        'expected_keeper_directory_sha256','expected_directory_root_public_hex',
        'keeper_receipt_files','keeper_receipt_shas','presented_keeper_ids',
        'presented_ledger_files','presented_ledger_shas',
        'presented_copy_snapshot_files','presented_copy_ack_set_files'}
    exact(data,keys,'GENUINE_EC348_REPLAY_INPUTS')
    path_values=[]
    for k,v in data.items():
        if k.endswith('_file'):
            need(type(v) is str,'EC348_ORIGINAL_FILE_PATH_MUST_BE_STRING')
            path_values.append(v)
        elif k.endswith('_files'):
            need(type(v) is list and len(v)<=64,'EC348_ORIGINAL_PATH_LIST_BOUND_INVALID')
            path_values.extend(v)
    for path in path_values:
        need(type(path) is str and os.path.isabs(path) and
             os.path.normpath(path)==path and len(path)<=4000 and
             '\\' not in path and path not in forbidden and
             not any(item.is_symlink() for item in (Path(path),*Path(path).parents)),
             'EC348_SOURCE_INPUT_PATH_NOT_RECEIVER_SAFE','permission_denied')
    need(all(old353._sha(s) for s in data['keeper_receipt_shas']),
         'NO_UNPINNED_EC348_KEEPER_ORIGINAL_IN_CANONICAL_REPLAY',
         'permission_denied')
    # The inherited production EC349 replay internally invokes real EC348,
    # EC347 etc.; never accept an old audit-report JSON in its place.
    return old349._replay(data)


def _directory(row,read,evaluation):
    rootref=row['channel_root_public_key_original']
    key=read(rootref,'root_'+rootref['sha256'],32)
    need(len(key)==32 and sha(key)==rootref['sha256'],
         'INDEPENDENT_PINNED_EC349_DIRECTORY_ROOT_KEY_INVALID','permission_denied')
    ref=row['signed_channel_directory_original']
    claim,_=_signed(ref,'directory_'+ref['sha256'],read,old349.DIR_FIELDS,
                    old349.DIRECTORY_SCHEMA,old349.D_DIRECTORY,key.hex())
    need(claim['schema']==old349.DIRECTORY_CLAIM and
         claim['channel_id']==row['tsa_channel_id'] and
         claim['root_authority']['public_hex']==key.hex() and
         claim['channel_role']=='independent_out_of_band_sha_anchor_claim' and
         claim['scope']=='bounded_offline_sha_anchor_and_time_witness_only' and
         claim['no_independence_or_trusted_clock_authority'] is True and
         old353._ident(claim['case_id']) and
         old353._sha(claim['ec348_inputs_canonical_sha256']) and
         old353._sha(claim['ec348_verified_result_canonical_sha256']) and
         old353._sha(claim['ec348_keeper_directory_original_raw_sha256']),
         'SIGNED_DIRECTORY_ROOT_CASE_AND_OLD_EC348_BINDING_INVALID',
         'permission_denied')
    roles=[claim[x] for x in ('root_authority','receipt_actor','time_actor')]
    need(all(old348._actor(x) for x in roles),
         'REAL_EC349_ROOT_RECEIPT_AND_WITNESS_ACTORS_INVALID',
         'permission_denied')
    for field in ('signer_id','public_hex','organization_id'):
        need(len({r[field] for r in roles})==3,
             'EC349_DIRECTORY_ROOT_RECEIPT_TIME_ROLE_COLLISION','permission_denied')
    vstart=old350._utc(claim['valid_from_utc'])
    vend=old350._utc(claim['valid_until_utc'])
    need(vstart<=vend and vstart<=evaluation,
         'EC349_SIGNED_DIRECTORY_VALIDITY_INVALID','permission_denied')
    return claim,key


def _receipt(ref,directory,dir_sha,read,evaluation):
    actor=directory['receipt_actor']
    claim,sig=_signed(ref,'receipt_'+ref['sha256'],read,old349.RECEIPT_FIELDS,
                      old349.RECEIPT_SCHEMA,old349.D_RECEIPT,actor['public_hex'])
    expected={'schema':old349.RECEIPT_CLAIM,'case_id':directory['case_id'],
      'ec348_inputs_canonical_sha256':directory['ec348_inputs_canonical_sha256'],
      'ec348_verified_result_canonical_sha256':directory['ec348_verified_result_canonical_sha256'],
      'channel_directory_original_raw_sha256':dir_sha,
      'channel_id':directory['channel_id'],
      'receipt_signer_id':actor['signer_id'],
      'receipt_signer_public_hex':actor['public_hex'],
      'receipt_signer_organization_id':actor['organization_id'],
      'scope':'signed_out_of_band_keeper_heads_claim_only',
      'no_remote_custody_or_external_time_authority':True}
    need(all(claim.get(k)==v for k,v in expected.items()) and
         old353._sha(claim['statement_nonce_sha256']),
         'REAL_EC349_RECEIPT_NOT_AUTHORIZED_BY_ROOT_SIGNED_DIRECTORY',
         'permission_denied')
    _keeper_shape(claim)
    seq=claim['sequence'];kind=claim['statement_kind']
    need(type(seq) is int and 1<=seq<=old349.MAX_SEQUENCES and
         kind in old349.KINDS and
         ((seq==1 and kind==old349.KINDS[0]) or
          (seq>1 and kind!=old349.KINDS[0])),
         'OLD_EC349_RECEIPT_KIND_OR_SEQUENCE_INVALID','permission_denied')
    received=old350._utc(claim['claimed_received_utc'])
    expires=old350._utc(claim['expires_utc'])
    need(old350._utc(directory['valid_from_utc'])<=received<=evaluation and
         received<=expires<=old350._utc(directory['valid_until_utc']),
         'REAL_EC349_RECEIPT_SIGNED_WINDOW_INVALID','permission_denied')
    if seq==1:
        need(claim['previous_statement_file'] is None and
             claim['previous_statement_original_raw_sha256'] is None,
             'OLD_EC349_CAPTURE_MUST_HAVE_NO_PREDECESSOR','permission_denied')
    else:
        need(type(claim['previous_statement_file']) is str and
             old353._sha(claim['previous_statement_original_raw_sha256']),
             'OLD_EC349_RENEWAL_REQUIRES_PINNED_PREDECESSOR',
             'permission_denied')
    return {'sha':ref['sha256'],'ref':ref,'claim':claim,'signature':sig,
            'received':received,'expires':expires}


def _witness(ref,directory,dir_sha,receipts,read,evaluation):
    actor=directory['time_actor']
    claim,sig=_signed(ref,'witness_'+ref['sha256'],read,old349.TIME_FIELDS,
                      old349.TIME_SCHEMA,old349.D_TIME,actor['public_hex'])
    owner=receipts.get(claim['receipt_original_raw_sha256'])
    expected={'schema':old349.TIME_CLAIM,'case_id':directory['case_id'],
        'channel_id':directory['channel_id'],
        'channel_directory_original_raw_sha256':dir_sha,
        'time_actor_id':actor['signer_id'],
        'time_actor_public_hex':actor['public_hex'],
        'time_actor_organization_id':actor['organization_id'],
        'time_provenance_kind':'separately_signed_local_clock_claim',
        'scope':'receipt_sha_time_provenance_claim_only',
        'not_a_trusted_utc_or_legal_timestamp':True}
    need(owner is not None and all(claim.get(k)==v for k,v in expected.items()) and
         claim['receipt_sequence']==owner['claim']['sequence'] and
         type(claim['uncertainty_seconds']) is int and
         0<=claim['uncertainty_seconds']<=3600 and
         old353._sha(claim['time_nonce_sha256']),
         'SIGNED_TIME_WITNESS_NOT_AUTHORIZED_FOR_EXACT_RECEIPT',
         'permission_denied')
    observed=old350._utc(claim['claimed_observed_utc'])
    need(old350._utc(directory['valid_from_utc'])<=observed<=evaluation and
         observed<=old350._utc(directory['valid_until_utc']),
         'OLD_EC349_SIGNED_WITNESS_TIME_WINDOW_INVALID',
         'permission_denied')
    return {'sha':ref['sha256'],'claim':claim,'signature':sig,'observed':observed}


def _channel(row,ec380_token,signedtime,read,evaluation,forbidden):
    """Verify one original receipt *from EC380*, never a caller-replaced head."""
    exact(row,CHANNEL_FIELDS,'EC381_CHANNEL')
    channel=row['tsa_channel_id']
    need(channel==ec380_token['tsa_channel_id'] and old353._ident(channel),
         'EC381_CHANNEL_NOT_PRESENT_IN_REAL_EC380_PARENT','permission_denied')
    directory,root=_directory(row,read,evaluation)
    directory_sha=row['signed_channel_directory_original']['sha256']
    original_root_sha=row['channel_root_public_key_original']['sha256']
    receiptref=ec380_token['ec349_receipt_original']
    ancestors=row['signed_receipt_predecessor_originals']
    siblings=row['signed_receipt_sibling_originals']
    witnesses=row['signed_time_witness_originals']
    need(type(ancestors) is list and type(siblings) is list and
         type(witnesses) is list and
         len(ancestors)+len(siblings)+1<=old349.MAX_SEQUENCES*2 and
         len(witnesses)<=old349.MAX_SEQUENCES*2,
         'EC349_SIGNED_ORIGINAL_LIST_BOUNDS_INVALID')
    # Stable canonical receipt ordering. Every original is individually
    # receiver SHA-pinned; original-signed predecessor path is never followed.
    refs=[*ancestors,receiptref,*siblings]
    ids=[r['sha256'] for r in refs]
    need(len(ids)==len(set(ids)),'SAME_SIGNED_RECEIPT_INCLUDED_TWICE',
         'permission_denied')
    docs={}
    for ref in refs:
        rec=_receipt(ref,directory,directory_sha,read,evaluation)
        need(rec['sha'] not in docs,'DUPLICATE_SIGNED_RECEIPT','permission_denied')
        docs[rec['sha']]=rec
    target=docs[receiptref['sha256']]
    need(len(ancestors)==target['claim']['sequence']-1 and
         [docs[x['sha256']]['claim']['sequence'] for x in ancestors]==
             list(range(1,target['claim']['sequence'])),
         'COMPLETE_TARGET_RECEIPT_PREDECESSOR_SEQUENCE_REQUIRED',
         'permission_denied')
    sibling_order=[(docs[r['sha256']]['claim']['sequence'],r['sha256']) for r in siblings]
    need(sibling_order==sorted(sibling_order),
         'EXTRA_VISIBLE_SIGNED_SIBLINGS_MUST_BE_CANONICALLY_SORTED',
         'permission_denied')
    grouped={}
    for rec in docs.values():
        claim=rec['claim'];seq=claim['sequence']
        grouped[seq]=grouped.get(seq,0)+1
        need(grouped[seq]<=2,'MORE_THAN_TWO_SIGNED_EC349_SIBLINGS',
             'permission_denied')
        if seq==1:continue
        pred=docs.get(claim['previous_statement_original_raw_sha256'])
        need(pred is not None and
             pred['ref']['path']==claim['previous_statement_file'] and
             pred['claim']['sequence']==seq-1 and
             pred['claim']['statement_kind']!=old349.KINDS[2] and
             pred['received']<=rec['received'],
             'REAL_EC349_SIGNED_CONTIGUOUS_PREDECESSOR_REQUIRED',
             'permission_denied')
    need(len({r['signature'] for r in docs.values()})==len(docs) and
         len({r['claim']['statement_nonce_sha256'] for r in docs.values()})==len(docs),
         'REPEATED_SIGNED_RECEIPT_SIGNATURE_OR_NONCE','permission_denied')
    ancestors_key=[r['claim']['keeper_visible_heads'] for r in docs.values()]
    originals_key=[r['claim']['keeper_signed_originals'] for r in docs.values()]
    need(all(x==ancestors_key[0] for x in ancestors_key) and
         all(x==originals_key[0] for x in originals_key),
         'SIGNED_EC348_KEEPER_BINDING_CHANGED_WITHIN_EC349_CHAIN',
         'permission_denied')
    consumed={r['claim']['previous_statement_original_raw_sha256'] for r in docs.values()
              if r['claim']['sequence']>1}
    visible_heads=sorted(x for x in docs if x not in consumed)
    fork=len(visible_heads)!=1
    unique_head=visible_heads[0] if len(visible_heads)==1 else None
    ancestor_expiry_gap=any(docs[r['claim']['previous_statement_original_raw_sha256']]['expires']
                            <r['received'] for r in docs.values()
                            if r['claim']['sequence']>1)
    rec_expired=(target['expires']<evaluation or
                 old350._utc(directory['valid_until_utc'])<evaluation)
    # Witnesses may also expose rival signed heads. They can never turn a
    # sibling fork into a winner or retroactively authorize a receipt.
    wdocs={};nonces={r['claim']['statement_nonce_sha256'] for r in docs.values()}
    sigs={r['signature'] for r in docs.values()}
    for ref in witnesses:
        w=_witness(ref,directory,directory_sha,docs,read,evaluation)
        rs=w['claim']['receipt_original_raw_sha256']
        need(rs not in wdocs and w['signature'] not in sigs and
             w['claim']['time_nonce_sha256'] not in nonces,
             'DUPLICATE_SIGNED_WITNESS_SIGNATURE_RECEIPT_OR_NONCE',
             'permission_denied')
        wdocs[rs]=w;sigs.add(w['signature']);nonces.add(w['claim']['time_nonce_sha256'])
    need(list(wdocs)==sorted(wdocs),'SIGNED_EC349_WITNESSES_MUST_BE_RECEIPT_SHA_SORTED',
         'permission_denied')
    witness=wdocs.get(receiptref['sha256'])
    # signedtime was recovered from *original cryptographic CMS/TSTInfo*,
    # never from an unsigned field inserted into the EC380 archive.
    witness_disagrees=True
    if witness:
        claim=witness['claim']
        witness_disagrees=(abs((witness['observed']-target['received']).total_seconds())>
               min(old349.MAX_WITNESS_RECEIPT_SKEW_SECONDS,claim['uncertainty_seconds']) or
               abs((witness['observed']-signedtime).total_seconds())>
               old349.MAX_WITNESS_RECEIPT_SKEW_SECONDS+claim['uncertainty_seconds'])
    ctx=_ec348_original(row['ec348_replay_inputs_original'],read,forbidden)
    source_ok=False
    if ctx is not None:
        source_ok=(directory['case_id']==ctx['report']['case_id'] and
           directory['ec348_inputs_canonical_sha256']==ctx['source_sha'] and
           directory['ec348_verified_result_canonical_sha256']==ctx['result_sha'] and
           directory['ec348_keeper_directory_original_raw_sha256']==
                ctx['inputs']['expected_keeper_directory_sha256'] and
           target['claim']['keeper_visible_heads']==ctx['keepers'] and
           target['claim']['keeper_signed_originals']==ctx['originals'])
        need(source_ok,'ACTUAL_REPLAYED_EC348_KEEPER_CUSTODY_MISMATCH',
             'permission_denied')
        # Old EC348 actors cannot be silently reincarnated as new signers.
        for field in ('public_hex','signer_id','organization_id'):
            need(not set(directory[k][field] for k in
                     ('root_authority','receipt_actor','time_actor')).intersection(
                     {a[field] for a in ctx['old_actors']}),
                 'EC349_CHANNEL_ACTOR_COLLIDES_WITH_REAL_EC348_ACTOR',
                 'permission_denied')
    return {'tsa_channel_id':channel,
      'original_signed_ec349_directory_sha256':directory_sha,
      'independently_pinned_ec349_root_public_sha256':original_root_sha,
      'authorized_signed_ec349_receipt_original_sha256':receiptref['sha256'],
      'receipt_actor_public_key_sha256':sha(bytes.fromhex(directory['receipt_actor']['public_hex'])),
      'time_actor_public_key_sha256':sha(bytes.fromhex(directory['time_actor']['public_hex'])),
      'actual_root_signed_directory_receipt_actor_authorization_verified':True,
      'visible_signed_receipt_count':len(docs),
      'signed_receipt_original_shas':list(docs),
      'visible_signed_receipt_head_shas':visible_heads,
      'target_is_only_visible_signed_head':unique_head==receiptref['sha256'],
      'visible_signed_fork_or_nonhead':fork or unique_head!=receiptref['sha256'],
      'signed_revocation_at_target':target['claim']['statement_kind']==old349.KINDS[2],
      'signed_ancestry_expiry_gap_or_target_stale':ancestor_expiry_gap or rec_expired,
      'target_signed_receipt_claimed_utc':target['claim']['claimed_received_utc'],
      'target_signed_receipt_sequence':target['claim']['sequence'],
      'signed_target_time_witness_original_sha256':witness['sha'] if witness else None,
      'signed_time_witness_original_shas':[w['sha'] for w in wdocs.values()],
      'real_signed_time_witness_count':len(wdocs),
      'signed_time_witness_missing_or_disagrees':witness_disagrees,
      'signed_time_witness_claimed_observed_utc':witness['claim']['claimed_observed_utc'] if witness else None,
      'real_ec348_full_keeper_original_replay_performed':ctx is not None,
      'real_ec348_full_keeper_original_binding_matches':source_ok,
      'claimed_ec348_source_digest_sha256':directory['ec348_inputs_canonical_sha256'],
      'claimed_ec348_keeper_result_digest_sha256':directory['ec348_verified_result_canonical_sha256'],
      'signature_actor_ids':{k:directory[k]['signer_id'] for k in
              ('root_authority','receipt_actor','time_actor')},
      'signature_actor_organizations':{k:directory[k]['organization_id'] for k in
              ('root_authority','receipt_actor','time_actor')},
      'signature_actor_public_key_hexes':{k:directory[k]['public_hex'] for k in
              ('root_authority','receipt_actor','time_actor')},
    }


def _engine(derive,**opts):
    parent_opts=_inputs(opts,derive)
    parent=previous.audit(**parent_opts)  # authentic production EC380->369 mandatory
    n=len(opts['historical_directory_root_shas'])
    parent_sha=_parent(parent,n)
    evaluation=old350._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        # Original file identity is checked by the inherited reader; no
        # supplied source path is ever searched or followed implicitly.
        p372.prior.lineage.parent.ref_check(ref,'EC381_'+role)
        key=ref['path']
        if key in cache:
            digest,raw,oldrole=cache[key]
            need(key not in forbidden and digest==ref['sha256'] and
                 role==oldrole and len(raw)<=cap,
                 'PINNED_ORIGINAL_ROLE_ALIAS_OR_MUTATED_SHA','permission_denied')
            return raw
        raw=p372._read(ref,'ec381_'+role,cap,pins,categories,forbidden)
        cache[key]=(ref['sha256'],raw,role)
        return raw
    ref380={'path':opts['historical_timestamp_archive_bundle_file'],
            'sha256':opts['expected_historical_timestamp_archive_bundle_sha256']}
    old380=old353.strict_json(read(ref380,'verified_ec380_parent_archive',
                                  previous.MAX_BUNDLE),'EC381_ACTUAL_EC380_ARCHIVE')
    exact(old380,previous.BUNDLE_FIELDS,'REAL_EC380_PARENT_ARCHIVE')
    need(old380['schema']==previous.BUNDLE_SCHEMA and
         type(old380['epochs']) is list and len(old380['epochs'])==n,
         'REAL_EC380_ARCHIVE_INHERITED_EPOCHS_INVALID','permission_denied')
    ref381={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=old353.strict_json(read(ref381,'receiver_ec381_channel_archive',MAX_BUNDLE),
                              'EC381_SIGNED_CHANNEL_ORIGINAL_RECEIVER_ARCHIVE')
    exact(bundle,BUNDLE_FIELDS,'EC381_RECEIVER_ARCHIVE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['parent_ec380_canonical_result_sha256']==parent_sha and
         bundle['ec380_historical_timestamp_archive_original_sha256']==ref380['sha256'] and
         bundle['claimed_directory_lineage_id']==old380['claimed_directory_lineage_id'] and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'EC381_ARCHIVE_NOT_BOUND_TO_LIVE_EC380_RESULT','permission_denied')
    # Older sender file names are untrusted labels, never new local evidence.
    ref377={'path':opts['historical_transparency_archive_bundle_file'],
        'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    doc377=old353.strict_json(read(ref377,'verified_ec377_parent_archive',
                             p379.p377.MAX_BUNDLE),'EC381_OLD_EC377_ORIGINAL')
    exact(doc377,p379.p377.BUNDLE_FIELDS,'AUTHENTIC_EC377_PARENT')
    need(doc377['schema']==p379.p377.BUNDLE_SCHEMA and
         len(doc377['epochs'])==n,'EC377_SIGNED_SOURCE_ARCHIVE_CHANGED',
         'permission_denied')
    for ep in doc377['epochs']:
        m=old353.strict_json(read(ep['ec353_publication_bundle_original'],
            'old_ec353_published_sender_labels_'+ep['ec353_publication_bundle_original']['sha256'],
             old353.MAX_BUNDLE),'EC381_OLD_EC353_LABELS')
        p379._old_sender_labels(m,forbidden)
    # Reopen source originals before protecting all parent CLI file paths.
    ref379={'path':opts['historical_source_archive_bundle_file'],
            'sha256':opts['expected_historical_source_archive_bundle_sha256']}
    old379=old353.strict_json(read(ref379,'verified_ec379_parent_archive',
                                 p379.MAX_BUNDLE),'EC381_AUTHENTIC_EC379_ATTESTERS')
    exact(old379,p379.BUNDLE_FIELDS,'REAL_EC379_ATTESTER_PARENT')
    need(old379['schema']==p379.BUNDLE_SCHEMA and
         old379['claimed_directory_lineage_id']==bundle['claimed_directory_lineage_id'] and
         len(old379['epochs'])==n,
         'EC379_SIGNED_PARENT_IDENTITY_NOT_REOPENED','permission_denied')
    # New receiver originals must not alias an inherited input bundle.
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=not parent['local_signed_timestamp_and_revocation_inputs_consistent']
    rows=[];inventory_rows=[];total_r=total_w=missing=0
    old_channels={};old_keys={}
    known_old_roles=set(opts['institution_root_public_key_shas']+
        opts['witness_public_key_shas']+opts['historical_directory_root_shas']+
        [opts['expected_sender_public_key_sha256'],
         opts['expected_receiver_public_key_sha256'],
         opts['expected_publisher_public_key_sha256'],
         opts['expected_publication_observer_public_key_sha256']])
    for i,(epoch,ep380,ep379,oldrow) in enumerate(zip(
          bundle['epochs'],old380['epochs'],old379['epochs'],
          parent['historical_timestamp_epoch_reviews'],strict=True)):
        exact(epoch,EPOCH_FIELDS,'EC381_RECEIVER_EPOCH')
        exact(ep380,previous.EPOCH_FIELDS,'ACTUAL_EC380_EPOCH')
        exact(ep379,p379.EPOCH_FIELDS,'ACTUAL_EC379_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             ep380['epoch_index']==i and ep379['epoch_index']==i and
             oldrow['epoch_index']==i,
             'RECEIVER_CHANNEL_EPOCH_ORDER_NOT_PARENT_ORDER','permission_denied')
        tokens=ep380['timestamps'];channels=epoch['channels']
        need(type(tokens) is list and type(channels) is list and
             len(channels)<=old349.MAX_CHANNELS and
             all(type(t) is dict and type(t.get('tsa_channel_id')) is str for t in tokens) and
             all(type(c) is dict and type(c.get('tsa_channel_id')) is str for c in channels),
             'EC381_CHANNEL_OR_REAL_EC380_TOKEN_BOUNDS_INVALID')
        index={t['tsa_channel_id']:t for t in tokens}
        need(len(index)==len(tokens) and
             [r['tsa_channel_id'] for r in channels]==sorted(set(
                 r['tsa_channel_id'] for r in channels)),
             'EC381_CHANNELS_NOT_CANONICAL_OR_PARENT_REPLAYED','permission_denied')
        need(oldrow['real_signed_rfc3161_token_and_ec349_receipt_imprint_count']==len(tokens),
             'EC380_PARENT_RESULT_RECEIPT_COUNTS_CHANGED','permission_denied')
        attesters={s['attester_public_key_original']['sha256'] for s in ep379['sources']}
        reserved_roles=set(known_old_roles)|attesters
        for log in doc377['epochs'][i]['logs']:
            reserved_roles.add(log['log_public_key_original']['sha256'])
            reserved_roles.add(log['witness_public_key_original']['sha256'])
        signed_sources={}
        for orig in ep379['sources']:
            source=p379._source(orig,read,evaluation,set())
            need(source['channel'] not in signed_sources,
                 'DUPLICATED_REOPENED_EC351_SIGNED_SOURCE','permission_denied')
            signed_sources[source['channel']]=(orig,source)
        epoch_rows=[];actor_keys=set();actor_ids=set();actor_orgs=set()
        for channel in channels:
            token=index.get(channel['tsa_channel_id'])
            need(token is not None,'EC349_DIRECTORY_UNBOUND_TO_REAL_EC380_TOKEN',
                 'permission_denied')
            need(channel['tsa_channel_id'] in signed_sources,
                 'EC380_TOKEN_HAS_NO_REOPENED_AUTHENTIC_EC351_SOURCE',
                 'permission_denied')
            source_orig,source=signed_sources[channel['tsa_channel_id']]
            root=old350._certificate(read(source_orig['tsa_root_certificate_original'],
                      'ec351_actual_tsa_root_certificate',old350.MAX_CERT_BYTES))
            receiptref=token['ec349_receipt_original']
            receipt_raw=read(receiptref,'receipt_'+receiptref['sha256'],
                             old350.MAX_RECEIPT_BYTES)
            tokenref=token['rfc3161_timestamp_original']
            token_raw=read(tokenref,'original_rfc3161_'+tokenref['sha256'],
                           old350.MAX_DER_BYTES)
            checked_token=old350._tsa_token(token_raw,receipt_raw,root,
                                           source['binding']['tsa_policy_oid'])
            signed_time=checked_token['token_gen_time']
            need(signed_time<=evaluation+timedelta(seconds=old350.MAX_SKEW_SECONDS),
                 'RECOVERED_SIGNED_TSTINFO_FUTURE_TIME_DENIED',
                 'permission_denied')
            checked=_channel(channel,token,signed_time,read,evaluation,forbidden)
            actor_info=checked['signature_actor_public_key_hexes']
            for role in ('root_authority','receipt_actor','time_actor'):
                public=actor_info[role]
                keysha=sha(bytes.fromhex(public))
                need(keysha not in reserved_roles and
                     keysha not in actor_keys and
                     checked['signature_actor_ids'][role] not in actor_ids and
                     checked['signature_actor_organizations'][role] not in actor_orgs,
                     'EC349_CROSS_CHANNEL_OR_EC351_ATTESTER_SIGNER_REUSE',
                     'permission_denied')
                actor_keys.add(keysha);actor_ids.add(checked['signature_actor_ids'][role])
                actor_orgs.add(checked['signature_actor_organizations'][role])
                oldowner=old_keys.get(keysha)
                need(oldowner is None or oldowner==(channel['tsa_channel_id'],role),
                     'EC349_SIGNER_ROTATED_ACROSS_CHANNEL_OR_ROLE',
                     'permission_denied')
                old_keys[keysha]=(channel['tsa_channel_id'],role)
            # One epoch cannot silently change a previously observed root,
            # witness key or directory case digest for the same channel.
            owner=old_channels.get(channel['tsa_channel_id'])
            if owner:
                previous_receipt_is_direct_ancestor=(
                    owner['sequence']-1<len(checked['signed_receipt_original_shas']) and
                    checked['signed_receipt_original_shas'][owner['sequence']-1]==
                       owner['receipt_sha'])
                if (owner['root']!=checked['independently_pinned_ec349_root_public_sha256'] or
                    owner['case']!=checked['claimed_ec348_source_digest_sha256'] or
                    owner['directory_sha']!=checked['original_signed_ec349_directory_sha256'] or
                    owner['actor_ids']!=checked['signature_actor_ids'] or
                    owner['actor_organizations']!=checked['signature_actor_organizations'] or
                    owner['receipt_key']!=checked['receipt_actor_public_key_sha256'] or
                    owner['time_key']!=checked['time_actor_public_key_sha256'] or
                    checked['target_signed_receipt_sequence']<=owner['sequence'] or
                    not previous_receipt_is_direct_ancestor or
                    (owner['witness_claim'] and
                     checked['signed_time_witness_claimed_observed_utc'] and
                     old350._utc(checked['signed_time_witness_claimed_observed_utc'])<=
                       old350._utc(owner['witness_claim']))):
                    flags[FLAGS[6]]=True
            old_channels[channel['tsa_channel_id']]={'root':checked['independently_pinned_ec349_root_public_sha256'],
                    'case':checked['claimed_ec348_source_digest_sha256'],
                    'directory_sha':checked['original_signed_ec349_directory_sha256'],
                    'actor_ids':checked['signature_actor_ids'],
                    'actor_organizations':checked['signature_actor_organizations'],
                    'sequence':checked['target_signed_receipt_sequence'],
                    'receipt_sha':checked['authorized_signed_ec349_receipt_original_sha256'],
                    'receipt_key':checked['receipt_actor_public_key_sha256'],
                    'time_key':checked['time_actor_public_key_sha256'],
                    'witness_claim':checked['signed_time_witness_claimed_observed_utc']}
            checked.pop('signature_actor_public_key_hexes')
            checked.pop('signature_actor_ids')
            checked.pop('signature_actor_organizations')
            epoch_rows.append(checked)
            flags[FLAGS[3]]|=(checked['visible_signed_fork_or_nonhead'] or
              checked['signed_revocation_at_target'] or
              checked['signed_ancestry_expiry_gap_or_target_stale'])
            flags[FLAGS[4]]|=checked['signed_time_witness_missing_or_disagrees']
            flags[FLAGS[5]]|=not checked['real_ec348_full_keeper_original_binding_matches']
        # Pairwise independent clock claims are only comparisons, never UTC.
        observed=[(r['tsa_channel_id'],old350._utc(r['signed_time_witness_claimed_observed_utc']))
                   for r in epoch_rows if r['signed_time_witness_claimed_observed_utc']]
        peer_disagree=(len(observed)==2 and abs((observed[0][1]-observed[1][1]).total_seconds())>
                    old349.MAX_CHANNEL_TIME_DIFFERENCE_SECONDS)
        flags[FLAGS[4]]|=peer_disagree
        flags[FLAGS[2]]|=not epoch_rows
        absent=sorted(set(index)-{r['tsa_channel_id'] for r in epoch_rows})
        missing+=len(absent);flags[FLAGS[2]]|=bool(absent)
        total_r+=sum(r['visible_signed_receipt_count'] for r in epoch_rows)
        total_w+=sum(r['real_signed_time_witness_count'] for r in epoch_rows)
        authority=[{k:r[k] for k in (
          'tsa_channel_id','original_signed_ec349_directory_sha256',
          'independently_pinned_ec349_root_public_sha256',
          'authorized_signed_ec349_receipt_original_sha256',
          'receipt_actor_public_key_sha256','time_actor_public_key_sha256',
          'signed_receipt_original_shas','visible_signed_receipt_head_shas',
          'claimed_ec348_source_digest_sha256',
          'claimed_ec348_keeper_result_digest_sha256',
          'real_ec348_full_keeper_original_binding_matches')} for r in epoch_rows]
        witness=[{k:r[k] for k in (
           'tsa_channel_id','signed_target_time_witness_original_sha256',
           'signed_time_witness_original_shas','signed_time_witness_claimed_observed_utc',
           'signed_time_witness_missing_or_disagrees')} for r in epoch_rows]
        authority_sha=sha(canonical.canonical(authority))
        witness_sha=sha(canonical.canonical(witness))
        rc=sum(r['visible_signed_receipt_count'] for r in epoch_rows)
        wc=sum(r['real_signed_time_witness_count'] for r in epoch_rows)
        need(rc<=MAX_RECEIPTS and wc<=MAX_TIMES,
             'ORIGINAL_EC349_TWO_CHANNEL_TOTAL_RECEIPT_OR_WITNESS_BOUND_EXCEEDED',
             'permission_denied')
        flags[FLAGS[1]]|=(authority_sha!=opts['historical_ec349_authority_inventory_shas'][i] or
                         witness_sha!=opts['historical_ec349_witness_inventory_shas'][i] or
                         rc<opts['minimum_historical_ec349_signed_receipt_counts'][i] or
                         wc<opts['minimum_historical_ec349_signed_witness_counts'][i])
        rows.append({'epoch_index':i,'real_root_authorized_ec349_channel_count':len(epoch_rows),
          'real_signed_ec349_receipt_original_count':rc,
          'real_signed_ec349_time_witness_original_count':wc,
          'missing_ec349_channel_directory_for_ec380_token_count':len(absent),
          'real_ec348_replayed_keeper_channel_count':sum(r['real_ec348_full_keeper_original_binding_matches'] for r in epoch_rows),
          'signed_receipt_fork_expiry_revocation_or_nonhead_visible':any(
             r['visible_signed_fork_or_nonhead'] or r['signed_revocation_at_target'] or
             r['signed_ancestry_expiry_gap_or_target_stale'] for r in epoch_rows),
          'signed_witness_missing_claim_disagreement_or_peer_mismatch':peer_disagree or any(
              r['signed_time_witness_missing_or_disagrees'] for r in epoch_rows),
          'ec348_keeper_source_originals_missing_for_channel':any(
              not r['real_ec348_full_keeper_original_binding_matches'] for r in epoch_rows),
          'ec349_signed_authority_inventory_sha256':authority_sha,
          'ec349_signed_witness_inventory_sha256':witness_sha,
          'all_local_directory_receipt_witness_evidence_consistent':bool(epoch_rows) and all(
              r['target_is_only_visible_signed_head'] and
              not r['signed_revocation_at_target'] and
              not r['signed_ancestry_expiry_gap_or_target_stale'] and
              not r['signed_time_witness_missing_or_disagrees'] for r in epoch_rows) and
              not peer_disagree and not absent})
        inventory_rows.append({'epoch_index':i,
          'receiver_epoch_signed_ec349_authority_originals':authority,
          'receiver_epoch_signed_ec349_witness_originals':witness,
          'ec380_timestamp_channels_without_old_ec349_directory':absent,
          'signed_ec349_authority_inventory_sha256':authority_sha,
          'signed_ec349_witness_inventory_sha256':witness_sha})
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inventory={'schema':INVENTORY_SCHEMA,
      'live_ec380_through_ec369_canonical_parent_sha256':parent_sha,
      'authenticated_ec380_timestamp_archive_original_sha256':ref380['sha256'],
      'receiver_ec381_channel_archive_original_sha256':ref381['sha256'],
      'claimed_directory_lineage_id':bundle['claimed_directory_lineage_id'],
      'historical_ec349_channel_epoch_original_reviews':inventory_rows}
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':'derive-historical-ec349-channel-inventory' if derive else
                'audit-historical-ec349-channel-archive',
      'status':next((OUTCOMES[j] for j,key in enumerate(FLAGS) if flags[key]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'historical_ec349_channel_archive_bundle_original_sha256':ref381['sha256'],
      'verified_live_parent_ec380_canonical_result_sha256':parent_sha,
      'receiver_verified_historical_ec349_channel_inventory_sha256':digest,
      'real_signed_ec349_receipt_original_count':total_r,
      'real_signed_ec349_time_witness_original_count':total_w,
      'missing_ec349_channel_directory_count':missing,
      'historical_ec349_channel_epoch_reviews':rows,
      'local_root_authorized_receipt_witness_and_keeper_binding_consistent':local,
      'sender_origin_path_required_or_read':False,
      'ec349_through_ec337_full_historical_parent_replay_performed':False,
      **flags,**{k:False for k in NEGATIVES},
      **({'unsigned_verified_historical_ec349_channel_inventory':inventory,
          'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
