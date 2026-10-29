#!/usr/bin/env python3
"""EC382: verify recovered genuine EC348 keeper originals beneath EC349.

Read-only: mandatory live EC381->EC369, plus optional fully recovered old
EC348->EC337 source. Never treat a SHA comparator or local Ed25519 key as
proof of actual independent physical custody, legal authority or global time.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json
import os

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec343_hold_receipts import timeline as old343
from ec347_readback_challenge import readback as old347
from ec348_external_custody import custody as old348
from ec349_dual_channel_anchor import anchor as old349
from ec350_tsa_timestamp import timestamp as old350
from ec353_transparency import transparency as old353
from ec372_historical_authority import authority_archive as p372
from ec381_historical_channel import channel_archive as previous

RESULT_SCHEMA = 'ces.ec382.receiver_true_ec348_keeper_source_readback_custody_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec382.unsigned_ec348_keeper_original_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec382.receiver_true_ec348_keeper_source_denial.v1'
BUNDLE_SCHEMA = 'ces.ec382.receiver_historic_ec348_keeper_original_archive.v1'
INVENTORY_SCHEMA = 'ces.ec382.receiver_verified_historic_ec348_keeper_inventory.v1'
MAX_BUNDLE = 140_000
MAX_SOURCE = 300_000
MAX_SIGNED = 300_000
MAX_KEEPER_ORIGINALS = old348.MAX_RECEIPTS
MAX_LATEST_RESPONSES = old347.MAX_RESPONSES
NEW_SCALARS = ('historical_ec348_keeper_archive_bundle_file',
               'expected_historical_ec348_keeper_archive_bundle_sha256')
AUDIT_ONLY = ('expected_retained_historical_ec348_keeper_inventory_sha256',)
NEW_REPEATS = (
 ('historical_ec348_keeper_original_inventory_shas', '--historical-ec348-keeper-original-inventory-sha256'),
 ('historical_ec347_readback_join_inventory_shas', '--historical-ec347-readback-join-inventory-sha256'),
 ('minimum_historical_ec348_signed_keeper_receipt_counts', '--minimum-historical-ec348-signed-keeper-receipt-count'),
 ('minimum_historical_ec348_retested_ledger_counts', '--minimum-historical-ec348-retested-ledger-count'),
)
REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS = (*previous.PARENT_SCALARS,*previous.NEW_SCALARS,*previous.AUDIT_ONLY)
PARENT_REPEATS = (*previous.PARENT_REPEATS,*previous.REPEAT_NAMES)
BUNDLE_FIELDS = {'schema','parent_ec381_canonical_result_sha256',
 'ec381_historical_channel_archive_original_sha256',
 'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS = {'epoch_index','channels'}
CHANNEL_FIELDS = {'tsa_channel_id','ec348_full_replay_inputs_original',
 'keeper_root_public_key_original','keeper_signed_directory_original',
 'keeper_signed_receipt_originals','keeper_signed_ledger_originals',
 'ec347_latest_signed_challenge_original','ec347_latest_signed_response_originals',
 'retested_snapshot_originals','retested_ack_set_originals'}
FLAGS = (
 'inherited_live_ec381_through_ec369_signed_original_dispute',
 'outside_retained_ec348_keeper_or_readback_inventory_floor_disagrees',
 'original_ec348_full_source_or_keeper_directory_missing',
 'signed_ec348_keeper_fork_revocation_expiry_or_stale_bytes_visible',
 'ec347_signed_readback_or_explicit_ledger_retest_incomplete',
 'ec349_original_signed_keeper_digest_or_receipt_join_disagrees',
 'historical_ec348_keeper_epoch_replay_or_head_rollback',
 'old_ec348_through_ec337_complete_independent_original_history_unavailable',
 'physical_external_custody_institutional_independence_and_trusted_clock_unproven',
)
OUTCOMES = (
 'ec382_inherited_signed_historical_channel_dispute',
 'ec382_outside_retained_keeper_readback_inventory_floor_disagrees',
 'ec382_old_keeper_full_source_or_signed_directory_missing',
 'ec382_signed_keeper_fork_revocation_expiry_or_content_conflict',
 'ec382_signed_readback_or_real_ledger_byte_retest_incomplete',
 'ec382_ec349_signed_keeper_history_digest_mismatch',
 'ec382_cross_epoch_signed_keeper_head_or_source_rollback',
 'ec382_old_ec348_through_ec337_full_independent_parent_incomplete',
 'ec382_independent_offsite_physical_custody_and_trusted_utc_unproven',
)
NEGATIVES = (
 'ec348_keeper_signature_proves_third_party_organization_legitimacy',
 'two_distinct_keeper_keys_prove_separately_managed_external_machines',
 'caller_provided_sha_floor_was_independently_retained_by_software',
 'signed_ledger_sha_proves_external_worm_or_cas_storage',
 'last_signed_ec347_readback_proves_global_current_physical_bytes',
 'locally_visible_keeper_siblings_prove_no_hidden_forks',
 'self_reported_keeper_expiry_proves_calibrated_utc',
 'ec349_root_directory_claim_proves_custody_site_presence',
 'ec353_sender_origin_path_read_as_receiver_original',
 'missing_original_replaced_by_generated_fake_signed_keeper_bytes',
 'network_private_signer_provider_worm_or_cas_invoked',
 'native_powershell_or_legacy_engine_modified',
 'mocked_ec366_to_ec337_fixture_replaced_or_final_acceptance_granted',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC382_'+code,status)


def exact(value,keys,label):
    need(type(value) is dict and set(value)==set(keys),label+'_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return previous.sha(raw)


def _inputs(opts,derive):
    allowed=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:allowed.update(AUDIT_ONLY)
    need(set(opts)==allowed,'EXACT_EC381_PARENT_AND_EC382_INPUTS_REQUIRED')
    parent={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    previous._inputs(parent,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC382_RECEIVER_KEEPER_ARCHIVE')
    if not derive:
        need(old353._sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_RETAINED_EC382_INVENTORY_PIN_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'EC382_EPOCH_COUNT_BOUND_INVALID')
    for key in REPEAT_NAMES:
        values=opts[key]
        need(type(values) is list and len(values)==n,key.upper()+'_ONE_PER_EPOCH_REQUIRED')
        if key.startswith('minimum_'):
            cap=old348.MAX_RECEIPTS*old349.MAX_CHANNELS if 'receipt' in key else old348.MAX_KEEPERS*old349.MAX_CHANNELS
            need(all(type(v) is int and 0<=v<=cap for v in values),key.upper()+'_BOUNDED_FLOOR_INVALID')
        else:
            need(all(old353._sha(v) for v in values),key.upper()+'_SHA_INVALID')
    return parent


def _parent(result,n):
    need(type(result) is dict and result.get('schema')==previous.RESULT_SCHEMA and
         result.get('exit_code')==2 and result.get('sender_origin_path_required_or_read') is False and
         result.get('ec349_through_ec337_full_historical_parent_replay_performed') is False and
         type(result.get('historical_ec349_channel_epoch_reviews')) is list and
         len(result['historical_ec349_channel_epoch_reviews'])==n,
         'REAL_LIVE_EC381_THROUGH_EC369_PARENT_REQUIRED','unavailable')
    return sha(canonical.canonical(result))


def _ref(ref,path,raw_sha,label):
    exact(ref,{'path','sha256'},label+'_REF')
    need(ref['path']==path and ref['sha256']==raw_sha,
         label+'_DOES_NOT_MATCH_REAL_FULL_SOURCE_INPUT','permission_denied')


def _json_original(raw,label):
    """Original legacy signed JSON may be pretty-printed, not canonical bytes.

    Ed25519 signs the canonical *claim*, while the caller SHA pins the exact
    whole original. Reject duplicate keys and non-JSON constants without
    rewriting or claiming a freshly normalized whole-file SHA.
    """
    try:
        obj=json.loads(raw.decode('utf-8'),object_pairs_hook=old353._object_pairs,
            parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (ValueError,UnicodeError,TypeError) as exc:
        raise errors.AnchorError('EC382_'+label+'_INVALID_SIGNED_ORIGINAL_JSON',
                                 'invalid_input') from exc
    need(type(obj) is dict,label+'_ROOT_OBJECT_REQUIRED','permission_denied')
    return obj


def _signed(ref,role,read,fields,schema,domain,public):
    doc=_json_original(read(ref,role,MAX_SIGNED),'SIGNED_'+role.upper())
    exact(doc,{'schema','claim','signature_ed25519'},role.upper()+'_SIGNATURE')
    exact(doc['claim'],fields,role.upper()+'_CLAIM')
    need(doc['schema']==schema,'OLD_SIGNED_'+role.upper()+'_SCHEMA_CHANGED',
         'permission_denied')
    old343._signed(doc,schema,domain,public,'EC382_ORIGINAL_'+role.upper())
    return doc['claim'],doc['signature_ed25519']


def _present_refs(refs,paths,shas,role,read,cap):
    need(type(refs) is list and len(refs)==len(paths)==len(shas) and
         all(type(r) is dict and set(r)=={'path','sha256'} for r in refs),
         role.upper()+'_EXACT_ORIGINAL_COUNT_REQUIRED','permission_denied')
    need(len({r['path'] for r in refs if type(r) is dict and 'path' in r})==len(refs),
         role.upper()+'_DUPLICATE_ORIGINAL_PATH','permission_denied')
    for i,(ref,p,digest) in enumerate(zip(refs,paths,shas,strict=True)):
        _ref(ref,p,digest,role.upper()+'_ENTRY')
        read(ref,role+'_'+ref['sha256'],cap)


def _ec347_latest(source,ctx,row,read):
    """Join final real EC347 signed challenge/replies from the replayed input.

    Production EC348._context -> EC347.audit_readbacks has already checked
    Ed25519 signatures and each signed challenge/response predecessor. Here
    we reopen exactly the old originals, not a newly supplied summary.
    """
    challenge={'path':source['readback_challenge_files'][-1],
               'sha256':source['readback_challenge_shas'][-1]}
    _ref(row['ec347_latest_signed_challenge_original'],challenge['path'],
         challenge['sha256'],'EC347_LATEST_CHALLENGE')
    actual=_json_original(read(challenge,'ec347_latest_challenge_'+challenge['sha256'],MAX_SIGNED),
                          'EC347_VERIFIED_SIGNED_CHALLENGE')
    exact(actual,{'schema','claim','signature_ed25519'},'LAST_EC347_SIGNED_CHALLENGE')
    claim=actual['claim'];round_no=len(source['readback_challenge_shas'])
    need(actual['schema']==old347.CHALLENGE_SCHEMA and
         type(claim) is dict and set(claim)==old347.C_FIELDS and
         claim['round_number']==round_no and
         claim['case_id']==ctx['report']['case_id'],
         'OLD_EC347_LAST_SIGNED_CHALLENGE_NOT_REPLAYED','permission_denied')
    latest=[];measured=0
    for path,digest in zip(source['readback_response_files'],
                           source['readback_response_shas'],strict=True):
        original={'path':path,'sha256':digest}
        # Production EC347 checked every signed original before returning.
        doc=_json_original(read(original,'ec347_replay_signed_response_'+digest,MAX_SIGNED),
                          'EC347_REPLAYED_SIGNED_RESPONSE')
        exact(doc,{'schema','claim','signature_ed25519'},'SIGNED_EC347_REPLY')
        rc=doc['claim']
        need(doc['schema']==old347.RESPONSE_SCHEMA and type(rc) is dict and
             set(rc)==old347.R_FIELDS,'OLD_EC347_REPLY_SCHEMA_CHANGED','permission_denied')
        if rc['round_number']==round_no:
            need(rc['challenge_file']==challenge['path'] and
                 rc['challenge_original_raw_sha256']==challenge['sha256'] and
                 rc['challenge_nonce_sha256']==claim['challenge_nonce_sha256'] and
                 rc['case_id']==claim['case_id'],
                 'LATEST_REPLY_NOT_ACTUALLY_BOUND_TO_ORIGINAL_SIGNED_CHALLENGE',
                 'permission_denied')
            latest.append(original)
            measured+=rc['response_kind']==old347.MEASURED
    refs=row['ec347_latest_signed_response_originals']
    need(type(refs) is list and refs==latest and len(latest)<=MAX_LATEST_RESPONSES,
         'MUST_SUPPLY_EXACT_REAL_SIGNED_LATEST_EC347_RESPONSES','permission_denied')
    return {'signed_latest_challenge_sha256':challenge['sha256'],
            'verified_signed_latest_response_original_shas':[r['sha256'] for r in latest],
            'latest_challenge_round':round_no,
            'latest_signed_response_count':len(latest),
            'actual_latest_round_measured_receiver_count':measured,
            'source_snapshot_original_sha256':claim['source_snapshot_original_raw_sha256'],
            'source_ack_set_original_sha256':claim['source_ack_set_original_raw_sha256']}


def _keeper_graph(row,source,ctx,read,evaluation):
    """Verify independent root/keeper signed originals and their visible graph.

    Production EC348 full source replay is mandatory and first, so a local
    fake directory or receipt cannot bypass genuine old EC347/EC346 ancestry.
    """
    ec347=_ec347_latest(source,ctx,row,read)
    real_dir=source['expected_keeper_directory_sha256']
    _ref(row['keeper_signed_directory_original'],source['keeper_directory_file'],real_dir,
         'ORIGINAL_KEEPER_DIRECTORY')
    rootref=row['keeper_root_public_key_original']
    exact(rootref,{'path','sha256'},'OLD_EC348_ROOT_KEY')
    root=read(rootref,'ec348_root_public_'+rootref['sha256'],32)
    need(len(root)==32 and root.hex()==source['expected_directory_root_public_hex'],
         'EC348_ROOT_PUBLIC_KEY_NOT_ACTUALLY_PINNED_AND_BOUND','permission_denied')
    dclaim,_=_signed(row['keeper_signed_directory_original'],
           'ec348_signed_keeper_directory_'+real_dir,read,old348.D_FIELDS,
           old348.DIRECTORY_SCHEMA,old348.D_DIRECTORY,root.hex())
    need(dclaim['schema']==old348.DIRECTORY_CLAIM and
         dclaim['case_id']==ctx['report']['case_id'] and
         dclaim['ec347_audit_inputs_canonical_sha256']==ctx['report']['ec347_audit_inputs_canonical_sha256'] and
         dclaim['ec347_latest_challenge_original_raw_sha256']==source['readback_challenge_shas'][-1] and
         dclaim['source_snapshot_original_raw_sha256']==ec347['source_snapshot_original_sha256'] and
         dclaim['source_ack_set_original_raw_sha256']==ec347['source_ack_set_original_sha256'] and
         dclaim['directory_authority']['public_hex']==root.hex() and
         len(dclaim['custodians'])==len(ctx['report']['keeper_outcomes']) and
         2<=len(dclaim['custodians'])<=old348.MAX_KEEPERS,
         'SIGNED_OLD_EC348_ROOT_KEEPER_GOVERNANCE_OR_SOURCE_BINDING_INVALID',
         'permission_denied')
    for k in ('public_hex','signer_id','organization_id'):
        actors=[dclaim['directory_authority'],*dclaim['custodians']]
        need(len({actor[k] for actor in actors})==len(actors),
             'KEEPER_AND_ROOT_SIGNER_ROLE_COLLISION','permission_denied')
    refs=row['keeper_signed_receipt_originals']
    paths=source['keeper_receipt_files'];shas=source['keeper_receipt_shas']
    need(type(refs) is list and len(refs)==len(paths)==len(shas)<=MAX_KEEPER_ORIGINALS and
         all(old353._sha(s) and s!=old348.UNPINNED for s in shas),
         'ONLY_ACTUALLY_INDEPENDENTLY_SHA_PINNED_KEEPER_ORIGINALS_ALLOWED',
         'permission_denied')
    actors={a['signer_id']:a for a in dclaim['custodians']}
    need(len(actors)==len(dclaim['custodians']),'DUPLICATED_KEEPER_ACTOR','permission_denied')
    known_by_path={};headmap=defaultdict(list);nonces=set();sigs=set()
    for ref,path,digest in zip(refs,paths,shas,strict=True):
        _ref(ref,path,digest,'OLD_EC348_SIGNED_KEEPER_RECEIPT')
        # Read without trusting actor claimed inside the document, then
        # verify only against the actual root-authorized keeper directory.
        raw=read(ref,'ec348_signed_receipt_'+digest,MAX_SIGNED)
        doc=_json_original(raw,'EC382_ORIGINAL_KEEPER_RECEIPT')
        exact(doc,{'schema','claim','signature_ed25519'},'EC348_SIGNED_RECEIPT')
        claim=doc['claim'];need(type(claim) is dict,'KEEPER_SIGNED_CLAIM_MISSING','permission_denied')
        actor=actors.get(claim.get('custodian_id'))
        need(actor is not None,'KEEPER_SIGNER_NOT_PRESENT_IN_SIGNED_ROOT_DIRECTORY','permission_denied')
        # Above raw read has the same ref/role in _signed below (idempotent).
        _signed(ref,'ec348_signed_receipt_'+digest,read,old348.R_FIELDS,
                old348.RECEIPT_SCHEMA,old348.D_RECEIPT,actor['public_hex'])
        need(claim['schema']==old348.RECEIPT_CLAIM and
             claim['case_id']==ctx['report']['case_id'] and
             claim['directory_original_raw_sha256']==real_dir and
             claim['ec347_audit_inputs_canonical_sha256']==ctx['report']['ec347_audit_inputs_canonical_sha256'] and
             claim['latest_challenge_original_raw_sha256']==source['readback_challenge_shas'][-1] and
             claim['latest_ec347_round']==ec347['latest_challenge_round'] and
             claim['custodian_public_hex']==actor['public_hex'] and
             claim['custodian_organization_id']==actor['organization_id'] and
             claim['ledger_id']==actor['ledger_id'] and
             claim['subject_receiver_id']==actor['subject_receiver_id'] and
             claim['statement_nonce_sha256'] not in nonces and
             doc['signature_ed25519'] not in sigs,
             'GOVERNED_KEEPER_RECEIPT_DOES_NOT_BIND_REAL_EC347_OR_SIGNER','permission_denied')
        nonces.add(claim['statement_nonce_sha256']);sigs.add(doc['signature_ed25519'])
        if claim['sequence']>1:
            previous_entry=known_by_path.get(claim['previous_statement_file'])
            need(previous_entry is not None and
                 previous_entry['sha']==claim['previous_statement_original_raw_sha256'] and
                 previous_entry['claim']['custodian_id']==claim['custodian_id'] and
                 previous_entry['claim']['sequence']+1==claim['sequence'] and
                 previous_entry['claim']['statement_kind']!=old348.REVOKE and
                 old350._utc(previous_entry['claim']['reported_utc'])<=
                    old350._utc(claim['reported_utc']),
                 'TRUE_SIGNED_KEEPER_PREDECESSOR_CHAIN_BROKEN','permission_denied')
        else:
            need(claim['statement_kind']==old348.STORE and
                 claim['previous_statement_file'] is None and
                 claim['previous_statement_original_raw_sha256'] is None,
                 'SIGNED_KEEPER_GENESIS_INCORRECT','permission_denied')
        known_by_path[path]={'sha':digest,'claim':claim}
        headmap[actor['signer_id']].append((digest,claim))
    need(len(known_by_path)==len(refs),'RECEIPT_ORIGINAL_PATH_COLLISION','permission_denied')
    summaries=[];has_fork=False;adverse=False
    for keeper in dclaim['custodians']:
        events=headmap[keeper['signer_id']]
        referenced={c['previous_statement_original_raw_sha256'] for _,c in events
                    if c['sequence']>1}
        heads=[(d,c) for d,c in events if d not in referenced]
        signed_fork=len(heads)>1
        has_fork|=signed_fork
        prior_row=next(x for x in ctx['report']['keeper_outcomes']
                       if x['custodian_id']==keeper['signer_id'])
        need(prior_row['signed_head_original_raw_sha256s']==[d for d,_ in heads] and
             prior_row['signed_receipt_count']==len(events) and
             prior_row['multiple_signed_heads_are_unresolved_forks']==signed_fork,
             'RECONSTRUCTED_KEEPER_HEAD_GRAPH_DIFFERS_FROM_LIVE_EC348_REPLAY',
             'permission_denied')
        if heads:
            head=heads[0] if len(heads)==1 else None
            if head is not None:
                adverse|=(head[1]['statement_kind']==old348.REVOKE or
                    old350._utc(head[1]['expires_utc'])<evaluation)
        summaries.append({'custodian_id':keeper['signer_id'],
             'custodian_public_sha256':sha(bytes.fromhex(keeper['public_hex'])),
             'subject_receiver_id':keeper['subject_receiver_id'],
             'signed_receipt_original_shas':[d for d,_ in events],
             'visible_head_original_shas':[d for d,_ in heads],
             'visible_fork':signed_fork,
             'newest_visible_sequence':max((c['sequence'] for _,c in events),default=0),
             'latest_signed_head_revoked_or_expired':
                len(heads)==1 and (heads[0][1]['statement_kind']==old348.REVOKE or
                   old350._utc(heads[0][1]['expires_utc'])<evaluation),
             'live_old_ec348_keeper_outcome':prior_row['outcome']})
    retest_paths=source['presented_ledger_files'];retest_shas=source['presented_ledger_shas']
    ledgers=row['keeper_signed_ledger_originals']
    _present_refs(ledgers,retest_paths,retest_shas,'ec348_ledger',read,MAX_SIGNED)
    # For each locally reopened old ledger, recompute actual exact JSON
    # equality with its corresponding signed head. A mere SHA label is never
    # allowed to substitute for a keeper ledger original.
    by_keeper={r['custodian_id']:r for r in ctx['report']['keeper_outcomes']}
    for ref,keeper_id in zip(ledgers,source['presented_keeper_ids'],strict=True):
        signed_row=by_keeper[keeper_id]
        need(signed_row['local_explicit_retest'] is not None and
             signed_row['local_explicit_retest']['explicit_ledger_original_read_and_sha_verified'] is True and
             signed_row['latest_single_head_ledger_original_raw_sha256']==ref['sha256'],
             'REPLAYED_LEDGER_NOT_A_GENUINE_VERIFIED_SIGNED_KEEPER_HEAD',
             'permission_denied')
        ledger=_json_original(read(ref,'ec348_ledger_'+ref['sha256'],MAX_SIGNED),
                        'EC348_ACTUAL_KEEPER_LEDGER_ORIGINAL')
        unique=[x for x in headmap[keeper_id] if x[0] in signed_row['signed_head_original_raw_sha256s']]
        need(len(unique)==1 and ledger==old348._ledger_fields(unique[0][1]),
             'OLD_LEDGER_ACTUAL_CONTENT_DIFFERS_FROM_REAL_SIGNED_HEAD','permission_denied')
    # The full old EC348 engine has already remeasured these exact local
    # physical bytes, including claimed SHA and byte lengths, against source.
    pair_rows=[]
    for typ,field,sourcefield,reportfield in (
         ('snapshot','retested_snapshot_originals','presented_copy_snapshot_files','actual_copy_snapshot_original_raw_sha256'),
         ('ack_set','retested_ack_set_originals','presented_copy_ack_set_files','actual_copy_ack_set_original_raw_sha256')):
        refs=row[field];paths=source[sourcefield]
        shas=[by_keeper[k]['local_explicit_retest'][reportfield]
              for k in source['presented_keeper_ids']]
        _present_refs(refs,paths,shas,'ec348_retested_'+typ,read,old348.copies.MAX_COPY_BYTES)
        pair_rows.append([r['sha256'] for r in refs])
    need(len(ledgers)==len(source['presented_keeper_ids']),
         'PRESENTED_LEDGER_CENSUS_INCOMPLETE','permission_denied')
    return {'keeper_root_key_original_sha256':row['keeper_root_public_key_original']['sha256'],
       'signed_keeper_directory_original_sha256':real_dir,
       'signed_keeper_receipt_original_shas':[r['sha256'] for r in row['keeper_signed_receipt_originals']],
       'keepers':summaries,'visible_signed_fork':has_fork,
       'signed_keeper_expired_revoked_or_source_drift':adverse or any(
           r['outcome']!=old348.OUTCOMES[7] for r in ctx['report']['keeper_outcomes']),
       'signed_keeper_receipt_count':len(row['keeper_signed_receipt_originals']),
       'explicit_ledger_original_shas':[r['sha256'] for r in ledgers],
       'retested_snapshot_original_shas':pair_rows[0],
       'retested_ack_set_original_shas':pair_rows[1],
       'true_original_ledger_and_copy_pair_retests':len(ledgers),
       'ec347':ec347}


def _channel(row,parent_channel,old_ec380_token,read,evaluation,forbidden):
    exact(row,CHANNEL_FIELDS,'EC382_KEEPER_CHANNEL')
    channel=row['tsa_channel_id']
    need(channel==parent_channel['tsa_channel_id']==old_ec380_token['tsa_channel_id'],
         'EC382_KEEPER_CHANNEL_NOT_IN_REAL_EC381_EC380_PAIR','permission_denied')
    reference=row['ec348_full_replay_inputs_original']
    if reference is None:
        need(all(row[k] is None for k in ('keeper_root_public_key_original',
                    'keeper_signed_directory_original','ec347_latest_signed_challenge_original')) and
             all(row[k]==[] for k in ('keeper_signed_receipt_originals',
               'keeper_signed_ledger_originals','ec347_latest_signed_response_originals',
               'retested_snapshot_originals','retested_ack_set_originals')),
             'MISSING_GENUINE_SOURCE_MUST_NOT_PROVIDE_UNAUTHENTICATED_SUBSTITUTES',
             'permission_denied')
        return {'tsa_channel_id':channel,'true_ec348_old_ec347_full_original_replay_performed':False,
                'full_signed_ec349_keeper_source_and_target_binding_matches':False,
                'ec348_signed_keeper_receipt_count':0,
                'ec348_genuine_retested_ledger_count':0,
                'old_ec347_last_signed_readback_corroborated':False,
                'signed_keeper_fork_or_adverse_head':False,
                'root_key_sha256':None,'signed_directory_sha256':None,
                'ec348_source_canonical_sha256':None,'ec348_result_canonical_sha256':None,
                'actual_ec347_latest_challenge_sha256':None,
                'keeper_signed_receipt_shas':[], 'keepers':[], 'signed_readback_original_shas':[],
                'old_ledger_signed_claim_original_shas':[],
                'local_byte_retested_snapshot_original_shas':[],
                'local_byte_retested_ack_set_original_shas':[]}
    # Real originals only: use the unchanged inherited EC349 -> EC348 ->
    # EC347 -> EC346 production replay; no report/fixture surrogate.
    ctx=previous._ec348_original(reference,read,forbidden)
    source=ctx['inputs']
    dclaim,_=previous._directory(parent_channel,read,evaluation)
    tokenref=old_ec380_token['ec349_receipt_original']
    signedreceipt=previous._receipt(tokenref,dclaim,
        parent_channel['signed_channel_directory_original']['sha256'],read,evaluation)
    verified=(dclaim['case_id']==ctx['report']['case_id'] and
        dclaim['ec348_inputs_canonical_sha256']==ctx['source_sha'] and
        dclaim['ec348_verified_result_canonical_sha256']==ctx['result_sha'] and
        dclaim['ec348_keeper_directory_original_raw_sha256']==
            source['expected_keeper_directory_sha256'] and
        signedreceipt['claim']['keeper_visible_heads']==ctx['keepers'] and
        signedreceipt['claim']['keeper_signed_originals']==ctx['originals'])
    need(verified,'REAL_EC349_SIGNED_DIRECTORY_RECEIPT_NOT_BOUND_TO_REAL_EC348_SOURCE',
         'permission_denied')
    # No EC349 directory actor may be relabeled from an old EC348/EC343
    # keeper or governance actor, even when EC381 had not yet replayed it.
    for role in ('root_authority','receipt_actor','time_actor'):
        for field in ('public_hex','signer_id','organization_id'):
            need(dclaim[role][field] not in {a[field] for a in ctx['old_actors']},
                 'EC349_SIGNER_ROLE_REUSES_REAL_EC348_KEEPER_OR_GOVERNANCE',
                 'permission_denied')
    # A parent EC381 epoch may independently point to a real source. It must
    # match exactly, not form a competing fork selected by this new archive.
    prior_ref=parent_channel['ec348_replay_inputs_original']
    if prior_ref is not None:
        need(reference==prior_ref,'SUPPLIED_EC348_ORIGINAL_DIFFERS_FROM_PARENT_EC381',
             'permission_denied')
    keeper=_keeper_graph(row,source,ctx,read,evaluation)
    ec347=keeper['ec347']
    return {'tsa_channel_id':channel,'true_ec348_old_ec347_full_original_replay_performed':True,
            'full_signed_ec349_keeper_source_and_target_binding_matches':verified,
            'ec348_signed_keeper_receipt_count':keeper['signed_keeper_receipt_count'],
            'ec348_genuine_retested_ledger_count':keeper['true_original_ledger_and_copy_pair_retests'],
            'old_ec347_last_signed_readback_corroborated':ec347['latest_signed_response_count']>0,
            'signed_keeper_fork_or_adverse_head':keeper['visible_signed_fork'] or
                keeper['signed_keeper_expired_revoked_or_source_drift'],
            'root_key_sha256':keeper['keeper_root_key_original_sha256'],
            'signed_directory_sha256':keeper['signed_keeper_directory_original_sha256'],
            'ec348_source_canonical_sha256':ctx['source_sha'],
            'ec348_result_canonical_sha256':ctx['result_sha'],
            'actual_ec347_latest_challenge_sha256':ec347['signed_latest_challenge_sha256'],
            'keeper_signed_receipt_shas':keeper['signed_keeper_receipt_original_shas'],
            'keepers':keeper['keepers'],
            'signed_readback_original_shas':ec347['verified_signed_latest_response_original_shas'],
            'old_ledger_signed_claim_original_shas':keeper['explicit_ledger_original_shas'],
            'local_byte_retested_snapshot_original_shas':keeper['retested_snapshot_original_shas'],
            'local_byte_retested_ack_set_original_shas':keeper['retested_ack_set_original_shas']}


def _engine(derive,**opts):
    parent_opts=_inputs(opts,derive)
    parent=previous.audit(**parent_opts)  # live EC381 -> 369 (mandatory)
    n=len(opts['historical_directory_root_shas'])
    parent_sha=_parent(parent,n)
    evaluation=old350._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC382_'+role)
        key=ref['path']
        if key in cache:
            digest,raw,oldrole=cache[key]
            need(key not in forbidden and digest==ref['sha256'] and role==oldrole and
                 len(raw)<=cap,'RECEIVER_ORIGINAL_ROLE_ALIAS_SHA_OR_CAP_MISMATCH',
                 'permission_denied')
            return raw
        raw=p372._read(ref,'ec382_'+role,cap,pins,categories,forbidden)
        cache[key]=(ref['sha256'],raw,role)
        return raw
    original381={'path':opts['historical_ec349_channel_archive_bundle_file'],
                 'sha256':opts['expected_historical_ec349_channel_archive_bundle_sha256']}
    original380={'path':opts['historical_timestamp_archive_bundle_file'],
                 'sha256':opts['expected_historical_timestamp_archive_bundle_sha256']}
    old381=old353.strict_json(read(original381,'verified_parent_ec381_original',previous.MAX_BUNDLE),
                              'EC382_AUTHENTIC_PARENT_EC381_ORIGINAL')
    old380=old353.strict_json(read(original380,'verified_parent_ec380_original',
                                  previous.previous.MAX_BUNDLE),
                              'EC382_AUTHENTIC_PARENT_EC380_ORIGINAL')
    exact(old381,previous.BUNDLE_FIELDS,'REAL_EC381_PARENT_RECEIVER_ARCHIVE')
    exact(old380,previous.previous.BUNDLE_FIELDS,'REAL_EC380_PARENT_TIMESTAMP_ARCHIVE')
    need(old381['schema']==previous.BUNDLE_SCHEMA and
         old380['schema']==previous.previous.BUNDLE_SCHEMA and
         len(old381['epochs'])==len(old380['epochs'])==n and
         old381['ec380_historical_timestamp_archive_original_sha256']==original380['sha256'],
         'ACTUAL_SIGNED_EC380_EC381_ORIGINALS_DISAGREE','permission_denied')
    ref382={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=old353.strict_json(read(ref382,'receiver_ec382_keeper_archive',MAX_BUNDLE),
                              'EC382_TRUE_KEEPER_ORIGINAL_ARCHIVE')
    exact(bundle,BUNDLE_FIELDS,'EC382_RECEIVER_ARCHIVE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['parent_ec381_canonical_result_sha256']==parent_sha and
         bundle['ec381_historical_channel_archive_original_sha256']==original381['sha256'] and
         bundle['claimed_directory_lineage_id']==old381['claimed_directory_lineage_id'] and
         len(bundle['epochs'])==n,
         'RECEIVER_EC382_NOT_BOUND_TO_LIVE_EC381_ORIGIN','permission_denied')
    # Sender publication paths are merely untrusted source labels and must
    # never be followed as EC382 receiver-original paths.
    parent377={'path':opts['historical_transparency_archive_bundle_file'],
               'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    old377=old353.strict_json(read(parent377,'verified_ec377_original',
        previous.p379.p377.MAX_BUNDLE),'EC382_REAL_EC377_PARENT')
    exact(old377,previous.p379.p377.BUNDLE_FIELDS,'AUTHENTIC_EC377_PARENT')
    need(old377['schema']==previous.p379.p377.BUNDLE_SCHEMA and
         len(old377['epochs'])==n,'OLD_EC377_REAL_SENDER_LABEL_SOURCE_CHANGED',
         'permission_denied')
    for ep in old377['epochs']:
        sender=old353.strict_json(read(ep['ec353_publication_bundle_original'],
            'old_ec353_sender_labels_'+ep['ec353_publication_bundle_original']['sha256'],
            old353.MAX_BUNDLE),'EC382_OLD_EC353_SENDER_LABELS')
        previous.p379._old_sender_labels(sender,forbidden)
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=not parent['local_root_authorized_receipt_witness_and_keeper_binding_consistent']
    counts_receipts=counts_ledgers=missing=0;rows=[];inventories=[];old_channels={}
    for idx,(epoch,prior_epoch,token_epoch) in enumerate(zip(
           bundle['epochs'],old381['epochs'],old380['epochs'],strict=True)):
        exact(epoch,EPOCH_FIELDS,'EC382_EPOCH');exact(prior_epoch,previous.EPOCH_FIELDS,
           'EC381_ACTUAL_PARENT_EPOCH')
        exact(token_epoch,previous.previous.EPOCH_FIELDS,'EC380_ACTUAL_PARENT_EPOCH')
        need(epoch['epoch_index']==prior_epoch['epoch_index']==token_epoch['epoch_index']==idx and
             type(epoch['channels']) is list and len(epoch['channels'])<=old349.MAX_CHANNELS and
             type(prior_epoch['channels']) is list and
             type(token_epoch['timestamps']) is list,
             'OLD_EC381_EC380_EC382_EPOCH_INDEX_OR_LIMIT_INVALID','permission_denied')
        channels=epoch['channels']
        ids=[c.get('tsa_channel_id') for c in channels if type(c) is dict]
        prior_ids=[c['tsa_channel_id'] for c in prior_epoch['channels']]
        need(len(ids)==len(channels) and ids==prior_ids==sorted(set(ids)),
             'OLD_EC381_AUTHENTIC_CHANNEL_CENSUS_MUST_BE_PRESERVED','permission_denied')
        tokenindex={r['tsa_channel_id']:r for r in token_epoch['timestamps']}
        need(len(tokenindex)==len(token_epoch['timestamps']) and
             all(c in tokenindex for c in ids),
             'REAL_EC380_SIGNED_TIMESTAMP_RECEIPT_TARGET_MISSING','permission_denied')
        results=[]
        for row,prior_row in zip(channels,prior_epoch['channels'],strict=True):
            result=_channel(row,prior_row,tokenindex[row['tsa_channel_id']],
                            read,evaluation,forbidden)
            results.append(result)
            flags[FLAGS[2]]|=not result['true_ec348_old_ec347_full_original_replay_performed']
            flags[FLAGS[3]]|=result['signed_keeper_fork_or_adverse_head']
            flags[FLAGS[4]]|=(not result['old_ec347_last_signed_readback_corroborated'] or
                              not result['ec348_genuine_retested_ledger_count'])
            flags[FLAGS[5]]|=not result['full_signed_ec349_keeper_source_and_target_binding_matches']
            if result['true_ec348_old_ec347_full_original_replay_performed']:
                owner=old_channels.get(result['tsa_channel_id'])
                if owner is not None:
                    old_keeper={r['custodian_id']:r for r in owner['keepers']}
                    new_keeper={r['custodian_id']:r for r in result['keepers']}
                    continuation=(owner['root_key_sha256']==result['root_key_sha256'] and
                        owner['signed_directory_sha256']==result['signed_directory_sha256'] and
                        owner['ec348_source_canonical_sha256']==result['ec348_source_canonical_sha256'] and
                        set(old_keeper)==set(new_keeper) and
                        all(old_keeper[k]['custodian_public_sha256']==v['custodian_public_sha256'] and
                            set(old_keeper[k]['signed_receipt_original_shas']).issubset(
                                v['signed_receipt_original_shas']) and
                            old_keeper[k]['newest_visible_sequence']<=v['newest_visible_sequence']
                            for k,v in new_keeper.items()))
                    flags[FLAGS[6]]|=not continuation
                old_channels[result['tsa_channel_id']]=result
        # The two old EC349 out-of-band channels can have different actors
        # and independent time claims, but both must anchor the SAME true
        # original EC348 source / keeper corpus in a single historic epoch.
        # Different signed keeper branches cannot be hidden by presenting
        # one otherwise cryptographically sound channel after another.
        if len(results)==2:
            shared=('root_key_sha256','signed_directory_sha256',
              'ec348_source_canonical_sha256','ec348_result_canonical_sha256',
              'actual_ec347_latest_challenge_sha256','keeper_signed_receipt_shas',
              'old_ledger_signed_claim_original_shas')
            flags[FLAGS[5]]|=any(results[0][k]!=results[1][k] for k in shared)
        flags[FLAGS[2]]|=not results
        rc=sum(r['ec348_signed_keeper_receipt_count'] for r in results)
        lc=sum(r['ec348_genuine_retested_ledger_count'] for r in results)
        counts_receipts+=rc;counts_ledgers+=lc
        missing+=sum(not r['true_ec348_old_ec347_full_original_replay_performed'] for r in results)
        keeper_inventory=[{k:r[k] for k in ('tsa_channel_id','root_key_sha256',
            'signed_directory_sha256','ec348_source_canonical_sha256',
            'ec348_result_canonical_sha256','keeper_signed_receipt_shas','keepers',
            'old_ledger_signed_claim_original_shas',
            'local_byte_retested_snapshot_original_shas',
            'local_byte_retested_ack_set_original_shas')} for r in results]
        readback_inventory=[{k:r[k] for k in ('tsa_channel_id',
            'actual_ec347_latest_challenge_sha256','signed_readback_original_shas',
            'old_ledger_signed_claim_original_shas')} for r in results]
        keeper_sha=sha(canonical.canonical(keeper_inventory))
        readback_sha=sha(canonical.canonical(readback_inventory))
        flags[FLAGS[1]]|=(keeper_sha!=opts['historical_ec348_keeper_original_inventory_shas'][idx] or
           readback_sha!=opts['historical_ec347_readback_join_inventory_shas'][idx] or
           rc<opts['minimum_historical_ec348_signed_keeper_receipt_counts'][idx] or
           lc<opts['minimum_historical_ec348_retested_ledger_counts'][idx])
        rows.append({'epoch_index':idx,'real_ec348_signed_keeper_receipt_original_count':rc,
            'real_ec348_explicit_custody_ledger_byte_retest_count':lc,
            'missing_true_full_ec348_keeper_sources':sum(not r['true_ec348_old_ec347_full_original_replay_performed'] for r in results),
            'visible_old_keeper_signed_fork_or_adverse_head':any(r['signed_keeper_fork_or_adverse_head'] for r in results),
            'signed_ec347_latest_round_original_join_missing':any(not r['old_ec347_last_signed_readback_corroborated'] for r in results),
            'keeper_original_inventory_sha256':keeper_sha,
            'ec347_readback_join_inventory_sha256':readback_sha,
            'local_recovered_real_signed_keeper_evidence_consistent':bool(results) and all(
                r['true_ec348_old_ec347_full_original_replay_performed'] and
                r['full_signed_ec349_keeper_source_and_target_binding_matches'] and
                r['old_ec347_last_signed_readback_corroborated'] and
                not r['signed_keeper_fork_or_adverse_head'] for r in results)})
        inventories.append({'epoch_index':idx,'true_keeper_originals':keeper_inventory,
             'signed_ec347_latest_readback_and_retested_ledger_joins':readback_inventory,
             'historical_keeper_original_inventory_sha256':keeper_sha,
             'historical_readback_join_inventory_sha256':readback_sha})
    p372.prior.lineage.parent.ref_check(ref382,'EC382_FINAL_ARCHIVE_REF')
    p372.prior.lineage.parent.ref_check(original381,'EC382_FINAL_PARENT_REF')
    p372.prior.lineage.parent.ref_check(original380,'EC382_FINAL_TIMESTAMP_REF')
    # Retest the pinned originals at the end to catch late local mutations.
    from ec376_historical_disclosure import disclosure_archive as p376
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inventory={'schema':INVENTORY_SCHEMA,
       'live_ec381_through_ec369_parent_result_canonical_sha256':parent_sha,
       'authenticated_ec381_channel_archive_original_sha256':original381['sha256'],
       'receiver_ec382_keeper_archive_original_sha256':ref382['sha256'],
       'claimed_directory_lineage_id':bundle['claimed_directory_lineage_id'],
       'historical_ec348_keeper_epoch_reviews':inventories}
    inventory_sha=sha(canonical.canonical(inventory))
    if not derive and inventory_sha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec348-keeper-inventory' if derive else
                 'audit-historical-ec348-keeper-archive',
       'status':next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),
                     OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_parent_ec381_canonical_result_sha256':parent_sha,
       'historical_ec348_keeper_archive_bundle_original_sha256':ref382['sha256'],
       'receiver_verified_historical_ec348_keeper_inventory_sha256':inventory_sha,
       'genuine_old_ec348_signed_keeper_receipt_original_count':counts_receipts,
       'genuine_old_ec348_retested_ledger_original_count':counts_ledgers,
       'missing_true_historical_ec348_full_source_count':missing,
       'historical_ec348_keeper_epoch_reviews':rows,
       'local_recovered_keeper_readback_original_binding_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec348_through_ec337_full_independent_historical_parent_acceptance_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_verified_historical_ec348_keeper_inventory':inventory,
           'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
