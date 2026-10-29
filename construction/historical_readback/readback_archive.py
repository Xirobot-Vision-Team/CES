#!/usr/bin/env python3
"""EC383: recover old EC347 signer authority and EC346 signed copy provenance.

Only a receiver-controlled, pinned-original, read-only reconciliation. The
unchanged EC382->EC369 live production ancestry is compulsory. Old EC347->337
full originals can be recovered and replayed, but no recovered signature or
claimed storage label certifies an independent physical site or trusted UTC.
"""
from __future__ import annotations

from pathlib import Path

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from hold_receipts import timeline as old343
from disclosure_custody import custody as old346
from readback_challenge import readback as old347
from external_custody import custody as old348
from dual_channel_anchor import anchor as old349
from transparency import transparency as old353
from historical_authority import authority_archive as p372
from historical_disclosure import disclosure_archive as p376
from historical_keeper import keeper_archive as previous

RESULT_SCHEMA = 'ces.ec383.receiver_original_ec347_signer_ec346_copy_site_provenance_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec383.unsigned_ec347_signer_ec346_site_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec383.receiver_ec347_signer_ec346_copy_site_denial.v1'
BUNDLE_SCHEMA = 'ces.ec383.receiver_historic_ec347_signer_ec346_copy_provenance_archive.v1'
INVENTORY_SCHEMA = 'ces.ec383.receiver_verified_historic_readback_copy_provenance_inventory.v1'
MAX_BUNDLE = 175_000
MAX_ORIGINAL = 300_000
NEW_SCALARS = ('historical_ec347_site_provenance_archive_bundle_file',
               'expected_historical_ec347_site_provenance_archive_bundle_sha256')
AUDIT_ONLY = ('expected_retained_historical_ec347_site_provenance_inventory_sha256',)
NEW_REPEATS = (
 ('historical_ec347_actor_authorization_inventory_shas','--historical-ec347-actor-authorization-inventory-sha256'),
 ('historical_ec346_copy_site_inventory_shas','--historical-ec346-copy-site-inventory-sha256'),
 ('minimum_historical_ec347_authorized_receiver_counts','--minimum-historical-ec347-authorized-receiver-count'),
 ('minimum_historical_ec346_signed_observation_counts','--minimum-historical-ec346-signed-observation-count'),
 ('minimum_historical_ec346_byte_retested_copy_counts','--minimum-historical-ec346-byte-retested-copy-count'),
)
REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS = (*previous.PARENT_SCALARS,*previous.NEW_SCALARS,*previous.AUDIT_ONLY)
PARENT_REPEATS = (*previous.PARENT_REPEATS,*previous.REPEAT_NAMES)
BUNDLE_FIELDS = {'schema','parent_ec382_canonical_result_sha256',
 'ec382_historical_keeper_archive_original_sha256','claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS = {'epoch_index','channels'}
CHANNEL_FIELDS = {'tsa_channel_id','ec343_authority_roster_original',
 'ec344_receiver_directory_original','ec344_source_checkpoint_original',
 'ec347_challenger_public_key_original','ec347_signed_challenge_originals',
 'ec347_signed_response_originals','ec346_signed_observation_originals',
 'ec345_verified_source_snapshot_original','ec345_verified_source_ack_set_original',
 'ec346_receiver_copy_site_originals'}
SITE_FIELDS = {'receiver_id','receiver_public_key_original',
 'ec346_latest_signed_observation_original','claimed_storage_id','copy_id',
 'explicit_copy_snapshot_original','explicit_copy_ack_set_original'}
FLAGS = (
 'inherited_live_ec382_through_ec369_original_dispute',
 'outside_retained_ec347_authority_or_ec346_site_inventory_floor_disagrees',
 'historical_ec347_ec346_full_original_source_or_actor_roster_missing',
 'old_ec347_registered_challenger_or_signed_receiver_authority_incomplete',
 'old_ec346_signed_copy_site_or_latest_original_binding_incomplete',
 'ec346_explicit_locally_retested_copy_bytes_missing_or_disagree',
 'historical_ec347_actor_or_ec346_site_epoch_rollback_or_channel_disagreement',
 'full_unmocked_old_ec346_through_ec337_external_source_unavailable',
 'offsite_physical_identity_independent_custody_and_calibrated_utc_unproven',
)
OUTCOMES = (
 'ec383_inherited_signed_original_receiver_parent_dispute',
 'ec383_outside_retained_challenger_site_inventory_or_floor_disagrees',
 'ec383_old_ec347_ec346_parent_source_or_signed_actor_roster_missing',
 'ec383_old_challenger_or_receiver_original_ed25519_authorization_missing',
 'ec383_old_ec346_source_site_signed_provenance_incomplete',
 'ec383_local_explicit_copy_byte_remeasurement_missing_or_disagrees',
 'ec383_old_ec347_ec346_cross_channel_or_cross_epoch_source_rollback',
 'ec383_old_ec346_through_ec337_independent_external_history_incomplete',
 'ec383_physical_external_site_identity_and_trusted_utc_unproven',
)
NEGATIVES = (
 'ec343_roster_or_ec347_signatures_prove_legal_challenger_identity',
 'two_receiver_public_keys_prove_two_independent_storage_sites',
 'signed_ec346_claimed_storage_id_is_independent_hardware_proof',
 'sha_pinned_signed_challenge_proves_all_receivers_reopened_bytes_now',
 'caller_supplied_inventory_was_independently_retained_by_this_software',
 'ec346_event_signature_proves_original_ec345_source_was_offsite',
 'locally_reopened_copy_is_globally_latest_or_worm_immutable',
 'self_reported_ec346_ec347_timestamp_is_trusted_utc',
 'all_hidden_signed_challenge_forks_or_observation_revocations_excluded',
 'ec353_sender_origin_labels_read_as_original_copy_paths',
 'missing_full_source_substituted_by_mock_receipt_or_generated_signer',
 'private_key_network_remote_provider_cas_worm_or_native_powershell_invoked',
 'inherited_ec366_to_ec337_mock_replaced_or_final_acceptance_granted',
)


def need(value, code, status='invalid_input'):
    if value is not True:
        raise errors.AnchorError('EC383_'+code,status)


def exact(value, fields, label):
    need(type(value) is dict and set(value)==set(fields),label+'_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return previous.sha(raw)


def _inputs(opts, derive):
    required = set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive: required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_LIVE_EC382_PARENT_AND_EC383_INPUTS_REQUIRED')
    parent={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    previous._inputs(parent,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC383_RECEIVER_EC347_ORIGINAL_ARCHIVE')
    if not derive:
        need(old353._sha(opts[AUDIT_ONLY[0]]),'EXTERNALLY_RETAINED_FINAL_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORICAL_EPOCH_LIMIT_INVALID')
    for name in REPEAT_NAMES:
        vals=opts[name]
        need(type(vals) is list and len(vals)==n,'ONE_EC383_FLOOR_PER_EPOCH_'+name.upper())
        if name.startswith('minimum_'):
            cap=(old349.MAX_CHANNELS*old346.prior.MAX_RECEIVERS if 'receiver' in name
                 else old349.MAX_CHANNELS*old346.MAX_EVENTS if 'observation' in name
                 else old349.MAX_CHANNELS*old346.prior.MAX_RECEIVERS)
            need(all(type(v) is int and 0<=v<=cap for v in vals),
                 'BOUNDED_EC383_COUNT_FLOOR_INVALID_'+name.upper())
        else:
            need(all(old353._sha(v) for v in vals),
                 'ORIGINAL_EC383_SHA_FLOOR_INVALID_'+name.upper())
    return parent


def _parent(result,n):
    need(type(result) is dict and result.get('schema')==previous.RESULT_SCHEMA and
         result.get('exit_code')==2 and
         result.get('sender_origin_path_required_or_read') is False and
         result.get('ec348_through_ec337_full_independent_historical_parent_acceptance_performed') is False and
         type(result.get('historical_ec348_keeper_epoch_reviews')) is list and
         len(result['historical_ec348_keeper_epoch_reviews'])==n,
         'ACTUAL_LIVE_EC382_THROUGH_EC369_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(result))


def _ref(ref, path, digest, label):
    previous._ref(ref,path,digest,label)


def _original(ref,role,read,cap=MAX_ORIGINAL):
    return previous._json_original(read(ref,role+'_'+ref['sha256'],cap),role)


def _signed(doc, fields, schema, domain, pub, label):
    exact(doc,{'schema','claim','signature_ed25519'},label+'_DOC')
    exact(doc['claim'],fields,label+'_CLAIM')
    need(doc['schema']==schema,label+'_SIGNED_SCHEMA_INVALID','permission_denied')
    old343._signed(doc,schema,domain,pub,'EC383_'+label)
    return doc['claim']


def _missing_channel(channel):
    return {'tsa_channel_id':channel,'full_original_signed_ec347_challenger_receiver_replay':False,
        'original_ec346_authorized_signed_observation_count':0,
        'genuine_ec347_registered_receiver_count':0,'actual_original_copy_byte_retest_count':0,
        'all_presented_signed_copy_bytes_match':False,
        'incomplete_explicit_copy_retest':True,'signed_site_or_readback_adverse':False,
        'challenger_public_key_sha256':None,'ec343_roster_original_sha256':None,
        'ec346_source_snapshot_sha256':None,'ec346_source_ack_set_sha256':None,
        'ec347_challenge_original_shas':[],'ec347_response_original_shas':[],
        'ec346_observation_original_shas':[], 'receiver_site_evidence':[]}


def _channel(row, oldrow, read, forbidden):
    """Verify exact old EC347/346 originals with previously authorized actor keys.

    This is an extra *authenticated* receiver original re-open on top of the
    unchanged production EC382 ancestor. Never dereference a signed copy path
    unless that exact copy pair is separately supplied in this receiver bundle.
    """
    exact(row,CHANNEL_FIELDS,'EC383_CHANNEL')
    need(row['tsa_channel_id']==oldrow['tsa_channel_id'],
         'NEW_CHANNEL_NOT_PRESENT_IN_AUTHENTIC_EC382','permission_denied')
    channel=row['tsa_channel_id']
    ref348=oldrow['ec348_full_replay_inputs_original']
    if ref348 is None:
        need(all(row[k] is None for k in (
              'ec343_authority_roster_original','ec344_receiver_directory_original',
              'ec344_source_checkpoint_original','ec347_challenger_public_key_original',
              'ec345_verified_source_snapshot_original','ec345_verified_source_ack_set_original')) and
             all(row[k]==[] for k in ('ec347_signed_challenge_originals',
              'ec347_signed_response_originals','ec346_signed_observation_originals',
              'ec346_receiver_copy_site_originals')),
             'ABSENT_REAL_EC348_SOURCE_MUST_NOT_ACCEPT_NEW_UNSIGNED_PROVENANCE',
             'permission_denied')
        return _missing_channel(channel)
    # The old engine replays EC349->348->347->346->345->337 actual source and
    # exact SHA-pinned original arguments, not a substituted audit summary.
    ctx=previous.previous._ec348_original(ref348,read,forbidden)
    source=ctx['inputs']
    ec346={k:source[k] for k in old347.PARENT_KEYS}
    roster,item,_,latest=old347._parent(ec346)
    original_refs=(
      ('ec343_authority_roster_original',source['roster_file'],source['expected_roster_sha256'],'ec343_authority_roster'),
      ('ec344_receiver_directory_original',source['directory_file'],source['expected_directory_sha256'],'ec344_receiver_directory'),
      ('ec344_source_checkpoint_original',source['checkpoint_file'],source['expected_checkpoint_sha256'],'ec344_source_checkpoint'),
      ('ec345_verified_source_snapshot_original',item['snapshot_file'],item['expected_snapshot_sha256'],'ec345_verified_source_snapshot'),
      ('ec345_verified_source_ack_set_original',item['ack_set_file'],item['expected_ack_set_sha256'],'ec345_verified_source_ack_set'),
    )
    for field,path,digest,role in original_refs:
        ref=row[field];_ref(ref,path,digest,field.upper())
        raw=read(ref,role+'_'+digest,old346.MAX_COPY_BYTES)
        need(len(raw)>0,role.upper()+'_ORIGINAL_EMPTY','permission_denied')
    roster_ref=row['ec343_authority_roster_original']
    roster_raw=read(roster_ref,'ec343_authority_roster_'+roster_ref['sha256'],
                    old346.MAX_COPY_BYTES)
    actual_roster=previous._json_original(roster_raw,'EC383_REAL_OLD_EC343_SIGNER_ROSTER')
    need(actual_roster==roster,'ORIGINAL_EC343_SIGNER_ROSTER_DIFFERS_FROM_AUTHENTIC_REPLAY',
         'permission_denied')
    proposer=roster['change_proposer']
    present_receivers=roster['receivers']
    need(type(present_receivers) is list and len(present_receivers)>=2 and
         all(proposer[key] not in {r[key] for r in present_receivers}
             for key in ('public_hex','signer_id','organization_id')),
         'EC347_CHALLENGER_NOT_DISTINCT_FROM_REGISTERED_RECEIVERS',
         'permission_denied')
    proposer_key=row['ec347_challenger_public_key_original']
    exact(proposer_key,{'path','sha256'},'EC347_CHALLENGER_ORIGINAL_PUBLIC_KEY')
    raw=read(proposer_key,'ec347_challenger_public_key_'+proposer_key['sha256'],32)
    need(len(raw)==32 and raw.hex()==proposer['public_hex'],
         'ORIGINAL_CHALLENGER_PUBLIC_KEY_NOT_IN_AUTHENTIC_EC343_ROSTER',
         'permission_denied')

    for field,paths,shas,role in (
        ('ec347_signed_challenge_originals',source['readback_challenge_files'],
             source['readback_challenge_shas'],'ec347_challenge'),
        ('ec347_signed_response_originals',source['readback_response_files'],
             source['readback_response_shas'],'ec347_response'),
        ('ec346_signed_observation_originals',source['observation_files'],
             source['observation_shas'],'ec346_observation')):
        refs=row[field]
        need(type(refs) is list and len(refs)==len(paths) and len(paths)==len(shas) and
             len({p for p in paths})==len(paths),
             'SIGNED_ORIGINAL_CENSUS_DIFFERS_FROM_ACTUALLY_REPLAYED_'+field.upper(),
             'permission_denied')
        for ref,path,digest in zip(refs,paths,shas,strict=True):
            _ref(ref,path,digest,field.upper())
            # Each original is reopened under a stable non-aliased role.
            read(ref,role+'_'+digest,MAX_ORIGINAL)

    # Check every exact signed challenge, all rounds and cryptographic signer
    # authority from the authenticated roster (not a caller-selected key).
    challenges={};context=old347._context(ec346,roster,item,latest)
    for idx,ref in enumerate(row['ec347_signed_challenge_originals'],start=1):
        c=_signed(_original(ref,'ec347_challenge',read),old347.C_FIELDS,
                  old347.CHALLENGE_SCHEMA,old347.D_CHALLENGE,proposer['public_hex'],
                  'OLD_EC347_CHALLENGER_SIGNED_CHALLENGE')
        need(c['round_number']==idx and
             all(c[k]==value for k,value in context.items()) and
             (c['previous_challenge_file'],c['previous_challenge_original_raw_sha256'])==
              ((None,None) if idx==1 else (row['ec347_signed_challenge_originals'][idx-2]['path'],
                                           row['ec347_signed_challenge_originals'][idx-2]['sha256'])),
             'ORIGINAL_EC347_CHALLENGE_AUTHORIZED_SOURCE_OR_PREDECESSOR_DISAGREES',
             'permission_denied')
        challenges[ref['path']]=(ref['sha256'],c)
    need(1<=len(challenges)<=old347.MAX_ROUNDS,'AUTHENTIC_CHALLENGE_SET_REQUIRED','permission_denied')

    # Old EC346 signer authorization was already proven by EC347._parent;
    # inspect the actual old Ed25519 observation signature again and bind it to
    # both the source and the latest signed receiver head.
    by_id={r['signer_id']:r for r in present_receivers}
    observations={};obs_by_receiver={}
    for ref in row['ec346_signed_observation_originals']:
        doc=_original(ref,'ec346_observation',read)
        claim=doc.get('claim')
        need(type(claim) is dict and claim.get('receiver_id') in by_id,
             'OLD_EC346_OBSERVATION_ACTOR_NOT_REGISTERED','permission_denied')
        actor=by_id[claim['receiver_id']]
        claim=_signed(doc,old346.FIELDS,old346.EVENT_SCHEMA,old346.EVENT_DOMAIN,
                      actor['public_hex'],'OLD_EC346_REGISTERED_SIGNED_COPY_EVENT')
        need(claim['receiver_public_hex']==actor['public_hex'] and
             claim['receiver_organization_id']==actor['organization_id'] and
             claim['ec343_roster_original_raw_sha256']==roster_ref['sha256'] and
             claim['source_snapshot_original_raw_sha256']==item['expected_snapshot_sha256'] and
             claim['source_ack_set_original_raw_sha256']==item['expected_ack_set_sha256'] and
             claim['target_item_id']==item['item_id'] and
             claim['target_slot_id']==item['slot_id'],
             'OLD_EC346_SIGNED_ACTOR_SOURCE_OR_SITE_BINDING_CHANGED','permission_denied')
        observations[ref['path']]=(ref['sha256'],claim)
        obs_by_receiver.setdefault(claim['receiver_id'],[]).append((ref,claim))
    need(set(obs_by_receiver)==set(latest) and all(
         events[-1][0]['path']==latest[actor][0] and
         events[-1][0]['sha256']==latest[actor][1] for actor,events in obs_by_receiver.items()),
         'ACTUAL_EC346_SIGNED_EVENT_HEAD_DIFFERENT_FROM_OLD_REPLAY','permission_denied')

    responses={};response_history={}
    for ref in row['ec347_signed_response_originals']:
        doc=_original(ref,'ec347_response',read);claim=doc.get('claim')
        need(type(claim) is dict and claim.get('receiver_id') in by_id,
             'EC347_RESPONSE_SIGNER_NOT_IN_OLD_AUTHENTIC_RECEIVER_ROSTER','permission_denied')
        actor=by_id[claim['receiver_id']]
        claim=_signed(doc,old347.R_FIELDS,old347.RESPONSE_SCHEMA,
                      old347.D_RESPONSE,actor['public_hex'],
                      'OLD_EC347_REGISTERED_RECEIVER_SIGNED_REPLY')
        challenge=challenges.get(claim['challenge_file'])
        need(challenge is not None and challenge[0]==claim['challenge_original_raw_sha256'] and
             challenge[1]['challenge_nonce_sha256']==claim['challenge_nonce_sha256'] and
             challenge[1]['round_number']==claim['round_number'] and
             actor['signer_id'] in challenge[1]['audience_receiver_ids'] and
             claim['receiver_public_hex']==actor['public_hex'] and
             claim['receiver_organization_id']==actor['organization_id'] and
             claim['ec346_latest_signed_event_original_raw_sha256']==latest[actor['signer_id']][1] and
             claim['ec346_audit_inputs_canonical_sha256']==context['ec346_audit_inputs_canonical_sha256'],
             'ACTUAL_EC347_ED25519_RESPONSE_NOT_BOUND_TO_AUTHENTIC_CHALLENGER_AND_EC346',
             'permission_denied')
        responses[ref['path']]=(ref['sha256'],claim)
        response_history.setdefault(actor['signer_id'],[]).append((ref,claim))
    latest_round=len(challenges)
    chosen={rid:entries[-1][1] for rid,entries in response_history.items()
            if entries[-1][1]['round_number']==latest_round}
    audience=next(reversed(challenges.values()))[1]['audience_receiver_ids']
    need(set(chosen)==set(audience) and
         len([c for c in responses.values() if c[1]['round_number']==latest_round])==len(audience),
         'LATEST_AUTHORIZED_EC347_RECEIVER_SIGNED_REPLY_CENSUS_INCOMPLETE',
         'permission_denied')

    sites=row['ec346_receiver_copy_site_originals']
    expected_order=[r['signer_id'] for r in present_receivers if r['signer_id'] in latest]
    need(type(sites) is list and len(sites)==len(expected_order) and
         all(type(s) is dict and set(s)==SITE_FIELDS for s in sites) and
         [s['receiver_id'] for s in sites]==expected_order,
         'EC346_REGISTERED_RECEIVER_SITE_CENSUS_AND_ORDER_REQUIRED','permission_denied')
    site_rows=[];count_retested=0;missing=False;disagree=False
    for site in sites:
        rid=site['receiver_id'];actor=by_id[rid]
        current=latest[rid];head=current[2]
        headref=site['ec346_latest_signed_observation_original']
        _ref(headref,current[0],current[1],'EC346_LATEST_ORIGINAL_SIGNED_HEAD')
        need(site['copy_id']==head['copy_id'] and
             site['claimed_storage_id']==head['claimed_storage_id'] and
             head['receiver_organization_id']==actor['organization_id'],
             'CLAIMED_SITE_LABEL_NOT_BOUND_TO_EC346_SIGNED_HEAD','permission_denied')
        keyref=site['receiver_public_key_original']
        exact(keyref,{'path','sha256'},'EC346_REGISTERED_RECEIVER_ORIGINAL_PUBLIC_KEY')
        raw=read(keyref,'ec346_receiver_public_key_'+rid+'_'+keyref['sha256'],32)
        need(len(raw)==32 and raw.hex()==actor['public_hex'] and
             raw.hex()!=proposer['public_hex'],
             'REAL_RECEIVER_PUBLIC_KEY_NOT_REGISTERED_OR_DISTINCT','permission_denied')
        reply=chosen.get(rid)
        if reply is None or reply['response_kind']!=old347.MEASURED:
            missing=True
        snapshot=site['explicit_copy_snapshot_original']
        ack=site['explicit_copy_ack_set_original']
        both=(snapshot is not None and ack is not None)
        need((snapshot is None and ack is None) or both,
             'LOCAL_EXPLICIT_REMEASURE_MUST_PRESENT_A_COMPLETE_COPY_PAIR',
             'permission_denied')
        # Only actually challenged measured receivers may present actual bytes.
        if reply is None or reply['response_kind']!=old347.MEASURED:
            need(not both,'UNCHALLENGED_OR_UNAVAILABLE_RECEIVER_COPY_NOT_TO_BE_OPENED',
                 'permission_denied')
        local_match=None;local_originals=None
        if reply is not None and reply['response_kind']==old347.MEASURED:
            need(reply['copy_id']==site['copy_id'] and
                 reply['claimed_storage_id']==site['claimed_storage_id'] and
                 reply['copy_snapshot_file']==head['copy_snapshot_file'] and
                 reply['copy_ack_set_file']==head['copy_ack_set_file'],
                 'LAST_SIGNED_READBACK_COPY_SITE_DIFFERS_FROM_EC346_OBSERVATION',
                 'permission_denied')
            if both:
                need(snapshot['path']==reply['copy_snapshot_file'] and
                     ack['path']==reply['copy_ack_set_file'] and
                     snapshot['path']!=ack['path'] and
                     snapshot['path'] not in forbidden and ack['path'] not in forbidden,
                     'EXPLICIT_LOCAL_COPY_PATH_MUST_MATCH_BOTH_OLD_SIGNED_ORIGINALS',
                     'permission_denied')
                actual=[]
                for ref,kind in ((snapshot,'snapshot'),(ack,'ack_set')):
                    exact(ref,{'path','sha256'},'EXPLICIT_EC346_'+kind.upper())
                    # The SHA pin belongs to the separate receiver archive.
                    # A changed *signed* copy is visible, not silently rewritten.
                    raw=read(ref,'ec346_local_retest_'+rid+'_'+kind,old346.MAX_COPY_BYTES)
                    need(len(raw)>0,'LOCAL_EC346_COPY_MUST_BE_NONEMPTY','permission_denied')
                    actual.append((sha(raw),len(raw)))
                local_originals=[snapshot['sha256'],ack['sha256']]
                local_match=(actual[0]==(reply['copy_snapshot_original_raw_sha256'],
                                        reply['copy_snapshot_byte_length']) and
                             actual[1]==(reply['copy_ack_set_original_raw_sha256'],
                                        reply['copy_ack_set_byte_length']) and
                             actual[0]==(head['copy_snapshot_original_raw_sha256'],
                                        head['copy_snapshot_byte_length']) and
                             actual[1]==(head['copy_ack_set_original_raw_sha256'],
                                        head['copy_ack_set_byte_length']) and
                             actual[0][0]==item['expected_snapshot_sha256'] and
                             actual[1][0]==item['expected_ack_set_sha256'])
                count_retested+=1;disagree|=not local_match
            else:
                missing=True
        site_rows.append({'receiver_id':rid,'receiver_public_key_sha256':keyref['sha256'],
              'registered_organization_id':actor['organization_id'],
              'claimed_storage_id':site['claimed_storage_id'],
              'copy_id':site['copy_id'],'ec346_signed_head_original_sha256':headref['sha256'],
              'ec346_observation_signed_sequence':head['sequence'],
              'ec346_signed_event_kind':head['event_kind'],
              'ec347_last_signed_response_sha256':(response_history[rid][-1][0]['sha256']
                                                  if rid in response_history else None),
              'ec347_last_response_kind':reply['response_kind'] if reply else None,
              'ec346_actual_explicit_local_snapshot_ack_original_shas':local_originals,
              'actual_local_bytes_match_ec346_ec347_and_original_source':local_match})
    return {'tsa_channel_id':channel,'full_original_signed_ec347_challenger_receiver_replay':True,
            'original_ec346_authorized_signed_observation_count':len(observations),
            'genuine_ec347_registered_receiver_count':len(audience),
            'actual_original_copy_byte_retest_count':count_retested,
            'all_presented_signed_copy_bytes_match':not disagree and count_retested>0,
            'incomplete_explicit_copy_retest':missing or count_retested==0,
            'signed_site_or_readback_adverse':disagree or any(
                s['ec346_signed_event_kind']==old346.REVOCATION for s in site_rows),
            'challenger_public_key_sha256':proposer_key['sha256'],
            'ec343_roster_original_sha256':roster_ref['sha256'],
            'ec346_source_snapshot_sha256':item['expected_snapshot_sha256'],
            'ec346_source_ack_set_sha256':item['expected_ack_set_sha256'],
            'ec347_challenge_original_shas':[r['sha256'] for r in row['ec347_signed_challenge_originals']],
            'ec347_response_original_shas':[r['sha256'] for r in row['ec347_signed_response_originals']],
            'ec346_observation_original_shas':[r['sha256'] for r in row['ec346_signed_observation_originals']],
            'receiver_site_evidence':site_rows}


def _engine(derive,**opts):
    parent_opts=_inputs(opts,derive)
    parent=previous.audit(**parent_opts)   # mandatory genuine EC382 -> EC369
    n=len(opts['historical_directory_root_shas'])
    parent_sha=_parent(parent,n)
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC383_'+role)
        path=ref['path']
        if path in cache:
            oldsha,raw,oldrole=cache[path]
            need(path not in forbidden and oldsha==ref['sha256'] and oldrole==role and
                 len(raw)<=cap,'ORIGINAL_ALIAS_SHA_OR_AUTHORIZATION_ROLE_CONFLICT',
                 'permission_denied')
            return raw
        raw=p372._read(ref,'ec383_'+role,cap,pins,categories,forbidden)
        cache[path]=(ref['sha256'],raw,role)
        return raw
    ref382={'path':opts['historical_ec348_keeper_archive_bundle_file'],
            'sha256':opts['expected_historical_ec348_keeper_archive_bundle_sha256']}
    original382=old353.strict_json(read(ref382,'real_ec382_receiver_archive',previous.MAX_BUNDLE),
                                    'EC383_ACTUAL_PARENT_RECEIVER_ORIGINAL')
    exact(original382,previous.BUNDLE_FIELDS,'REAL_EC382_RECEIVER_ARCHIVE')
    need(original382['schema']==previous.BUNDLE_SCHEMA and
         len(original382['epochs'])==n and
         original382['claimed_directory_lineage_id']==opts['claimed_historical_directory_lineage_id'],
         'RECEIVER_EC382_ORIGINAL_NOT_THE_REAL_LIVE_PARENT','permission_denied')
    ref383={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=old353.strict_json(read(ref383,'receiver_ec383_site_archive',MAX_BUNDLE),
                              'EC383_SIGNED_SITE_PROVENANCE_ARCHIVE')
    exact(bundle,BUNDLE_FIELDS,'EC383_ORIGINAL_ARCHIVE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['parent_ec382_canonical_result_sha256']==parent_sha and
         bundle['ec382_historical_keeper_archive_original_sha256']==ref382['sha256'] and
         bundle['claimed_directory_lineage_id']==original382['claimed_directory_lineage_id'] and
         len(bundle['epochs'])==n,
         'ORIGINAL_EC383_SOURCE_NOT_BOUND_TO_LIVE_EC382_ORIGIN',
         'permission_denied')
    # Exactly the same hard sender-source deny boundary as EC382. Signed
    # ancient sender-origin labels are not receiver-readable copy evidence.
    parent377={'path':opts['historical_transparency_archive_bundle_file'],
               'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    old377=old353.strict_json(read(parent377,'verified_ec377_original',
        previous.previous.p379.p377.MAX_BUNDLE),'EC383_REAL_EC377_PARENT')
    exact(old377,previous.previous.p379.p377.BUNDLE_FIELDS,
          'EC383_AUTHENTIC_EC377_PARENT')
    need(old377['schema']==previous.previous.p379.p377.BUNDLE_SCHEMA and
         len(old377['epochs'])==n,'EC383_EC377_REAL_SENDER_LABEL_SOURCE_CHANGED',
         'permission_denied')
    for ep in old377['epochs']:
        sender=old353.strict_json(read(ep['ec353_publication_bundle_original'],
             'old_ec353_sender_labels_'+ep['ec353_publication_bundle_original']['sha256'],
             old353.MAX_BUNDLE),'EC383_OLD_EC353_SENDER_LABELS')
        previous.previous.p379._old_sender_labels(sender,forbidden)
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=not parent['local_recovered_keeper_readback_original_binding_consistent']
    rows=[];inventories=[];previous_sites={};total_obs=total_receivers=total_retests=0
    for idx,(epoch,older) in enumerate(zip(bundle['epochs'],original382['epochs'],strict=True)):
        exact(epoch,EPOCH_FIELDS,'EC383_EPOCH')
        exact(older,previous.EPOCH_FIELDS,'EC383_ACTUAL_OLD_EC382_EPOCH')
        need(epoch['epoch_index']==older['epoch_index']==idx and
             type(epoch['channels']) is list and type(older['channels']) is list and
             len(epoch['channels'])==len(older['channels'])<=old349.MAX_CHANNELS,
             'REAL_EC382_CHANNEL_EPOCH_AND_COUNT_MUST_BE_IDENTICAL',
             'permission_denied')
        ids=[r.get('tsa_channel_id') for r in epoch['channels'] if type(r) is dict]
        oldids=[r['tsa_channel_id'] for r in older['channels']]
        need(len(ids)==len(epoch['channels']) and ids==oldids==sorted(set(ids)),
             'EC383_AUTHENTIC_EC382_CHANNEL_IDENTITIES_AND_ORDER_REQUIRED',
             'permission_denied')
        results=[]
        for row,oldrow in zip(epoch['channels'],older['channels'],strict=True):
            result=_channel(row,oldrow,read,forbidden)
            results.append(result)
            flags[FLAGS[2]]|=not result['full_original_signed_ec347_challenger_receiver_replay']
            flags[FLAGS[3]]|=(result['genuine_ec347_registered_receiver_count']==0)
            flags[FLAGS[4]]|=(result['original_ec346_authorized_signed_observation_count']==0 or
                              result['signed_site_or_readback_adverse'])
            flags[FLAGS[5]]|=(result['incomplete_explicit_copy_retest'] or
                              not result['all_presented_signed_copy_bytes_match'])
            if result['full_original_signed_ec347_challenger_receiver_replay']:
                previous_result=previous_sites.get(result['tsa_channel_id'])
                if previous_result is not None:
                    old_site={s['receiver_id']:s for s in previous_result['receiver_site_evidence']}
                    new_site={s['receiver_id']:s for s in result['receiver_site_evidence']}
                    flags[FLAGS[6]]|=(previous_result['ec343_roster_original_sha256']!=
                                      result['ec343_roster_original_sha256'] or
                        previous_result['challenger_public_key_sha256']!=
                                      result['challenger_public_key_sha256'] or
                        previous_result['ec346_source_snapshot_sha256']!=
                                      result['ec346_source_snapshot_sha256'] or
                        previous_result['ec346_source_ack_set_sha256']!=
                                      result['ec346_source_ack_set_sha256'] or
                        not set(old_site).issubset(new_site) or
                        any(old_site[k]['ec346_signed_head_original_sha256']!=
                            new_site[k]['ec346_signed_head_original_sha256'] and
                            old_site[k]['ec346_observation_signed_sequence']>=
                            new_site[k]['ec346_observation_signed_sequence']
                            for k in set(old_site)&set(new_site)))
                previous_sites[result['tsa_channel_id']]=result
        # Both historical EC349 channels in one epoch must have exactly one
        # EC347 challenger/receiver roster, source and signed EC346 history.
        if len(results)==2:
            compared=('ec343_roster_original_sha256','challenger_public_key_sha256',
                      'ec346_source_snapshot_sha256','ec346_source_ack_set_sha256',
                      'ec347_challenge_original_shas','ec347_response_original_shas',
                      'ec346_observation_original_shas','receiver_site_evidence')
            flags[FLAGS[6]]|=any(results[0][k]!=results[1][k] for k in compared)
        countreceivers=sum(r['genuine_ec347_registered_receiver_count'] for r in results)
        countobs=sum(r['original_ec346_authorized_signed_observation_count'] for r in results)
        countretests=sum(r['actual_original_copy_byte_retest_count'] for r in results)
        total_receivers+=countreceivers;total_obs+=countobs;total_retests+=countretests
        actors=[{k:r[k] for k in ('tsa_channel_id','challenger_public_key_sha256',
                'ec343_roster_original_sha256','ec347_challenge_original_shas',
                'ec347_response_original_shas','genuine_ec347_registered_receiver_count',
                'receiver_site_evidence')} for r in results]
        sites=[{k:r[k] for k in ('tsa_channel_id','ec346_source_snapshot_sha256',
                'ec346_source_ack_set_sha256','ec346_observation_original_shas',
                'receiver_site_evidence','actual_original_copy_byte_retest_count',
                'all_presented_signed_copy_bytes_match')} for r in results]
        actorsha=sha(canonical.canonical(actors));sitesha=sha(canonical.canonical(sites))
        flags[FLAGS[1]]|=(actorsha!=opts['historical_ec347_actor_authorization_inventory_shas'][idx] or
           sitesha!=opts['historical_ec346_copy_site_inventory_shas'][idx] or
           countreceivers<opts['minimum_historical_ec347_authorized_receiver_counts'][idx] or
           countobs<opts['minimum_historical_ec346_signed_observation_counts'][idx] or
           countretests<opts['minimum_historical_ec346_byte_retested_copy_counts'][idx])
        rows.append({'epoch_index':idx,'verified_ec347_challenged_receiver_count':countreceivers,
                     'verified_ec346_signed_observation_original_count':countobs,
                     'explicit_current_copy_pair_local_retest_count':countretests,
                     'missing_true_old_ec346_signed_source_count':sum(
                         not r['full_original_signed_ec347_challenger_receiver_replay'] for r in results),
                     'ec347_challenger_actor_original_inventory_sha256':actorsha,
                     'ec346_signed_site_and_retested_byte_inventory_sha256':sitesha,
                     'local_original_signed_ec347_authority_ec346_site_consistent':
                          bool(results) and all(r['full_original_signed_ec347_challenger_receiver_replay'] and
                             r['all_presented_signed_copy_bytes_match'] and
                             not r['incomplete_explicit_copy_retest'] and
                             not r['signed_site_or_readback_adverse'] for r in results)})
        inventories.append({'epoch_index':idx,
             'registered_signed_challenger_and_receiver_actor_originals':actors,
             'ec346_signed_source_and_explicit_copy_site_originals':sites,
             'ec347_authorized_actor_inventory_sha256':actorsha,
             'ec346_signed_site_inventory_sha256':sitesha})
    p372.prior.lineage.parent.ref_check(ref382,'EC383_FINAL_PARENT_REF')
    p372.prior.lineage.parent.ref_check(ref383,'EC383_FINAL_ARCHIVE_REF')
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inventory={'schema':INVENTORY_SCHEMA,
       'live_ec382_through_ec369_parent_result_canonical_sha256':parent_sha,
       'authenticated_ec382_keeper_archive_original_sha256':ref382['sha256'],
       'receiver_ec383_site_provenance_original_sha256':ref383['sha256'],
       'claimed_directory_lineage_id':bundle['claimed_directory_lineage_id'],
       'historical_ec347_challenger_ec346_copy_site_epoch_reviews':inventories}
    invsha=sha(canonical.canonical(inventory))
    if not derive and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec347-site-provenance-inventory' if derive else
                 'audit-historical-ec347-site-provenance-archive',
       'status':next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),
                     OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_parent_ec382_canonical_result_sha256':parent_sha,
       'historical_ec347_site_archive_bundle_original_sha256':ref383['sha256'],
       'receiver_verified_historical_ec347_site_inventory_sha256':invsha,
       'genuine_old_ec347_authorized_receiver_count':total_receivers,
       'genuine_old_ec346_signed_observation_original_count':total_obs,
       'genuine_old_ec346_current_copy_local_retest_count':total_retests,
       'historical_ec347_site_epoch_reviews':rows,
       'local_ec347_challenger_receiver_ec346_signed_source_originals_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec346_through_ec337_full_independent_original_historical_acceptance_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_verified_historical_ec347_site_provenance_inventory':inventory,
           'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
