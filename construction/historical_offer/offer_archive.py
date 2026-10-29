#!/usr/bin/env python3
"""EC384 original EC344 signed receiver views and EC345 signed disclosure offers.

Receiver-held, SHA-pinned *actual original* verification, strictly underneath
live EC383 -> EC369.  EC344 directory and checkpoint are unsigned assertions;
only an authorized EC344 receiver view is signed.  EC345 proposer requests
and registered receiver offers are signed, but physical delivery is not.
"""
from __future__ import annotations

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from offline_authority import authority as clock
from hold_receipts import timeline as old343
from receiver_visibility import visibility as old344
from disclosure_challenge import challenge as old345
from disclosure_custody import custody as old346
from dual_channel_anchor import anchor as old349
from transparency import transparency as old353
from historical_authority import authority_archive as p372
from historical_disclosure import disclosure_archive as p376
from historical_readback import readback_archive as parent

RESULT_SCHEMA='ces.ec384.receiver_original_ec344_view_ec345_authorized_disclosure_unresolved.v1'
DERIVE_SCHEMA='ces.ec384.unsigned_original_ec344_view_ec345_disclosure_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec384.receiver_original_ec344_view_ec345_disclosure_denial.v1'
BUNDLE_SCHEMA='ces.ec384.receiver_historic_ec344_view_ec345_signed_offer_archive.v1'
INVENTORY_SCHEMA='ces.ec384.receiver_verified_historic_visibility_offer_inventory.v1'
MAX_BUNDLE=170_000
MAX_ORIGINAL=300_000
NEW_SCALARS=('historical_ec345_disclosure_archive_bundle_file',
             'expected_historical_ec345_disclosure_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_ec345_disclosure_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec344_signed_visibility_inventory_shas','--historical-ec344-signed-visibility-inventory-sha256'),
 ('historical_ec345_authorized_offer_inventory_shas','--historical-ec345-authorized-offer-inventory-sha256'),
 ('minimum_historical_ec344_signed_visibility_counts','--minimum-historical-ec344-signed-visibility-count'),
 ('minimum_historical_ec345_signed_challenge_counts','--minimum-historical-ec345-signed-challenge-count'),
 ('minimum_historical_ec345_signed_offer_counts','--minimum-historical-ec345-signed-offer-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec383_canonical_result_sha256',
               'ec383_historical_site_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={'tsa_channel_id','ec345_disclosure_issuer_public_key_original',
                'ec344_ec345_registered_receiver_keys_originals',
                'ec344_signed_visibility_originals',
                'ec345_signed_challenge_originals',
                'ec345_signed_response_originals'}
RECEIVER_KEY_FIELDS={'receiver_id','receiver_public_key_original'}
FLAGS=(
 'inherited_live_ec383_through_ec369_signed_original_dispute',
 'outside_retained_ec344_visibility_or_ec345_offer_inventory_floor_disagrees',
 'old_ec344_ec345_full_original_source_or_publication_checkpoint_missing',
 'old_ec344_signed_receiver_visibility_authority_incomplete',
 'old_ec345_proposer_challenge_authority_or_predecessor_incomplete',
 'old_ec345_registered_receiver_signed_disclosure_offer_missing_or_conflicting',
 'old_ec344_ec345_signed_source_cross_channel_or_epoch_rollback',
 'full_unmocked_old_ec345_through_ec337_external_original_chain_unavailable',
 'unsigned_checkpoint_physical_delivery_independent_identity_and_trusted_utc_unproven',
)
OUTCOMES=(
 'ec384_inherited_original_signed_receiver_parent_dispute',
 'ec384_outside_retained_signed_visibility_offer_inventory_floor_disagrees',
 'ec384_original_old_ec344_ec345_publication_or_source_missing',
 'ec384_old_ec344_signed_registered_receiver_views_incomplete',
 'ec384_old_ec345_proposer_signed_challenge_or_predecessor_incomplete',
 'ec384_old_ec345_signed_receivers_offer_conflict_or_missing',
 'ec384_original_ec344_ec345_signed_source_channel_or_epoch_rollback',
 'ec384_old_ec345_through_ec337_independent_history_incomplete',
 'ec384_unsigned_checkpoint_physical_transfer_or_trusted_utc_unproven',
)
NEGATIVES=(
 'unsigned_ec344_directory_or_checkpoint_is_a_signed_publication_authorization',
 'signed_ec344_view_proves_original_physically_delivered_or_globally_visible',
 'ec345_proposer_challenge_is_a_signed_receiver_offer',
 'ec345_receiver_offer_proves_physical_custody_or_complete_delivery',
 'signed_utc_claim_is_calibrated_trusted_time',
 'visible_signed_views_exclude_all_hidden_publication_forks',
 'caller_supplied_retained_sha_was_independently_archived_by_this_software',
 'new_receiver_public_key_overrides_old_ec343_roster_authority',
 'new_source_reference_replaces_original_ec346_or_ec383_verified_source',
 'ec353_sender_labels_are_original_receiver_paths',
 'missing_old_source_is_replaced_by_generated_keys_or_mock_proof',
 'private_signers_network_provider_cas_worm_or_native_ps_invoked',
 'inherited_ec366_to_ec337_mock_removed_or_final_acceptance_granted',
)


def need(v,code,status='invalid_input'):
    if v is not True:raise errors.AnchorError('EC384_'+code,status)


def exact(obj,keys,code):
    need(type(obj) is dict and set(obj)==set(keys),code+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    required=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_LIVE_PARENT_AND_EC384_ARGUMENTS_REQUIRED')
    popts={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(popts,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC384_RECEIVER_SIGNED_VISIBILITY_OFFER_ARCHIVE')
    if not derive:need(old353._sha(opts[AUDIT_ONLY[0]]),'RETAINED_EC384_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORICAL_EPOCH_BOUNDS')
    for key in REPEAT_NAMES:
        vals=opts[key]
        need(type(vals) is list and len(vals)==n,'ONE_FLOOR_PER_EPOCH_'+key.upper())
        if key.startswith('minimum_'):
            cap=(old349.MAX_CHANNELS*old344.MAX_VIEWS if 'visibility' in key
                 else old349.MAX_CHANNELS*old345.MAX_CHALLENGES if 'challenge' in key
                 else old349.MAX_CHANNELS*old345.MAX_RESPONSES)
            need(all(type(x) is int and 0<=x<=cap for x in vals),
                 'BOUNDED_EC384_SIGNED_COUNT_FLOOR_'+key.upper())
        else:need(all(old353._sha(x) for x in vals),
                  'EXACT_EC384_OUTSIDE_SHA_FLOOR_'+key.upper())
    return popts


def _parent(result,n):
    need(type(result) is dict and result.get('schema')==parent.RESULT_SCHEMA and
         result.get('exit_code')==2 and
         result.get('sender_origin_path_required_or_read') is False and
         result.get('ec346_through_ec337_full_independent_original_historical_acceptance_performed') is False and
         type(result.get('historical_ec347_site_epoch_reviews')) is list and
         len(result['historical_ec347_site_epoch_reviews'])==n,
         'LIVE_EC383_THROUGH_EC369_ORIGINAL_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(result))


def _ref(ref,path,digest,role):parent._ref(ref,path,digest,'EC384_'+role)


def _signed(doc,fields,schema,domain,pub,role):
    exact(doc,{'schema','claim','signature_ed25519'},role+'_SIGNED_DOCUMENT')
    exact(doc['claim'],fields,role+'_SIGNED_CLAIM')
    need(doc['schema']==schema,role+'_SCHEMA','permission_denied')
    old343._signed(doc,schema,domain,pub,'EC384_'+role)
    return doc['claim']


def _original(ref,read,role):
    return parent.previous._json_original(
        read(ref,role+'_'+ref['sha256'],MAX_ORIGINAL),'EC384_'+role)


def _missing(channel):
    return {'tsa_channel_id':channel,'full_original_ec344_ec345_source_replay':False,
      'ec343_roster_original_sha256':None,'ec344_directory_original_sha256':None,
      'ec344_checkpoint_original_sha256':None,'ec345_proposer_key_original_sha256':None,
      'verified_ec345_source_snapshot_sha256':None,'verified_ec345_source_ack_sha256':None,
      'verified_target_item_id':None,'signed_ec344_view_original_shas':[],
      'signed_ec345_challenge_original_shas':[],'signed_ec345_response_original_shas':[],
      'signed_ec344_registered_view_count':0,'signed_ec345_authorized_challenge_count':0,
      'signed_ec345_registered_receiver_offer_count':0,
      'receiver_key_original_shas':[],'signed_view_claim_conflict':False,
      'signed_offer_claim_conflict_or_missing':True,'signed_ec345_predecessor_incomplete':True,
      'verified_disclosed_target_has_signed_offer':False}


def _channel(row,oldrow,older382,read,forbidden):
    """Reopen every old original under its actual SHA and legacy signing domain."""
    exact(row,CHANNEL_FIELDS,'ORIGINAL_CHANNEL')
    need(row['tsa_channel_id']==oldrow['tsa_channel_id']==older382['tsa_channel_id'],
         'SOURCE_CHANNEL_NOT_IN_LIVE_EC383_OR_EC382','permission_denied')
    channel=row['tsa_channel_id']
    ref348=older382['ec348_full_replay_inputs_original']
    if ref348 is None:
        need(row['ec345_disclosure_issuer_public_key_original'] is None and
             all(row[k]==[] for k in CHANNEL_FIELDS if k not in (
                 'tsa_channel_id','ec345_disclosure_issuer_public_key_original')),
             'MISSING_AUTHENTIC_OLD_SOURCE_CANNOT_ACCEPT_NEW_UNVERIFIED_ORIGINALS',
             'permission_denied')
        return _missing(channel)
    # The genuine prior original replay re-opens historic EC349->EC348->EC347
    # ->EC346->EC345->EC344->EC343 and older originals. No audit report proxy.
    ctx=parent.previous.previous._ec348_original(ref348,read,forbidden)
    src=ctx['inputs'];target=src['item_id']
    for field,path,digest in (
        ('ec343_authority_roster_original',src['roster_file'],src['expected_roster_sha256']),
        ('ec344_receiver_directory_original',src['directory_file'],src['expected_directory_sha256']),
        ('ec344_source_checkpoint_original',src['checkpoint_file'],src['expected_checkpoint_sha256'])):
        _ref(oldrow[field],path,digest,'EC383_BOUND_'+field.upper())
    proposer_ref=row['ec345_disclosure_issuer_public_key_original']
    _ref(proposer_ref,oldrow['ec347_challenger_public_key_original']['path'],
         oldrow['ec347_challenger_public_key_original']['sha256'],
         'AUTHENTIC_EC383_PROPOSER_ORIGINAL')
    roster=_original(oldrow['ec343_authority_roster_original'],read,'ec343_roster')
    directory=_original(oldrow['ec344_receiver_directory_original'],read,'ec344_directory')
    checkpoint=_original(oldrow['ec344_source_checkpoint_original'],read,'ec344_checkpoint')
    exact(directory,old344.DIRECTORY_FIELDS,'ORIGINAL_EC344_DIRECTORY')
    exact(checkpoint,old344.CHECKPOINT_FIELDS,'ORIGINAL_EC344_CHECKPOINT')
    need(roster.get('case_id')==directory.get('case_id')==checkpoint.get('case_id') and
         directory['schema']==old344.DIRECTORY_SCHEMA and
         checkpoint['schema']==old344.CHECKPOINT_SCHEMA and
         directory['ec343_roster_original_raw_sha256']==src['expected_roster_sha256'] and
         checkpoint['ec343_roster_original_raw_sha256']==src['expected_roster_sha256'] and
         checkpoint['directory_original_raw_sha256']==src['expected_directory_sha256'] and
         directory['round_nonce_sha256']==checkpoint['round_nonce_sha256'] and
         directory['not_a_global_or_authoritative_recipient_registry'] is True and
         checkpoint['not_a_global_or_complete_fork_inventory'] is True,
         'OLD_EC344_UNSIGNED_CHECKPOINT_OR_DIRECTORY_SOURCE_DIFFERENCE',
         'permission_denied')
    old344._validate_announcements(checkpoint['announcements'])
    need(type(roster.get('receivers')) is list and
         2<=len(roster['receivers'])<=old343.MAX_RECEIVERS and
         type(directory['receivers']) is list and
         [a['signer_id'] for a in directory['receivers']]==[a['signer_id'] for a in roster['receivers']] and
         directory['receivers']==roster['receivers'],
         'EC344_REGISTERED_RECEIVER_DIRECTORY_MUST_MATCH_SOURCE_ROSTER',
         'permission_denied')
    byactor={a['signer_id']:a for a in roster['receivers']}
    proposer=roster['change_proposer']
    raw=read(proposer_ref,'ec345_proposer_original_key_'+proposer_ref['sha256'],32)
    need(len(raw)==32 and raw.hex()==proposer['public_hex'] and
         all(proposer[k] not in {a[k] for a in roster['receivers']}
             for k in ('public_hex','signer_id','organization_id')),
         'EC345_PROPOSER_ORIGINAL_KEY_NOT_AUTHORIZED_OR_ROLE_DISTINCT',
         'permission_denied')
    keyrows=row['ec344_ec345_registered_receiver_keys_originals']
    need(type(keyrows) is list and len(keyrows)==len(byactor) and
         all(type(x) is dict and set(x)==RECEIVER_KEY_FIELDS for x in keyrows) and
         [x['receiver_id'] for x in keyrows]==list(byactor),
         'AUTHENTIC_EC344_EC345_REGISTERED_RECEIVER_KEY_CENSUS_AND_ORDER',
         'permission_denied')
    oldsites={s['receiver_id']:s for s in oldrow['ec346_receiver_copy_site_originals']}
    keyshas=[]
    for krow in keyrows:
        actor=byactor[krow['receiver_id']];ref=krow['receiver_public_key_original']
        if actor['signer_id'] in oldsites:
            _ref(ref,oldsites[actor['signer_id']]['receiver_public_key_original']['path'],
                 oldsites[actor['signer_id']]['receiver_public_key_original']['sha256'],
                 'MUST_REUSE_AUTHENTIC_EC383_REGISTERED_RECEIVER_KEY')
        original=read(ref,'ec344_ec345_receiver_key_'+actor['signer_id']+'_'+ref['sha256'],32)
        need(len(original)==32 and original.hex()==actor['public_hex'] and
             original.hex()!=proposer['public_hex'],
             'REAL_EC344_EC345_ORIGINAL_RECEIVER_PUBLIC_KEY_NOT_REGISTERED',
             'permission_denied')
        keyshas.append(ref['sha256'])
    byid={item['item_id']:item for item in checkpoint['announcements']}
    need(target in byid and target in src['disclosed_item_ids'] and
         target not in src['presented_item_ids'] and
         src['anchor_item_id'] in src['presented_item_ids'] and
         src['disclosed_item_ids']==[x for x in byid if x in src['disclosed_item_ids']],
         'EC345_DISCLOSURE_TARGET_NOT_IN_AUTHENTIC_EC344_CHECKPOINT_AND_BASELINE',
         'permission_denied')
    item=byid[target]
    for field,path,digest in (
        ('ec345_verified_source_snapshot_original',item['snapshot_file'],item['expected_snapshot_sha256']),
        ('ec345_verified_source_ack_set_original',item['ack_set_file'],item['expected_ack_set_sha256'])):
        _ref(oldrow[field],path,digest,'EC383_VERIFIED_EC345_SOURCE')
    for field,paths,shas,kind in (
        ('ec344_signed_visibility_originals',src['view_files'],src['view_shas'],'ec344_view'),
        ('ec345_signed_challenge_originals',src['challenge_files'],src['challenge_shas'],'ec345_challenge'),
        ('ec345_signed_response_originals',src['response_files'],src['response_shas'],'ec345_response')):
        refs=row[field]
        need(type(refs) is list and len(refs)==len(paths)==len(shas) and
             len(set(paths))==len(paths),
             'OLD_ORIGINAL_SIGNED_CENSUS_ORDER_MUST_MATCH_REPLAY_'+field.upper(),
             'permission_denied')
        for ref,path,digest in zip(refs,paths,shas,strict=True):
            _ref(ref,path,digest,'SOURCE_'+kind.upper())
    # EC344 checkpoint is NOT signed. These Ed25519 statements are the
    # separately authenticated historical publication-view evidence.
    signed_views={};nonces=set();view_claims=[]
    for ref in row['ec344_signed_visibility_originals']:
        doc=_original(ref,read,'ec344_view')
        claim=doc.get('claim');need(type(claim) is dict and
             claim.get('receiver_id') in byactor,
             'EC344_SIGNED_VIEW_SIGNER_NOT_IN_EC343_ROSTER','permission_denied')
        actor=byactor[claim['receiver_id']]
        claim=_signed(doc,old344.VIEW_CLAIM_FIELDS,old344.VIEW_SCHEMA,
                      old344.DOMAIN,actor['public_hex'],'REGISTERED_EC344_SIGNED_VIEW')
        observed=claim['observed_announcements']
        need(type(observed) is list and
             all(type(v) is dict and set(v)==old344.OBS_FIELDS for v in observed),
             'SIGNED_EC344_VIEW_EXACT_OBSERVATION_CENSUS','permission_denied')
        expected=old344._view_claim(roster,src['expected_roster_sha256'],
            src['expected_directory_sha256'],src['expected_checkpoint_sha256'],
            checkpoint,actor,[v['item_id'] for v in observed],
            claim['view_nonce_sha256'],claim['reported_utc'])
        need(claim==expected and
             clock._time(claim['reported_utc'])<=clock._time(src['timeline_evaluation_utc']) and
             claim['view_nonce_sha256'] not in nonces,
             'ORIGINAL_EC344_SIGNED_VIEW_SOURCE_TIME_NONCE_OR_ROLE_DISAGREES',
             'permission_denied')
        nonces.add(claim['view_nonce_sha256'])
        views=signed_views.setdefault(actor['signer_id'],[])
        need(len(views)<old344.MAX_PER_RECEIVER,
             'TOO_MANY_SIGNED_EC344_VIEWS_PER_RECEIVER','permission_denied')
        views.append(ref['sha256']);view_claims.append(claim)
    need(len(signed_views)>=2,'TWO_INDEPENDENT_REGISTERED_RECEIVER_SIGNED_VIEWS_REQUIRED',
         'permission_denied')
    # Verified view claims may differ; do not quietly turn divergence into
    # independently established publication availability.
    view_sets={rid:{tuple(o['item_id'] for o in v['observed_announcements'])
                    for v in view_claims if v['receiver_id']==rid}
               for rid in signed_views}
    conflict=any(len(v)>1 for v in view_sets.values()) or len({tuple(sorted(v))
        for v in view_sets.values()})>1
    signed_challenges=[];by_challenge={};last={};nonce_set=set(nonces)
    for ref in row['ec345_signed_challenge_originals']:
        claim=_signed(_original(ref,read,'ec345_challenge'),old345.CHALLENGE_FIELDS,
            old345.CHALLENGE_SCHEMA,old345.CHALLENGE_DOMAIN,proposer['public_hex'],
            'AUTHORIZED_EC345_ISSUER_SIGNED_CHALLENGE')
        expected=old345._challenge_claim(r=roster,roster_sha=src['expected_roster_sha256'],
            d=directory,directory_sha=src['expected_directory_sha256'],
            c=checkpoint,checkpoint_sha=src['expected_checkpoint_sha256'],
            item_id=claim['target_item_id'],anchor_item_id=src['anchor_item_id'],
            baseline_presented_item_ids=src['presented_item_ids'],view_shas=src['view_shas'],
            audience_receiver_ids=claim['audience_receiver_ids'],
            attempt_number=claim['attempt_number'],
            previous_challenge_file=claim['previous_challenge_file'],
            previous_challenge_sha=claim['previous_challenge_original_raw_sha256'],
            challenge_nonce_sha256=claim['challenge_nonce_sha256'],
            issued_utc=claim['issued_utc'])
        prior=last.get(claim['target_item_id'])
        need(claim==expected and
             (prior is None and claim['attempt_number']==1 and
               claim['previous_challenge_file'] is None and
               claim['previous_challenge_original_raw_sha256'] is None or
              prior is not None and claim['attempt_number']==prior[1]['attempt_number']+1 and
               claim['previous_challenge_file']==prior[0]['path'] and
               claim['previous_challenge_original_raw_sha256']==prior[0]['sha256']) and
             claim['challenge_nonce_sha256'] not in nonce_set and
             clock._time(src['timeline_evaluation_utc'])<=clock._time(claim['issued_utc'])<=
                 clock._time(src['disclosure_evaluation_utc']),
             'EC345_SIGNED_CHALLENGE_PREDECESSOR_SCOPE_TIME_OR_NONCE_INVALID',
             'permission_denied')
        if prior is not None:
            old345._next_attempt_consistent(prior[1],claim)
        nonce_set.add(claim['challenge_nonce_sha256'])
        signed_challenges.append((ref,claim));by_challenge[ref['sha256']]=claim
        last[claim['target_item_id']]=(ref,claim)
    order=[(list(byid).index(c['target_item_id']),c['attempt_number'])
           for _,c in signed_challenges]
    need(order==sorted(set(order)) and 1<=len(signed_challenges)<=old345.MAX_CHALLENGES,
         'SIGNED_EC345_CHALLENGE_CANONICAL_ITEM_AND_ATTEMPT_ORDER_REQUIRED',
         'permission_denied')
    responses=[];offer_count=0;offer_for_target=False;conflicting=False;responded={};seq=[]
    for ref in row['ec345_signed_response_originals']:
        doc=_original(ref,read,'ec345_response');claim=doc.get('claim')
        need(type(claim) is dict and claim.get('receiver_id') in byactor,
             'EC345_SIGNED_RESPONSE_RECEIVER_NOT_REGISTERED','permission_denied')
        actor=byactor[claim['receiver_id']]
        challenge=by_challenge.get(claim.get('challenge_original_raw_sha256'))
        need(challenge is not None,'EC345_SIGNED_RESPONSE_UNAUTHENTIC_CHALLENGE_SHA',
             'permission_denied')
        claim=_signed(doc,old345.RESPONSE_FIELDS,old345.RESPONSE_SCHEMA,
            old345.RESPONSE_DOMAIN,actor['public_hex'],'REGISTERED_EC345_SIGNED_RESPONSE')
        expected=old345._response_claim(roster,src['expected_roster_sha256'],
              claim['challenge_original_raw_sha256'],challenge,actor,
              claim['response_kind'],claim['response_nonce_sha256'],claim['reported_utc'])
        parentidx=next(i for i,(r,_) in enumerate(signed_challenges)
                       if r['sha256']==claim['challenge_original_raw_sha256'])
        pair=(parentidx,challenge['audience_receiver_ids'].index(actor['signer_id']))
        need(claim==expected and claim['response_nonce_sha256'] not in nonce_set and
             pair not in responded and
             clock._time(claim['reported_utc'])<=clock._time(src['disclosure_evaluation_utc']),
             'EC345_SIGNED_RESPONSE_SCOPE_TIME_DUPLICATE_OR_NONCE_INVALID',
             'permission_denied')
        nonce_set.add(claim['response_nonce_sha256']);responded[pair]=True;seq.append(pair)
        responses.append((ref,claim))
        if claim['response_kind']==old345.OFFER:
            offer_count+=1
            offer_for_target|=challenge['target_item_id']==target
    need(seq==sorted(seq),'EC345_SIGNED_RESPONSE_CHALLENGE_AUDIENCE_ORDER_REQUIRED',
         'permission_denied')
    needs=[c for _,c in signed_challenges if c['target_item_id']==target]
    # A genuine signed `unavailable_claim` (or an unanswered challenge) is
    # adverse *evidence*, not a malformed signature. Surface a missing offer
    # as explicitly unresolved instead of incorrectly issuing permission_denied.
    need(len(needs)>0,'ORIGINAL_EC345_CHALLENGE_MUST_NAME_VERIFIED_SOURCE',
         'permission_denied')
    conflicting=any(any(c['response_kind']==old345.OFFER for _,c in responses
                if c['challenge_original_raw_sha256']==r['sha256']) and
                any(c['response_kind']==old345.UNAVAILABLE for _,c in responses
                if c['challenge_original_raw_sha256']==r['sha256'])
                for r,_ in signed_challenges)
    return {'tsa_channel_id':channel,'full_original_ec344_ec345_source_replay':True,
        'ec343_roster_original_sha256':src['expected_roster_sha256'],
        'ec344_directory_original_sha256':src['expected_directory_sha256'],
        'ec344_checkpoint_original_sha256':src['expected_checkpoint_sha256'],
        'ec345_proposer_key_original_sha256':proposer_ref['sha256'],
        'verified_ec345_source_snapshot_sha256':item['expected_snapshot_sha256'],
        'verified_ec345_source_ack_sha256':item['expected_ack_set_sha256'],
        'verified_target_item_id':target,
        'signed_ec344_view_original_shas':[r['sha256'] for r in row['ec344_signed_visibility_originals']],
        'signed_ec345_challenge_original_shas':[r['sha256'] for r in row['ec345_signed_challenge_originals']],
        'signed_ec345_response_original_shas':[r['sha256'] for r in row['ec345_signed_response_originals']],
        'signed_ec344_registered_view_count':len(row['ec344_signed_visibility_originals']),
        'signed_ec345_authorized_challenge_count':len(signed_challenges),
        'signed_ec345_registered_receiver_offer_count':offer_count,
        'receiver_key_original_shas':keyshas,
        'signed_view_claim_conflict':conflict,
        'signed_offer_claim_conflict_or_missing':conflicting or not offer_for_target,
        'signed_ec345_predecessor_incomplete':False,
        'verified_disclosed_target_has_signed_offer':offer_for_target}


def _engine(derive,**opts):
    popts=_inputs(opts,derive)
    parent_result=parent.audit(**popts)  # mandatory real EC383->369
    n=len(opts['historical_directory_root_shas'])
    psha=_parent(parent_result,n)
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC384_'+role)
        path=ref['path']
        if path in cache:
            oldsha,raw,oldrole=cache[path]
            need(path not in forbidden and oldsha==ref['sha256'] and oldrole==role and
                 len(raw)<=cap,'ORIGINAL_PATH_ALIAS_SHA_OR_EVIDENCE_ROLE_CONFLICT',
                 'permission_denied')
            return raw
        raw=p372._read(ref,'ec384_'+role,cap,pins,categories,forbidden)
        cache[path]=(ref['sha256'],raw,role)
        return raw
    ref383={'path':opts['historical_ec347_site_provenance_archive_bundle_file'],
        'sha256':opts['expected_historical_ec347_site_provenance_archive_bundle_sha256']}
    old383=old353.strict_json(read(ref383,'authentic_ec383_receiver_archive',parent.MAX_BUNDLE),
                            'EC384_REAL_EC383_ORIGINAL')
    exact(old383,parent.BUNDLE_FIELDS,'ORIGINAL_EC383_ARCHIVE')
    need(old383['schema']==parent.BUNDLE_SCHEMA and len(old383['epochs'])==n and
         old383['claimed_directory_lineage_id']==opts['claimed_historical_directory_lineage_id'],
         'EC383_PARENT_RECEIVER_ORIGINAL_SOURCE_MISMATCH','permission_denied')
    ref382={'path':opts['historical_ec348_keeper_archive_bundle_file'],
        'sha256':opts['expected_historical_ec348_keeper_archive_bundle_sha256']}
    old382=old353.strict_json(read(ref382,'authentic_ec382_receiver_archive',
                    parent.previous.MAX_BUNDLE),'EC384_REAL_EC382_ORIGINAL')
    exact(old382,parent.previous.BUNDLE_FIELDS,'ORIGINAL_EC382_ARCHIVE')
    need(old382['schema']==parent.previous.BUNDLE_SCHEMA and len(old382['epochs'])==n,
         'MISSING_AUTHENTIC_EC382_REAL_SOURCE','permission_denied')
    ref384={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=old353.strict_json(read(ref384,'receiver_ec384_visibility_offer_archive',MAX_BUNDLE),
                             'EC384_RECEIVER_ORIGINAL')
    exact(bundle,BUNDLE_FIELDS,'EC384_ORIGINAL_ARCHIVE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['parent_ec383_canonical_result_sha256']==psha and
         bundle['ec383_historical_site_archive_original_sha256']==ref383['sha256'] and
         bundle['claimed_directory_lineage_id']==old383['claimed_directory_lineage_id'] and
         len(bundle['epochs'])==n,
         'EC384_ARCHIVE_MUST_BIND_ACTUAL_PARENT_RESULT_AND_SOURCE','permission_denied')
    # Reuse the same externally signed sender-label exclusion used in EC383.
    ref377={'path':opts['historical_transparency_archive_bundle_file'],
            'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    old377=old353.strict_json(read(ref377,'authentic_ec377_sender_label_parent',
                     parent.previous.previous.p379.p377.MAX_BUNDLE),
                           'EC384_REAL_EC377_PARENT')
    exact(old377,parent.previous.previous.p379.p377.BUNDLE_FIELDS,'EC377_REAL_PARENT')
    need(old377['schema']==parent.previous.previous.p379.p377.BUNDLE_SCHEMA and
         len(old377['epochs'])==n,'EC377_SENDER_LABEL_PARENT_CHANGED','permission_denied')
    for ep in old377['epochs']:
        sender=old353.strict_json(read(ep['ec353_publication_bundle_original'],
              'old_ec353_sender_labels_'+ep['ec353_publication_bundle_original']['sha256'],
              old353.MAX_BUNDLE),'EC384_OLD_EC353_SENDER_LABELS')
        parent.previous.previous.p379._old_sender_labels(sender,forbidden)
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not parent_result['local_ec347_challenger_receiver_ec346_signed_source_originals_consistent']
    rows=[];inventories=[];prev_channels={};total_view=total_challenge=total_offer=0
    for idx,(epoch,old_ep,keeper_ep) in enumerate(zip(
         bundle['epochs'],old383['epochs'],old382['epochs'],strict=True)):
        exact(epoch,EPOCH_FIELDS,'EC384_EPOCH')
        exact(old_ep,parent.EPOCH_FIELDS,'EC383_AUTHENTIC_EPOCH')
        exact(keeper_ep,parent.previous.EPOCH_FIELDS,'EC382_AUTHENTIC_EPOCH')
        need(epoch['epoch_index']==old_ep['epoch_index']==keeper_ep['epoch_index']==idx and
             type(epoch['channels']) is list and type(old_ep['channels']) is list and
             type(keeper_ep['channels']) is list and
             len(epoch['channels'])==len(old_ep['channels'])==len(keeper_ep['channels'])<=
                old349.MAX_CHANNELS,
             'ORIGINAL_EC384_EC383_EC382_EPOCH_CENSUS_MUST_MATCH','permission_denied')
        ids=[r.get('tsa_channel_id') for r in epoch['channels'] if type(r) is dict]
        oldids=[r['tsa_channel_id'] for r in old_ep['channels']]
        keeperids=[r['tsa_channel_id'] for r in keeper_ep['channels']]
        need(len(ids)==len(epoch['channels']) and ids==oldids==keeperids==sorted(set(ids)),
             'SIGNED_CHANNEL_IDENTITIES_ORDER_OR_CENSUS_CHANGED','permission_denied')
        results=[]
        for row,older,keeper in zip(epoch['channels'],old_ep['channels'],
                                     keeper_ep['channels'],strict=True):
            r=_channel(row,older,keeper,read,forbidden)
            results.append(r)
            flags[FLAGS[2]]|=not r['full_original_ec344_ec345_source_replay']
            flags[FLAGS[3]]|=r['signed_ec344_registered_view_count']==0 or r['signed_view_claim_conflict']
            flags[FLAGS[4]]|=r['signed_ec345_authorized_challenge_count']==0 or r['signed_ec345_predecessor_incomplete']
            flags[FLAGS[5]]|=r['signed_offer_claim_conflict_or_missing'] or not r['verified_disclosed_target_has_signed_offer']
            if r['full_original_ec344_ec345_source_replay']:
                previous=prev_channels.get(r['tsa_channel_id'])
                if previous is not None:
                    same=('ec343_roster_original_sha256','ec344_directory_original_sha256',
                          'ec344_checkpoint_original_sha256','ec345_proposer_key_original_sha256',
                          'verified_target_item_id','verified_ec345_source_snapshot_sha256',
                          'verified_ec345_source_ack_sha256','receiver_key_original_shas')
                    flags[FLAGS[6]]|=(any(r[k]!=previous[k] for k in same) or
                          any(r[k][:len(previous[k])]!=previous[k] for k in (
                             'signed_ec344_view_original_shas',
                             'signed_ec345_challenge_original_shas',
                             'signed_ec345_response_original_shas')))
                prev_channels[r['tsa_channel_id']]=r
        if len(results)==2:
            same=('ec343_roster_original_sha256','ec344_directory_original_sha256',
                  'ec344_checkpoint_original_sha256','ec345_proposer_key_original_sha256',
                  'verified_target_item_id','verified_ec345_source_snapshot_sha256',
                  'verified_ec345_source_ack_sha256','receiver_key_original_shas',
                  'signed_ec344_view_original_shas','signed_ec345_challenge_original_shas',
                  'signed_ec345_response_original_shas','signed_offer_claim_conflict_or_missing')
            flags[FLAGS[6]]|=any(results[0][k]!=results[1][k] for k in same)
        views=[{k:r[k] for k in ('tsa_channel_id','ec343_roster_original_sha256',
               'ec344_directory_original_sha256','ec344_checkpoint_original_sha256',
               'receiver_key_original_shas','signed_ec344_view_original_shas',
               'signed_view_claim_conflict')} for r in results]
        offers=[{k:r[k] for k in ('tsa_channel_id','ec345_proposer_key_original_sha256',
                'verified_target_item_id','verified_ec345_source_snapshot_sha256',
                'verified_ec345_source_ack_sha256','signed_ec345_challenge_original_shas',
                'signed_ec345_response_original_shas','signed_offer_claim_conflict_or_missing')}
                for r in results]
        vsha=sha(canonical.canonical(views));osha=sha(canonical.canonical(offers))
        cv=sum(r['signed_ec344_registered_view_count'] for r in results)
        cc=sum(r['signed_ec345_authorized_challenge_count'] for r in results)
        co=sum(r['signed_ec345_registered_receiver_offer_count'] for r in results)
        total_view+=cv;total_challenge+=cc;total_offer+=co
        flags[FLAGS[1]]|=(vsha!=opts['historical_ec344_signed_visibility_inventory_shas'][idx] or
           osha!=opts['historical_ec345_authorized_offer_inventory_shas'][idx] or
           cv<opts['minimum_historical_ec344_signed_visibility_counts'][idx] or
           cc<opts['minimum_historical_ec345_signed_challenge_counts'][idx] or
           co<opts['minimum_historical_ec345_signed_offer_counts'][idx])
        rows.append({'epoch_index':idx,'signed_ec344_receiver_visibility_original_count':cv,
          'signed_ec345_authorized_challenge_original_count':cc,
          'signed_ec345_receiver_offer_original_count':co,
          'ec344_signed_visibility_inventory_sha256':vsha,
          'ec345_authorized_disclosure_offer_inventory_sha256':osha,
          'missing_full_historical_source_channels':sum(
              not r['full_original_ec344_ec345_source_replay'] for r in results),
          'local_authentic_signed_ec344_ec345_offer_source_consistent':bool(results) and
              all(r['full_original_ec344_ec345_source_replay'] and
                  not r['signed_view_claim_conflict'] and
                  not r['signed_offer_claim_conflict_or_missing'] for r in results)})
        inventories.append({'epoch_index':idx,'original_ec344_registered_signed_views':views,
          'original_ec345_authorized_signed_disclosure_offers':offers,
          'ec344_signed_visibility_inventory_sha256':vsha,
          'ec345_signed_offer_inventory_sha256':osha})
    p372.prior.lineage.parent.ref_check(ref383,'EC384_FINAL_REAL_EC383_PARENT_REF')
    p372.prior.lineage.parent.ref_check(ref384,'EC384_FINAL_RECEIVER_ARCHIVE_REF')
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inv={'schema':INVENTORY_SCHEMA,
         'live_ec383_through_ec369_parent_result_canonical_sha256':psha,
         'authenticated_ec383_site_archive_original_sha256':ref383['sha256'],
         'receiver_ec384_disclosure_archive_original_sha256':ref384['sha256'],
         'claimed_directory_lineage_id':bundle['claimed_directory_lineage_id'],
         'historical_ec344_signed_views_ec345_signed_offers_epoch_reviews':inventories}
    invsha=sha(canonical.canonical(inv))
    if not derive and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec345-disclosure-inventory' if derive else
                  'audit-historical-ec345-disclosure-archive',
       'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                      OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_parent_ec383_canonical_result_sha256':psha,
       'historical_ec345_disclosure_archive_bundle_original_sha256':ref384['sha256'],
       'receiver_verified_historical_ec345_disclosure_inventory_sha256':invsha,
       'genuine_old_ec344_receiver_signed_view_original_count':total_view,
       'genuine_old_ec345_authorized_challenge_original_count':total_challenge,
       'genuine_old_ec345_receiver_signed_offer_original_count':total_offer,
       'historical_ec345_disclosure_epoch_reviews':rows,
       'local_ec344_signed_views_ec345_authorized_offer_originals_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec345_through_ec337_full_independent_original_historical_acceptance_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_verified_historical_ec345_disclosure_inventory':inv,
           'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
