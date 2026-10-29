#!/usr/bin/env python3
"""EC374: receiver-held original EC357 review and EC358 owner/reviewer epochs.

Every audit really replays production EC373 -> EC372 -> EC371 -> EC370 ->
EC369, then verifies receiver-side, independently SHA-pinned original bytes
using the unchanged historic EC357 and EC358 Ed25519 signing domains.
Neither the old EC357 nor EC358 *canonical parent result* is reconstructed:
their deeper signed input ancestors are not all furnished by this protocol.
A locally coherent slice is necessarily exit 2 / unresolved, never PASS.
"""
from __future__ import annotations

from collections import defaultdict

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec357_provenance import provenance as ec357
from ec358_reviewer_epochs import epochs as ec358
from ec359_owner_distribution import distribution as ec359
from ec360_authority_directory import authority as ec360
from ec373_historical_inclusion import inclusion_archive as prior

RESULT_SCHEMA='ces.ec374.receiver_historical_owner_reviewer_signed_originals_unresolved.v1'
DERIVE_SCHEMA='ces.ec374.unsigned_historical_owner_reviewer_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec374.receiver_historical_owner_reviewer_signed_originals_denial.v1'
BUNDLE_SCHEMA='ces.ec374.receiver_historical_owner_reviewer_originals.v1'
INVENTORY_SCHEMA='ces.ec374.receiver_verified_ec357_ec358_original_sha_inventory.v1'
MAX_BUNDLE=66_000
NEW_SCALARS=('historical_owner_epoch_bundle_file',
             'expected_historical_owner_epoch_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_owner_inventory_sha256',)
NEW_REPEATS=(
 ('historical_owner_a_head_shas','--historical-owner-a-head-sha256'),
 ('historical_owner_b_head_shas','--historical-owner-b-head-sha256'),
 ('minimum_historical_owner_a_epochs','--minimum-historical-owner-a-epoch'),
 ('minimum_historical_owner_b_epochs','--minimum-historical-owner-b-epoch'),
 ('historical_reviewer_a_key_shas','--historical-reviewer-a-key-sha256'),
 ('historical_reviewer_b_key_shas','--historical-reviewer-b-key-sha256'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
BUNDLE_FIELDS={'schema','parent_ec373_canonical_result_sha256',
 'ec373_historical_inclusion_bundle_original_sha256',
 'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','signed_parent_ec357_canonical_result_sha256',
              'source_a','source_b'}
SOURCE_FIELDS={'owner_public_key_original','claimed_owner_id',
 'claimed_source_id','source_review_public_key_original',
 'source_review_signed_original','signed_parent_ec356_canonical_result_sha256',
 'signed_ec356_custody_bundle_original_sha256','reviewer_epoch_events',
 'selected_owner_epoch_head_sha256'}
EVENT_PIN_FIELDS={'event_original','previous_reviewer_public_key_original',
                  'current_reviewer_public_key_original'}
FLAGS=(
 'inherited_ec373_ec372_ec371_ec370_ec369_receiver_dispute_unresolved',
 'external_historical_owner_inventory_head_epoch_or_reviewer_pin_mismatch',
 'historical_genuine_ec358_owner_epoch_fork_or_signed_revocation',
 'historical_signed_reviewer_key_continuity_or_selected_head_rollback',
 'historical_ec357_source_review_signed_revocation_or_scope_conflict',
 'historical_ec358_owner_reviewer_or_parent_claim_cross_epoch_conflict',
 'historical_ec357_ec358_signed_utc_is_untrusted_or_stale',
 'historical_owner_signatures_only_partially_recover_ec357_to_ec337',
)
OUTCOMES=(
 'ec374_inherited_receiver_historical_inclusion_or_authority_dispute',
 'ec374_external_owner_head_epoch_reviewer_or_inventory_floor_mismatch',
 'ec374_genuine_ec358_owner_epoch_fork_or_revoke',
 'ec374_reviewer_chain_or_selected_head_rollback',
 'ec374_ec357_signed_source_review_revocation_or_scope_conflict',
 'ec374_cross_epoch_owner_reviewer_or_old_parent_claim_conflict',
 'ec374_signed_owner_source_time_claim_untrusted',
 'ec374_only_partial_ec357_ec358_owner_and_reviewer_originals_recovered',
)
NEGATIVES=(
 'complete_ec365_to_ec337_historical_original_parent_chain_replayed',
 'actual_ec357_or_ec358_canonical_result_recomputed_from_old_original_inputs',
 'actual_ec359_or_ec360_canonical_result_recomputed_from_old_original_inputs',
 'genuine_ec357_source_review_signature_proves_ec356_parent_contents',
 'ec358_signed_parent_ec357_result_sha_is_a_reconstructed_result',
 'ec359_signed_parent_ec358_result_sha_is_a_reconstructed_result',
 'historical_owner_signature_proves_official_legal_owner_or_reviewer',
 'source_review_original_proves_global_latest_or_full_fork_absence',
 'historical_ec362_other_copy_label_originals_reopened',
 'signed_revocation_or_inherited_adverse_result_overridden',
 'trusted_utc_external_custody_remote_network_cas_worm_provider_verified',
 'private_signer_or_native_powershell_cli_modified',
 'old_deep_historical_mock_removed_or_final_acceptance_proven',
)


def need(condition,reason,status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC374_'+reason,status)


def exact(doc,fields,role):
    need(type(doc) is dict and set(doc)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return prior.sha(raw)


def _inputs(opts,derive):
    old=(*prior.parent.current.prior.SCALARS,
         *prior.parent.current.prior.REPEAT_NAMES,
         *prior.parent.current.NEW_SCALARS,
         *prior.parent.current.NEW_REPEAT_NAMES,
         *prior.parent.prior.NEW_SCALARS,*prior.parent.prior.REPEAT_NAMES,
         *prior.parent.prior.AUDIT_ONLY,
         *prior.parent.NEW_SCALARS,*prior.parent.NEW_REPEAT_NAMES,
         *prior.parent.AUDIT_ONLY,
         *prior.NEW_SCALARS,*prior.REPEAT_NAMES,*prior.AUDIT_ONLY)
    required=set(old)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_PRODUCTION_EC373_AND_NEW_INPUTS_REQUIRED')
    parent_opts={k:opts[k] for k in old}
    prior._inputs(parent_opts,False)
    ec360.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                    'EC374_HISTORIC_OWNER_BUNDLE')
    need(opts[NEW_SCALARS[0]] is not None and opts[NEW_SCALARS[1]] is not None,
         'EXTERNAL_RECEIVER_OWNER_BUNDLE_SHA_PIN_REQUIRED')
    if not derive:need(tr._sha(opts[AUDIT_ONLY[0]]),
                       'EXTERNAL_OWNER_INVENTORY_SHA_PIN_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    for key in REPEAT_NAMES:
        arr=opts[key]
        need(type(arr) is list and len(arr)==n,
             key.upper()+'_EXACT_EPOCH_COUNT_REQUIRED')
        if key.startswith('minimum_'):
            need(all(type(x) is int and 0<=x<ec358.MAX_EVENTS_PER_SOURCE for x in arr),
                 key.upper()+'_EPOCH_FLOOR_OUT_OF_BOUNDS')
        else:
            need(all(tr._sha(x) for x in arr),key.upper()+'_INVALID_SHA_STREAM')
    return parent_opts


def _event_history(i,slot,row,source_review,owner_key,reviewer_sha,
                   parent357,now,read):
    refs=row['reviewer_epoch_events']
    need(type(refs) is list and 1<=len(refs)<=ec358.MAX_EVENTS_PER_SOURCE,
         'ORIGINAL_EC358_EVENT_HISTORY_REQUIRED_AND_BOUNDED')
    events={};children=defaultdict(list);genesis=[]
    fork=False;revoked=False;stale=False
    reviewer_paths={};reviewer_keys=set()
    owner_sha=sha(owner_key)
    for item in refs:
        exact(item,EVENT_PIN_FIELDS,'EC358_SIGNED_EPOCH_REFERENCE')
        eventref=item['event_original']
        raw=read(eventref,'signed_ec358_event',ec358.MAX_EVENT)
        digest=sha(raw)
        need(digest not in events,'DUPLICATE_EC358_SIGNED_EVENT_ORIGINAL',
             'permission_denied')
        doc=tr.strict_json(raw,'EC374_HISTORICAL_EC358_EPOCH')
        exact(doc,ec358.EVENT_FIELDS,'EC358_ORIGINAL_SIGNED_EVENT')
        need(doc['schema']==ec358.EVENT_SCHEMA and doc['slot']==slot and
             doc['source_id']==source_review['source_id'] and
             doc['claimed_owner_id']==row['claimed_owner_id'] and
             doc['owner_public_key_original_sha256']==owner_sha and
             doc['parent_ec357_canonical_result_sha256']==parent357 and
             doc['parent_source_review_original_sha256']==row[
                       'source_review_signed_original']['sha256'],
             'EC358_SIGNED_OWNER_SOURCE_OR_EC357_ANCESTRY_MISMATCH',
             'permission_denied')
        epoch=doc['epoch'];operation=doc['operation']
        prev=doc['previous_event_original_sha256']
        previous_key=doc['previous_reviewer_public_key_original_sha256']
        current_key=doc['current_reviewer_public_key_original_sha256']
        need(type(epoch) is int and 0<=epoch<ec358.MAX_EVENTS_PER_SOURCE and
             operation in ('issue','rotate','revoke') and
             (prev is None or tr._sha(prev)),
             'EC358_SIGNED_EPOCH_NUMBER_OR_OPERATION_INVALID',
             'permission_denied')
        issued=tr._utc(doc['issued_utc']);expires=tr._utc(doc['expires_utc'])
        need(issued<expires and expires-issued<=ec358.MAX_VALIDITY,
             'EC358_SIGNED_TIME_SPAN_INVALID','permission_denied')
        if operation=='issue':
            need(epoch==0 and prev is None and previous_key is None and
                 tr._sha(current_key),
                 'EC358_SIGNED_ISSUE_GENESIS_INVALID','permission_denied')
        elif operation=='rotate':
            need(epoch>0 and tr._sha(prev) and tr._sha(previous_key) and
                 tr._sha(current_key) and previous_key!=current_key,
                 'EC358_SIGNED_ROTATION_SHAPE_INVALID','permission_denied')
        else:
            need(epoch>0 and tr._sha(prev) and tr._sha(previous_key) and
                 current_key is None,
                 'EC358_SIGNED_TERMINAL_REVOKE_SHAPE_INVALID','permission_denied')
            revoked=True
        body={k:v for k,v in doc.items() if k not in ec358.SIGNATURE_FIELDS.values()}
        ec358._sig(owner_key,doc['signature_owner_ed25519_hex'],
                   ec358.DOMAINS['owner'],body,'EC374_EC358_OWNER')
        for direction,hashed,required in (
            ('previous',previous_key,operation in ('rotate','revoke')),
            ('current',current_key,operation in ('issue','rotate'))):
            ref=item[direction+'_reviewer_public_key_original']
            signature=doc[ec358.SIGNATURE_FIELDS[direction]]
            if not required:
                need(ref is None and signature is None,
                     'UNEXPECTED_EC358_REVIEWER_KEY_OR_SIGNATURE',
                     'permission_denied')
                continue
            need(type(ref) is dict and ref.get('sha256')==hashed,
                 'EC358_REVIEWER_ORIGINAL_PIN_NOT_SIGNED_KEY',
                 'permission_denied')
            public=read(ref,'historic_reviewer_public_key',32)
            need(len(public)==32 and sha(public)==hashed and hashed!=owner_sha,
                 'EC358_REVIEWER_KEY_LENGTH_OR_OWNER_COLLISION',
                 'permission_denied')
            oldref=reviewer_paths.setdefault(hashed,ref)
            need(oldref==ref,'SAME_REVIEWER_KEY_SWITCHED_ORIGINAL_COPY_PIN',
                 'permission_denied')
            reviewer_keys.add(hashed)
            ec358._sig(public,signature,ec358.DOMAINS[direction],body,
                       'EC374_EC358_'+direction.upper())
        if prev is None:genesis.append(digest)
        else:children[prev].append(digest)
        if issued>now or expires<now or now-issued>ec358.MAX_AGE:stale=True
        events[digest]=(doc,issued)
    need(bool(genesis),'EC358_ORIGINAL_ISSUE_GENESIS_MISSING',
         'permission_denied')
    for digest,(doc,issued) in events.items():
        prev=doc['previous_event_original_sha256']
        if prev is not None:
            need(prev in events,'MISSING_REAL_EC358_SIGNED_PREDECESSOR',
                 'permission_denied')
            old,old_issued=events[prev]
            need(old['operation']!='revoke' and old['epoch']+1==doc['epoch'] and
                 doc['previous_reviewer_public_key_original_sha256']==old[
                     'current_reviewer_public_key_original_sha256'],
                 'EC358_REVOKED_PARENT_OR_REVIEWER_EPOCH_LINK_INVALID',
                 'permission_denied')
            if issued<old_issued:stale=True
        visited=set();cursor=digest
        while cursor is not None:
            need(cursor not in visited,'EC358_SIGNED_ANCESTRY_CYCLE',
                 'permission_denied')
            visited.add(cursor)
            cursor=events[cursor][0]['previous_event_original_sha256']
    if len(genesis)!=1 or any(len(x)>1 for x in children.values()):fork=True
    endpoints=[x for x in events if not children.get(x)]
    if len(endpoints)!=1:fork=True
    chosen_sha=row['selected_owner_epoch_head_sha256']
    need(tr._sha(chosen_sha) and chosen_sha in events,
         'SELECTED_EC358_HEAD_NOT_ACTUALLY_SIGNED_OR_PRESENT',
         'permission_denied')
    selected=events[chosen_sha][0]
    if children.get(chosen_sha):fork=True
    if selected['operation']=='revoke':revoked=True
    # A valid initial issue signed by a *new* reviewer is possible, but a
    # current source-review authority must be the real selected final key.
    actual_reviewer=selected['current_reviewer_public_key_original_sha256']
    mismatch=(actual_reviewer!=reviewer_sha)
    selected_epoch=selected['epoch']
    return {'epoch_index':i,'slot':slot,'owner_sha':owner_sha,
      'owner_id':row['claimed_owner_id'],'source_id':row['claimed_source_id'],
      'source_review_sha':row['source_review_signed_original']['sha256'],
      'source_reviewer_sha':reviewer_sha,'reviewer_key_shas':sorted(reviewer_keys),
      'parent_ec357_claim':parent357,
      'parent_ec356_claim':row['signed_parent_ec356_canonical_result_sha256'],
      'custody_ec356_claim':row['signed_ec356_custody_bundle_original_sha256'],
      'event_shas':sorted(events),'selected_head':chosen_sha,
      'selected_epoch':selected_epoch,'selected_operation':selected['operation'],
      'selected_reviewer_sha':actual_reviewer,'fork':fork,'revoked':revoked,
      'reviewer_mismatch':mismatch,'clock':stale}


def _engine(derive,**opts):
    oldopts=_inputs(opts,derive)
    inherited=prior.audit(**oldopts)  # mandatory real EC373->EC369 replay
    need(type(inherited) is dict and inherited.get('schema')==prior.RESULT_SCHEMA
         and inherited.get('exit_code')==2 and
         inherited.get('sender_origin_path_required_or_read') is False,
         'LIVE_PRODUCTION_EC373_THROUGH_EC369_AUDIT_REQUIRED','unavailable')
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set()
    def read(ref,role,cap):
        return prior.parent._read(ref,'ec374_'+role,cap,pins,categories,forbidden)
    historical,manifests=prior._open_historical(oldopts,read,forbidden)
    oldref={'path':opts['historical_inclusion_bundle_file'],
            'sha256':opts['expected_historical_inclusion_bundle_sha256']}
    oldb=tr.strict_json(read(oldref,'ec373_historic_inclusion_bundle',prior.MAX_BUNDLE),
                         'EC374_REOPEN_EC373_HISTORIC_INCLUSION')
    exact(oldb,prior.BUNDLE_FIELDS,'OLD_EC373_HISTORIC_INCLUSION')
    need(oldb['schema']==prior.BUNDLE_SCHEMA and
         oldb['claimed_directory_lineage_id']==opts[
                          'claimed_historical_directory_lineage_id'],
         'TRUE_EC373_INCLUSION_ORIGINAL_ID_MISMATCH','permission_denied')
    newref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    b=tr.strict_json(read(newref,'ec374_historic_owner_epoch_bundle',MAX_BUNDLE),
                     'EC374_REAL_RECEIVER_OWNER_EPOCH_BUNDLE')
    exact(b,BUNDLE_FIELDS,'EC374_OWNER_EPOCH_BUNDLE')
    parent_sha=sha(canonical.canonical(inherited))
    need(b['schema']==BUNDLE_SCHEMA and
         b['parent_ec373_canonical_result_sha256']==parent_sha and
         b['ec373_historical_inclusion_bundle_original_sha256']==oldref['sha256']
         and b['claimed_directory_lineage_id']==opts[
                                'claimed_historical_directory_lineage_id'],
         'EC374_BUNDLE_NOT_BOUND_TO_REAL_LIVE_PARENT_OR_ORIGINAL',
         'permission_denied')
    rows=b['epochs'];previous=oldb['epochs']
    need(type(rows) is list and len(rows)==len(previous)==len(historical['epochs'])
         and 1<=len(rows)<=prior.parent.MAX_EPOCHS,
         'EC358_EVENTS_MUST_COVER_EXACT_HISTORICAL_EPOCHS')
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=not inherited[
                    'local_pinned_historical_inclusion_and_issuer_slice_consistent']
    # Keys from the live current audit and *all* historic source/root roles.
    known_roles=set(opts['institution_root_public_key_shas']+
       opts['witness_public_key_shas']+opts['historical_directory_root_shas']+
       [opts['expected_sender_public_key_sha256'],
        opts['expected_receiver_public_key_sha256'],
        opts['expected_publisher_public_key_sha256'],
        opts['expected_publication_observer_public_key_sha256']])
    # Genuine inherited EC372 authority and EC371 custodian public keys are
    # role boundaries too, even when the old issuer and witness are not named
    # as new caller inputs. Reopen the exact parent original, not a self-made
    # signer-role allowlist or old sender copy label.
    authorityref={'path':opts['historical_authority_bundle_file'],
                  'sha256':opts['expected_historical_authority_bundle_sha256']}
    oldauth=tr.strict_json(read(authorityref,'ec372_historic_authority_bundle',
                               prior.parent.MAX_BUNDLE),
                           'EC374_REOPEN_EC372_ROOT_ISSUER_ROLES')
    exact(oldauth,prior.parent.BUNDLE_FIELDS,'OLD_ROOT_AUTHORITY_BUNDLE')
    need(oldauth['schema']==prior.parent.BUNDLE_SCHEMA and
         oldauth['claimed_directory_lineage_id']==opts[
             'claimed_historical_directory_lineage_id'] and
         type(oldauth['epochs']) is list and
         len(oldauth['epochs'])==len(rows),
         'EC372_ORIGINAL_SOURCE_ROLE_BINDING_INVALID','permission_denied')
    for i,authority_epoch in enumerate(oldauth['epochs']):
        exact(authority_epoch,prior.parent.EPOCH_FIELDS,
              'EC372_TRUE_AUTHORITY_EPOCH')
        need(type(authority_epoch['epoch_index']) is int and
             authority_epoch['epoch_index']==i,
             'EC372_ROLE_EPOCH_INDEX_INVALID','permission_denied')
        for slot in ('a','b'):
            auth=authority_epoch['source_'+slot]
            exact(auth,prior.parent.SOURCE_FIELDS,'EC372_SOURCE_ROLE_ORIGINALS')
            for field in ('authority_root_public_key_original',
                          'origin_witness_public_key_original',
                          'issuer_public_key_original'):
                need(tr._sha(auth[field]['sha256']),
                     'INHERITED_EC372_SIGNING_KEY_SHA_MALFORMED',
                     'permission_denied')
                known_roles.add(auth[field]['sha256'])
            key=historical['epochs'][i][
                 'source_'+slot+'_custodian_public_key_original']
            need(tr._sha(key['sha256']),
                 'INHERITED_EC371_CUSTODIAN_KEY_SHA_MALFORMED',
                 'permission_denied')
            known_roles.add(key['sha256'])
    owner_signers=set();reviewer_ownership={};reviews=[]
    for i,epoch in enumerate(rows):
        exact(epoch,EPOCH_FIELDS,'EC374_HISTORIC_OWNER_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i,
             'OWNER_EPOCH_INDEX_MUST_BE_CONTIGUOUS')
        p357=epoch['signed_parent_ec357_canonical_result_sha256']
        need(tr._sha(p357),'SIGNED_EC357_PARENT_RESULT_CLAIM_MALFORMED')
        oldepoch=previous[i]
        exact(oldepoch,prior.EPOCH_FIELDS,'OLD_SIGNED_EC373_EPOCH')
        slot_claims=[]
        for slot in ('a','b'):
            source=epoch['source_'+slot]
            exact(source,SOURCE_FIELDS,'EC374_SOURCE_'+slot.upper())
            oldsource=oldepoch['source_'+slot]
            exact(oldsource,prior.SOURCE_FIELDS,'OLD_EC373_SOURCE_'+slot.upper())
            need(source['owner_public_key_original']==oldsource[
                         'owner_public_key_original'] and
                 source['claimed_owner_id']==oldsource['claimed_owner_id'] and
                 tr._ident(source['claimed_owner_id']) and
                 tr._ident(source['claimed_source_id']),
                 'EC358_OWNER_ORIGINAL_AND_ID_MUST_MATCH_TRUE_EC359_SOURCE',
                 'permission_denied')
            own=read(source['owner_public_key_original'],
                     'ec358_owner_public_key',32)
            need(len(own)==32 and sha(own)==source[
                      'owner_public_key_original']['sha256'],
                 'REAL_EC358_OWNER_PUBKEY_BYTES_MISMATCH','permission_denied')
            ownsha=sha(own)
            # Old EC373 verifies the real issuer originals. Reopen its selected
            # genuine EC359 *original* and bind the exact signed owner head.
            selected359=oldsource['selected_owner_distribution_head_sha256']
            selection=[p for p in oldsource[
                   'issuer_signed_owner_distribution_originals']
                   if p['sha256']==selected359]
            need(len(selection)==1,
                 'REAL_EC359_SIGNED_SELECTED_ISSUER_ORIGINAL_MISSING',
                 'permission_denied')
            d359=tr.strict_json(read(selection[0],
                'ec359_selected_signed_issuer_original',ec359.MAX_RECORD),
                'EC374_REOPEN_SIGNED_SELECTED_EC359_ISSUER')
            exact(d359,ec359.RECORD_FIELDS,'EC359_VERIFIED_ISSUER_RECORD')
            need(d359['parent_ec358_canonical_result_sha256']==oldsource[
                    'signed_parent_ec358_canonical_result_sha256'] and
                 d359['parent_owner_head_event_original_sha256']==source[
                    'selected_owner_epoch_head_sha256'] and
                 d359['owner_public_key_original_sha256']==ownsha and
                 d359['claimed_owner_id']==source['claimed_owner_id'],
                 'TRUE_EC359_ISSUER_SIGNED_EC358_HEAD_OR_OWNER_LINK_INVALID',
                 'permission_denied')
            reviewkeyref=source['source_review_public_key_original']
            pub=read(reviewkeyref,'historic_reviewer_public_key',32)
            reviewer_sha=sha(pub)
            need(len(pub)==32 and reviewer_sha==reviewkeyref['sha256'] and
                 reviewer_sha not in known_roles and reviewer_sha!=ownsha,
                 'EC357_REVIEWER_KEY_REUSES_EXISTING_SIGNER_OR_WRONG_BYTES',
                 'permission_denied')
            other=reviewer_ownership.setdefault(reviewer_sha,slot)
            need(other==slot,'REVIEWER_KEY_CROSSES_TWO_SOURCE_ROLES',
                 'permission_denied')
            reviewraw=read(source['source_review_signed_original'],
                           'old_ec357_source_review',ec357.MAX_SOURCE)
            review,issued,expires=ec357._review(reviewraw,pub)
            need(review['source_id']==source['claimed_source_id'] and
                 review['source_authority_public_key_original_sha256']==reviewer_sha
                 and review['parent_ec356_canonical_result_sha256']==source[
                    'signed_parent_ec356_canonical_result_sha256'] and
                 review['ec356_custody_bundle_original_sha256']==source[
                    'signed_ec356_custody_bundle_original_sha256'],
                 'EC357_VERIFIED_SOURCE_REVIEW_SIGNED_ANCESTRY_OR_SCOPE_MISMATCH',
                 'permission_denied')
            # These are original signed *claims*; old EC356 parent evidence is
            # not re-imported, and source custodian identity is not a trust CA.
            if any(root['root_state']!='active' for root in review['root_records']):
                flags[FLAGS[4]]=True
            if issued>now or expires<now or now-issued>ec357.MAX_AGE:
                flags[FLAGS[6]]=True
            state=_event_history(i,slot,source,review,own,reviewer_sha,
                                 p357,now,read)
            if (state['selected_head']!=opts[
                    'historical_owner_'+slot+'_head_shas'][i] or
                state['selected_epoch']<opts[
                    'minimum_historical_owner_'+slot+'_epochs'][i] or
                reviewer_sha!=opts['historical_reviewer_'+slot+'_key_shas'][i]):
                flags[FLAGS[1]]=True
            if state['fork'] or state['revoked']:
                flags[FLAGS[2]]=True
            if state['reviewer_mismatch']:
                flags[FLAGS[3]]=True
            if state['clock']:
                flags[FLAGS[6]]=True
            for reviewer in state['reviewer_key_shas']:
                need(reviewer not in known_roles and reviewer not in owner_signers,
                     'EC358_REVIEWER_PUBLIC_KEY_REUSES_KNOWN_SIGNING_ROLE',
                     'permission_denied')
                claimed=reviewer_ownership.setdefault(reviewer,slot)
                need(claimed==slot,'EC358_REVIEWER_CROSSES_SOURCE_OWNERSHIP',
                     'permission_denied')
            need(ownsha not in known_roles and ownsha not in reviewer_ownership,
                 'EC358_OWNER_PUBLIC_KEY_REUSES_EXISTING_SIGNER_ROLE',
                 'permission_denied')
            owner_signers.add(ownsha)
            state['signed_ec359_parent_ec358_claim']=oldsource[
                    'signed_parent_ec358_canonical_result_sha256']
            state['selected_ec359_original_sha']=selected359
            state['historic_custodian_manifest_sha']=historical['epochs'][i][
                 'source_'+slot+'_manifest_original']['sha256']
            reviews.append(state)
            slot_claims.append(state)
        a,both=slot_claims
        if a['owner_sha']==both['owner_sha'] or a['owner_id']==both['owner_id'] or (
             a['source_reviewer_sha']==both['source_reviewer_sha']):
            flags[FLAGS[5]]=True
        if (a['parent_ec356_claim']!=both['parent_ec356_claim'] or
            a['custody_ec356_claim']!=both['custody_ec356_claim'] or
            a['signed_ec359_parent_ec358_claim']!=both[
                'signed_ec359_parent_ec358_claim']):
            flags[FLAGS[5]]=True
    need(not set(pins).intersection(forbidden),
         'UNOPENED_HISTORICAL_SENDER_SOURCE_COPY_LABEL_WAS_READ',
         'permission_denied')
    tsa._check_late(pins)
    # Reject distinct aliases to one inode even when both copies hash alike.
    ec357._late_identity_check(pins,set())
    for slot in ('a','b'):
        history=[r for r in reviews if r['slot']==slot]
        for before,after in zip(history,history[1:]):
            if (before['owner_sha']!=after['owner_sha'] or
                before['owner_id']!=after['owner_id'] or
                before['source_id']!=after['source_id'] or
                before['source_reviewer_sha']!=after['source_reviewer_sha'] or
                before['parent_ec357_claim']!=after['parent_ec357_claim'] or
                before['parent_ec356_claim']!=after['parent_ec356_claim'] or
                before['custody_ec356_claim']!=after['custody_ec356_claim'] or
                before['signed_ec359_parent_ec358_claim']!=after[
                    'signed_ec359_parent_ec358_claim']):
                flags[FLAGS[5]]=True
            if before['selected_head']!=after['selected_head'] and (
                 before['selected_head'] not in after['event_shas'] or
                 after['selected_epoch']<=before['selected_epoch']):
                flags[FLAGS[5]]=True
            # Reviewer/owner key changes across epochs without a verified old
            # parent handoff are *not* promoted to continuity.
    flags[FLAGS[-1]]=True
    inventory={'schema':INVENTORY_SCHEMA,
       'verified_live_ec373_canonical_result_sha256':parent_sha,
       'ec373_historical_inclusion_bundle_original_sha256':oldref['sha256'],
       'ec374_historical_owner_epoch_bundle_original_sha256':newref['sha256'],
       'claimed_historical_directory_lineage_id':opts[
                             'claimed_historical_directory_lineage_id'],
       'receiver_verified_original_ec357_ec358_sources':[
          {k:r[k] for k in ('epoch_index','slot','owner_sha','owner_id',
           'source_id','source_review_sha','source_reviewer_sha','event_shas',
           'selected_head','selected_epoch','selected_operation',
           'selected_reviewer_sha','parent_ec357_claim','parent_ec356_claim',
           'custody_ec356_claim','signed_ec359_parent_ec358_claim',
           'selected_ec359_original_sha','historic_custodian_manifest_sha')}
          for r in reviews]}
    digest=sha(canonical.canonical(inventory))
    if not derive and opts[AUDIT_ONLY[0]]!=digest:flags[FLAGS[1]]=True
    local=not any(flags[key] for key in FLAGS[:-1])
    status=next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),
                OUTCOMES[-1])+'_unresolved'
    doc={'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':'derive-historical-owner-inventory' if derive else
                'audit-historical-owner-archive',
      'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
      'historical_owner_epoch_bundle_original_sha256':newref['sha256'],
      'verified_live_parent_ec373_canonical_result_sha256':parent_sha,
      'receiver_verified_historical_owner_inventory_sha256':digest,
      'verified_real_ec357_source_review_signature_count':len(reviews),
      'verified_real_ec358_owner_epoch_event_count':sum(
                                              len(r['event_shas']) for r in reviews),
      'verified_owner_source_epoch_review_count':len(reviews),
      'historical_owner_source_epoch_reviews':[
       {k:r[k] for k in ('epoch_index','slot','owner_sha','source_reviewer_sha',
                        'selected_head','selected_epoch','selected_operation',
                        'selected_reviewer_sha','fork','revoked',
                        'reviewer_mismatch','clock')}
       for r in reviews],
      'local_pinned_historical_owner_reviewer_slice_consistent':local,
      'sender_origin_path_required_or_read':False,
      'ec365_to_ec337_full_parent_original_replay_performed':False,
      **flags,**{key:False for key in NEGATIVES}}
    if derive:
        doc['unsigned_verified_historical_owner_inventory']=inventory
        doc['caller_external_inventory_pin_created_or_certified']=False
    return doc


def audit(**opts):return _engine(False,**opts)


def derive_inventory(**opts):return _engine(True,**opts)
