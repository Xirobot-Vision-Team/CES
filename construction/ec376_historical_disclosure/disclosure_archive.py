#!/usr/bin/env python3
"""EC376 historical EC354 gossip + EC355 request/receipt ORIGINAL replay.

The real EC375 audit is always executed first; it invokes the real EC374..369
production receiver chain. We then reopen receiver-owned, independently pinned
old EC354/EC355 *unsigned* manifests as inventories only and verify the true
original signed EC354 auditor, challenge and reply, and original signed EC355
request and receipt domains. All old embedded original paths are historical
labels and NEVER read authority. Reopened furnished bytes are joined to the
EC356 ACKs already truly authenticated by EC375, not mistaken for a complete
EC353 log/witness proof or rebuilt EC355/EC356 canonical parent result.

All lawful outcomes exit 2 unresolved; no authority to sign, download or write.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import transparency as tr
from ec354_gossip import gossip as ec354
from ec355_disclosure import disclosure as ec355
from ec356_custody import custody as ec356
from ec371_historical_archive import archive as p371
from ec372_historical_authority import authority_archive as p372
from ec375_historical_custody import custody_archive as prior

RESULT_SCHEMA = 'ces.ec376.receiver_old_ec354_ec355_signed_disclosure_bridge_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec376.unsigned_historic_disclosure_original_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec376.receiver_old_ec355_signed_disclosure_denial.v1'
BUNDLE_SCHEMA = 'ces.ec376.receiver_historic_ec355_disclosure_original_archive.v1'
INVENTORY_SCHEMA = 'ces.ec376.receiver_verified_old_ec354_ec355_original_sha_inventory.v1'
MAX_BUNDLE = 160_000
MAX_OLD_BUNDLE = 100_000
MAX_RECEIVER_REPLIES = ec354.MAX_REPLIES
MAX_RECEIVER_REQUESTS = ec355.MAX_REQUESTS
MAX_RECEIVER_RECEIPTS = ec355.MAX_RECEIPTS
NEW_SCALARS = ('historical_disclosure_archive_bundle_file',
               'expected_historical_disclosure_archive_bundle_sha256')
AUDIT_ONLY = ('expected_retained_historical_disclosure_inventory_sha256',)
NEW_REPEATS = (
    ('historical_disclosure_gossip_bundle_shas', '--historical-disclosure-gossip-bundle-sha256'),
    ('historical_disclosure_request_bundle_shas', '--historical-disclosure-request-bundle-sha256'),
    ('historical_disclosure_auditor_key_inventory_shas', '--historical-disclosure-auditor-key-inventory-sha256'),
    ('minimum_historical_disclosure_request_counts', '--minimum-historical-disclosure-request-count'),
    ('minimum_historical_disclosure_receipt_counts', '--minimum-historical-disclosure-receipt-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
PARENT_SCALARS = (*prior.PARENT_SCALARS, *prior.NEW_SCALARS, *prior.AUDIT_ONLY)
PARENT_REPEATS = (*prior.PARENT_REPEATS, *prior.REPEAT_NAMES)
BUNDLE_FIELDS = {'schema','parent_ec375_canonical_result_sha256',
                 'ec375_historical_custody_archive_original_sha256',
                 'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS = {'epoch_index','ec354_gossip_bundle_original',
                'ec355_disclosure_bundle_original','auditors','exchanges',
                'disclosure_requests'}
AUDITOR_FIELDS = {'auditor_id','public_key_original','signed_reference_original'}
EXCHANGE_FIELDS = {'signed_challenge_original','signed_reply_originals'}
REQUEST_FIELDS = {'signed_request_original','responses'}
RESPONSE_FIELDS = {'signed_receipt_original','checkpoint_original',
                   'witness_original','consistency_original'}
FLAGS = (
    'inherited_ec375_through_ec369_signed_original_dispute_unresolved',
    'independently_retained_old_gossip_disclosure_or_auditor_inventory_mismatch',
    'real_signed_ec354_gossip_reply_or_challenge_fork_conflict_visible',
    'real_signed_ec355_request_fork_or_receipt_equivocation_visible',
    'old_signed_disclosure_coverage_or_ec356_two_role_original_quorum_missing',
    'old_ec355_signed_receipt_or_auditor_cross_epoch_conflict_visible',
    'old_ec354_ec355_claimed_utc_stale_or_untrusted',
    'ec354_ec355_true_signature_slice_not_complete_old_ec353_to_ec337_ancestry',
)
OUTCOMES = (
    'ec376_inherited_original_signed_custody_or_directory_dispute',
    'ec376_outside_retained_old_disclosure_original_inventory_disagrees',
    'ec376_real_signed_gossip_conflicting_reply_or_challenge',
    'ec376_real_signed_disclosure_request_fork_or_receipt_equivocation',
    'ec376_old_signed_disclosure_coverage_or_two_role_copy_quorum_missing',
    'ec376_old_signed_disclosure_across_epochs_disagrees',
    'ec376_old_signed_claimed_utc_stale_or_untrusted',
    'ec376_true_ec354_ec355_crypto_bridge_only_not_complete_old_parent',
)
NEGATIVES = (
    'complete_old_ec355_canonical_parent_result_reconstructed',
    'complete_old_ec356_canonical_parent_result_reconstructed',
    'complete_old_ec354_through_ec337_canonical_parent_replay_performed',
    'old_ec353_log_checkpoint_or_witness_signatures_reverified',
    'old_ec354_challenge_claim_proves_witnessed_ec353_checkpoint',
    'signed_gossip_reply_alone_proves_furnished_log_checkpoint',
    'signed_ec355_receipt_bytes_alone_prove_ec353_log_witness_validity',
    'prior_ec355_ec354_sender_paths_opened_as_authority',
    'old_ec362_source_copy_or_ec369_sender_paths_opened',
    'historical_disclosure_receipts_prove_external_physical_custody',
    'self_signed_auditors_prove_official_realworld_institution_independence',
    'old_signed_utc_claims_prove_trusted_external_timestamp',
    'external_sha_pin_proves_global_latest_or_no_hidden_forks',
    'valid_signature_repairs_inherited_revocation_or_dispute',
    'private_signer_network_provider_cas_worm_writer_or_native_ps_invoked',
    'old_deep_mock_replaced_or_final_user_acceptance_proven',
)


def need(ok, reason, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC376_' + reason, status)


def exact(doc, fields, role):
    need(type(doc) is dict and set(doc)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw): return prior.sha(raw)


def _inputs(opts, derive):
    required = set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive: required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_PARENT_EC375_AND_NEW_RECEIVER_INPUTS_REQUIRED')
    parent = {key:opts[key] for key in (*PARENT_SCALARS,*PARENT_REPEATS)}
    prior._inputs(parent,False)
    p371.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC376_INDEPENDENT_RECEIVER_ARCHIVE')
    need(opts[NEW_SCALARS[0]] is not None and opts[NEW_SCALARS[1]] is not None,
         'OUTSIDE_RETAINED_DISCLOSURE_ARCHIVE_PIN_REQUIRED')
    if not derive: need(tr._sha(opts[AUDIT_ONLY[0]]),
                        'OUTSIDE_RETAINED_DISCLOSURE_SHA_INVENTORY_REQUIRED')
    epochs=len(opts['historical_directory_root_shas'])
    need(1<=epochs<=p371.MAX_EPOCHS,'HISTORICAL_EPOCH_COUNT_OUT_OF_BOUNDS')
    for key in REPEAT_NAMES:
        arr=opts[key]
        need(type(arr) is list and len(arr)==epochs,
             key.upper()+'_EXACT_HISTORICAL_EPOCH_COUNT_REQUIRED')
        if key.startswith('minimum_'):
            bound=MAX_RECEIVER_REQUESTS if 'request_' in key else MAX_RECEIVER_RECEIPTS
            need(all(type(x) is int and 0<=x<=bound for x in arr),
                 key.upper()+'_BOUNDED_COUNT_REQUIRED')
        else:
            need(all(tr._sha(x) for x in arr),key.upper()+'_SHA256_INVALID')
    return parent


def _oldref(ref, forbidden):
    # Exact SHA pin label is validated, but its path is never read.
    p371.prior._ref(ref)
    forbidden.add(ref['path'])
    return ref['sha256']


def _read_old_label(oldref, newref, read, forbidden, role, limit):
    need(_oldref(oldref,forbidden)==newref.get('sha256') if type(newref) is dict else False,
         'OLD_ORIGINAL_SHA_NOT_BOUND_TO_RECEIVER_PIN_'+role.upper(),
         'permission_denied')
    return read(newref,'ec376_'+role,limit)


def _actor_sources(old, fresh, read, forbidden, role_keys, now):
    need(type(old) is list and type(fresh) is list and
         3<=len(old)==len(fresh)<=ec354.MAX_AUDITORS,
         'THREE_OR_FOUR_OLD_GOSSIP_AUDITOR_ORIGINALS_REQUIRED')
    actors={};identities=[];orgs=set()
    for old_row,recv in zip(old,fresh):
        exact(old_row,{'auditor_id','auditor_public_key','auditor_reference'},
              'OLD_EC354_AUDITOR_MANIFEST')
        exact(recv,AUDITOR_FIELDS,'RECEIVER_EC354_AUDITOR')
        need(recv['auditor_id']==old_row['auditor_id'] and
             recv['auditor_id'] not in actors,
             'GOSSIP_AUDITOR_ORIGINAL_ORDER_OR_ID_MISMATCH','permission_denied')
        key=_read_old_label(old_row['auditor_public_key'],recv['public_key_original'],
                            read,forbidden,'ec354_auditor_key',32)
        keysha=sha(key)
        need(len(key)==32 and keysha not in role_keys,
             'EC354_AUDITOR_KEY_COLLIDES_WITH_OLD_CUSTODY_OR_OTHER_ROLE',
             'permission_denied')
        role_keys.add(keysha)
        raw=_read_old_label(old_row['auditor_reference'],recv['signed_reference_original'],
                            read,forbidden,'ec354_signed_auditor_reference',ec354.MAX_ORIGINAL)
        doc=tr.strict_json(raw,'EC376_REAL_EC354_AUDITOR_REFERENCE')
        # Historical self-signed reference is checked inside its ORIGINAL
        # window, not artificially against the receiver's current wall-clock.
        at=tr._utc(doc['valid_from_utc'])
        actor=ec354._auditor(raw,key,keysha,sha(raw),at)
        need(actor['id']==recv['auditor_id'] and at<=now and
             actor['from']<=actor['until'] and
             actor['organization'].casefold() not in orgs,
             'TRUE_OLD_AUDITOR_ID_VALIDITY_OR_ORGANIZATION_COLLISION',
             'permission_denied')
        orgs.add(actor['organization'].casefold())
        actors[actor['id']]={'id':actor['id'],'key':key,
            'reference_sha':sha(raw),'from':actor['from'],
            'until':actor['until'],'organization':actor['organization'],
            'key_sha':keysha}
        identities.append({'auditor_id':actor['id'],
            'public_key_original_sha256':keysha})
    need(list(actors)==sorted(actors),'GOSSIP_AUDITORS_NOT_SORTED')
    return actors,sha(canonical.canonical(identities)),identities


def _gossip(old, fresh, actors, read, forbidden, now):
    need(type(old) is list and type(fresh) is list and
         len(old)==len(fresh)<=ec354.MAX_CHALLENGES,
         'GOSSIP_CHALLENGE_MANIFEST_COUNT_MISMATCH')
    claims={};challenges={};chall_ids=set();nonces=set();fork_counter=Counter()
    conflict=False;replies_count=0;reply_shas=set()
    for entry,recv in zip(old,fresh):
        exact(entry,{'challenge','replies'},'OLD_EC354_EXCHANGE_MANIFEST')
        exact(recv,EXCHANGE_FIELDS,'RECEIVER_EC354_SIGNED_EXCHANGE')
        need(type(entry['replies']) is list and type(recv['signed_reply_originals']) is list
             and len(entry['replies'])==len(recv['signed_reply_originals'])<=2,
             'EC354_SIGNED_REPLY_ORIGINAL_COUNT_DISAGREES')
        cp_ref=recv['signed_challenge_original']
        raw=_read_old_label(entry['challenge'],cp_ref,read,forbidden,
                            'ec354_signed_challenge',ec354.MAX_ORIGINAL)
        doc=tr.strict_json(raw,'EC376_REAL_EC354_SIGNED_CHALLENGE')
        exact(doc,('schema','challenge_id','challenger_auditor_id',
            'responder_auditor_id','challenger_reference_original_sha256',
            'responder_reference_original_sha256','parent_publication_bundle_original_sha256',
            'log_id','log_reference_original_sha256','checkpoint_original_sha256',
            'tree_size','root_hash_sha256','previous_challenge_original_sha256',
            'nonce_hex','issued_utc','signature_ed25519_hex'),
            'REAL_EC354_SIGNED_CHALLENGE')
        actor=actors.get(doc['challenger_auditor_id'])
        target=actors.get(doc['responder_auditor_id'])
        when=tr._utc(doc['issued_utc'])
        need(doc['schema']==ec354.CHALLENGE_SCHEMA and
             tr._ident(doc['challenge_id']) and
             actor is not None and target is not None and actor is not target and
             doc['challenger_reference_original_sha256']==actor['reference_sha'] and
             doc['responder_reference_original_sha256']==target['reference_sha'] and
             all(tr._sha(doc[k]) for k in (
                'parent_publication_bundle_original_sha256',
                'log_reference_original_sha256','checkpoint_original_sha256',
                'root_hash_sha256')) and
             tr._ident(doc['log_id']) and
             type(doc['tree_size']) is int and 1<=doc['tree_size']<=tr.MAX_LOG_LEAVES and
             (doc['previous_challenge_original_sha256']==ec354.GENESIS or
              tr._sha(doc['previous_challenge_original_sha256'])) and
             type(doc['nonce_hex']) is str and ec354.NONCE_RE.fullmatch(doc['nonce_hex']) is not None and
             actor['from']<=when<=actor['until'] and
             target['from']<=when<=target['until'] and when<=now,
             'REAL_GOSSIP_CHALLENGE_SIGNED_FIELDS_OR_HISTORIC_SCOPE_INVALID',
             'permission_denied')
        ec354._verify(actor['key'],doc,'signature_ed25519_hex',
                      ec354.CHALLENGE_DOMAIN,'EC376_REAL_OLD_CHALLENGE')
        digest=cp_ref['sha256']
        need(digest not in challenges and doc['challenge_id'] not in chall_ids and
             doc['nonce_hex'] not in nonces,
             'SIGNED_GOSSIP_CHALLENGE_ID_NONCE_OR_SHA_REPLAY','permission_denied')
        challenges[digest]={'doc':doc,'when':when,'pair':(
            doc['challenger_auditor_id'],doc['responder_auditor_id'],doc['log_id'])}
        chall_ids.add(doc['challenge_id']);nonces.add(doc['nonce_hex'])
        source=doc.copy();source['_sha']=digest
        reply_views=[]
        for r_old,r_new in zip(entry['replies'],recv['signed_reply_originals']):
            rraw=_read_old_label(r_old,r_new,read,forbidden,'ec354_signed_gossip_reply',
                                 ec354.MAX_ORIGINAL)
            r,responded,state=ec354._read_reply(rraw,source,{
                k:{'id':v['id'],'ref_sha':v['reference_sha'],'public_key':v['key'],
                   'from':v['from'],'until':v['until']} for k,v in actors.items()},
                {},now)
            need(r_new['sha256'] not in reply_shas,
                 'REUSED_OLD_SIGNED_REPLY_SHA','permission_denied')
            reply_shas.add(r_new['sha256']);replies_count+=1
            if r['response_kind']=='checkpoint_view':
                need(r_new['sha256'] not in claims,
                     'REUSED_GOSSIP_CLAIM_ORIGINAL_SHA','permission_denied')
                claims[r_new['sha256']]={
                    'gossip_reply_original_sha256':r_new['sha256'],
                    'gossip_challenge_original_sha256':digest,
                    'log_id':r['log_id'],
                    'claimed_checkpoint_original_sha256':r['checkpoint_original_sha256'],
                    'claimed_tree_size':r['tree_size'],
                    'claimed_root_hash_sha256':r['root_hash_sha256'],
                    'challenger_auditor_id':doc['challenger_auditor_id'],
                    'original_responder_auditor_id':doc['responder_auditor_id'],
                    'gossip_reply_utc_claim':r['responded_utc'],
                    'parent_challenged_checkpoint_original_sha256':doc['checkpoint_original_sha256'],
                    'parent_challenged_tree_size':doc['tree_size'],
                    'parent_challenged_root_hash_sha256':doc['root_hash_sha256']}
            reply_views.append((r['response_kind'],r['checkpoint_original_sha256'],
                                r['tree_size'],r['root_hash_sha256']))
        if len(reply_views)==2 and reply_views[0]!=reply_views[1]: conflict=True
    need(replies_count<=MAX_RECEIVER_REPLIES,'TOO_MANY_GENUINE_EC354_SIGNED_REPLIES')
    for digest,row in challenges.items():
        parent=row['doc']['previous_challenge_original_sha256']
        if parent!=ec354.GENESIS:
            oldrow=challenges.get(parent)
            need(oldrow is not None and oldrow['pair']==row['pair'] and
                 oldrow['when']<=row['when'],
                 'SIGNED_CHALLENGE_PREDECESSOR_MISSING_ROLE_CHANGED_OR_TIME_REVERSED',
                 'permission_denied')
        fork_counter[(row['pair'],parent)]+=1
        seen=set();cur=digest
        while cur!=ec354.GENESIS:
            need(cur in challenges and cur not in seen and len(seen)<ec354.MAX_CHAIN,
                 'SIGNED_CHALLENGE_HISTORY_CYCLE_OR_TOO_LONG','permission_denied')
            seen.add(cur)
            cur=challenges[cur]['doc']['previous_challenge_original_sha256']
    return claims,conflict or any(n>1 for n in fork_counter.values()),len(challenges),replies_count


def _disclosures(old, fresh, claims, actors, old_gossip_sha, read, forbidden, now):
    need(type(old) is list and type(fresh) is list and
         len(old)==len(fresh)<=MAX_RECEIVER_REQUESTS,
         'EC355_DISCLOSURE_REQUEST_ORIGINAL_COUNT_DISAGREES')
    requests={};receipts={};seen_ids=set();nonces=set();
    predecessor_counter=Counter();per_target=Counter();equivocation=False
    response_count=0;furnished_count=0
    for oldreq,recv in zip(old,fresh):
        exact(oldreq,{'request','responses'},'OLD_EC355_DISCLOSURE_REQUEST')
        exact(recv,REQUEST_FIELDS,'RECEIVER_EC355_SIGNED_REQUEST')
        need(type(oldreq['responses']) is list and type(recv['responses']) is list and
             len(oldreq['responses'])==len(recv['responses'])<=ec355.MAX_PER_REQUEST,
             'EC355_SIGNED_RESPONSE_ENTRY_COUNT_DISAGREES')
        reqref=recv['signed_request_original']
        raw=_read_old_label(oldreq['request'],reqref,read,forbidden,
                            'ec355_signed_request',ec354.MAX_ORIGINAL)
        reqdata=tr.strict_json(raw,'EC376_REAL_EC355_REQUEST')
        claim=claims.get(reqdata.get('gossip_reply_original_sha256'))
        need(claim is not None,
             'EC355_REQUEST_NOT_ANCHORING_REAL_SIGNED_EC354_GOSSIP_REPLY',
             'permission_denied')
        req,issued=ec355._request(raw,reqref['sha256'],claim,actors,
            {'expected_gossip_bundle_sha256':old_gossip_sha},now)
        need(req['request_id'] not in seen_ids and req['nonce_hex'] not in nonces and
             reqref['sha256'] not in requests,
             'SIGNED_EC355_REQUEST_ID_NONCE_OR_SHA_REPLAY','permission_denied')
        seen_ids.add(req['request_id']);nonces.add(req['nonce_hex'])
        req['_sha']=reqref['sha256']
        target=(req['gossip_reply_original_sha256'],req['requested_role'],
                req['requested_auditor_id'])
        per_target[target]+=1
        need(per_target[target]<=ec355.MAX_ROUNDS,
             'SIGNED_REQUEST_EXCEEDS_ALLOWED_TARGET_ROUNDS')
        requests[reqref['sha256']]={'body':req,'issued':issued,'target':target}
        visible=[]
        for oldresponse,newresponse in zip(oldreq['responses'],recv['responses']):
            exact(oldresponse,{'receipt','checkpoint','witness_statement','consistency_proof'},
                  'OLD_EC355_SIGNED_RESPONSE')
            exact(newresponse,RESPONSE_FIELDS,'RECEIVER_EC355_SIGNED_RESPONSE')
            rref=newresponse['signed_receipt_original']
            receipt_raw=_read_old_label(oldresponse['receipt'],rref,read,forbidden,
                                        'ec355_signed_receipt',ec354.MAX_ORIGINAL)
            rd,responded=ec355._receipt(receipt_raw,req,claim,actors,now)
            need(rref['sha256'] not in receipts,
                 'SIGNED_EC355_RECEIPT_ORIGINAL_SHA_REPLAY','permission_denied')
            cp=newresponse['checkpoint_original'];wit=newresponse['witness_original']
            proof=newresponse['consistency_original']
            if rd['response_kind']=='furnished_originals':
                need(type(cp) is dict and type(wit) is dict,
                     'SIGNED_FURNISHED_DISCLOSURE_REQUIRES_TWO_ORIGINAL_BYTES')
                cpbytes=_read_old_label(oldresponse['checkpoint'],cp,read,forbidden,
                    'ec355_furnished_checkpoint_original_bytes',tr.MAX_CHECKPOINT)
                witbytes=_read_old_label(oldresponse['witness_statement'],wit,read,forbidden,
                    'ec355_furnished_witness_original_bytes',tr.MAX_WITNESS)
                need(cp['sha256']==rd['checkpoint_original_sha256'] and
                     wit['sha256']==rd['witness_original_sha256'] and
                     len(cpbytes)==rd['claimed_checkpoint_length'] and
                     len(witbytes)==rd['claimed_witness_length'],
                     'SIGNED_RECEIPT_CHECKPOINT_OR_WITNESS_ACTUAL_BYTES_DISAGREE',
                     'permission_denied')
                furnished_count+=1
            else:
                need(cp is None and wit is None and
                     oldresponse['checkpoint'] is None and
                     oldresponse['witness_statement'] is None,
                     'NONFURNISHED_SIGNED_RECEIPT_CANNOT_CARRY_ORIGINAL_BYTES',
                     'permission_denied')
            if oldresponse['consistency_proof'] is not None:
                need(type(proof) is dict and rd['response_kind']=='furnished_originals',
                     'CONSISTENCY_CLAIM_REQUIRES_FURNISHED_ORIGINAL')
                # Exact original is pinned and reopened, but genuine EC353
                # checkpoint ancestry/RFC6962 proof inputs are not supplied;
                # never label the proof as verified consistency.
                _read_old_label(oldresponse['consistency_proof'],proof,read,forbidden,
                                'ec355_unreplayed_consistency_original',tr.MAX_PROOF)
            else:
                need(proof is None,'RECEIVER_ADDED_ABSENT_HISTORICAL_PROOF')
            receipts[rref['sha256']]={'request_sha':reqref['sha256'],
                'gossip_sha':req['gossip_reply_original_sha256'],
                'requested_role':req['requested_role'],
                'requester_id':req['requester_auditor_id'],
                'respondent_id':rd['respondent_auditor_id'],
                'kind':rd['response_kind'],
                'log_id':rd['log_id'],
                'cp_sha':rd['checkpoint_original_sha256'],
                'wit_sha':rd['witness_original_sha256'],
                'cp_length':rd['claimed_checkpoint_length'],
                'wit_length':rd['claimed_witness_length'],
                'responded_utc':rd['responded_utc']}
            visible.append((rd['response_kind'],rd['checkpoint_original_sha256'],
                rd['witness_original_sha256'],rd['claimed_checkpoint_length'],
                rd['claimed_witness_length']))
            response_count+=1
        if len(visible)==2 and visible[0]!=visible[1]:equivocation=True
    need(response_count<=MAX_RECEIVER_RECEIPTS,'TOO_MANY_EC355_RECEIPT_ORIGINALS')
    for digest,row in requests.items():
        earlier=row['body']['previous_request_original_sha256']
        if earlier!=ec355.GENESIS:
            parent=requests.get(earlier)
            need(parent is not None and parent['target']==row['target'] and
                 parent['issued']<=row['issued'],
                 'SIGNED_REQUEST_PREDECESSOR_MISSING_ROLE_CHANGE_OR_TIME_REVERSED',
                 'permission_denied')
        predecessor_counter[(row['target'],earlier)]+=1
        seen=set();cur=digest
        while cur!=ec355.GENESIS:
            need(cur in requests and cur not in seen and len(seen)<ec355.MAX_ROUNDS,
                 'SIGNED_REQUEST_HISTORY_CYCLE_OR_TOO_LONG','permission_denied')
            seen.add(cur);cur=requests[cur]['body']['previous_request_original_sha256']
    return (requests,receipts,
            equivocation or any(n>1 for n in predecessor_counter.values()),
            response_count,furnished_count)


def _ack_join(epoch, oldcust, requests, receipts, read, now):
    # Every old signed EC356 ACK was actually cryptographically verified in
    # the mandatory EC375 production parent. Reopen exactly its SHA-pinned
    # old original and check causal/reference joins against genuine EC355
    # request/receipt signatures; no attacker-authored audit report is used.
    per_role=defaultdict(set);per_pair=defaultdict(set)
    all_ack_shas=[];joined=0;seen_receipt_roles=defaultdict(set)
    for slot in ('a','b'):
        src=oldcust['source_'+slot]
        for item in src['acknowledgements']:
            ref=item['acknowledgement_signed_original']
            raw=read(ref,'ec376_reopen_ec375_verified_old_ec356_ack',ec356.MAX_RECORD)
            body=tr.strict_json(raw,'EC376_TRUE_OLD_EC356_SIGNED_ACK_ORIGINAL')
            exact(body,('schema','acknowledgement_id',
                'parent_disclosure_bundle_original_sha256','gossip_reply_original_sha256',
                'ec355_request_original_sha256','ec355_receipt_original_sha256',
                'ec355_requested_role','log_id','checkpoint_original_sha256',
                'witness_original_sha256','checkpoint_length','witness_length',
                'custody_status','institution_id','channel_id',
                'channel_authorization_original_sha256','previous_ack_original_sha256',
                'nonce_hex','acknowledged_utc','signature_ed25519_hex'),
                'REOPENED_PRIOR_VERIFIED_EC356_ACK')
            req=requests.get(body['ec355_request_original_sha256'])
            receipt=receipts.get(body['ec355_receipt_original_sha256'])
            need(body['schema']==ec356.ACK_SCHEMA and req is not None and
                 receipt is not None and receipt['kind']=='furnished_originals' and
                 body['parent_disclosure_bundle_original_sha256']==epoch[
                     'ec355_disclosure_bundle_original']['sha256'] and
                 receipt['request_sha']==body['ec355_request_original_sha256'] and
                 receipt['gossip_sha']==body['gossip_reply_original_sha256'] and
                 body['gossip_reply_original_sha256']==req['body'][
                     'gossip_reply_original_sha256'] and
                 body['ec355_requested_role']==req['body']['requested_role']==receipt[
                     'requested_role'] and
                 body['log_id']==receipt['log_id'] and
                 body['checkpoint_original_sha256']==receipt['cp_sha'] and
                 body['witness_original_sha256']==receipt['wit_sha'] and
                 body['checkpoint_length']==receipt['cp_length'] and
                 body['witness_length']==receipt['wit_length'] and
                 tr._utc(receipt['responded_utc'])<=tr._utc(body['acknowledged_utc'])<=now,
                 'TRUE_SIGNED_EC356_ACK_UNBOUND_TO_TRUE_EC355_REQUEST_RECEIPT_OR_TIME',
                 'permission_denied')
            per_role[body['gossip_reply_original_sha256']].add(body['ec355_requested_role'])
            if body['custody_status']=='custodied_originals':
                per_pair[body['gossip_reply_original_sha256']].add((
                    body['checkpoint_original_sha256'],body['witness_original_sha256'],
                    body['ec355_requested_role'],slot))
            seen_receipt_roles[body['ec355_receipt_original_sha256']].add(slot)
            all_ack_shas.append(ref['sha256']);joined+=1
    need(len(set(all_ack_shas))==len(all_ack_shas),
         'DUPLICATED_REOPENED_OLD_EC356_ACK_SHA','permission_denied')
    # This is a real cross-role *byte equivalence* and a signed-recipient
    # assertion. It does NOT establish genuine legal/physical independence.
    paired=any(any(a[0:2]==b[0:2] and a[2]!=b[2] and a[3]!=b[3]
                for a in pairs for b in pairs) for pairs in per_pair.values())
    claim_coverage=all({'original_responder','independent_peer'}<=roles
                       for roles in per_role.values())
    return joined,paired,claim_coverage,sorted(all_ack_shas),len(seen_receipt_roles)


def _engine(derive,**opts):
    parent_opts=_inputs(opts,derive)
    inherited=prior.audit(**parent_opts)  # REAL production EC375→EC374→...→EC369
    need(type(inherited) is dict and inherited.get('schema')==prior.RESULT_SCHEMA and
         inherited.get('exit_code')==2 and
         inherited.get('sender_origin_path_required_or_read') is False,
         'ACTUAL_PRODUCTION_EC375_THROUGH_EC369_REPLAY_REQUIRED','unavailable')
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set()
    def read(ref,role,limit):
        return p372._read(ref,role,limit,pins,categories,forbidden)
    oldcustref={'path':opts['historical_custody_archive_bundle_file'],
                'sha256':opts['expected_historical_custody_archive_bundle_sha256']}
    oldcust=tr.strict_json(read(oldcustref,'reopen_real_ec375_custody_archive',
                                prior.MAX_BUNDLE),'EC376_OLD_EC375_RECEIVER_ARCHIVE')
    exact(oldcust,prior.BUNDLE_FIELDS,'OLD_EC375_REAL_CUSTODY_ARCHIVE')
    need(oldcust['schema']==prior.BUNDLE_SCHEMA,
         'OLD_EC375_ARCHIVE_SCHEMA_MISMATCH','permission_denied')
    newref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    new=tr.strict_json(read(newref,'ec376_receiver_historical_signed_disclosure_archive',
                            MAX_BUNDLE),'EC376_NEW_RECEIVER_ARCHIVE')
    exact(new,BUNDLE_FIELDS,'RECEIVER_DISCLOSURE_ARCHIVE')
    parent_digest=sha(canonical.canonical(inherited))
    need(new['schema']==BUNDLE_SCHEMA and
         new['parent_ec375_canonical_result_sha256']==parent_digest and
         new['ec375_historical_custody_archive_original_sha256']==oldcustref['sha256'] and
         new['claimed_directory_lineage_id']==opts['claimed_historical_directory_lineage_id']
         ==oldcust['claimed_directory_lineage_id'],
         'NEW_RECEIVER_ARCHIVE_NOT_BOUND_TO_LIVE_EC375_PARENT','permission_denied')
    epochs=new['epochs'];old_epochs=oldcust['epochs']
    need(type(epochs) is list and len(epochs)==len(old_epochs)==len(
         opts['historical_directory_root_shas']) and 1<=len(epochs)<=p371.MAX_EPOCHS,
         'RECEIVER_DISCLOSURE_EPOCH_COUNT_NOT_EXACT_LIVE_PARENT')
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not inherited[
        'local_pinned_historical_custody_signatures_and_source_inventory_consistent']
    blocked=set(opts['institution_root_public_key_shas']+
        opts['witness_public_key_shas']+opts['historical_directory_root_shas']+
        [opts['expected_sender_public_key_sha256'],
         opts['expected_receiver_public_key_sha256'],
         opts['expected_publisher_public_key_sha256'],
         opts['expected_publication_observer_public_key_sha256']])
    for item in inherited['historical_custody_source_epoch_reviews']:
        blocked.update([item['root_public_key_sha'],item['channel_public_key_sha']])
    # Across epochs, an unchanged signed gossip claim + respondent/role must
    # not silently alternate the signed furnished evidence. Receipt SHA alone
    # cannot detect this: distinct genuinely signed receipts have distinct SHA.
    summaries=[];inventory_rows=[];all_receipt_claims=defaultdict(set)
    seen_auditor_ids={}  # No silent rebind of one claimed auditor ID/key.
    for i,epoch in enumerate(epochs):
        exact(epoch,EPOCH_FIELDS,'HISTORICAL_DISCLOSURE_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             old_epochs[i]['epoch_index']==i,
             'HISTORICAL_DISCLOSURE_EPOCH_NOT_CONTIGUOUS')
        old_gossip_ref=epoch['ec354_gossip_bundle_original']
        old_disclosure_ref=epoch['ec355_disclosure_bundle_original']
        gossip_doc=tr.strict_json(read(old_gossip_ref,'genuine_old_ec354_unsigned_manifest',
                                     MAX_OLD_BUNDLE),'EC376_REAL_OLD_EC354_BUNDLE')
        disclosure_doc=tr.strict_json(read(old_disclosure_ref,'genuine_old_ec355_unsigned_manifest',
                                         MAX_OLD_BUNDLE),'EC376_REAL_OLD_EC355_BUNDLE')
        exact(gossip_doc,{'schema','auditors','exchanges'},'REAL_OLD_GOSSIP_MANIFEST')
        exact(disclosure_doc,{'schema','requests'},'REAL_OLD_DISCLOSURE_MANIFEST')
        need(gossip_doc['schema']==ec354.BUNDLE_SCHEMA and
             disclosure_doc['schema']==ec355.BUNDLE_SCHEMA,
             'OLD_EC354_EC355_UNSIGNED_MANIFEST_SCHEMAS_INVALID','permission_denied')
        roles=set(blocked)
        actors,keydigest,key_inventory=_actor_sources(gossip_doc['auditors'],
            epoch['auditors'],read,forbidden,roles,now)
        for auditor_id,actor in actors.items():
            identity=(actor['key_sha'],actor['reference_sha'])
            old_identity=seen_auditor_ids.setdefault(auditor_id,identity)
            # A new self-signed auditor reference can be valid but is not a
            # signed EC354 key-rotation chain. Preserve the discontinuity as
            # adverse until its independent institutional lineage is supplied.
            if old_identity!=identity: flags[FLAGS[5]]=True
        claims,gossip_fork,challenge_count,reply_count=_gossip(gossip_doc['exchanges'],
            epoch['exchanges'],actors,read,forbidden,now)
        (requests,receipts,request_fork,receipt_count,
            furnished_count)=_disclosures(disclosure_doc['requests'],
            epoch['disclosure_requests'],claims,actors,old_gossip_ref['sha256'],
            read,forbidden,now)
        joined,quorum,coverage,acks,unique_receipts=_ack_join(epoch,old_epochs[i],
            requests,receipts,read,now)
        # Every EC356 authenticated ACK must map to an original EC355 signed
        # request+receipt, and the actual reopened original must match its bytes.
        expected_signed_ack=sum(len(old_epochs[i]['source_'+slot]['acknowledgements'])
                                for slot in ('a','b'))
        need(joined==expected_signed_ack and joined>=2,
             'HISTORICAL_ACK_ORIGINAL_COVERAGE_LOSS','permission_denied')
        if (old_gossip_ref['sha256']!=opts[
               'historical_disclosure_gossip_bundle_shas'][i] or
            old_disclosure_ref['sha256']!=opts[
               'historical_disclosure_request_bundle_shas'][i] or
            keydigest!=opts['historical_disclosure_auditor_key_inventory_shas'][i] or
            len(requests)<opts['minimum_historical_disclosure_request_counts'][i] or
            len(receipts)<opts['minimum_historical_disclosure_receipt_counts'][i]):
            flags[FLAGS[1]]=True
        flags[FLAGS[2]] |= gossip_fork
        flags[FLAGS[3]] |= request_fork
        flags[FLAGS[4]] |= not (quorum and coverage and len(claims)>0)
        # Retain all signed old gossip claims and disclosure responses, even if
        # they aren't selected by the prior EC356 ACK. No convenience subset.
        for r in receipts.values():
            claim_key=(r['gossip_sha'],r['requested_role'],r['respondent_id'])
            signed_view=(r['kind'],r['cp_sha'],r['wit_sha'],
                         r['cp_length'],r['wit_length'])
            prev=all_receipt_claims[claim_key]
            if prev and signed_view not in prev: flags[FLAGS[5]]=True
            prev.add(signed_view)
        if any(now-tr._utc(receipt['responded_utc'])>ec355.MAX_FRESHNESS
               for receipt in receipts.values()): flags[FLAGS[6]]=True
        summary={'epoch_index':i,
            'original_ec354_gossip_bundle_sha256':old_gossip_ref['sha256'],
            'original_ec355_disclosure_bundle_sha256':old_disclosure_ref['sha256'],
            'auditor_key_inventory_sha256':keydigest,
            'real_self_signed_ec354_auditor_count':len(actors),
            'real_signed_ec354_challenge_count':challenge_count,
            'real_signed_ec354_gossip_reply_count':reply_count,
            'real_signed_ec355_request_count':len(requests),
            'real_signed_ec355_receipt_count':receipt_count,
            'real_ec355_furnished_original_copy_pair_count':furnished_count,
            'real_ec356_ack_to_ec355_receipt_join_count':joined,
            'ec354_signed_gossip_conflict_or_fork_visible':gossip_fork,
            'ec355_signed_request_fork_or_equivocation_visible':request_fork,
            'same_original_claimed_by_two_separate_signed_ec355_roles':quorum,
            'acknowledged_gossip_claims_cover_both_roles':coverage}
        summaries.append(summary)
        inventory_rows.append({
            'epoch_index':i,
            'old_ec354_gossip_bundle_original_sha256':old_gossip_ref['sha256'],
            'old_ec355_disclosure_bundle_original_sha256':old_disclosure_ref['sha256'],
            'auditor_signer_originals':key_inventory,
            'genuine_signed_ec354_challenge_original_shas':sorted(
                item['signed_challenge_original']['sha256'] for item in epoch['exchanges']),
            'genuine_signed_ec354_reply_original_shas':sorted(
                pin['sha256'] for item in epoch['exchanges']
                for pin in item['signed_reply_originals']),
            'genuine_signed_ec355_request_original_shas':sorted(requests),
            'genuine_signed_ec355_receipt_original_shas':sorted(receipts),
            'genuine_earlier_ec356_verified_ack_original_shas':acks})
    # Avoid laundering a historic sender path label into new read authority.
    need(not set(pins).intersection(forbidden),
         'HISTORICAL_SENDER_PATH_LABEL_ALIASED_RECEIVER_COPY',
         'permission_denied')
    prior.tsa._check_late(pins)
    prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[-1]]=True
    inventory={'schema':INVENTORY_SCHEMA,
        'verified_live_parent_ec375_canonical_result_sha256':parent_digest,
        'ec375_custody_archive_original_sha256':oldcustref['sha256'],
        'receiver_ec376_disclosure_archive_original_sha256':newref['sha256'],
        'claimed_directory_lineage_id':new['claimed_directory_lineage_id'],
        'historical_signed_original_epoch_rows':inventory_rows}
    digest=sha(canonical.canonical(inventory))
    if not derive and opts[AUDIT_ONLY[0]]!=digest: flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:-1])
    status=next((OUTCOMES[j] for j,k in enumerate(FLAGS) if flags[k]),
                OUTCOMES[-1])+'_unresolved'
    doc={'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
        'command':'derive-historical-disclosure-inventory' if derive else
                  'audit-historical-disclosure-archive',
        'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
        'historical_disclosure_archive_bundle_original_sha256':newref['sha256'],
        'verified_live_parent_ec375_canonical_result_sha256':parent_digest,
        'receiver_verified_historical_disclosure_inventory_sha256':digest,
        'verified_real_ec354_self_signed_auditor_count':sum(r[
            'real_self_signed_ec354_auditor_count'] for r in summaries),
        'verified_real_ec354_signed_gossip_challenge_count':sum(r[
            'real_signed_ec354_challenge_count'] for r in summaries),
        'verified_real_ec354_signed_gossip_reply_count':sum(r[
            'real_signed_ec354_gossip_reply_count'] for r in summaries),
        'verified_real_ec355_signed_request_count':sum(r[
            'real_signed_ec355_request_count'] for r in summaries),
        'verified_real_ec355_signed_receipt_count':sum(r[
            'real_signed_ec355_receipt_count'] for r in summaries),
        'verified_ec355_furnished_checkpoint_witness_original_pair_count':sum(r[
            'real_ec355_furnished_original_copy_pair_count'] for r in summaries),
        'verified_real_ec356_ack_to_ec355_signed_receipt_join_count':sum(r[
            'real_ec356_ack_to_ec355_receipt_join_count'] for r in summaries),
        'historical_disclosure_epoch_reviews':summaries,
        'local_pinned_historical_disclosure_signatures_and_ack_links_consistent':local,
        'sender_origin_path_required_or_read':False,
        'ec354_through_ec337_full_historical_parent_replay_performed':False,
        **flags,**{key:False for key in NEGATIVES}}
    if derive:
        doc['unsigned_verified_historical_disclosure_inventory']=inventory
        doc['caller_external_inventory_pin_created_or_certified']=False
    return doc


def audit(**opts): return _engine(False,**opts)


def derive_inventory(**opts): return _engine(True,**opts)
