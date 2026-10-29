#!/usr/bin/env python3
"""EC377: historic *original* EC353 log, witness and RFC6962 replay.

The production EC376 audit is a mandatory parent. The retained unsigned EC353
publication manifest is used only to join original SHAs, NEVER to grant access
through its embedded historical sender paths. Every signed checkpoint and
witness is verified under the original unchanged EC353 domains. Every presented
inclusion is recomputed on actual receiver-held original leaf bytes. Signed
forks remain adverse; neither signatures nor inclusion prove legal identities,
complete EC352->EC337 historic parent results, or a global absence of forks.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import transparency as tr
from ec354_gossip import gossip as ec354
from ec355_disclosure import disclosure as ec355
from ec371_historical_archive import archive as p371
from ec372_historical_authority import authority_archive as p372
from ec376_historical_disclosure import disclosure_archive as previous

RESULT_SCHEMA='ces.ec377.receiver_genuine_old_ec353_signed_merkle_ancestry_unresolved.v1'
DERIVE_SCHEMA='ces.ec377.unsigned_receiver_old_ec353_original_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec377.receiver_genuine_old_ec353_merkle_denial.v1'
BUNDLE_SCHEMA='ces.ec377.receiver_historical_ec353_transparency_original_archive.v1'
INVENTORY_SCHEMA='ces.ec377.receiver_verified_old_ec353_merkle_original_sha_inventory.v1'
MAX_BUNDLE=190_000
MAX_OLD_MANIFEST=tr.MAX_BUNDLE
NEW_SCALARS=('historical_transparency_archive_bundle_file',
             'expected_historical_transparency_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_transparency_inventory_sha256',)
NEW_REPEATS=(
 ('historical_transparency_publication_bundle_shas','--historical-transparency-publication-bundle-sha256'),
 ('historical_transparency_log_key_inventory_shas','--historical-transparency-log-key-inventory-sha256'),
 ('historical_transparency_signed_head_inventory_shas','--historical-transparency-signed-head-inventory-sha256'),
 ('minimum_historical_transparency_tree_sizes','--minimum-historical-transparency-tree-size'),
 ('minimum_historical_transparency_inclusion_counts','--minimum-historical-transparency-inclusion-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*previous.PARENT_SCALARS,*previous.NEW_SCALARS,*previous.AUDIT_ONLY)
PARENT_REPEATS=(*previous.PARENT_REPEATS,*previous.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec376_canonical_result_sha256',
               'ec376_historical_disclosure_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','ec353_publication_bundle_original','logs'}
LOG_FIELDS={'log_id','log_public_key_original','log_reference_original',
            'witness_public_key_original','witness_reference_original',
            'checkpoints','inclusions'}
CHECKPOINT_FIELDS={'signed_checkpoint_original','signed_witness_original',
                   'consistency_original'}
INCLUSION_FIELDS={'proof_original','artifact_original'}
FLAGS=(
 'inherited_true_ec376_through_ec369_original_dispute_unresolved',
 'independently_retained_ec353_log_key_head_or_inclusion_floor_mismatch',
 'real_old_ec353_signed_log_fork_or_rfc6962_consistency_dispute_visible',
 'old_ec353_signed_witness_independence_or_log_role_conflict_visible',
 'old_ec353_original_inclusion_or_gossip_disclosure_coverage_unresolved',
 'old_ec353_signed_claimed_utc_stale_or_causal_conflict_visible',
 'old_ec353_cross_epoch_signed_head_key_or_ancestry_conflict_visible',
 'genuine_old_ec353_crypto_slice_not_complete_old_ec352_through_ec337_ancestry',
)
OUTCOMES=(
 'ec377_inherited_receiver_old_signed_original_adversity',
 'ec377_outside_retained_old_transparency_key_head_or_inclusion_floor_disagrees',
 'ec377_true_old_signed_merkle_fork_or_consistency_dispute',
 'ec377_genuine_witness_organizational_or_key_role_conflict',
 'ec377_real_ec353_merkle_inclusion_or_old_claim_coverage_incomplete',
 'ec377_signed_publication_claimed_utc_causal_or_freshness_dispute',
 'ec377_historical_signed_log_identity_or_head_ancestry_dispute',
 'ec377_genuine_old_ec353_crypto_only_parent_history_incomplete',
)
NEGATIVES=(
 'complete_old_ec353_through_ec337_canonical_parent_results_rebuilt',
 'old_ec352_registry_root_event_signatures_and_issuer_replayed',
 'ec353_unsigned_original_manifest_proves_authorized_external_log',
 'ec353_signed_log_and_witness_keys_prove_official_legal_independence',
 'ec353_valid_merkle_leaf_proves_authorized_old_registry_issuer',
 'ec353_valid_merkle_tree_proves_global_completeness_or_no_hidden_forks',
 'old_ec354_gossip_signed_claim_alone_proves_witnessed_checkpoint',
 'old_ec355_signed_receipt_alone_proves_checkpoint_and_merkle_validity',
 'old_ec353_or_ec354_sender_origin_label_paths_opened',
 'old_ec362_source_copy_or_ec369_sender_paths_opened',
 'signed_witness_utc_proves_independently_calibrated_external_time',
 'verified_originals_prove_external_physical_custody',
 'old_parent_canonical_ec355_or_ec356_results_reproduced',
 'new_private_signer_network_provider_cas_worm_or_native_ps_invoked',
 'historic_ec366_to_ec337_deep_mock_replaced_or_final_acceptance_proven',
)


def need(ok,reason,status='invalid_input'):
    if ok is not True:raise errors.AnchorError('EC377_'+reason,status)


def exact(doc,fields,role):
    need(type(doc) is dict and set(doc)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return previous.sha(raw)


def _inputs(opts,derive):
    keys=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:keys.update(AUDIT_ONLY)
    need(set(opts)==keys,'EXACT_PRODUCTION_PARENT_AND_RECEIVER_INPUTS_REQUIRED')
    parent={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    previous._inputs(parent,False)
    p371.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC377_INDEPENDENT_RECEIVER_ARCHIVE')
    if not derive:need(tr._sha(opts[AUDIT_ONLY[0]]),
                       'OUTSIDE_RETAINED_UNSIGNED_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=p371.MAX_EPOCHS,'HISTORIC_EPOCH_COUNT_INVALID')
    for key in REPEAT_NAMES:
        values=opts[key]
        need(type(values) is list and len(values)==n,
             key.upper()+'_ONE_PER_HISTORICAL_EPOCH_REQUIRED')
        if key.startswith('minimum_'):
            cap=tr.MAX_LOG_LEAVES if 'tree_sizes' in key else 2*tr.MAX_INCLUSIONS_PER_LOG
            need(all(type(v) is int and 0<=v<=cap for v in values),
                 key.upper()+'_COUNT_FLOOR_OUT_OF_BOUNDS')
        else:
            need(all(tr._sha(v) for v in values),key.upper()+'_ORIGINAL_SHA_INVALID')
    return parent


def _pair(old,receiver,read,forbidden,role,limit):
    previous._oldref(old,forbidden)
    need(type(receiver) is dict and old['sha256']==receiver.get('sha256'),
         role+'_ORIGINAL_LABEL_SHA_NOT_EQUAL_RECEIVER_PIN','permission_denied')
    return read(receiver,role,limit)


def _log(old,receiver,read,forbidden,evaluation,used_keys,orgs,caller_exclusions):
    exact(old,{'log_id','log_reference','log_public_key','witness_reference',
               'witness_public_key','checkpoints','inclusions'},'OLD_EC353_LOG')
    exact(receiver,LOG_FIELDS,'RECEIVER_EC353_LOG')
    logid=old['log_id']
    need(tr._ident(logid) and receiver['log_id']==logid,
         'LOG_ID_OR_SORTED_RECEIVER_MAPPING_MISMATCH','permission_denied')
    oldc=old['checkpoints'];newc=receiver['checkpoints']
    oldi=old['inclusions'];newi=receiver['inclusions']
    need(type(oldc) is list and type(newc) is list and
         1<=len(oldc)==len(newc)<=tr.MAX_CHECKPOINTS_PER_LOG and
         type(oldi) is list and type(newi) is list and
         1<=len(oldi)==len(newi)<=tr.MAX_INCLUSIONS_PER_LOG,
         'REAL_OLD_CHECKPOINT_OR_INCLUSION_COUNT_MISMATCH')
    kref=receiver['log_public_key_original'];wref=receiver['witness_public_key_original']
    key=_pair(old['log_public_key'],kref,read,forbidden,'signed_log_key',32)
    witness_key=_pair(old['witness_public_key'],wref,read,forbidden,'signed_witness_key',32)
    need(len(key)==len(witness_key)==32 and kref['sha256']!=wref['sha256'] and
         not {kref['sha256'],wref['sha256']}.intersection(used_keys|caller_exclusions),
         'LOG_OR_WITNESS_SIGNER_KEY_REUSED_AS_ANOTHER_ROLE','permission_denied')
    used_keys.update((kref['sha256'],wref['sha256']))
    log_ref=receiver['log_reference_original'];wit_ref=receiver['witness_reference_original']
    raw_ref=_pair(old['log_reference'],log_ref,read,forbidden,
                  'ec353_log_signed_self_reference',tr.MAX_REFERENCE)
    raw_wref=_pair(old['witness_reference'],wit_ref,read,forbidden,
                   'ec353_witness_signed_self_reference',tr.MAX_REFERENCE)
    # Original EC353 verifier and domains, without weakening key validity.
    log_doc=tr._ref(raw_ref,key,kref['sha256'],logid,evaluation,is_witness=False)
    wit_doc=tr._ref(raw_wref,witness_key,wref['sha256'],logid,evaluation,is_witness=True)
    log={'id':logid,'log_key':key,'witness_key':witness_key,
         'log_ref':log_doc,'witness_ref':wit_doc,'log_ref_sha':log_ref['sha256'],
         'witness_ref_sha':wit_ref['sha256']}
    for name in (log_doc['claimed_log_organization'],wit_doc['claimed_witness_organization']):
        orgs[name.casefold()]+=1
    cps={};witnesses={};proof_pins=[];signed_causal=[]
    for oldrow,newrow in zip(oldc,newc):
        exact(oldrow,{'checkpoint','witness_statement','consistency_proof'},
              'OLD_EC353_CHECKPOINT_ROW')
        exact(newrow,CHECKPOINT_FIELDS,'RECEIVER_EC353_CHECKPOINT_ROW')
        raw_cp=_pair(oldrow['checkpoint'],newrow['signed_checkpoint_original'],
                     read,forbidden,'real_old_ec353_signed_checkpoint',tr.MAX_CHECKPOINT)
        cp=tr._checkpoint(raw_cp,log,evaluation)
        raw_wit=_pair(oldrow['witness_statement'],newrow['signed_witness_original'],
                      read,forbidden,'real_old_ec353_signed_witness',tr.MAX_WITNESS)
        witness=tr._witness(raw_wit,cp,log,evaluation)
        need(cp['sha256'] not in cps and witness['sha256'] not in witnesses,
             'REUSED_SIGNED_CHECKPOINT_OR_WITNESS_ORIGINAL')
        cp['witness']=witness
        cp['witness_sha']=witness['sha256']
        cp['consistency_pin']=newrow['consistency_original']
        cp['consistency_old_label']=oldrow['consistency_proof']
        cps[cp['sha256']]=cp
        witnesses[witness['sha256']]=cp['sha256']
        signed_causal.append((cp['issued'],witness['claimed_time']))
    graph_dispute=False;missing_consistency=False
    children=Counter(cp['body']['previous_checkpoint_original_sha256'] for cp in cps.values())
    for cp in cps.values():
        prev=cp['body']['previous_checkpoint_original_sha256']
        oldproof=cp['consistency_old_label'];newproof=cp['consistency_pin']
        if prev==tr.GENESIS:
            need(oldproof is None and newproof is None,
                 'GENESIS_CHECKPOINT_CANNOT_HAVE_CONSISTENCY_PROOF')
        else:
            need(prev in cps and prev!=cp['sha256'],
                 'OLD_SIGNED_CHECKPOINT_PREDECESSOR_MISSING_OR_SELF','permission_denied')
            predecessor=cps[prev]
            if predecessor['size']>cp['size'] or predecessor['issued']>cp['issued']:
                graph_dispute=True
            if predecessor['size']==cp['size'] and predecessor['root']!=cp['root']:
                graph_dispute=True
            if oldproof is None or newproof is None:
                need(oldproof is None and newproof is None,
                     'OLD_CONSISTENCY_RECEIVER_PIN_PRESENCE_MISMATCH')
                if (predecessor['size'],predecessor['root'])!=(cp['size'],cp['root']):
                    missing_consistency=True
            else:
                rawproof=_pair(oldproof,newproof,read,forbidden,
                               'ec353_actual_rfc6962_consistency',tr.MAX_PROOF)
                if not tr._parse_consistency(rawproof,logid,predecessor,cp):
                    graph_dispute=True
                proof_pins.append(newproof['sha256'])
    ancestry={}
    for digest,cp in cps.items():
        chain=[];current=digest;seen=set()
        while current!=tr.GENESIS:
            need(current in cps and current not in seen and len(seen)<=tr.MAX_CHECKPOINTS_PER_LOG,
                 'SIGNED_CHECKPOINT_HISTORY_CYCLE_OR_MISSING_ANCESTOR',
                 'permission_denied')
            seen.add(current);chain.append(current)
            current=cps[current]['body']['previous_checkpoint_original_sha256']
        chain.reverse();ancestry[digest]=chain
        if any(cps[b]['issued']-cps[a]['issued']>tr.MAX_CHECKPOINT_GAP
               for a,b in zip(chain,chain[1:])):graph_dispute=True
    heads=sorted(set(cps)-{p for p in children if p!=tr.GENESIS})
    fork=(len(heads)!=1 or children[tr.GENESIS]!=1 or
          any(count>1 for prev,count in children.items() if prev!=tr.GENESIS) or
          any(a['size']==b['size'] and a['root']!=b['root']
              for a in cps.values() for b in cps.values()))
    artifacts={};inclusion_pins=[];covered=[];visited=set()
    for oldrow,newrow in zip(oldi,newi):
        exact(newrow,INCLUSION_FIELDS,'RECEIVER_EC353_INCLUSION_ROW')
        # The *old EC353 manifest* furnishes a proof path only, not an old
        # EC352 artifact label. The receiver supplies a separate original
        # leaf and SHA; this does not authenticate its EC352 issuing signer.
        rawproof=_pair(oldrow,newrow['proof_original'],read,forbidden,
                       'old_ec353_real_rfc6962_inclusion',tr.MAX_PROOF)
        proof=tr.strict_json(rawproof,'EC377_REAL_INCLUSION_PROOF')
        cp=cps.get(proof.get('checkpoint_original_sha256'))
        need(cp is not None,'INCLUSION_CHECKPOINT_NOT_IN_REAL_SIGNED_HISTORY',
             'permission_denied')
        kind=proof.get('artifact_kind');artifact_sha=proof.get('artifact_original_sha256')
        need(kind in ('registry_root_reference','registry_event') and tr._sha(artifact_sha),
             'INCLUSION_OLD_EC352_ARTIFACT_KIND_OR_SHA_INVALID')
        artifact_ref=newrow['artifact_original']
        need(type(artifact_ref) is dict and artifact_ref.get('sha256')==artifact_sha,
             'INCLUSION_RECEIVED_ARTIFACT_SHA_NOT_EQUAL_PROOF','permission_denied')
        raw_artifact=read(artifact_ref,'old_ec352_merkle_leaf_original',32_000)
        artifacts[(kind,artifact_sha)]=raw_artifact
        identity=(cp['sha256'],kind,artifact_sha)
        need(identity not in visited,'DUPLICATED_OLD_EC353_CHECKPOINT_LEAF_PROOF')
        visited.add(identity)
        _,_,ok=tr._parse_inclusion(rawproof,logid,cp,artifacts)
        need(ok,'REAL_RFC6962_OLD_ORIGINAL_INCLUSION_NOT_VERIFIED',
             'permission_denied')
        inclusion_pins.append(newrow['proof_original']['sha256'])
        covered.append({'checkpoint_original_sha256':cp['sha256'],
                        'artifact_kind':kind,'artifact_original_sha256':artifact_sha})
    stale=any(evaluation>cp['witness']['claimed_time']+tr.MAX_WITNESS_FRESHNESS
              for cp in cps.values() if cp['sha256'] in heads)
    oldest=any(wit_when<cp_when for cp_when,wit_when in signed_causal)
    return {'id':logid,'log_reference_sha':log_ref['sha256'],
        'log_key_sha':kref['sha256'],'witness_key_sha':wref['sha256'],
        'witness_reference_sha':wit_ref['sha256'],
        'checkpoints':cps,'witnesses':witnesses,'heads':heads,
        'ancestry':ancestry,'fork':fork,'consistency_dispute':graph_dispute or missing_consistency,
        'stale':stale or oldest,'inclusion_count':len(covered),
        'leaf_coverage':covered,
        'evidence':{'log_id':logid,'log_public_key_original_sha256':kref['sha256'],
          'witness_public_key_original_sha256':wref['sha256'],
          'log_reference_original_sha256':log_ref['sha256'],
          'witness_reference_original_sha256':wit_ref['sha256'],
          'signed_checkpoint_original_shas':sorted(cps),
          'signed_witness_original_shas':sorted(witnesses),
          'consistency_original_shas':sorted(proof_pins),
          'inclusion_original_shas':sorted(inclusion_pins),
          'actual_leaf_originals':sorted(covered,key=lambda x:(x['checkpoint_original_sha256'],
                                         x['artifact_kind'],x['artifact_original_sha256']))}}


def _bind_claims(old_gossip,recv_ec376,logs,read,evaluation,publication_sha):
    # Parent EC376 already verified *every* one of these exact signed originals.
    # Reopening rather than borrowing its summary prevents a newly asserted
    # unsigned SHA from being counted as an authenticated EC354 claim.
    exact(old_gossip,{'schema','auditors','exchanges'},'REOPEN_TRUE_EC354_GOSSIP_MANIFEST')
    need(old_gossip['schema']==ec354.BUNDLE_SCHEMA and
         len(old_gossip['exchanges'])==len(recv_ec376['exchanges']),
         'REOPENED_EC354_EXCHANGE_COUNT_CHANGED','permission_denied')
    challenge_count=0;replies=0;temporal_dispute=False
    for oldex,newex in zip(old_gossip['exchanges'],recv_ec376['exchanges']):
        exact(newex,previous.EXCHANGE_FIELDS,'REOPEN_EC376_SIGNED_EXCHANGE')
        challenge_ref=newex['signed_challenge_original']
        c=tr.strict_json(read(challenge_ref,'reopen_ec376_verified_ec354_challenge',
                              ec354.MAX_ORIGINAL),'OLD_EC354_CHALLENGE')
        need(challenge_ref['sha256']==oldex['challenge']['sha256'],
             'SIGNED_CHALLENGE_REOPENED_SHA_CHANGED','permission_denied')
        log=logs.get(c.get('log_id'))
        cp=log['checkpoints'].get(c.get('checkpoint_original_sha256')) if log else None
        need(cp is not None and c['parent_publication_bundle_original_sha256']==publication_sha and
             c['log_reference_original_sha256']==log['log_reference_sha'] and
             c['tree_size']==cp['size'] and
             c['root_hash_sha256']==cp['body']['root_hash_sha256'],
             'SIGNED_EC354_CHALLENGE_NOT_MATCHING_GENUINE_EC353_SIGNED_CHECKPOINT',
             'permission_denied')
        challenged=tr._utc(c['issued_utc'])
        if cp['issued']>challenged or cp['witness']['claimed_time']>challenged:
            temporal_dispute=True
        challenge_count+=1
        for ref in newex['signed_reply_originals']:
            r=tr.strict_json(read(ref,'reopen_ec376_verified_ec354_reply',
                                ec354.MAX_ORIGINAL),'OLD_EC354_REPLY')
            if r['response_kind']=='checkpoint_view':
                target=log['checkpoints'].get(r['checkpoint_original_sha256'])
                need(target is not None and
                     r['tree_size']==target['size'] and
                     r['root_hash_sha256']==target['body']['root_hash_sha256'],
                     'SIGNED_EC354_REPLY_HAS_NO_REAL_SIGNED_EC353_CHECKPOINT',
                     'permission_denied')
                if target['issued']>tr._utc(r['responded_utc']) or (
                    target['witness']['claimed_time']>tr._utc(r['responded_utc'])):
                    temporal_dispute=True
            replies+=1
    return challenge_count,replies,temporal_dispute


def _bind_disclosures(ec376_epoch,old_disclosure,logs,read):
    exact(old_disclosure,{'schema','requests'},'OLD_EC355_REOPEN_DISCLOSURE')
    need(old_disclosure['schema']==ec355.BUNDLE_SCHEMA and
         len(old_disclosure['requests'])==len(ec376_epoch['disclosure_requests']),
         'REOPENED_EC355_REQUEST_COUNT_CHANGED','permission_denied')
    furnished=0;causal=False
    for old,new in zip(old_disclosure['requests'],ec376_epoch['disclosure_requests']):
        exact(new,previous.REQUEST_FIELDS,'TRUE_RECEIVER_EC355_REQUEST_REOPEN')
        req=tr.strict_json(read(new['signed_request_original'],
              'reopen_ec376_verified_ec355_request',ec354.MAX_ORIGINAL),
              'EC377_REOPEN_OLD_SIGNED_REQUEST')
        log=logs.get(req.get('log_id'))
        need(log is not None,'OLD_EC355_REQUEST_UNKNOWN_AUTHENTICATED_LOG',
             'permission_denied')
        for original,recv in zip(old['responses'],new['responses']):
            exact(recv,previous.RESPONSE_FIELDS,'REOPEN_EC376_RECEIPT')
            rec=tr.strict_json(read(recv['signed_receipt_original'],
                   'reopen_ec376_verified_ec355_receipt',ec354.MAX_ORIGINAL),
                   'EC377_REOPEN_SIGNED_RECEIPT')
            if rec['response_kind']!='furnished_originals':continue
            cp=log['checkpoints'].get(rec['checkpoint_original_sha256'])
            need(cp is not None and rec['witness_original_sha256']==cp['witness_sha'] and
                 recv['checkpoint_original']['sha256']==cp['sha256'] and
                 recv['witness_original']['sha256']==cp['witness_sha'] and
                 rec['log_id']==log['id'],
                 'REAL_EC355_FURNISHED_CHECKPOINT_WITNESS_NOT_EC353_SIGNED_VERIFIED',
                 'permission_denied')
            # EC376 checked exact receiver bytes and the signed lengths and
            # bound these true receipts to every original signed EC356 ACK.
            if cp['witness']['claimed_time']>tr._utc(rec['responded_utc']):causal=True
            furnished+=1
    return furnished,causal


def _engine(derive,**opts):
    parent_opts=_inputs(opts,derive)
    inherited=previous.audit(**parent_opts)  # mandatory REAL EC376 -> ... -> EC369
    need(type(inherited) is dict and inherited.get('schema')==previous.RESULT_SCHEMA and
         inherited.get('exit_code')==2 and
         inherited.get('sender_origin_path_required_or_read') is False,
         'REAL_PRODUCTION_EC376_THROUGH_EC369_REPLAY_REQUIRED','unavailable')
    evaluation=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set()
    def read(ref,role,cap):return p372._read(ref,'ec377_'+role,cap,pins,categories,forbidden)
    old_ec376_ref={'path':opts['historical_disclosure_archive_bundle_file'],
          'sha256':opts['expected_historical_disclosure_archive_bundle_sha256']}
    old376=tr.strict_json(read(old_ec376_ref,'reopen_real_ec376_receiver_archive',
         previous.MAX_BUNDLE),'REOPEN_REAL_EC376_RECEIVER_ARCHIVE')
    exact(old376,previous.BUNDLE_FIELDS,'REOPEN_EC376_RECEIVER_ARCHIVE')
    need(old376['schema']==previous.BUNDLE_SCHEMA,
         'REAL_EC376_RECEIVER_ARCHIVE_SCHEMA_CHANGED','permission_denied')
    ref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    doc=tr.strict_json(read(ref,'independently_pinned_ec377_receiver_archive',
         MAX_BUNDLE),'EC377_RECEIVER_ARCHIVE')
    exact(doc,BUNDLE_FIELDS,'EC377_RECEIVER_ARCHIVE')
    parent_sha=sha(canonical.canonical(inherited))
    need(doc['schema']==BUNDLE_SCHEMA and
         doc['parent_ec376_canonical_result_sha256']==parent_sha and
         doc['ec376_historical_disclosure_archive_original_sha256']==old_ec376_ref['sha256'] and
         doc['claimed_directory_lineage_id']==opts['claimed_historical_directory_lineage_id']==
           old376['claimed_directory_lineage_id'],
         'EC377_ARCHIVE_NOT_BOUND_TO_AUTHENTICATED_LIVE_EC376_PARENT','permission_denied')
    epochs=doc['epochs']
    need(type(epochs) is list and len(epochs)==len(old376['epochs'])==len(
         opts['historical_directory_root_shas']),
         'EC377_EPOCH_COUNT_OR_INHERITED_EPOCH_DISAGREEMENT')
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not inherited[
       'local_pinned_historical_disclosure_signatures_and_ack_links_consistent']
    previous_keys=set(opts['institution_root_public_key_shas']+
        opts['witness_public_key_shas']+opts['historical_directory_root_shas']+
        [opts['expected_sender_public_key_sha256'],opts['expected_receiver_public_key_sha256'],
         opts['expected_publisher_public_key_sha256'],
         opts['expected_publication_observer_public_key_sha256']])
    for e in inherited['historical_disclosure_epoch_reviews']:
        # Parent inventory SHA is retained independently by EC376 audit;
        # each original auditor key is reopened from that exact archive.
        need(type(e) is dict,'PARENT_EC376_EPOCH_REVIEW_REQUIRED')
    for e in old376['epochs']:
        for aud in e['auditors']:
            previous_keys.add(aud['public_key_original']['sha256'])
    # The EC375 old custody root/channel originals were authenticated by
    # EC376's mandatory parent. Reopen that receiver archive solely to forbid
    # a genuine historic custodial signer key being recycled as an allegedly
    # independent EC353 log or witness signing key.
    old375=tr.strict_json(read({'path':opts['historical_custody_archive_bundle_file'],
        'sha256':opts['expected_historical_custody_archive_bundle_sha256']},
        'reopen_prior_signed_custody_role_key_inventory',previous.prior.MAX_BUNDLE),
        'EC377_AUTHENTICATED_EC375_CUSTODY_RECEIVER_ARCHIVE')
    exact(old375,previous.prior.BUNDLE_FIELDS,'REOPEN_AUTHENTICATED_EC375_ARCHIVE')
    need(old375['schema']==previous.prior.BUNDLE_SCHEMA and
         len(old375['epochs'])==len(old376['epochs']),
         'REAL_PRIOR_CUSTODY_EPOCH_OR_SCHEMA_CHANGED','permission_denied')
    for e in old375['epochs']:
        for slot in ('a','b'):
            source=e['source_'+slot]
            previous_keys.update((source['root_public_key_original']['sha256'],
                                  source['channel_public_key_original']['sha256']))
    summaries=[];inventory_rows=[];identities={};prior_heads={}
    total_challenges=total_replies=total_furnished=total_inclusions=total_checkpoints=0
    for i,epoch in enumerate(epochs):
        exact(epoch,EPOCH_FIELDS,'HISTORICAL_EC353_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             old376['epochs'][i]['epoch_index']==i,
             'EC353_OLD_RECEIVER_EPOCH_INDEX_NOT_CONTIGUOUS')
        pub_ref=epoch['ec353_publication_bundle_original']
        pub=tr.strict_json(read(pub_ref,'old_ec353_unsigned_publication_manifest',
                     MAX_OLD_MANIFEST),'REAL_OLD_EC353_PUBLICATION_BUNDLE')
        exact(pub,{'schema','logs'},'REAL_OLD_EC353_BUNDLE')
        need(pub['schema']==tr.BUNDLE_SCHEMA and type(pub['logs']) is list and
             len(pub['logs'])==2 and type(epoch['logs']) is list and
             len(epoch['logs'])==2,
             'REAL_EC353_TWO_LOG_MANIFEST_OR_RECEIVER_COUNT_INVALID',
             'permission_denied')
        used=set();orgs=Counter();logs={}
        for auditor in old376['epochs'][i]['auditors']:
            # EC376 verified this exact auditor self-signature. Reopening its
            # original claimed organization allows a conservative *claimed*
            # organization collision flag, not a legal independence verdict.
            actor=tr.strict_json(read(auditor['signed_reference_original'],
                 'old_ec354_auditor_role_organization',ec354.MAX_ORIGINAL),
                 'EC377_REOPEN_VERIFIED_OLD_AUDITOR_REFERENCE')
            need(actor['auditor_id']==auditor['auditor_id'] and
                 actor['schema']==ec354.AUDITOR_SCHEMA,
                 'REAL_OLD_AUDITOR_ORIGINAL_REFERENCE_REBOUND','permission_denied')
            orgs[actor['claimed_auditor_organization'].casefold()]+=1
        for oldlog,newlog in zip(pub['logs'],epoch['logs']):
            log=_log(oldlog,newlog,read,forbidden,evaluation,used,orgs,previous_keys)
            need(log['id'] not in logs,'DUPLICATED_REAL_EC353_LOG_ID')
            logs[log['id']]=log
        need(list(logs)==sorted(logs),'REAL_OLD_EC353_LOGS_NOT_SORTED')
        log_identity=[{'log_id':l['id'],
          'log_public_key_original_sha256':l['log_key_sha'],
          'witness_public_key_original_sha256':l['witness_key_sha']}
          for l in logs.values()]
        head_identity=[{'log_id':l['id'],'signed_head_original_shas':l['heads']}
          for l in logs.values()]
        keyhash=sha(canonical.canonical(log_identity))
        headhash=sha(canonical.canonical(head_identity))
        flags[FLAGS[1]] |= (pub_ref['sha256']!=opts[
             'historical_transparency_publication_bundle_shas'][i] or
             keyhash!=opts['historical_transparency_log_key_inventory_shas'][i] or
             headhash!=opts['historical_transparency_signed_head_inventory_shas'][i])
        challenges,replies,gossip_causal=_bind_claims(
             tr.strict_json(read(old376['epochs'][i]['ec354_gossip_bundle_original'],
                        'reopen_original_ec354_gossip_manifest',previous.MAX_OLD_BUNDLE),
                        'EC377_OLD_GOSSIP'),old376['epochs'][i],logs,read,evaluation,
             pub_ref['sha256'])
        furnished,disclosure_causal=_bind_disclosures(old376['epochs'][i],
            tr.strict_json(read(old376['epochs'][i][
                'ec355_disclosure_bundle_original'],'ec355_old_disclosure_manifest',
                previous.MAX_OLD_BUNDLE),'EC377_OLD_DISCLOSURE'),logs,read)
        checkpoints=sum(len(l['checkpoints']) for l in logs.values())
        inclusions=sum(l['inclusion_count'] for l in logs.values())
        heads_floor=min((max(l['checkpoints'][head]['size'] for head in l['heads'])
                         if l['heads'] else 0) for l in logs.values())
        flags[FLAGS[1]] |= (heads_floor<opts[
            'minimum_historical_transparency_tree_sizes'][i] or
            inclusions<opts['minimum_historical_transparency_inclusion_counts'][i])
        flags[FLAGS[2]] |= any(l['fork'] or l['consistency_dispute'] for l in logs.values())
        flags[FLAGS[3]] |= any(n>1 for n in orgs.values())
        flags[FLAGS[4]] |= (not challenges or not replies or not furnished or
                            any(not l['heads'] or not l['inclusion_count'] for l in logs.values()))
        flags[FLAGS[5]] |= (gossip_causal or disclosure_causal or
                            any(l['stale'] for l in logs.values()))
        for log in logs.values():
            ident=(log['log_key_sha'],log['witness_key_sha'],log['log_reference_sha'],
                   log['witness_reference_sha'])
            prev=identities.setdefault(log['id'],ident)
            if prev!=ident:flags[FLAGS[6]]=True
            prior_head=prior_heads.get(log['id'])
            if prior_head is not None:
                # Only the actual signed predecessor ancestry from the new
                # epoch can confirm movement from the previous signed head.
                if len(prior_head)!=1 or len(log['heads'])!=1 or not (
                    prior_head[0] in log['ancestry'][log['heads'][0]]):
                    flags[FLAGS[6]]=True
            prior_heads[log['id']]=log['heads']
        summaries.append({'epoch_index':i,
            'old_ec353_publication_bundle_original_sha256':pub_ref['sha256'],
            'real_signed_log_reference_and_witness_key_inventory_sha256':keyhash,
            'real_signed_checkpoint_head_inventory_sha256':headhash,
            'genuinely_verified_log_reference_count':len(logs),
            'genuinely_verified_signed_checkpoint_count':checkpoints,
            'genuinely_verified_signed_witness_count':checkpoints,
            'genuinely_recomputed_original_rfc6962_inclusion_count':inclusions,
            'old_ec354_true_signed_challenges_bound':challenges,
            'old_ec354_true_signed_replies_bound':replies,
            'old_ec355_signed_furnished_pairs_bound':furnished,
            'signed_checkpoint_fork_or_merkle_consistency_dispute':any(
                   l['fork'] or l['consistency_dispute'] for l in logs.values()),
            'claimed_log_witness_organization_overlap':any(v>1 for v in orgs.values()),
            'old_signed_witness_causal_or_freshness_dispute':gossip_causal or
                    disclosure_causal or any(l['stale'] for l in logs.values()),
            'signed_log_heads_at_least_external_tree_size_floor':heads_floor>=opts[
                    'minimum_historical_transparency_tree_sizes'][i]})
        inventory_rows.append({'epoch_index':i,
            'old_ec353_publication_bundle_original_sha256':pub_ref['sha256'],
            'real_signed_log_and_witness_originals':[l['evidence'] for l in logs.values()],
            'real_signed_head_inventory_sha256':headhash,
            'old_ec354_signed_challenge_original_shas':sorted(ex[
                'signed_challenge_original']['sha256'] for ex in old376['epochs'][i]['exchanges']),
            'old_ec355_original_furnished_checkpoint_witness_pairs':sorted(
                [{'checkpoint_original_sha256':rec['checkpoint_original']['sha256'],
                 'witness_original_sha256':rec['witness_original']['sha256']}
                 for req in old376['epochs'][i]['disclosure_requests']
                 for rec in req['responses'] if rec['checkpoint_original'] is not None],
                key=lambda x:(x['checkpoint_original_sha256'],x['witness_original_sha256']))})
        total_challenges+=challenges;total_replies+=replies;total_furnished+=furnished
        total_checkpoints+=checkpoints;total_inclusions+=inclusions
    need(not set(pins).intersection(forbidden),
         'ORIGINAL_SENDER_HISTORIC_PATH_LABEL_ALIASES_RECEIVER_FILE',
         'permission_denied')
    previous.prior.tsa._check_late(pins)
    previous.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[-1]]=True
    inventory={'schema':INVENTORY_SCHEMA,
       'verified_live_parent_ec376_canonical_result_sha256':parent_sha,
       'ec376_disclosure_archive_original_sha256':old_ec376_ref['sha256'],
       'receiver_ec377_transparency_archive_original_sha256':ref['sha256'],
       'claimed_directory_lineage_id':doc['claimed_directory_lineage_id'],
       'old_ec353_signed_original_epoch_rows':inventory_rows}
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[name] for name in FLAGS[:-1])
    status=next((OUTCOMES[j] for j,name in enumerate(FLAGS) if flags[name]),
                OUTCOMES[-1])+'_unresolved'
    result={'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-transparency-inventory' if derive else
                 'audit-historical-transparency-archive',
       'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
       'historical_transparency_archive_bundle_original_sha256':ref['sha256'],
       'verified_live_parent_ec376_canonical_result_sha256':parent_sha,
       'receiver_verified_historical_transparency_inventory_sha256':digest,
       'verified_real_ec353_signed_log_reference_count':sum(
           r['genuinely_verified_log_reference_count'] for r in summaries),
       'verified_real_ec353_signed_checkpoint_count':total_checkpoints,
       'verified_real_ec353_signed_witness_count':total_checkpoints,
       'verified_original_rfc6962_merkle_inclusion_count':total_inclusions,
       'verified_bound_old_ec354_signed_challenge_count':total_challenges,
       'verified_bound_old_ec354_signed_reply_count':total_replies,
       'verified_bound_old_ec355_furnished_original_pair_count':total_furnished,
       'historical_transparency_epoch_reviews':summaries,
       'local_pinned_ec353_signatures_merkle_and_old_claims_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec353_through_ec337_full_historical_parent_replay_performed':False,
       **flags,**{key:False for key in NEGATIVES}}
    if derive:
        result['unsigned_verified_historical_transparency_inventory']=inventory
        result['caller_external_inventory_pin_created_or_certified']=False
    return result


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
