#!/usr/bin/env python3
"""EC378: authenticate historic EC352 *original* signer registry ancestry.

Re-runs production EC377 on every derive/audit, then reopens receiver-held
SHA-pinned EC352 originals and verifies UNMODIFIED EC352 signature domains.
Reopens EC377 authenticated EC353 signed log history and checks that the exact
EC352 root and event bytes occur in the unique signed-head ancestry of BOTH
logs. Old sender paths are SHA labels only and never used as input paths.

No self-signed historic root proves official issuer identity; no complete
EC352->EC337 historic canonical parent result or global log census is claimed.
"""
from __future__ import annotations

from collections import Counter

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from key_registry import registry as old352
from transparency import transparency as old353
from historical_authority import authority_archive as p372
from historical_custody import custody_archive as p375
from historical_disclosure import disclosure_archive as p376
from historical_transparency import transparency_archive as previous

RESULT_SCHEMA='ces.ec378.receiver_real_ec352_issuer_signed_registry_merkle_ancestry_unresolved.v1'
DERIVE_SCHEMA='ces.ec378.unsigned_receiver_old_ec352_signed_registry_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec378.receiver_real_ec352_registry_merkle_denial.v1'
BUNDLE_SCHEMA='ces.ec378.receiver_historical_ec352_registry_original_archive.v1'
INVENTORY_SCHEMA='ces.ec378.receiver_verified_old_ec352_signed_registry_original_inventory.v1'
MAX_BUNDLE=125_000
NEW_SCALARS=('historical_registry_archive_bundle_file',
             'expected_historical_registry_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_registry_inventory_sha256',)
NEW_REPEATS=(
 ('historical_registry_root_key_inventory_shas','--historical-registry-root-key-inventory-sha256'),
 ('historical_registry_signed_head_inventory_shas','--historical-registry-signed-head-inventory-sha256'),
 ('minimum_historical_registry_signed_event_counts','--minimum-historical-registry-signed-event-count'),
 ('minimum_historical_registry_dual_log_inclusion_counts','--minimum-historical-registry-dual-log-inclusion-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*previous.PARENT_SCALARS,*previous.NEW_SCALARS,*previous.AUDIT_ONLY)
PARENT_REPEATS=(*previous.PARENT_REPEATS,*previous.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec377_canonical_result_sha256',
               'ec377_historical_transparency_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','claimed_tsa_channel_ids','registries'}
REGISTRY_FIELDS={'registry_channel_id','root_public_key_original',
                 'root_reference_original','events'}
EVENT_FIELDS={'signed_event_original','signer_public_key_original'}
FLAGS=(
 'inherited_true_ec377_through_ec369_original_dispute_unresolved',
 'outside_retained_registry_root_head_or_count_floor_disagrees',
 'original_ec352_signed_event_fork_or_revocation_conflict',
 'original_ec352_root_operator_parent_role_or_issuer_claim_conflict',
 'true_ec353_two_signed_log_head_lineage_registry_inclusion_missing',
 'old_registry_signed_event_expiry_gap_or_statement_claim_incomplete',
 'cross_epoch_registry_root_or_signed_head_ancestry_dispute',
 'genuine_old_ec352_signatures_not_full_ec351_through_ec337_canonical_parent',
)
OUTCOMES=(
 'ec378_inherited_true_old_transparency_or_disclosure_dispute',
 'ec378_outside_retained_old_registry_original_inventory_disagrees',
 'ec378_real_signed_registry_fork_or_revocation_dispute',
 'ec378_root_operator_key_or_claimed_issuer_role_conflict',
 'ec378_true_signed_two_log_ec352_artifact_membership_incomplete',
 'ec378_signed_registry_snapshot_freshness_or_source_authority_incomplete',
 'ec378_old_registry_cross_epoch_root_or_head_dispute',
 'ec378_crypto_only_original_ec352_not_complete_old_parent_ancestry',
)
NEGATIVES=(
 'old_ec352_through_ec337_canonical_parent_results_rebuilt',
 'old_ec351_source_attestation_issuer_authority_originals_replayed',
 'self_signed_old_registry_root_proves_official_issuer_identity',
 'old_registry_root_claim_proves_legal_institution_independence',
 'old_ec353_merkle_leaf_alone_proves_root_issuer_authorization',
 'old_ec352_signature_proves_global_complete_key_revocation_census',
 'old_registry_signed_time_proves_independent_trusted_utc',
 'unsigned_receiver_manifest_proves_global_log_latest_or_no_hidden_forks',
 'old_ec353_or_old_ec352_sender_original_label_paths_opened',
 'old_ec362_or_ec369_sender_origin_paths_opened',
 'ec377_parent_report_or_external_sender_pass_substituted',
 'verified_originals_prove_external_physical_custody',
 'old_ec355_or_ec356_canonical_parent_result_rebuilt',
 'private_signer_network_provider_cas_worm_or_native_ps_invoked',
 'historic_ec366_to_ec337_mock_removed_or_final_acceptance_proven',
)


def need(value,reason,status='invalid_input'):
    if value is not True:
        raise errors.AnchorError('EC378_'+reason,status)


def exact(obj,fields,kind):
    need(type(obj) is dict and set(obj)==set(fields),kind+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return previous.sha(raw)


def _inputs(opts,derive):
    required=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_RECEIVER_AND_LIVE_PARENT_INPUTS_REQUIRED')
    parent={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    previous._inputs(parent,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC378_RECEIVER_ARCHIVE')
    if not derive:need(old353._sha(opts[AUDIT_ONLY[0]]),
                       'OUTSIDE_RETAINED_UNSIGNED_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORICAL_EPOCH_COUNT_INVALID')
    for k in REPEAT_NAMES:
        values=opts[k]
        need(type(values) is list and len(values)==n,
             k.upper()+'_ONE_PER_HISTORICAL_EPOCH_REQUIRED')
        if k.startswith('minimum_'):
            cap=old352.MAX_EVENTS if 'signed_event' in k else 2*(2+old352.MAX_EVENTS)
            need(all(type(v) is int and 0<=v<=cap for v in values),
                 k.upper()+'_FLOOR_OUT_OF_BOUNDS')
        else:
            need(all(old353._sha(v) for v in values),
                 k.upper()+'_EXTERNAL_SHA_INVALID')
    return parent


def _reopen_logs(epoch,archive_epoch,read,forbidden,evaluation):
    """Verify real old EC353 Ed25519/Merkle again; prove leaf on true head."""
    old_pub=old353.strict_json(read(archive_epoch['ec353_publication_bundle_original'],
                     'ec378_reopen_old_ec353_publication_sha_labels',old353.MAX_BUNDLE),
                     'EC378_OLD_EC353_PUBLICATION')
    exact(old_pub,{'schema','logs'},'OLD_EC353_PUBLICATION')
    need(old_pub['schema']==old353.BUNDLE_SCHEMA and
         type(old_pub['logs']) is list and len(old_pub['logs'])==2 and
         type(archive_epoch['logs']) is list and len(archive_epoch['logs'])==2,
         'REAL_EC353_TWO_LOGS_REQUIRED','permission_denied')
    logs={};used=set();organizations=Counter()
    for old,new in zip(old_pub['logs'],archive_epoch['logs']):
        log=previous._log(old,new,read,forbidden,evaluation,used,organizations,set())
        need(log['id'] not in logs,'DUPLICATE_REAL_EC353_LOG_ID')
        logs[log['id']]=log
    need(list(logs)==sorted(logs),'HISTORIC_REAL_LOGS_SORTED_REQUIRED')
    memberships={}
    for log in logs.values():
        # A signature on a losing fork must not manufacture sufficient coverage.
        heads=log['heads']
        authentic=not log['fork'] and not log['consistency_dispute'] and len(heads)==1
        ancestors=set(log['ancestry'][heads[0]]) if authentic else set()
        memberships[log['id']]={
           (leaf['artifact_kind'],leaf['artifact_original_sha256'])
           for leaf in log['leaf_coverage'] if leaf['checkpoint_original_sha256'] in ancestors}
    return logs,memberships,{name.casefold() for name in organizations}


def _registry(r,read,evaluation,claimed_channels,forbidden,used_roles):
    exact(r,REGISTRY_FIELDS,'RECEIVER_OLD_EC352_REGISTRY')
    ident=r['registry_channel_id']
    need(old353._ident(ident),'REGISTRY_CHANNEL_ID_INVALID')
    rootref=r['root_reference_original'];rootkeyref=r['root_public_key_original']
    rootkey=read(rootkeyref,'true_old_ec352_root_public_key',old352.MAX_SIGNER_KEY_BYTES)
    rawroot=read(rootref,'true_old_ec352_self_signed_root',old352.MAX_ROOT_BYTES)
    rootdoc=old352._parse_root(rawroot,rootkey,rootkeyref['sha256'],evaluation,ident)
    events=r['events']
    need(type(events) is list and 1<=len(events)<=old352.MAX_PER_REGISTRY,
         'SIGNED_EVENT_COUNT_PER_REGISTRY_INVALID')
    need(rootkeyref['sha256'] not in used_roles,
         'ROOT_KEY_COLLIDES_WITH_ANOTHER_ROLE','permission_denied')
    used_roles.add(rootkeyref['sha256'])
    originals={('registry_root_reference',rootref['sha256'])}
    parsed=[];signer_shas=set()
    for event in events:
        exact(event,EVENT_FIELDS,'RECEIVER_OLD_EC352_SIGNED_EVENT')
        eventref=event['signed_event_original'];signerref=event['signer_public_key_original']
        signerkey=read(signerref,'true_old_ec352_signer_key',old352.MAX_SIGNER_KEY_BYTES)
        raw=read(eventref,'true_old_ec352_root_and_operator_signed_event',old352.MAX_EVENT_BYTES)
        doc=old352._parse_event(raw,rootkey,rootkeyref['sha256'],rootref['sha256'],
              signerkey,signerref['sha256'],ident,claimed_channels,evaluation)
        need(old353._utc(rootdoc['valid_from_utc'])<=doc['issued'] and
             doc['expiry']<=old353._utc(rootdoc['valid_until_utc']),
             'ACTUAL_SIGNED_EVENT_OUTSIDE_OWN_ROOT_REFERENCE_WINDOW',
             'permission_denied')
        # Stronger than _parse_event: signer may not be a previous root, log,
        # witness, issuer/custody or another registry's operator signer.
        signer_shas.add(signerref['sha256'])
        parsed.append(doc)
        originals.add(('registry_event',eventref['sha256']))
    need(not signer_shas.intersection(used_roles),
         'OPERATOR_KEY_REUSED_AS_OTHER_ROLE','permission_denied')
    used_roles.update(signer_shas)
    history=old352._validate_chain(parsed)   # real old rotation/prior signer signatures
    heads=[e['sha256'] for e in history['heads']]
    # Signed revocation/fork/freshness is *not* suppressed by valid signatures.
    fork=history['forked']
    revoked=any(e['document']['event_kind']=='revoke' for e in history['heads'])
    stale=any(e['expiry']<evaluation for e in history['heads'])
    gap=any(b['issued']>a['expiry'] for head in history['heads'] for a,b in
            zip(head['history'],head['history'][1:]))
    # Source statements themselves must be replayed from old EC351 originals
    # before asserting a retroactive authorization. No such replay here.
    regrant=any(entry['authorization']=='revoked' for e in parsed
                for entry in e['document']['entries'])
    return {'id':ident,'root_sha':rootkeyref['sha256'],
            'root_ref_sha':rootref['sha256'],'root_doc':rootdoc,
            'heads':heads,'events':parsed,'originals':originals,
            'fork':fork,'revoked':revoked or regrant,'stale':stale or gap,
            'evidence':{'registry_channel_id':ident,
               'original_root_public_key_sha256':rootkeyref['sha256'],
               'original_self_signed_root_reference_sha256':rootref['sha256'],
               'claimed_issuer_organization':rootdoc['claimed_issuer_organization'],
               'signed_event_original_shas':sorted(e['sha256'] for e in parsed),
               'signed_operator_public_key_original_shas':sorted(signer_shas),
               'verified_signed_terminal_head_original_shas':sorted(heads),
               'signed_revocation_or_fork_visible':fork or revoked or regrant,
               'claimed_signed_event_expiry_or_causal_gap':stale or gap}}


def _engine(derive,**opts):
    parent_opts=_inputs(opts,derive)
    inherited=previous.audit(**parent_opts)  # mandatory REAL EC377 -> ... -> EC369
    need(type(inherited) is dict and inherited.get('schema')==previous.RESULT_SCHEMA and
         inherited.get('exit_code')==2 and
         inherited.get('sender_origin_path_required_or_read') is False and
         inherited.get('ec353_through_ec337_full_historical_parent_replay_performed') is False and
         type(inherited.get('historical_transparency_epoch_reviews')) is list and
         len(inherited['historical_transparency_epoch_reviews'])==len(
             opts['historical_directory_root_shas']),
         'REAL_PRODUCTION_EC377_THROUGH_EC369_REPLAY_REQUIRED','unavailable')
    parent_sha=sha(canonical.canonical(inherited))
    evaluation=old353._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set();cached={}
    def read(ref,role,cap):
        # The exact old EC352 leaf read by EC353 is deliberately the SAME
        # receiver original later authenticated under the EC352 signature.
        # The shared legacy reader rejects a second category for one file;
        # pin the bytes once and only allow this narrowly defined promotion.
        key=ref.get('path') if type(ref) is dict else None
        if key in cached:
            oldsha,raw,oldroles=cached[key]
            permitted={'old_ec352_merkle_leaf_original',
                'true_old_ec352_self_signed_root',
                'true_old_ec352_root_and_operator_signed_event'}
            need(key not in forbidden and ref.get('sha256')==oldsha and
                 len(raw)<=cap and (role in oldroles or
                 (role in permitted and oldroles.issubset(permitted))),
                 'REUSED_ORIGINAL_PATH_CROSSES_FORBIDDEN_ROLE_OR_ORIGIN',
                 'permission_denied')
            oldroles.add(role)
            return raw
        raw=p372._read(ref,'ec378_'+role,cap,pins,categories,forbidden)
        cached[key]=(ref['sha256'],raw,{role})
        return raw
    prev_ref={'path':opts['historical_transparency_archive_bundle_file'],
              'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    prevdoc=old353.strict_json(read(prev_ref,'reopen_true_ec377_archive',previous.MAX_BUNDLE),
                                'EC378_OLD_EC377_RECEIVER_ARCHIVE')
    exact(prevdoc,previous.BUNDLE_FIELDS,'REOPEN_TRUE_EC377_ARCHIVE')
    need(prevdoc['schema']==previous.BUNDLE_SCHEMA and
         prevdoc['claimed_directory_lineage_id']==opts[
            'claimed_historical_directory_lineage_id'] and
         len(prevdoc['epochs'])==len(opts['historical_directory_root_shas']),
         'REAL_PARENT_EC377_ARCHIVE_SCHEMA_OR_LINEAGE_CHANGED','permission_denied')
    bundle_ref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=old353.strict_json(read(bundle_ref,'independently_pinned_ec378_receiver_archive',
                MAX_BUNDLE),'EC378_RECEIVER_SIGNED_REGISTRY_ARCHIVE')
    exact(bundle,BUNDLE_FIELDS,'EC378_RECEIVER_ARCHIVE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['parent_ec377_canonical_result_sha256']==parent_sha and
         bundle['ec377_historical_transparency_archive_original_sha256']==prev_ref['sha256'] and
         bundle['claimed_directory_lineage_id']==prevdoc['claimed_directory_lineage_id'] and
         type(bundle['epochs']) is list and len(bundle['epochs'])==len(prevdoc['epochs']),
         'RECEIVER_ARCHIVE_NOT_BOUND_TO_LIVE_TRUE_EC377_PARENT','permission_denied')
    # Reopen the exact verified EC376/EC375 receiver archives solely to
    # prevent an alleged historic registry signer from reusing an actual
    # previously authenticated auditor or old root/channel custody key.
    custody_archive=old353.strict_json(read({
        'path':opts['historical_custody_archive_bundle_file'],
        'sha256':opts['expected_historical_custody_archive_bundle_sha256']},
        'verified_ec375_old_custodial_signer_inventory',p375.MAX_BUNDLE),
        'EC378_REOPEN_EC375_CUSTODY')
    disclosure_archive=old353.strict_json(read({
        'path':opts['historical_disclosure_archive_bundle_file'],
        'sha256':opts['expected_historical_disclosure_archive_bundle_sha256']},
        'verified_ec376_old_auditor_signer_inventory',p376.MAX_BUNDLE),
        'EC378_REOPEN_EC376_DISCLOSURE')
    exact(custody_archive,p375.BUNDLE_FIELDS,'REAL_EC375_CUSTODY_ARCHIVE')
    exact(disclosure_archive,p376.BUNDLE_FIELDS,'REAL_EC376_DISCLOSURE_ARCHIVE')
    need(custody_archive['schema']==p375.BUNDLE_SCHEMA and
         disclosure_archive['schema']==p376.BUNDLE_SCHEMA and
         len(custody_archive['epochs'])==len(bundle['epochs']) and
         len(disclosure_archive['epochs'])==len(bundle['epochs']),
         'ACTUAL_SIGNED_PARENT_CUSTODY_OR_AUDITOR_ARCHIVE_MISMATCH',
         'permission_denied')
    old_actor_keys=set()
    for cust,disc in zip(custody_archive['epochs'],disclosure_archive['epochs'],strict=True):
        for slot in ('a','b'):
            src=cust['source_'+slot]
            old_actor_keys.update((src['root_public_key_original']['sha256'],
                                   src['channel_public_key_original']['sha256']))
        for aud in disc['auditors']:
            old_actor_keys.add(aud['public_key_original']['sha256'])
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not inherited['local_pinned_ec353_signatures_merkle_and_old_claims_consistent']
    previous_root={};previous_heads={};rows=[];inventory_rows=[]
    root_keys_all=set();issuer_organizations=Counter()
    total_events=total_covered=total_missing=0
    for i,(epoch,old_epoch) in enumerate(zip(bundle['epochs'],prevdoc['epochs'],strict=True)):
        exact(epoch,EPOCH_FIELDS,'EC378_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             old_epoch['epoch_index']==i,'OLD_AND_NEW_EPOCH_INDEX_DISAGREES')
        logs,memberships,log_claims=_reopen_logs(epoch,old_epoch,read,forbidden,evaluation)
        registries=epoch['registries']
        need(type(registries) is list and len(registries)==2,
             'TWO_ORIGINAL_EC352_REGISTRIES_PER_EPOCH_REQUIRED')
        exclusions=set(old_actor_keys)|set(opts['institution_root_public_key_shas']+
             opts['witness_public_key_shas']+
             opts['historical_directory_root_shas']+
             [opts['expected_sender_public_key_sha256'],
              opts['expected_receiver_public_key_sha256'],
              opts['expected_publisher_public_key_sha256'],
              opts['expected_publication_observer_public_key_sha256']])
        for log in logs.values():
            exclusions.update((log['log_key_sha'],log['witness_key_sha']))
        actual=[];active_roles=set(exclusions)
        channel_labels=epoch['claimed_tsa_channel_ids']
        need(type(channel_labels) is list and 1<=len(channel_labels)<=4 and
             all(old353._ident(c) for c in channel_labels) and
             channel_labels==sorted(set(channel_labels)),
             'UNSIGNED_OLD_EC351_TSA_CHANNEL_LABEL_FORMAT_INVALID')
        channels=set(channel_labels)
        # Caller labels bound to old signed entries; not authenticated EC351
        # source statements, TSA issuers or trust anchors.
        for registry in registries:
            actual.append(_registry(registry,read,evaluation,channels,forbidden,active_roles))
        need([r['id'] for r in actual]==sorted(set(r['id'] for r in actual)),
             'TWO_SIGNED_REGISTRIES_UNIQUE_SORTED_REQUIRED')
        head_keys=[{'registry_channel_id':r['id'],
                    'root_public_key_original_sha256':r['root_sha'],
                    'root_reference_original_sha256':r['root_ref_sha']}
                    for r in actual]
        head_rows=[{'registry_channel_id':r['id'],
                    'signed_terminal_head_original_shas':r['heads']} for r in actual]
        key_hash=sha(canonical.canonical(head_keys))
        head_hash=sha(canonical.canonical(head_rows))
        flags[FLAGS[1]] |= (key_hash!=opts['historical_registry_root_key_inventory_shas'][i] or
             head_hash!=opts['historical_registry_signed_head_inventory_shas'][i])
        current_originals=set().union(*(r['originals'] for r in actual))
        total_events_i=sum(len(r['events']) for r in actual)
        need(total_events_i<=old352.MAX_EVENTS,'EC352_EVENT_TOTAL_BOUNDED_REQUIRED')
        coverage={name:sorted(current_originals.intersection(sha_set))
                  for name,sha_set in memberships.items()}
        covered=sum(len(memberships[logid].intersection(current_originals))
                    for logid in memberships)
        missing=sum(len(current_originals-memberships[logid]) for logid in memberships)
        flags[FLAGS[1]] |= (total_events_i<opts[
               'minimum_historical_registry_signed_event_counts'][i] or
             covered<opts['minimum_historical_registry_dual_log_inclusion_counts'][i])
        flags[FLAGS[2]] |= any(r['fork'] or r['revoked'] for r in actual)
        for r in actual:
            org=r['root_doc']['claimed_issuer_organization'].casefold()
            issuer_organizations[org]+=1
            if org in log_claims:flags[FLAGS[3]]=True
            if (r['root_sha'] in root_keys_all and r['id'] not in previous_root):
                flags[FLAGS[3]]=True
            root_keys_all.add(r['root_sha'])
            old=previous_root.get(r['id'])
            if old is not None:
                if (old['root_sha'],old['root_ref_sha'])!=(r['root_sha'],r['root_ref_sha']):
                    # EC352 has no independently old-root signed root-transfer
                    # signature domain. A new self-signed root cannot inherit
                    # previous authority merely by retaining the channel ID.
                    flags[FLAGS[6]]=True
                prior_heads=previous_heads.get(r['id'],[])
                if len(prior_heads)!=1 or len(r['heads'])!=1 or not any(
                    head['sha256']==prior_heads[0] for event in r['events']
                    for head in event.get('history',[])
                    if event['sha256']==r['heads'][0]):
                    flags[FLAGS[6]]=True
            previous_root[r['id']]=r
            previous_heads[r['id']]=r['heads']
        flags[FLAGS[4]] |= bool(missing) or any(
             log['fork'] or log['consistency_dispute'] for log in logs.values())
        flags[FLAGS[5]] |= any(r['stale'] for r in actual)
        total_events+=total_events_i;total_covered+=covered;total_missing+=missing
        rows.append({'epoch_index':i,
           'real_old_ec352_self_signed_registry_root_count':len(actual),
           'genuine_old_ec352_root_and_operator_signed_event_count':total_events_i,
           'old_ec353_verified_signed_log_count':len(logs),
           'signed_head_ancestry_verified_registry_original_inclusions':covered,
           'registry_original_two_log_inclusions_missing':missing,
           'real_signed_registry_root_key_inventory_sha256':key_hash,
           'real_signed_registry_terminal_head_inventory_sha256':head_hash,
           'original_registry_signed_fork_or_revocation_visible':any(
                 r['fork'] or r['revoked'] for r in actual),
           'signed_registry_causal_or_freshness_gap_visible':any(r['stale'] for r in actual),
           'signed_old_registry_cross_epoch_root_or_head_conflict_visible':flags[FLAGS[6]]})
        inventory_rows.append({'epoch_index':i,
           'true_ec353_publication_original_sha256':old_epoch[
                  'ec353_publication_bundle_original']['sha256'],
           'original_signed_registry_key_inventory_sha256':key_hash,
           'original_signed_registry_head_inventory_sha256':head_hash,
           'real_old_ec352_signed_registry_originals':[r['evidence'] for r in actual],
           'real_signed_ec353_log_leaf_membership':[{'log_id':logid,
             'covered_originals':[{'artifact_kind':kind,'original_sha256':digest}
                 for kind,digest in coverage[logid]]}
                 for logid in sorted(memberships)]})
    # All official issuer organization names remain self-asserted; even
    # *different* ones do not prove independent legal institutions.
    flags[FLAGS[3]] |= any(n>len(bundle['epochs']) for n in issuer_organizations.values())
    need(not set(pins).intersection(forbidden),
         'HISTORICAL_SENDER_ORIGINAL_LABEL_ALIASES_RECEIVER_FILE',
         'permission_denied')
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[-1]]=True
    inventory={'schema':INVENTORY_SCHEMA,
       'verified_live_parent_ec377_canonical_result_sha256':parent_sha,
       'ec377_transparency_archive_original_sha256':prev_ref['sha256'],
       'receiver_ec378_signed_registry_archive_original_sha256':bundle_ref['sha256'],
       'claimed_directory_lineage_id':bundle['claimed_directory_lineage_id'],
       'historical_signed_registry_original_epoch_rows':inventory_rows}
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:-1])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-registry-inventory' if derive else
                 'audit-historical-registry-archive',
       'status':next((OUTCOMES[j] for j,k in enumerate(FLAGS) if flags[k]),
                     OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'historical_registry_archive_bundle_original_sha256':bundle_ref['sha256'],
       'verified_live_parent_ec377_canonical_result_sha256':parent_sha,
       'receiver_verified_historical_registry_inventory_sha256':digest,
       'verified_original_ec352_self_signed_root_reference_count':2*len(rows),
       'verified_original_ec352_root_and_operator_signed_event_count':total_events,
       'verified_original_ec352_signed_merkle_log_membership_count':total_covered,
       'missing_signed_head_ancestry_registry_log_memberships':total_missing,
       'historical_registry_epoch_reviews':rows,
       'local_signed_ec352_registry_signatures_and_dual_log_links_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec352_through_ec337_full_historical_parent_replay_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_verified_historical_registry_inventory':inventory,
           'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
