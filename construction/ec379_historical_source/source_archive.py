#!/usr/bin/env python3
"""EC379: replay original EC351 signed source/attester evidence under EC378.

Offline receiver originals only.  The production EC378->EC369 audit is mandatory.
Reopen and verify unchanged EC351 Ed25519 source attestation bytes, actual
policy source bytes and the pinned TSA root DER certificate, then independently
reverify the EC352 signed registry history that claims to authorize each source.
Actual EC350->EC337 RFC3161/CRL/OCSP originals and outside legal trust remain
incomplete; even pristine supplied cryptography always returns 2/unresolved.
"""
from __future__ import annotations

from collections import Counter
from datetime import timedelta
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as old350
from ec351_tsa_provenance import provenance as old351
from ec352_key_registry import registry as old352
from ec353_transparency import transparency as old353
from ec372_historical_authority import authority_archive as p372
from ec375_historical_custody import custody_archive as p375
from ec376_historical_disclosure import disclosure_archive as p376
from ec377_historical_transparency import transparency_archive as p377
from ec378_historical_registry import registry_archive as previous

RESULT_SCHEMA='ces.ec379.receiver_authentic_old_ec351_source_registry_binding_unresolved.v1'
DERIVE_SCHEMA='ces.ec379.unsigned_old_ec351_source_registry_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec379.receiver_old_ec351_source_registry_denial.v1'
BUNDLE_SCHEMA='ces.ec379.receiver_historical_ec351_source_original_archive.v1'
INVENTORY_SCHEMA='ces.ec379.receiver_verified_old_ec351_source_original_inventory.v1'
MAX_BUNDLE=100_000
MAX_TSA_ROOT=old350.MAX_CERT_BYTES
NEW_SCALARS=('historical_source_archive_bundle_file',
             'expected_historical_source_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_source_inventory_sha256',)
NEW_REPEATS=(
 ('historical_source_attestation_inventory_shas','--historical-source-attestation-inventory-sha256'),
 ('historical_source_registry_binding_inventory_shas','--historical-source-registry-binding-inventory-sha256'),
 ('minimum_historical_signed_source_counts','--minimum-historical-signed-source-count'),
 ('minimum_historical_authorized_registry_match_counts','--minimum-historical-authorized-registry-match-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*previous.PARENT_SCALARS,*previous.NEW_SCALARS,*previous.AUDIT_ONLY)
PARENT_REPEATS=(*previous.PARENT_REPEATS,*previous.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec378_canonical_result_sha256',
               'ec378_historical_registry_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','sources'}
SOURCE_FIELDS={'tsa_channel_id','source_attestation_original',
               'attester_public_key_original','policy_source_document_original',
               'tsa_root_certificate_original'}
FLAGS=(
 'inherited_live_ec378_through_ec369_dispute_unresolved',
 'external_retained_ec351_source_inventory_or_minimum_floor_disagrees',
 'real_signed_ec351_source_missing_from_issued_ec352_registry',
 'real_ec352_registry_revocation_fork_or_signed_authorization_dispute',
 'real_ec351_attester_key_role_or_claimed_source_conflict',
 'signed_ec351_source_epoch_rollback_or_channel_discontinuity',
 'historical_ec350_tsa_token_crl_ocsp_issuer_originals_incomplete',
 'authentic_ec351_signature_is_not_complete_ec350_through_ec337_parent',
)
OUTCOMES=(
 'ec379_inherited_historical_registry_or_merkle_dispute',
 'ec379_independent_retained_source_inventory_or_floor_disagrees',
 'ec379_signed_source_issuer_binding_missing',
 'ec379_signed_source_registry_revocation_or_authorization_dispute',
 'ec379_source_signer_claimed_role_or_organization_dispute',
 'ec379_historical_signed_source_rollback_or_discontinuity',
 'ec379_old_tsa_timestamp_and_signed_revocation_originals_incomplete',
 'ec379_partial_old_ec351_crypto_not_full_ec350_parent',
)
NEGATIVES=(
 'complete_old_ec350_through_ec337_canonical_parent_replay_performed',
 'complete_old_ec351_parent_result_reconstructed',
 'real_rfc3161_tstinfo_signed_token_and_ec349_receipt_replayed',
 'historic_crl_and_ocsp_responder_signed_status_replayed',
 'attester_public_key_proves_official_issuer_or_independent_institution',
 'source_uri_or_caller_pinned_der_proves_legal_policy_qualification',
 'old_ec352_signed_registry_alone_proves_ec351_source_authenticity',
 'real_ec351_source_signature_proves_independent_trusted_utc',
 'old_ec353_signed_merkle_inclusion_proves_global_absence_of_hidden_forks',
 'historical_source_or_ec353_sender_origin_label_path_opened',
 'unsigned_receiver_inventory_or_parent_report_substituted_for_signed_originals',
 'independent_physical_custody_or_remote_worm_commit_proven',
 'network_key_generation_private_signer_trust_store_or_native_ps_invoked',
 'ec366_to_ec337_historical_mock_removed_or_final_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC379_'+code,status)


def exact(obj,keys,label):
    need(type(obj) is dict and set(obj)==set(keys),label+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return previous.sha(raw)


def _inputs(opts,derive):
    keys=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:keys.update(AUDIT_ONLY)
    need(set(opts)==keys,'EXACT_LIVE_PARENT_AND_NEW_RECEIVER_INPUTS_REQUIRED')
    parent={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    previous._inputs(parent,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC379_RECEIVER_HISTORICAL_SOURCE_ARCHIVE')
    if not derive:need(old353._sha(opts[AUDIT_ONLY[0]]),
                       'INDEPENDENTLY_RETAINED_UNSIGNED_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORICAL_EPOCH_COUNT_INVALID')
    for k in REPEAT_NAMES:
        values=opts[k]
        need(type(values) is list and len(values)==n,
             k.upper()+'_ONE_PER_HISTORICAL_EPOCH_REQUIRED')
        if k.startswith('minimum_'):
            cap=4 if 'signed_source' in k else 8
            need(all(type(x) is int and 0<=x<=cap for x in values),
                 k.upper()+'_FLOOR_OUT_OF_BOUNDS')
        else:
            need(all(old353._sha(x) for x in values),k.upper()+'_SHA_INVALID')
    return parent


def _source(original,read,evaluation,exclusion):
    """Check the actual *unchanged EC351* signature domain without fabricating
    token generation time, which only the missing old EC350 token can establish.
    """
    exact(original,SOURCE_FIELDS,'HISTORICAL_SOURCE')
    channel=original['tsa_channel_id']
    need(old353._ident(channel),'HISTORICAL_TSA_CHANNEL_ID_INVALID')
    statementref=original['source_attestation_original']
    keyref=original['attester_public_key_original']
    sourceref=original['policy_source_document_original']
    rootref=original['tsa_root_certificate_original']
    key=read(keyref,'ec351_attester_public_key',old351.MAX_PUBLIC_KEY)
    source=read(sourceref,'ec351_actual_policy_source_document',old351.MAX_SOURCE)
    rawroot=read(rootref,'ec351_actual_tsa_root_certificate',MAX_TSA_ROOT)
    statement=read(statementref,'ec351_actual_original_signed_statement',old351.MAX_ATTESTATION)
    need(keyref['sha256'] not in exclusion and len(key)==32,
         'EC351_ATTESTER_REUSES_REGISTRY_OR_OLDER_SIGNER_ROLE',
         'permission_denied')
    need(bool(source),'EMPTY_ORIGIN_POLICY_SOURCE_DOCUMENT')
    root=old350._certificate(rawroot)
    old350._cert_key_usage(root,must_ca=True)
    old350._cert_signed_by(root,root)
    der_sha=sha(root.public_bytes(Encoding.DER))
    doc=old351._read_statement(statement)
    fields={'schema','channel_id','tsa_root_original_sha256',
            'tsa_root_certificate_der_sha256','tsa_policy_oid',
            'source_document_original_sha256','attester_public_key_original_sha256',
            'claimed_source_organization','claimed_source_uri',
            'issued_utc','expires_utc','signature_ed25519_hex'}
    need(set(doc)==fields and all(type(v) is str for v in doc.values()),
         'ORIGINAL_EC351_ATTESTATION_EXACT_STRING_FIELDS_REQUIRED')
    expected={'schema':old351.ATTESTATION_SCHEMA,'channel_id':channel,
              'tsa_root_original_sha256':rootref['sha256'],
              'tsa_root_certificate_der_sha256':der_sha,
              'tsa_policy_oid':doc['tsa_policy_oid'],
              'source_document_original_sha256':sourceref['sha256'],
              'attester_public_key_original_sha256':keyref['sha256']}
    need(all(doc[k]==v for k,v in expected.items()) and
         old352.POLICY_RE.fullmatch(doc['tsa_policy_oid']) is not None,
         'REAL_EC351_SOURCE_ROOT_DER_POLICY_OR_SIGNER_SHA_MISMATCH',
         'permission_denied')
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 .,_()&/-]{2,119}',
                      doc['claimed_source_organization']) is not None and
         old352.HTTPS_RE.fullmatch(doc['claimed_source_uri']) is not None,
         'SIGNED_EC351_SOURCE_ORGANIZATION_OR_URI_INVALID')
    issued=old350._utc(doc['issued_utc'])
    expires=old350._utc(doc['expires_utc'])
    need(issued<=evaluation<=expires and
         expires-issued<=timedelta(days=366),
         'ORIGINAL_EC351_SIGNED_SOURCE_EXPIRED_OR_WINDOW_INVALID',
         'permission_denied')
    sig=doc['signature_ed25519_hex']
    need(re.fullmatch('[0-9a-f]{128}',sig) is not None,
         'ORIGINAL_EC351_SIGNATURE_BYTES_INVALID')
    body={k:v for k,v in doc.items() if k!='signature_ed25519_hex'}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(sig),old351.DOMAIN+canonical.canonical(body))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise errors.AnchorError('EC379_REAL_EC351_ATTESTER_ED25519_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    binding={
      'source_attestation_original_sha256':statementref['sha256'],
      'attester_public_key_original_sha256':keyref['sha256'],
      'source_document_original_sha256':sourceref['sha256'],
      'tsa_root_original_sha256':rootref['sha256'],
      'tsa_root_der_sha256':der_sha,
      'tsa_policy_oid':doc['tsa_policy_oid']}
    return {'channel':channel,'attester_sha':keyref['sha256'],
      'issued':issued,'binding':binding,'document':doc,
      'evidence':{'tsa_channel_id':channel,**binding,
         'claimed_source_organization':doc['claimed_source_organization'],
         'claimed_source_uri_unfetched':doc['claimed_source_uri'],
         'signed_source_issued_utc_as_untrusted_claim':doc['issued_utc'],
         'signed_source_expires_utc_as_untrusted_claim':doc['expires_utc'],
         'actual_tsa_root_certificate_self_signature_checked':True,
         'original_ec351_ed25519_source_attestation_verified':True,
         'old_ec350_tsa_token_gen_time_reconstructed':False}}


def _claim_status(verified_reg,source,evaluation):
    heads=[e for e in verified_reg['events'] if e['sha256'] in verified_reg['heads']]
    compatibility={'id':verified_reg['id'],'root_ref_sha':verified_reg['root_ref_sha'],
      'root_key_sha':verified_reg['root_sha'],
      'events_count':len(verified_reg['events']),'forked':verified_reg['fork'],
      'heads':verified_reg['heads'],'head_objects':heads}
    return old352._observe_registry(source['channel'],source['binding'],
                                    source['issued'],compatibility,evaluation)[
                                        'key_binding_status']


def _old_sender_labels(value,found):
    """Collect untrusted old sender-side path *labels*, never open them."""
    if type(value) is dict:
        for k,v in value.items():
            if k=='path' and type(v) is str:found.add(v)
            else:_old_sender_labels(v,found)
    elif type(value) is list:
        for item in value:_old_sender_labels(item,found)


def _engine(derive,**opts):
    parent_opts=_inputs(opts,derive)
    inherited=previous.audit(**parent_opts)  # mandatory REAL EC378->EC369
    n=len(opts['historical_directory_root_shas'])
    need(type(inherited) is dict and inherited.get('schema')==previous.RESULT_SCHEMA and
         inherited.get('exit_code')==2 and
         inherited.get('sender_origin_path_required_or_read') is False and
         inherited.get('ec352_through_ec337_full_historical_parent_replay_performed') is False and
         type(inherited.get('historical_registry_epoch_reviews')) is list and
         len(inherited['historical_registry_epoch_reviews'])==n,
         'ACTUAL_PRODUCTION_EC378_THROUGH_EC369_PARENT_REQUIRED','unavailable')
    parent_sha=sha(canonical.canonical(inherited))
    evaluation=old350._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set()
    cache={}
    def read(ref,role,cap):
        key=ref.get('path') if type(ref) is dict else None
        if key in cache:
            digest,data,roles=cache[key]
            need(key not in forbidden and ref.get('sha256')==digest and
                 len(data)<=cap and role in roles,
                 'ORIGINAL_ROLE_ALIAS_OR_SHA_COLLISION','permission_denied')
            return data
        raw=p372._read(ref,'ec379_'+role,cap,pins,categories,forbidden)
        cache[key]=(ref['sha256'],raw,{role})
        return raw
    parent_ref={'path':opts['historical_registry_archive_bundle_file'],
                'sha256':opts['expected_historical_registry_archive_bundle_sha256']}
    parent_bundle=old353.strict_json(read(parent_ref,'verified_ec378_registry_archive',
                                         previous.MAX_BUNDLE),'EC379_OLD_EC378_REGISTRY')
    exact(parent_bundle,previous.BUNDLE_FIELDS,'AUTHENTIC_EC378_PARENT_ARCHIVE')
    need(parent_bundle['schema']==previous.BUNDLE_SCHEMA and
         parent_bundle['claimed_directory_lineage_id']==opts[
             'claimed_historical_directory_lineage_id'] and
         type(parent_bundle['epochs']) is list and len(parent_bundle['epochs'])==n,
         'ACTUAL_EC378_PARENT_ARCHIVE_MISMATCH','permission_denied')
    bundle_ref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=old353.strict_json(read(bundle_ref,'independently_pinned_ec379_archive',
                                     MAX_BUNDLE),'EC379_TRUE_OLD_EC351_SOURCE_ARCHIVE')
    exact(bundle,BUNDLE_FIELDS,'EC379_RECEIVER_ARCHIVE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['parent_ec378_canonical_result_sha256']==parent_sha and
         bundle['ec378_historical_registry_archive_original_sha256']==parent_ref['sha256'] and
         bundle['claimed_directory_lineage_id']==parent_bundle['claimed_directory_lineage_id'] and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'EC379_SOURCE_ARCHIVE_NOT_BOUND_TO_LIVE_EC378_PARENT','permission_denied')
    # These authenticated EC377 receiver originals are reopened only to derive
    # the old, UNTRUSTED path label denylist. Paths embedded in old manifest
    # are never passed to read().
    old377=old353.strict_json(read({
      'path':opts['historical_transparency_archive_bundle_file'],
      'sha256':opts['expected_historical_transparency_archive_bundle_sha256']},
      'verified_old_ec377_receiver_archive',p377.MAX_BUNDLE),'EC379_EC377_ARCHIVE')
    exact(old377,p377.BUNDLE_FIELDS,'REAL_EC377_PARENT_ARCHIVE')
    need(old377['schema']==p377.BUNDLE_SCHEMA and
         type(old377['epochs']) is list and len(old377['epochs'])==n,
         'AUTHENTIC_EC377_PARENT_ARCHIVE_MISMATCH','permission_denied')
    for epoch in old377['epochs']:
        pub=old353.strict_json(read(epoch['ec353_publication_bundle_original'],
             'verified_old_ec353_unsigned_sender_label_manifest',old353.MAX_BUNDLE),
             'EC379_EC353_OLD_PUBLICATION')
        _old_sender_labels(pub,forbidden)
    # Reopen the independently SHA-pinned, already-production-verified old
    # EC375/376 receiver bundles. Historic source-attester public keys may not
    # impersonate their custodial roots, channel signers or auditors.
    cust=old353.strict_json(read({
       'path':opts['historical_custody_archive_bundle_file'],
       'sha256':opts['expected_historical_custody_archive_bundle_sha256']},
       'verified_old_ec375_custody_archive',p375.MAX_BUNDLE),'EC379_CUSTODY')
    disc=old353.strict_json(read({
       'path':opts['historical_disclosure_archive_bundle_file'],
       'sha256':opts['expected_historical_disclosure_archive_bundle_sha256']},
       'verified_old_ec376_disclosure_archive',p376.MAX_BUNDLE),'EC379_DISCLOSURE')
    exact(cust,p375.BUNDLE_FIELDS,'VERIFIED_OLD_EC375_CUSTODY')
    exact(disc,p376.BUNDLE_FIELDS,'VERIFIED_OLD_EC376_AUDITORS')
    need(cust['schema']==p375.BUNDLE_SCHEMA and disc['schema']==p376.BUNDLE_SCHEMA and
         len(cust['epochs'])==n and len(disc['epochs'])==n,
         'REAL_PARENT_OLD_SIGNER_INVENTORY_MISSING','permission_denied')
    old_actor_keys=set()
    for c,d in zip(cust['epochs'],disc['epochs'],strict=True):
        for slot in ('a','b'):
            old_actor_keys.update((c['source_'+slot]['root_public_key_original']['sha256'],
                c['source_'+slot]['channel_public_key_original']['sha256']))
        for auditor in d['auditors']:
            old_actor_keys.add(auditor['public_key_original']['sha256'])
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not inherited['local_signed_ec352_registry_signatures_and_dual_log_links_consistent']
    rows=[];inventory_rows=[];previous_claims={};attester_channel_owners={}
    total_signed=total_matches=total_missing=0
    for i,(epoch,parent_epoch) in enumerate(zip(bundle['epochs'],parent_bundle['epochs'],strict=True)):
        exact(epoch,EPOCH_FIELDS,'EC379_EPOCH')
        exact(parent_epoch,previous.EPOCH_FIELDS,'PARENT_EC378_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             parent_epoch['epoch_index']==i,'HISTORICAL_EPOCH_INDEX_INVALID')
        channels=parent_epoch['claimed_tsa_channel_ids']
        need(type(channels) is list and channels==sorted(set(channels)) and
             1<=len(channels)<=4,'OLD_EC378_CLAIMED_CHANNEL_LABELS_INVALID')
        regdocs=parent_epoch['registries']
        need(type(regdocs) is list and len(regdocs)==2,
             'AUTHENTIC_TWO_EC352_REGISTRIES_REQUIRED')
        role_exclusion=set(old_actor_keys)|set(opts['institution_root_public_key_shas']+
                  opts['witness_public_key_shas']+
                  opts['historical_directory_root_shas']+
                  [opts['expected_sender_public_key_sha256'],
                   opts['expected_receiver_public_key_sha256'],
                   opts['expected_publisher_public_key_sha256'],
                   opts['expected_publication_observer_public_key_sha256']])
        for log in old377['epochs'][i]['logs']:
            role_exclusion.add(log['log_public_key_original']['sha256'])
            role_exclusion.add(log['witness_public_key_original']['sha256'])
        active_roles=set(role_exclusion)
        checked=[]
        for r in regdocs:
            verified=previous._registry(r,read,evaluation,set(channels),forbidden,
                                        active_roles)
            checked.append(verified)
        # The already-authenticated EC352 root/operational keys are forbidden
        # as alleged EC351 source signers, but are not pre-excluded during
        # EC352._registry's own noncolliding signer-history verification.
        role_exclusion=active_roles
        need([r['id'] for r in checked]==sorted(set(r['id'] for r in checked)),
             'REAL_SIGNED_EC352_REGISTRIES_NOT_UNIQUE_SORTED')
        sources=epoch['sources']
        need(type(sources) is list and len(sources)<=4,
             'EC351_SIGNED_SOURCE_ORIGINALS_EXCEED_EPOCH_LIMIT')
        supplied=[];attester_owners=set()
        for obj in sources:
            source=_source(obj,read,evaluation,role_exclusion)
            need(source['channel'] in channels and source['attester_sha'] not in attester_owners,
                 'UNCLAIMED_TSA_CHANNEL_OR_SIGNER_REUSE','permission_denied')
            existing_owner=attester_channel_owners.get(source['attester_sha'])
            need(existing_owner is None or existing_owner==source['channel'],
                 'ATTESTER_SIGNING_KEY_REUSED_ACROSS_HISTORICAL_CHANNELS',
                 'permission_denied')
            attester_channel_owners[source['attester_sha']]=source['channel']
            attester_owners.add(source['attester_sha'])
            supplied.append(source)
        need([s['channel'] for s in supplied]==sorted(set(s['channel'] for s in supplied)),
             'EC351_SOURCES_UNIQUE_ASCENDING_REQUIRED')
        signed_count=len(supplied)
        missing=set(channels)-{s['channel'] for s in supplied}
        fullbind=[];evidence=[];counts=Counter()
        for source in supplied:
            by_registry=[{'registry_channel_id':r['id'],
                          'real_signed_ec352_binding_status':_claim_status(r,source,evaluation)}
                         for r in checked]
            exactmatches=sum(x['real_signed_ec352_binding_status']==
                            'authorized_claim_exact_binding' for x in by_registry)
            total_matches+=exactmatches
            evidence.append({**source['evidence'],
                             'real_signed_ec352_registry_authorization_reviews':by_registry})
            fullbind.append({'tsa_channel_id':source['channel'],
                             'signed_attestation_original_sha256':source['binding'][
                                  'source_attestation_original_sha256'],
                             'signed_registry_statuses':by_registry})
            if exactmatches!=2:flags[FLAGS[3]]=True
            if any(x['real_signed_ec352_binding_status'] in (
                     'attester_key_revoked_in_signed_history','registry_signer_revoked',
                     'fork_no_winner','contradictory_signed_binding') for x in by_registry):
                flags[FLAGS[3]]=True
            owner=source['document']['claimed_source_organization'].casefold()
            counts[owner]+=1
            old=previous_claims.get(source['channel'])
            if old is not None and (source['issued']<old['issued'] or
                (source['issued']==old['issued'] and
                 source['binding']!=old['binding'])):
                flags[FLAGS[5]]=True
            previous_claims[source['channel']]=source
        matches=sum(x['real_signed_ec352_binding_status']==
                    'authorized_claim_exact_binding' for ent in fullbind
                    for x in ent['signed_registry_statuses'])
        keyrows=[{'tsa_channel_id':s['channel'],**s['binding']} for s in supplied]
        keyhash=sha(canonical.canonical(keyrows))
        bindhash=sha(canonical.canonical(fullbind))
        flags[FLAGS[1]] |= (keyhash!=opts[
            'historical_source_attestation_inventory_shas'][i] or
            bindhash!=opts['historical_source_registry_binding_inventory_shas'][i] or
            signed_count<opts['minimum_historical_signed_source_counts'][i] or
            matches<opts['minimum_historical_authorized_registry_match_counts'][i])
        flags[FLAGS[2]] |= bool(missing)
        flags[FLAGS[3]] |= any(r['fork'] or r['revoked'] or r['stale'] for r in checked)
        flags[FLAGS[4]] |= any(count>1 for count in counts.values())
        flags[FLAGS[5]] |= bool(missing) and i>0
        total_signed+=signed_count;total_missing+=len(missing)
        rows.append({'epoch_index':i,'actual_old_ec351_signed_source_original_count':signed_count,
            'real_ec352_independent_registry_count':2,
            'real_signed_ec352_exact_source_authorization_match_count':matches,
            'old_ec351_missing_claimed_tsa_channel_source_count':len(missing),
            'old_ec351_source_original_inventory_sha256':keyhash,
            'real_signed_ec352_source_binding_inventory_sha256':bindhash,
            'real_signed_source_or_registry_revocation_or_fork_visible':any(
                r['fork'] or r['revoked'] or r['stale'] for r in checked),
            'old_ec351_signed_source_claimed_issuer_role_collision_visible':any(
                count>1 for count in counts.values()),
            'old_ec351_external_crl_ocsp_and_tsa_token_still_missing':True})
        inventory_rows.append({'epoch_index':i,
            'original_ec378_registry_archive_sha256':parent_ref['sha256'],
            'signed_ec351_source_originals':evidence,
            'claimed_tsa_channels_without_furnished_signed_source':sorted(missing),
            'signed_source_inventory_sha256':keyhash,
            'registry_authorization_inventory_sha256':bindhash})
    # Do not hide parent-archive references from the protected set: only NEW
    # source original paths are denied if they alias a parent scalar or sender.
    # The inherited historical reader also records inode/identity evidence;
    # recheck both original whole SHA and file identity after all processing.
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[6]]=True
    flags[FLAGS[7]]=True
    inventory={'schema':INVENTORY_SCHEMA,
       'verified_live_parent_ec378_canonical_result_sha256':parent_sha,
       'authenticated_ec378_registry_archive_original_sha256':parent_ref['sha256'],
       'receiver_ec379_source_archive_original_sha256':bundle_ref['sha256'],
       'claimed_directory_lineage_id':bundle['claimed_directory_lineage_id'],
       'historical_old_ec351_signed_source_epoch_rows':inventory_rows}
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:6])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':'derive-historical-source-inventory' if derive else
                'audit-historical-source-archive',
      'status':next((OUTCOMES[j] for j,key in enumerate(FLAGS) if flags[key]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'historical_source_archive_bundle_original_sha256':bundle_ref['sha256'],
      'verified_live_parent_ec378_canonical_result_sha256':parent_sha,
      'receiver_verified_historical_source_inventory_sha256':digest,
      'verified_old_ec351_signed_source_statement_count':total_signed,
      'verified_old_ec351_signed_registry_authorization_match_count':total_matches,
      'missing_old_ec351_channel_source_original_count':total_missing,
      'historical_source_epoch_reviews':rows,
      'local_pinned_ec351_source_signatures_and_old_registry_binding_consistent':local,
      'sender_origin_path_required_or_read':False,
      'ec350_through_ec337_full_historical_parent_replay_performed':False,
      **flags,**{key:False for key in NEGATIVES},
      **({'unsigned_verified_historical_source_inventory':inventory,
          'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
