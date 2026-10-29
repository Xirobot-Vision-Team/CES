#!/usr/bin/env python3
"""EC389 receiver-only audit of external publication and custody of old EC339 revoked status.

An actual EC388->EC369 audit and original source replay are mandatory.  The
new witness and custodian claims are separately Ed25519 signed over disjoint
domains; their public keys are pinned to an outside-supplied roster SHA and raw
original copies.  No supplied key, digest, signature or claimed clock is by
itself independent institutional authority, trusted UTC, global completeness,
physical custody, or current old-issuer authorization.
"""
from __future__ import annotations

import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec338_independent_custody import ceremony as old338
from ec339_offline_authority import authority as old339
from ec340_issuer_root_rotation import rotation as old340
from ec353_transparency import transparency as old353
from ec372_historical_authority import authority_archive as p372
from ec377_historical_transparency import transparency_archive as p377
from ec379_historical_source import source_archive as p379
from ec388_historical_revocation import revocation_archive as parent

RESULT_SCHEMA='ces.ec389.receiver_external_ec339_revocation_witness_custody_unresolved.v1'
DERIVE_SCHEMA='ces.ec389.unsigned_external_ec339_revocation_witness_custody_unresolved.v1'
DENIAL_SCHEMA='ces.ec389.receiver_external_ec339_revocation_witness_custody_denial.v1'
BUNDLE_SCHEMA='ces.ec389.receiver_external_ec339_revocation_publication_archive.v1'
ROSTER_SCHEMA='ces.ec389.receiver_outside_retained_external_verifier_roster.v1'
WITNESS_SCHEMA='ces.ec389.external_signed_revocation_publication_original.v1'
WITNESS_CLAIM_SCHEMA='ces.ec389.external_revocation_publication_claim.v1'
CUSTODY_SCHEMA='ces.ec389.external_signed_revocation_custody_original.v1'
CUSTODY_CLAIM_SCHEMA='ces.ec389.external_revocation_custody_claim.v1'
INVENTORY_SCHEMA='ces.ec389.receiver_external_revocation_witness_custody_inventory.v1'
WITNESS_DOMAIN=b'CES/EC389/ExternalOldEC339Revocation/Publication/v1\0'
CUSTODY_DOMAIN=b'CES/EC389/ExternalOldEC339Revocation/Custody/v1\0'
MAX_BUNDLE=400_000
MAX_ROSTER=22_000
MAX_SIGNED=12_000
ZERO='0'*64
NEW_SCALARS=(
 'historical_ec339_external_witness_custody_archive_bundle_file',
 'expected_historical_ec339_external_witness_custody_archive_bundle_sha256',
 'expected_outside_retained_ec389_external_verifier_roster_sha256',
)
AUDIT_ONLY=('expected_retained_historical_ec339_external_witness_custody_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_external_publication_inventory_shas','--historical-ec339-external-publication-inventory-sha256'),
 ('historical_ec339_external_custody_inventory_shas','--historical-ec339-external-custody-inventory-sha256'),
 ('minimum_historical_ec339_external_witness_custody_pair_counts','--minimum-historical-ec339-external-witness-custody-pair-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec388_canonical_result_sha256',
 'ec388_historical_revocation_archive_original_sha256','claimed_directory_lineage_id',
 'external_verifier_roster_original','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','witnesses','custodians'}
KEY_FIELDS={'signer_id','public_hex','public_key_original'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={'tsa_channel_id','external_revocation_publication_and_custody_originals'}
PAIR_FIELDS={'signed_witness_original','signed_custody_original'}
SIGNED_FIELDS={'schema','claim','signature_ed25519'}
WITNESS_CLAIM_FIELDS={'schema','directory_lineage_id','tsa_channel_id','first_published_epoch_index',
 'role','ec338_actor_receipt_original_sha256','ec339_issuer_grant_original_sha256',
 'ec339_signed_revoked_status_original_sha256','ec339_verifier_challenge_sha256',
 'ec339_signed_as_of_utc','ec339_revoked_effective_utc','witness_id',
 'publication_sequence','previous_signed_witness_original_sha256','claimed_published_utc'}
CUSTODY_CLAIM_FIELDS={'schema','directory_lineage_id','tsa_channel_id','first_published_epoch_index',
 'role','ec339_signed_revoked_status_original_sha256','signed_witness_original_sha256',
 'custodian_id','custody_sequence','previous_signed_custody_original_sha256',
 'claimed_deposited_utc'}
FLAGS=(
 'inherited_live_ec388_through_ec369_revocation_original_or_historical_dispute',
 'outside_retained_external_key_publication_custody_sha_or_count_disagrees',
 'authentic_old_ec339_revocation_original_not_available_in_parent',
 'visible_signed_ec339_revocation_missing_external_witness_or_custody',
 'witness_publication_or_custody_signed_clock_order_claim_disagrees',
 'dual_channel_external_witness_equivocation_or_conflicting_custody_history',
 'later_epoch_external_signed_publication_or_custody_rollback',
 'full_unmocked_external_ec339_to_ec337_and_global_revocation_not_proven',
 'external_witness_real_world_independence_trusted_time_and_physical_custody_not_proven',
)
OUTCOMES=(
 'ec389_inherited_old_revocation_or_original_parent_dispute',
 'ec389_outside_retained_external_publication_sha_or_count_disagrees',
 'ec389_genuine_ec339_revoked_source_not_recovered',
 'ec389_visible_signed_revocation_missing_external_original_publication_or_custody',
 'ec389_signed_external_witness_or_custody_clock_claim_disagrees',
 'ec389_visible_external_witness_or_custody_fork_conflict',
 'ec389_cross_epoch_external_signed_history_rollback',
 'ec389_full_global_revocation_and_unmocked_old_source_chain_not_proven',
 'ec389_institutional_witness_custody_and_trusted_utc_not_proven',
)
NEGATIVES=(
 'external_witness_verifier_roster_sha_proves_offsite_independent_legal_key_authority',
 'self_declared_external_witness_id_proves_different_real_person_or_institution',
 'signed_publication_claimed_published_utc_is_calibrated_trusted_time',
 'signed_custody_claimed_deposited_utc_proves_physical_delivery_or_worm_freeze',
 'witness_or_custodian_signature_is_old_ec339_issuer_authorization',
 'signed_revocation_publication_claim_proves_complete_global_crl_ocsp',
 'unsigned_derived_sha_inventory_self_certifies_independent_offsite_retention',
 'ec353_sender_origin_label_is_accepted_as_an_external_receiver_original',
 'unseen_signed_forks_or_unprovided_revocations_are_disproved',
 'missing_old_signed_ec339_original_can_be_replaced_by_external_self_assertion',
 'private_key_signer_network_provider_cas_worm_git_ci_or_native_ps_write_performed',
 'old_ec317_ec318_unmocked_production_or_final_user_acceptance_completed',
)
IDENT=re.compile(r'[A-Za-z][A-Za-z0-9_.:-]{0,95}\Z')
HEX64=re.compile(r'[0-9a-f]{64}\Z')
HEX128=re.compile(r'[0-9a-f]{128}\Z')


def need(condition,code,status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC389_'+code,status)


def exact(obj,fields,label):
    need(type(obj) is dict and set(obj)==set(fields),label+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    keys=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:keys.update(AUDIT_ONLY)
    need(set(opts)==keys,'EXACT_EC388_PARENT_AND_EC389_INPUTS_REQUIRED')
    earlier={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(earlier,False)  # Includes all inherited audit-only independent pins.
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                            'EC389_RECEIVER_EXTERNAL_SIGNED_ARCHIVE')
    need(old353._sha(opts[NEW_SCALARS[2]]),
         'INDEPENDENTLY_SUPPLIED_EXTERNAL_ROSTER_SHA_REQUIRED')
    if not derive:
        need(old353._sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_RETAINED_WHOLE_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORIC_EPOCH_BOUNDS_REQUIRED')
    for name in REPEAT_NAMES:
        arr=opts[name]
        need(type(arr) is list and len(arr)==n,'EXACT_PER_EPOCH_EXTERNAL_CENSUS_'+name.upper())
        if name.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=16 for v in arr),
                 'EXTERNAL_SIGNED_PAIR_COUNT_FLOOR_OUT_OF_BOUNDS')
        else:
            need(all(old353._sha(v) for v in arr),
                 'EXTERNAL_PUBLICATION_OR_CUSTODY_RETENTION_SHA_REQUIRED')
    return earlier


def _parent(report,n):
    need(type(report) is dict and report.get('schema')==parent.RESULT_SCHEMA and
         report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
         report.get('command')=='audit-historical-ec339-retirement-archive' and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         type(report.get('historical_ec339_retirement_epoch_reviews')) is list and
         len(report['historical_ec339_retirement_epoch_reviews'])==n and
         type(report.get('local_old_ec339_signed_grant_revocation_retirement_originals_consistent')) is bool and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(report[k] is True for k in parent.FLAGS[-2:]) and
         report['local_old_ec339_signed_grant_revocation_retirement_originals_consistent']==(
             not any(report[k] for k in parent.FLAGS[:7])) and
         report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
             if report[k]),parent.OUTCOMES[-1])+'_unresolved' and
         old353._sha(report.get('verified_live_parent_ec387_canonical_result_sha256')) and
         old353._sha(report.get('historical_ec339_retirement_archive_original_sha256')) and
         old353._sha(report.get('receiver_verified_old_ec339_retirement_inventory_sha256')),
         'ACTUAL_UNCHANGED_LIVE_EC388_TO_EC369_PARENT_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(report))


def _signed(doc,outer_schema,claim_schema,fields,pub,domain,label):
    exact(doc,SIGNED_FIELDS,label+'_SIGNED')
    exact(doc['claim'],fields,label+'_CLAIM')
    need(doc['schema']==outer_schema and doc['claim']['schema']==claim_schema and
         type(doc['signature_ed25519']) is str and
         HEX128.fullmatch(doc['signature_ed25519']) is not None,
         label+'_SIGNED_SCHEMA_AND_SIGNATURE_FORMAT_REQUIRED','permission_denied')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(doc['signature_ed25519']),domain+canonical.canonical(doc['claim']))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise errors.AnchorError('EC389_'+label+'_ED25519_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return doc['claim']


def _roster(doc,ref,retained_sha,read,known_old_keys):
    exact(doc,ROSTER_FIELDS,'ROSTER')
    need(doc['schema']==ROSTER_SCHEMA and type(doc['claimed_directory_lineage_id']) is str and
         IDENT.fullmatch(doc['claimed_directory_lineage_id']) is not None and
         ref['sha256']==retained_sha,
         'OUTSIDE_RETAINED_VERIFIER_ROSTER_OR_LINEAGE_MISMATCH','permission_denied')
    parties={};key_seen=set(known_old_keys);ids=set();key_paths=set()
    for part in ('witnesses','custodians'):
        lst=doc[part]
        need(type(lst) is list and 1<=len(lst)<=2,
             'ONE_OR_TWO_PINNED_EXTERNAL_'+part.upper()+'_REQUIRED')
        group={}
        for entry in lst:
            exact(entry,KEY_FIELDS,'EXTERNAL_PUBLIC_KEY')
            signer_id=entry['signer_id'];pub=entry['public_hex']
            need(type(signer_id) is str and IDENT.fullmatch(signer_id) is not None and
                 type(pub) is str and HEX64.fullmatch(pub) is not None and
                 pub!='00'*32 and signer_id not in ids and pub not in key_seen,
                 'EXTERNAL_WITNESS_CUSTODIAN_OLD_ISSUER_ACTOR_KEY_COLLISION',
                 'permission_denied')
            p372.prior.lineage.parent.ref_check(entry['public_key_original'],
                 'EC389_PINNED_EXTERNAL_SIGNER_RAW_KEY')
            need(entry['public_key_original']['path'] not in key_paths,
                 'DISTINCT_EXTERNAL_SIGNERS_MUST_NOT_REUSE_KEY_ORIGINAL_PATH',
                 'permission_denied')
            key_paths.add(entry['public_key_original']['path'])
            key=read(entry['public_key_original'],'external_'+part+'_public_key',32)
            need(len(key)==32 and key.hex()==pub,
                 'EXTERNAL_ED25519_PUBLIC_KEY_MUST_BE_RAW_PINNED_32_BYTES',
                 'permission_denied')
            ids.add(signer_id);key_seen.add(pub);group[signer_id]=pub
        parties[part]=group
    return parties


def _channel(row,original,result,roster,read,idx,lineage):
    """Witness and custody must bind a truly verified EC388 signed 'revoked'."""
    exact(row,CHANNEL_FIELDS,'EXTERNAL_CHANNEL')
    channel=row['tsa_channel_id']
    need(channel==original['tsa_channel_id']==result['tsa_channel_id'],
         'EXACT_PARENT_SIGNED_CHANNEL_ID_REQUIRED','permission_denied')
    pairs=row['external_revocation_publication_and_custody_originals']
    need(type(pairs) is list and len(pairs)<=8,'MAX_EIGHT_SIGNED_PAIRS_PER_CHANNEL')
    source={}
    for role_idx,hist in enumerate(result['ec339_verified_role_histories']):
        original_role=original['ec339_role_retirement_reviews'][role_idx]
        need(hist['role']==original_role['role']==old340.ROLES[role_idx],
             'EC388_AUTHENTIC_ROLE_AND_ORDER_REQUIRED','permission_denied')
        for position,status in enumerate(hist['additional_signed_statuses']):
            ref=original_role['additional_challenged_status_originals'][position]['signed_status_original']
            need(ref['sha256']==status['sha256'],
                 'SIGNED_REVOKED_STATUS_MUST_REUSE_TRUE_EC388_PATH_AND_SHA',
                 'permission_denied')
            if status['state']=='revoked':
                source[status['sha256']]=(hist,status,ref)
    prev_w=prev_c=ZERO;last_pub=last_deposit=None
    verified=[];seen_status=set();seen_w=set();seen_c=set();time_dispute=False
    for i,pair in enumerate(pairs):
        exact(pair,PAIR_FIELDS,'WITNESS_CUSTODY_PAIR')
        wref=pair['signed_witness_original'];cref=pair['signed_custody_original']
        for ref in (wref,cref):
            p372.prior.lineage.parent.ref_check(ref,'EC389_EXTERNAL_SIGNED_ORIGINAL')
        need(wref['path']!=cref['path'] and wref['sha256']!=cref['sha256'] and
             wref['sha256'] not in seen_w and cref['sha256'] not in seen_c,
             'NO_DUPLICATE_SIGNED_WITNESS_OR_CUSTODY_ORIGINAL', 'permission_denied')
        seen_w.add(wref['sha256']);seen_c.add(cref['sha256'])
        witness=old353.strict_json(read(wref,'external_signed_revocation_publication',MAX_SIGNED),
                                    'EC389_WITNESS')
        exact(witness,SIGNED_FIELDS,'EXTERNAL_WITNESS')
        claim=witness['claim']
        need(type(claim) is dict and claim.get('witness_id') in roster['witnesses'],
             'EXTERNALLY_PINNED_WITNESS_VERIFICATION_KEY_REQUIRED','permission_denied')
        claim=_signed(witness,WITNESS_SCHEMA,WITNESS_CLAIM_SCHEMA,
                      WITNESS_CLAIM_FIELDS,roster['witnesses'][claim['witness_id']],
                      WITNESS_DOMAIN,'WITNESS')
        status_sha=claim['ec339_signed_revoked_status_original_sha256']
        need(status_sha in source and status_sha not in seen_status,
             'WITNESS_MUST_REFERENCE_ONE_VISIBLE_VERIFIED_EC388_REVOKED_STATUS',
             'permission_denied')
        seen_status.add(status_sha)
        hist,status,status_ref=source[status_sha]
        need(claim['directory_lineage_id']==lineage and
             claim['tsa_channel_id']==channel and
             type(claim['first_published_epoch_index']) is int and
             0<=claim['first_published_epoch_index']<=idx and
             claim['role']==hist['role'] and
             claim['ec338_actor_receipt_original_sha256']==hist['actor_receipt_sha256'] and
             claim['ec339_issuer_grant_original_sha256']==hist['issuer_grant_sha256'] and
             claim['ec339_verifier_challenge_sha256']==status['verifier_challenge_sha256'] and
             claim['ec339_signed_as_of_utc']==status['as_of_utc'] and
             claim['ec339_revoked_effective_utc']==status['revoked_effective_utc'] and
             type(claim['publication_sequence']) is int and claim['publication_sequence']==i+1 and
             claim['previous_signed_witness_original_sha256']==prev_w,
             'SIGNED_WITNESS_STATUS_CHALLENGE_SOURCE_EPOCH_AND_HASH_CHAIN_MUST_MATCH',
             'permission_denied')
        need(old338._utc(claim['claimed_published_utc']),
             'SIGNED_WITNESS_CLAIMED_UTC_FORMAT_REQUIRED','permission_denied')
        pub_t=old339._time(claim['claimed_published_utc'])
        time_dispute|=pub_t<old339._time(status['as_of_utc']) or (
                      last_pub is not None and pub_t<last_pub)
        last_pub=pub_t
        custody=old353.strict_json(read(cref,'external_signed_revocation_custody',MAX_SIGNED),
                                    'EC389_CUSTODY')
        exact(custody,SIGNED_FIELDS,'EXTERNAL_CUSTODY')
        cclaim=custody['claim']
        need(type(cclaim) is dict and cclaim.get('custodian_id') in roster['custodians'],
             'EXTERNALLY_PINNED_CUSTODIAN_VERIFICATION_KEY_REQUIRED','permission_denied')
        cclaim=_signed(custody,CUSTODY_SCHEMA,CUSTODY_CLAIM_SCHEMA,
                       CUSTODY_CLAIM_FIELDS,roster['custodians'][cclaim['custodian_id']],
                       CUSTODY_DOMAIN,'CUSTODY')
        need(cclaim['directory_lineage_id']==lineage and cclaim['tsa_channel_id']==channel and
             cclaim['first_published_epoch_index']==claim['first_published_epoch_index'] and
             cclaim['role']==hist['role'] and
             cclaim['ec339_signed_revoked_status_original_sha256']==status_sha and
             cclaim['signed_witness_original_sha256']==wref['sha256'] and
             type(cclaim['custody_sequence']) is int and cclaim['custody_sequence']==i+1 and
             cclaim['previous_signed_custody_original_sha256']==prev_c and
             old338._utc(cclaim['claimed_deposited_utc']),
             'SIGNED_CUSTODY_MUST_BIND_TRUE_WITNESS_STATUS_AND_SEQUENCE',
             'permission_denied')
        deposit_t=old339._time(cclaim['claimed_deposited_utc'])
        time_dispute|=deposit_t<pub_t or (last_deposit is not None and deposit_t<last_deposit)
        last_deposit=deposit_t
        verified.append({'role':hist['role'],'old_ec339_revoked_status_sha256':status_sha,
            'old_ec339_revoked_status_original_path':status_ref['path'],
            'old_ec338_actor_receipt_sha256':hist['actor_receipt_sha256'],
            'old_ec339_issuer_grant_sha256':hist['issuer_grant_sha256'],
            'old_ec339_signed_revoked_effective_utc_claim':status['revoked_effective_utc'],
            'old_ec339_signed_as_of_utc_claim':status['as_of_utc'],
            'original_signed_challenge_sha256':status['verifier_challenge_sha256'],
            'first_published_epoch_index':claim['first_published_epoch_index'],
            'signed_witness_original_path':wref['path'],
            'signed_witness_original_sha256':wref['sha256'],
            'witness_id':claim['witness_id'],
            'claimed_published_utc':claim['claimed_published_utc'],
            'signed_custody_original_path':cref['path'],
            'signed_custody_original_sha256':cref['sha256'],
            'custodian_id':cclaim['custodian_id'],
            'claimed_deposited_utc':cclaim['claimed_deposited_utc'],
            'publication_sequence':i+1,'custody_sequence':i+1})
        prev_w=wref['sha256'];prev_c=cref['sha256']
    # A missing record is not permission to reconstruct old issuer evidence.
    return {'tsa_channel_id':channel,
        'authentic_parent_ec339_old_revoked_status_count':len(source),
        'genuine_signed_external_publication_custody_pair_count':len(verified),
        'missing_external_signed_witness_custody_for_visible_revocations':len(seen_status)!=len(source),
        'signed_claimed_clock_order_disagreement':time_dispute,
        'verified_signed_external_publication_custody':verified,
        'signed_external_witness_head_sha256':prev_w,
        'signed_external_custody_head_sha256':prev_c}


def _engine(derive,**opts):
    earlier=_inputs(opts,derive)
    actual=parent.audit(**earlier)  # No externally supplied parent report or mocked PASS.
    n=len(opts['historical_directory_root_shas'])
    psha=_parent(actual,n)
    pins={};cats={};forbidden=set();cache={}
    def read(ref,label,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC389_'+label)
        path=ref['path']
        if path in cache:
            digest,raw=cache[path]
            need(path not in forbidden and digest==ref['sha256'] and len(raw)<=cap,
                 'EXTERNAL_SIGNED_ORIGINAL_PATH_SHA_CAP_OR_ORIGIN_REUSE',
                 'permission_denied')
            return raw
        raw=p372._read(ref,'ec389_'+label,cap,pins,cats,forbidden)
        cache[path]=(ref['sha256'],raw)
        return raw
    def archive(ref,label,fields,schema,cap):
        doc=old353.strict_json(read(ref,label,cap),'EC389_'+label)
        exact(doc,fields,label)
        need(doc['schema']==schema and type(doc['epochs']) is list and
             len(doc['epochs'])==n,
             'AUTHENTIC_PARENT_ARCHIVE_OR_EPOCH_SCHEMA_REQUIRED',
             'permission_denied')
        return doc
    parent_ref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    cur_ref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    old=archive(parent_ref,'ec388_original_parent',parent.BUNDLE_FIELDS,
                parent.BUNDLE_SCHEMA,parent.MAX_BUNDLE)
    cur=archive(cur_ref,'external_publication_and_custody',BUNDLE_FIELDS,BUNDLE_SCHEMA,
                MAX_BUNDLE)
    need(cur['parent_ec388_canonical_result_sha256']==psha and
         cur['ec388_historical_revocation_archive_original_sha256']==parent_ref['sha256'] and
         old['claimed_directory_lineage_id']==cur['claimed_directory_lineage_id']==
              opts['claimed_historical_directory_lineage_id'] and
         actual['historical_ec339_retirement_archive_original_sha256']==parent_ref['sha256'],
         'LIVE_PARENT_CANONICAL_SHA_OR_TRUE_ORIGINAL_LINEAGE_MISMATCH',
         'permission_denied')
    root_ref={'path':opts[parent.parent.parent.NEW_SCALARS[0]],
              'sha256':opts[parent.parent.parent.NEW_SCALARS[1]]}
    rotation_ref={'path':opts[parent.parent.NEW_SCALARS[0]],
                  'sha256':opts[parent.parent.NEW_SCALARS[1]]}
    root=archive(root_ref,'ec386_original_root',parent.parent.parent.BUNDLE_FIELDS,
                 parent.parent.parent.BUNDLE_SCHEMA,parent.parent.parent.MAX_BUNDLE)
    rotated=archive(rotation_ref,'ec387_original_rotation',parent.parent.BUNDLE_FIELDS,
                    parent.parent.BUNDLE_SCHEMA,parent.parent.MAX_BUNDLE)
    need(rotated['ec386_historical_root_archive_original_sha256']==root_ref['sha256'] and
         old['ec387_historical_rotation_archive_original_sha256']==rotation_ref['sha256'] and
         root['claimed_directory_lineage_id']==rotated['claimed_directory_lineage_id']==
         old['claimed_directory_lineage_id'],
         'EC386_EC387_EC388_AUTHENTIC_ANCESTOR_ARCHIVE_BOUND', 'permission_denied')
    # Explicitly ban EC353 sender-origin labels before opening new signer material.
    index_ref={'path':opts['historical_transparency_archive_bundle_file'],
               'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    sender=archive(index_ref,'ec377_sender_index',p377.BUNDLE_FIELDS,
                   p377.BUNDLE_SCHEMA,p377.MAX_BUNDLE)
    for ep in sender['epochs']:
        label_ref=ep['ec353_publication_bundle_original']
        label=old353.strict_json(read(label_ref,'sender_labels_untrusted',old353.MAX_BUNDLE),
                                 'EC389_OLD_SENDER_LABELS')
        p379._old_sender_labels(label,forbidden)
        forbidden.add(label_ref['path'])
    forbidden.add(index_ref['path'])
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    roster_ref=cur['external_verifier_roster_original']
    p372.prior.lineage.parent.ref_check(roster_ref,'EC389_EXTERNAL_ROSTER_ORIGINAL')
    roster=old353.strict_json(read(roster_ref,'external_witness_custodian_roster',MAX_ROSTER),
                              'EC389_EXTERNAL_ROSTER')
    need(roster.get('claimed_directory_lineage_id')==cur['claimed_directory_lineage_id'],
         'EXTERNAL_VERIFIER_ROSTER_LINEAGE_MUST_MATCH_AUTHENTIC_OLD',
         'permission_denied')
    # Build old issuer+actor public keys only from true originally authenticated EC338 policy.
    known_old_keys=set();channel_sources=[]
    for i,(ep,p_ep,rot_ep,root_ep) in enumerate(zip(
            cur['epochs'],old['epochs'],rotated['epochs'],root['epochs'],strict=True)):
        for row,fields in ((ep,EPOCH_FIELDS),(p_ep,parent.EPOCH_FIELDS),
                           (rot_ep,parent.parent.EPOCH_FIELDS),
                           (root_ep,parent.parent.parent.EPOCH_FIELDS)):
            exact(row,fields,'AUTHENTIC_EPOCH')
            need(row['epoch_index']==i and type(row['channels']) is list,
                 'ORIGINAL_EPOCH_INDEX_REQUIRED','permission_denied')
        channels=(ep['channels'],p_ep['channels'],rot_ep['channels'],root_ep['channels'])
        ids=[[r.get('tsa_channel_id') for r in rows] for rows in channels]
        need(1<=len(ids[0])<=2 and ids[0]==ids[1]==ids[2]==ids[3] and
             ids[0]==sorted(set(ids[0])),
             'EXACT_AUTHENTIC_EC386_EC387_EC388_CHANNELS_REQUIRED',
             'permission_denied')
        channel_sources.append(list(zip(*channels,strict=True)))
        for src in p_ep['channels']:
            if src['ec338_policy_original'] is None:continue
            raw=read(src['ec338_policy_original'],'old_ec338_issuer_actor_policy',
                     old338.MAX_POLICY)
            policy=old339.io.parse(raw,old338.MAX_POLICY)
            need(type(policy) is dict and raw==canonical.canonical(policy)+b'\n',
                 'AUTHENTIC_OLD_EC338_POLICY_LF_CANONICAL_REQUIRED','permission_denied')
            for actor in policy['actors']:known_old_keys.add(actor['public_hex'])
        for src in rot_ep['channels']:
            if src['ec339_predecessor_authority_roster_original'] is None:continue
            raw=read(src['ec339_predecessor_authority_roster_original'],
                     'old_ec339_issuer_roster',old339.MAX_ROSTER)
            issuer=old339.io.parse(raw,old339.MAX_ROSTER)
            need(type(issuer) is dict and raw==canonical.canonical(issuer)+b'\n',
                 'AUTHENTIC_OLD_EC339_ROSTER_LF_CANONICAL_REQUIRED','permission_denied')
            for role in issuer['issuers']:known_old_keys.add(role['issuer_public_hex'])
            # The external verifier cannot quietly be a rotated successor,
            # the old EC340 observer or any historical EC387 signer either.
            for key_copy in src['ec340_original_public_key_sources']:
                known_old_keys.add(key_copy['public_hex'])
        for src in root_ep['channels']:
            for key_copy in src['ec341_signer_public_key_copies']:
                known_old_keys.add(key_copy['public_hex'])
    party=_roster(roster,roster_ref,opts[NEW_SCALARS[2]],read,known_old_keys)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not actual['local_old_ec339_signed_grant_revocation_retirement_originals_consistent']
    seen_by_channel={};by_role_channel={};epoch_reviews=[];inventory=[];pairs_total=0
    for idx,rows in enumerate(channel_sources):
        results=[];historic_rows=[];publication=[];custodies=[]
        for row,old_row,rot_row,root_row in rows:
            exact(row,CHANNEL_FIELDS,'EXTERNAL_RECEIVER_CHANNEL')
            # Original old EC338+339 signatures rechecked, with the real EC386/387
            # originals, rather than a caller-furnished status SHA list.
            historic=parent._channel(old_row,rot_row,root_row,read)
            current=_channel(row,old_row,historic,party,read,idx,cur['claimed_directory_lineage_id'])
            historic_rows.append(historic)
            results.append(current)
            flags[FLAGS[2]]|=not historic['full_original_ec339_role_retirement_replay']
            flags[FLAGS[3]]|=current['missing_external_signed_witness_custody_for_visible_revocations']
            flags[FLAGS[4]]|=current['signed_claimed_clock_order_disagreement']
            previous=seen_by_channel.get(row['tsa_channel_id'])
            if previous is not None:
                before=previous['verified_signed_external_publication_custody']
                after=current['verified_signed_external_publication_custody']
                if (len(after)<len(before) or after[:len(before)]!=before or
                    (before and after[:len(before)]==before and
                     any(x['first_published_epoch_index']!=idx for x in after[len(before):]))):
                    flags[FLAGS[6]]=True
            else:
                if any(e['first_published_epoch_index']!=idx for e in
                       current['verified_signed_external_publication_custody']):
                    flags[FLAGS[6]]=True
            seen_by_channel[row['tsa_channel_id']]=current
            for record in current['verified_signed_external_publication_custody']:
                prior=by_role_channel.setdefault(('w',record['witness_id'],
                     row['tsa_channel_id'],record['publication_sequence']),
                     record['signed_witness_original_sha256'])
                if prior!=record['signed_witness_original_sha256']:flags[FLAGS[5]]=True
                prior=by_role_channel.setdefault(('c',record['custodian_id'],
                     row['tsa_channel_id'],record['custody_sequence']),
                     record['signed_custody_original_sha256'])
                if prior!=record['signed_custody_original_sha256']:flags[FLAGS[5]]=True
            publication.append({'tsa_channel_id':row['tsa_channel_id'],
                'records':[{'role':r['role'],'ec339_revoked_sha256':r['old_ec339_revoked_status_sha256'],
                    'signed_witness_sha256':r['signed_witness_original_sha256'],
                    'witness_id':r['witness_id'],'claimed_published_utc':r['claimed_published_utc'],
                    'sequence':r['publication_sequence']}
                    for r in current['verified_signed_external_publication_custody']]})
            custodies.append({'tsa_channel_id':row['tsa_channel_id'],
                'records':[{'role':r['role'],'ec339_revoked_sha256':r['old_ec339_revoked_status_sha256'],
                    'signed_custody_sha256':r['signed_custody_original_sha256'],
                    'signed_witness_sha256':r['signed_witness_original_sha256'],
                    'custodian_id':r['custodian_id'],'claimed_deposited_utc':r['claimed_deposited_utc'],
                    'sequence':r['custody_sequence']}
                    for r in current['verified_signed_external_publication_custody']]})
        # EC388 already audited these historic originals.  A changed source
        # between that audit and this receiver replay must be denied rather
        # than silently turned into a newly derived witness inventory.
        role_originals=[{'tsa_channel_id':r['tsa_channel_id'],
            'root_retirement_utc_claim':r['ec340_effective_utc'],
            'ec338_policy_sha256':r['ec338_policy_sha256'],
            'ec339_roster_sha256':r['ec339_issuer_roster_sha256'],
            'role_reviews':r['ec339_verified_role_histories']} for r in historic_rows]
        transitions=[{'tsa_channel_id':r['tsa_channel_id'],
            'signed_revocation_history':r['ec339_signed_retirement_statuses']}
            for r in historic_rows]
        parent_epoch=actual['historical_ec339_retirement_epoch_reviews'][idx]
        need(type(parent_epoch) is dict and parent_epoch.get('epoch_index')==idx and
             parent_epoch.get('old_ec339_role_original_inventory_sha256')==sha(canonical.canonical(role_originals)) and
             parent_epoch.get('old_ec339_revocation_transition_inventory_sha256')==sha(canonical.canonical(transitions)) and
             parent_epoch.get('verified_old_ec338_signed_actor_receipt_count')==sum(
                 r['ec338_signed_actor_receipt_count'] for r in historic_rows) and
             parent_epoch.get('verified_old_ec339_boundary_status_count')==sum(
                 r['ec339_challenged_retirement_status_count'] for r in historic_rows) and
             parent_epoch.get('verified_old_ec339_revoked_status_transition_count')==sum(
                 r['ec339_signed_revocation_transition_count'] for r in historic_rows),
             'REOPENED_OLD_EC339_SOURCE_MUST_MATCH_LIVE_EC388_EPOCH_REPORT',
             'permission_denied')
        # Compare independently visible signed record heads across two original
        # channels; a different SHA per channel isn't automatically a fork.
        # Both channels can separately publish the same old status.  Only a
        # signer+channel+sequence equivocation is a visible contradiction.
        pub_sha=sha(canonical.canonical(publication))
        custody_sha=sha(canonical.canonical(custodies))
        c=sum(r['genuine_signed_external_publication_custody_pair_count'] for r in results)
        pairs_total+=c
        flags[FLAGS[1]]|=(pub_sha!=opts[NEW_REPEATS[0][0]][idx] or
            custody_sha!=opts[NEW_REPEATS[1][0]][idx] or
            c<opts[NEW_REPEATS[2][0]][idx])
        epoch_reviews.append({'epoch_index':idx,'verified_external_signed_publication_custody_pair_count':c,
          'visible_parent_ec339_signed_revoked_status_count':sum(
              r['authentic_parent_ec339_old_revoked_status_count'] for r in results),
          'external_publication_inventory_sha256':pub_sha,
          'external_custody_inventory_sha256':custody_sha,
          'missing_external_signed_witness_custody_channels':sum(
              r['missing_external_signed_witness_custody_for_visible_revocations'] for r in results),
          'signed_external_claim_time_disagreement_channels':sum(
              r['signed_claimed_clock_order_disagreement'] for r in results),
          'local_signed_external_publication_custody_consistent':all(
              not r['missing_external_signed_witness_custody_for_visible_revocations'] and
              not r['signed_claimed_clock_order_disagreement'] for r in results)})
        inventory.append({'epoch_index':idx,'verified_external_revocation_source_and_signed_pairs':results,
             'external_publication_inventory_sha256':pub_sha,
             'external_custody_inventory_sha256':custody_sha})
    # Check verifier public copies and the SHA-pinned roster again after all
    # evidence parsing; a replaced key is not retroactively made authoritative.
    for entry in (*roster['witnesses'],*roster['custodians']):
        keyref=entry['public_key_original']
        raw=p372._read(keyref,'ec389_late_external_signer_public_key',32,{}, {},set())
        need(len(raw)==32 and raw.hex()==entry['public_hex'] and sha(raw)==keyref['sha256'],
             'EXTERNAL_VERIFIER_KEY_CHANGED_AFTER_SIGNATURE_CHECK','permission_denied')
    raw=p372._read(roster_ref,'ec389_late_externally_pinned_roster',MAX_ROSTER,{}, {},set())
    need(sha(raw)==roster_ref['sha256'],
         'EXTERNAL_VERIFIER_ROSTER_CHANGED_AFTER_SIGNER_CHECK','permission_denied')
    # Late independent reread of all pair files and outside public-key originals.
    for r in inventory:
        for channel in r['verified_external_revocation_source_and_signed_pairs']:
            for pair in channel['verified_signed_external_publication_custody']:
                for path,hashval in ((pair['signed_witness_original_path'],pair['signed_witness_original_sha256']),
                                     (pair['signed_custody_original_path'],pair['signed_custody_original_sha256'])):
                    ref={'path':path,'sha256':hashval}
                    raw=p372._read(ref,'ec389_late_signed_original',MAX_SIGNED,{}, {},set())
                    need(sha(raw)==hashval,'EXTERNAL_SIGNED_ORIGINAL_CHANGED_AFTER_VERIFICATION',
                         'permission_denied')
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    derived={'schema':INVENTORY_SCHEMA,
        'live_ec388_to_ec369_parent_canonical_result_sha256':psha,
        'receiver_original_ec388_revocation_archive_sha256':parent_ref['sha256'],
        'receiver_original_ec389_external_archive_sha256':cur_ref['sha256'],
        'receiver_original_external_verifier_roster_sha256':roster_ref['sha256'],
        'claimed_directory_lineage_id':cur['claimed_directory_lineage_id'],
        'historical_external_revocation_epoch_reviews':inventory}
    digest=sha(canonical.canonical(derived))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec339-external-witness-inventory' if derive else
                 'audit-historical-ec339-external-witness-archive',
       'status':next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_parent_ec388_canonical_result_sha256':psha,
       'historical_ec339_external_witness_archive_original_sha256':cur_ref['sha256'],
       'receiver_verified_external_revocation_witness_custody_inventory_sha256':digest,
       'genuine_external_signed_witness_custody_pair_count':pairs_total,
       'historical_ec339_external_witness_epoch_reviews':epoch_reviews,
       'local_external_signed_revocation_publication_custody_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
       **flags,**{name:False for name in NEGATIVES},
       **({'unsigned_external_ec339_revocation_witness_custody_inventory':derived,
           'caller_roster_and_sha_independently_offsite_certified':False}
          if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
