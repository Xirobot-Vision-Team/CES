#!/usr/bin/env python3
"""EC390 receiver-only third-party signed archive-head and receipt history.

The mandatory live EC389->EC369 audit precedes this check. Every claimed
third-party head is signed over the complete visible EC389 original-SHA pair
snapshot; a different key separately signs its receipt. A valid contradictory
head is *retained as adverse evidence*, not silently discarded or promoted to
trusted time, legal custody, global fork finality, or old issuer authorization.
"""
from __future__ import annotations

import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from independent_custody import ceremony as old338
from offline_authority import authority as old339
from issuer_root_rotation import rotation as old340
from transparency import transparency as tr
from historical_authority import authority_archive as oldfiles
from historical_transparency import transparency_archive as oldindex
from historical_source import source_archive as oldsource
from external_revocation import witness_custody as parent

RESULT_SCHEMA = 'ces.ec390.receiver_independent_signed_archive_heads_receipts_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec390.unsigned_independent_archive_heads_receipts_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec390.receiver_independent_archive_heads_receipts_denial.v1'
BUNDLE_SCHEMA = 'ces.ec390.receiver_independent_ec339_revocation_archive_heads_bundle.v1'
ROSTER_SCHEMA = 'ces.ec390.outside_retained_independent_archive_receiver_roster.v1'
HEAD_SCHEMA = 'ces.ec390.independent_signed_revocation_archive_head_original.v1'
HEAD_CLAIM_SCHEMA = 'ces.ec390.independent_revocation_archive_head_claim.v1'
RECEIPT_SCHEMA = 'ces.ec390.independent_signed_archive_head_receipt_original.v1'
RECEIPT_CLAIM_SCHEMA = 'ces.ec390.independent_archive_head_receipt_claim.v1'
INVENTORY_SCHEMA = 'ces.ec390.receiver_unsigned_independent_archive_heads_receipts_inventory.v1'
HEAD_DOMAIN = b'CES/EC390/IndependentOldEC339Revocation/ArchiveHead/v1\0'
RECEIPT_DOMAIN = b'CES/EC390/IndependentOldEC339Revocation/HeadReceipt/v1\0'
ZERO = '0'*64
MAX_BUNDLE = 120_000
MAX_ROSTER = 22_000
MAX_SIGNED = 16_000
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_.:-]{0,95}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX128 = re.compile(r'[0-9a-f]{128}\Z')
NEW_SCALARS = (
    'historical_ec339_independent_archive_heads_bundle_file',
    'expected_historical_ec339_independent_archive_heads_bundle_sha256',
    'expected_outside_retained_ec390_independent_archive_roster_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_independent_archive_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_independent_signed_head_inventory_shas',
     '--historical-ec339-independent-signed-head-inventory-sha256'),
    ('historical_ec339_independent_signed_receipt_inventory_shas',
     '--historical-ec339-independent-signed-receipt-inventory-sha256'),
    ('minimum_historical_ec339_independent_signed_checkpoint_counts',
     '--minimum-historical-ec339-independent-signed-checkpoint-count'),
)
REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS = (*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
BUNDLE_FIELDS = {'schema','parent_ec389_canonical_result_sha256',
    'ec389_external_witness_archive_original_sha256','claimed_directory_lineage_id',
    'independent_archive_roster_original','epochs'}
ROSTER_FIELDS = {'schema','claimed_directory_lineage_id','archivists','receipt_attestors'}
KEY_FIELDS = {'signer_id','public_hex','public_key_original'}
EPOCH_FIELDS = {'epoch_index','channels'}
CHANNEL_FIELDS = {'tsa_channel_id','signed_archive_head_original','signed_head_receipt_original'}
SIGNED_FIELDS = {'schema','claim','signature_ed25519'}
PAIR_FIELDS = {'ec339_revoked_status_original_sha256','ec389_signed_witness_original_sha256',
               'ec389_signed_custody_original_sha256'}
HEAD_CLAIM_FIELDS = {'schema','directory_lineage_id','tsa_channel_id','epoch_index',
    'parent_ec389_canonical_result_sha256','ec389_external_witness_archive_original_sha256',
    'ec389_parent_derived_inventory_sha256','archivist_id','checkpoint_sequence',
    'previous_signed_archive_head_original_sha256','ec389_signed_source_pairs',
    'claimed_archived_utc'}
RECEIPT_CLAIM_FIELDS = {'schema','directory_lineage_id','tsa_channel_id','epoch_index',
    'signed_archive_head_original_sha256','ec389_signed_source_pairs_sha256',
    'receipt_attestor_id','receipt_sequence','previous_signed_receipt_original_sha256',
    'claimed_received_utc'}
FLAGS = (
    'inherited_live_ec389_to_ec369_signed_revocation_or_receipt_dispute',
    'outside_retained_signed_checkpoint_sha_or_minimum_count_disagrees',
    'authentic_ec389_original_pairs_or_parent_inventory_disagree_on_reread',
    'visible_ec389_external_revocation_missing_independent_head_or_receipt',
    'signed_third_party_head_conflicts_with_verified_ec389_original_snapshot',
    'signed_archive_or_receipt_claimed_clock_order_disagrees',
    'cross_epoch_signed_retained_head_or_receipt_rollback_or_broken_predecessor',
    'third_party_signed_checkpoint_coverage_cannot_certify_hidden_forks',
    'outside_signer_authority_trusted_utc_and_physical_retention_not_proven',
)
OUTCOMES = (
    'ec390_inherited_signed_revocation_parent_dispute',
    'ec390_independent_retained_checkpoint_inventory_or_floor_disagrees',
    'ec390_reopened_ec389_verified_originals_or_inventory_disagree',
    'ec390_missing_independent_signed_archive_head_or_receipt',
    'ec390_independent_signed_head_disagrees_with_authentic_revocation_history',
    'ec390_signed_third_party_clock_claim_disagreement',
    'ec390_visible_retained_head_or_receipt_history_rollback',
    'ec390_unseen_forks_and_global_external_history_not_proven',
    'ec390_legal_independent_time_and_physical_custody_not_proven',
)
NEGATIVES = (
    'outside_supplied_roster_sha_proves_real_independent_registered_archive_authority',
    'different_ed25519_keys_prove_different_real_people_or_physical_sites',
    'signed_archive_head_proves_complete_global_ec339_crl_ocsp_or_undisclosed_forks_absent',
    'signed_archive_claimed_utc_is_calibrated_trusted_wall_clock',
    'signed_receipt_claimed_utc_proves_actual_physical_transfer_or_worm_storage',
    'retained_hash_supplied_with_receiver_bundle_proves_historical_prior_retention',
    'third_party_archive_signatures_extend_old_ec339_issuer_authority',
    'signed_conflicting_heads_select_a_globally_authoritative_history_winner',
    'sender_ec353_origin_path_accepted_as_verified_receiver_original',
    'unsigned_derived_inventory_is_itself_signed_or_independent_legal_certification',
    'private_key_network_provider_cas_worm_git_ci_or_powershell_write_performed',
    'unmocked_ec317_ec318_and_final_user_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC390_'+code,status)


def exact(doc,fields,label):
    need(type(doc) is dict and set(doc)==set(fields),label+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    expected=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'EXACT_EC389_PARENT_AND_EC390_INPUTS_REQUIRED')
    older={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(older,False)
    oldfiles.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                                'EC390_RECEIVER_ARCHIVE_HEAD_BUNDLE')
    need(tr._sha(opts[NEW_SCALARS[2]]),'OUTSIDE_PRE_RETAINED_ARCHIVE_ROSTER_SHA_REQUIRED')
    if not derive:
        need(tr._sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_RETAINED_DERIVED_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'MAX_THREE_HISTORIC_EPOCHS_REQUIRED')
    for name in REPEAT_NAMES:
        arr=opts[name]
        need(type(arr) is list and len(arr)==n,'EXACT_PER_EPOCH_INDEPENDENT_SIGNED_HISTORY_'+name.upper())
        if name.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=2 for v in arr),
                 'MAX_TWO_SIGNED_CHECKPOINTS_PER_EPOCH')
        else:
            need(all(tr._sha(v) for v in arr),'SIGNED_CHECKPOINT_RETENTION_SHA_REQUIRED')
    return older


def _parent(report,n):
    need(type(report) is dict and report.get('schema')==parent.RESULT_SCHEMA and
         report.get('command')=='audit-historical-ec339-external-witness-archive' and
         report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         type(report.get('historical_ec339_external_witness_epoch_reviews')) is list and
         len(report['historical_ec339_external_witness_epoch_reviews'])==n and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] is True for k in parent.FLAGS[-2:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         type(report.get('local_external_signed_revocation_publication_custody_consistent')) is bool and
         report['local_external_signed_revocation_publication_custody_consistent']==(
            not any(report[k] for k in parent.FLAGS[:7])) and
         report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
            if report[k]),parent.OUTCOMES[-1])+'_unresolved' and
         all(type(ep) is dict and ep.get('epoch_index')==i and
             type(ep.get('verified_external_signed_publication_custody_pair_count')) is int and
             0<=ep['verified_external_signed_publication_custody_pair_count']<=16 and
             tr._sha(ep.get('external_publication_inventory_sha256')) and
             tr._sha(ep.get('external_custody_inventory_sha256'))
             for i,ep in enumerate(report['historical_ec339_external_witness_epoch_reviews'])) and
         tr._sha(report.get('historical_ec339_external_witness_archive_original_sha256')) and
         tr._sha(report.get('receiver_verified_external_revocation_witness_custody_inventory_sha256')) and
         tr._sha(report.get('verified_live_parent_ec388_canonical_result_sha256')),
         'ACTUAL_UNCHANGED_LIVE_EC389_TO_EC369_RECEIVER_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(report))


def _signed(doc,outer_schema,claim_schema,fields,pub,domain,label):
    exact(doc,SIGNED_FIELDS,label+'_SIGNED')
    exact(doc['claim'],fields,label+'_CLAIM')
    need(doc['schema']==outer_schema and doc['claim']['schema']==claim_schema and
         type(doc['signature_ed25519']) is str and
         HEX128.fullmatch(doc['signature_ed25519']) is not None,
         label+'_SCHEMA_OR_ED25519_SIGNATURE_ENCODING','permission_denied')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(doc['signature_ed25519']),domain+canonical.canonical(doc['claim']))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise errors.AnchorError('EC390_'+label+'_ED25519_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return doc['claim']


def _roster(roster,ref,retained,read,excluded_ids,excluded_public):
    exact(roster,ROSTER_FIELDS,'INDEPENDENT_ARCHIVE_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and ref['sha256']==retained and
         type(roster['claimed_directory_lineage_id']) is str and
         IDENT.fullmatch(roster['claimed_directory_lineage_id']) is not None,
         'INDEPENDENT_ARCHIVE_ROSTER_SHA_LINEAGE_REQUIRED','permission_denied')
    parties={};seen_id=set(excluded_ids);seen_key=set(excluded_public);paths=set()
    for group in ('archivists','receipt_attestors'):
        party=roster[group]
        need(type(party) is list and 1<=len(party)<=2,'ONE_OR_TWO_DISTINCT_'+group.upper()+'_REQUIRED')
        verified={}
        for key in party:
            exact(key,KEY_FIELDS,'EXTERNAL_ARCHIVE_PUBLIC_KEY')
            sid=key['signer_id'];pub=key['public_hex'];refkey=key['public_key_original']
            need(type(sid) is str and IDENT.fullmatch(sid) is not None and
                 type(pub) is str and HEX64.fullmatch(pub) is not None and
                 pub!='00'*32 and sid not in seen_id and pub not in seen_key,
                 'NO_OLD_SIGNER_OR_ARCHIVIST_RECEIPT_REUSED_PUBLIC_KEY_OR_ID',
                 'permission_denied')
            oldfiles.prior.lineage.parent.ref_check(refkey,'EC390_ARCHIVE_RAW_PUBKEY')
            need(refkey['path'] not in paths,'NO_REUSED_ARCHIVE_PUBLIC_KEY_PATH',
                 'permission_denied')
            raw=read(refkey,'signed_archive_raw_public_key',32)
            need(len(raw)==32 and raw.hex()==pub,
                 'RAW_ED25519_PUBLIC_KEY_MUST_MATCH_SIGNED_ROLE_ROSTER','permission_denied')
            verified[sid]=pub
            seen_id.add(sid);seen_key.add(pub);paths.add(refkey['path'])
        parties[group]=verified
    return parties


def _source_epoch(ep,roster,read,idx,lineage):
    """Rebuild exactly the EC389 signed source-pair inventory, not a caller list."""
    exact(ep,parent.EPOCH_FIELDS,'EC389_AUTHENTIC_EPOCH')
    need(ep['epoch_index']==idx and type(ep['channels']) is list and
         1<=len(ep['channels'])<=2,'EC389_AUTHENTIC_EPOCH_AND_CHANNELS_REQUIRED')
    publication=[];custodies=[];data={};ids=[];count=0
    for ch in ep['channels']:
        exact(ch,parent.CHANNEL_FIELDS,'EC389_AUTHENTIC_CHANNEL')
        cid=ch['tsa_channel_id'];ids.append(cid)
        pairs=ch['external_revocation_publication_and_custody_originals']
        need(type(cid) is str and IDENT.fullmatch(cid) is not None and
             type(pairs) is list and len(pairs)<=8,
             'EC389_AUTHENTIC_CHANNEL_SIGNED_PAIR_BOUND_REQUIRED','permission_denied')
        pubs=[];deps=[];snapshot=[];last_pub=last_dep=None
        pw=pc=ZERO
        for i,pair in enumerate(pairs):
            exact(pair,parent.PAIR_FIELDS,'EC389_ORIGINAL_PAIR')
            wref=pair['signed_witness_original'];cref=pair['signed_custody_original']
            need(wref['path']!=cref['path'] and wref['sha256']!=cref['sha256'],
                 'EC389_SIGNATURE_ORIGINAL_PATHS_AND_SHA_MUST_DIFFER','permission_denied')
            w=tr.strict_json(read(wref,'reopen_ec389_signed_witness',parent.MAX_SIGNED),
                             'EC390_REOPEN_EC389_WITNESS')
            exact(w,parent.SIGNED_FIELDS,'EC389_REOPEN_SIGNED_WITNESS')
            wc=w['claim']
            need(type(wc) is dict and wc.get('witness_id') in roster['witnesses'],
                 'EC389_ORIGINAL_WITNESS_SIGNER_REQUIRED','permission_denied')
            wc=parent._signed(w,parent.WITNESS_SCHEMA,parent.WITNESS_CLAIM_SCHEMA,
                parent.WITNESS_CLAIM_FIELDS,roster['witnesses'][wc['witness_id']],
                parent.WITNESS_DOMAIN,'REOPEN_EC389_WITNESS')
            c=tr.strict_json(read(cref,'reopen_ec389_signed_custody',parent.MAX_SIGNED),
                             'EC390_REOPEN_EC389_CUSTODY')
            exact(c,parent.SIGNED_FIELDS,'EC389_REOPEN_SIGNED_CUSTODY')
            cc=c['claim']
            need(type(cc) is dict and cc.get('custodian_id') in roster['custodians'],
                 'EC389_ORIGINAL_CUSTODIAN_SIGNER_REQUIRED','permission_denied')
            cc=parent._signed(c,parent.CUSTODY_SCHEMA,parent.CUSTODY_CLAIM_SCHEMA,
                parent.CUSTODY_CLAIM_FIELDS,roster['custodians'][cc['custodian_id']],
                parent.CUSTODY_DOMAIN,'REOPEN_EC389_CUSTODY')
            need(wc['directory_lineage_id']==cc['directory_lineage_id']==lineage and
                 wc['tsa_channel_id']==cc['tsa_channel_id']==cid and
                 wc['role']==cc['role'] in old340.ROLES and
                 wc['ec339_signed_revoked_status_original_sha256']==
                   cc['ec339_signed_revoked_status_original_sha256'] and
                 cc['signed_witness_original_sha256']==wref['sha256'] and
                 type(wc['publication_sequence']) is int and wc['publication_sequence']==i+1 and
                 type(cc['custody_sequence']) is int and cc['custody_sequence']==i+1 and
                 wc['previous_signed_witness_original_sha256']==pw and
                 cc['previous_signed_custody_original_sha256']==pc and
                 type(wc['first_published_epoch_index']) is int and
                 0<=wc['first_published_epoch_index']<=idx and
                 wc['first_published_epoch_index']==cc['first_published_epoch_index'] and
                 old338._utc(wc['claimed_published_utc']) and
                 old338._utc(cc['claimed_deposited_utc']),
                 'REOPENED_EC389_SIGNED_PAIR_IDENTITY_SEQUENCE_OR_SHA_CHAIN_INVALID',
                 'permission_denied')
            last_pub=old339._time(wc['claimed_published_utc'])
            last_dep=old339._time(cc['claimed_deposited_utc'])
            snapshot.append({'ec339_revoked_status_original_sha256':
                               wc['ec339_signed_revoked_status_original_sha256'],
                             'ec389_signed_witness_original_sha256':wref['sha256'],
                             'ec389_signed_custody_original_sha256':cref['sha256']})
            pubs.append({'role':wc['role'], 'ec339_revoked_sha256':
                wc['ec339_signed_revoked_status_original_sha256'],
                'signed_witness_sha256':wref['sha256'],'witness_id':wc['witness_id'],
                'claimed_published_utc':wc['claimed_published_utc'],'sequence':i+1})
            deps.append({'role':wc['role'],'ec339_revoked_sha256':
                wc['ec339_signed_revoked_status_original_sha256'],
                'signed_custody_sha256':cref['sha256'],
                'signed_witness_sha256':wref['sha256'],'custodian_id':cc['custodian_id'],
                'claimed_deposited_utc':cc['claimed_deposited_utc'],'sequence':i+1})
            pw=wref['sha256'];pc=cref['sha256']
        count+=len(snapshot)
        data[cid]={'pairs':snapshot,'last_deposit':last_dep,
                   'witness_head_sha256':pw,'custody_head_sha256':pc}
        publication.append({'tsa_channel_id':cid,'records':pubs})
        custodies.append({'tsa_channel_id':cid,'records':deps})
    need(ids==sorted(set(ids)),'EC389_AUTHENTIC_CHANNEL_ORDER','permission_denied')
    return data,sha(canonical.canonical(publication)),sha(canonical.canonical(custodies)),count


def _channel(row,source,signers,read,idx,lineage,parent_sha,archive_sha,inventory_sha,
             previous,flag_set):
    """Verify both *distinct* signatures; preserve signed disagreeing snapshots."""
    exact(row,CHANNEL_FIELDS,'SIGNED_HEAD_RECEIPT_CHANNEL')
    cid=row['tsa_channel_id'];need(cid in source,'EC389_CHANNEL_REQUIRED','permission_denied')
    href=row['signed_archive_head_original'];rref=row['signed_head_receipt_original']
    need((href is None and rref is None) or
         (href is not None and (rref is None or href!=rref)),
         'RECEIPT_REQUIRES_SIGNED_HEAD_AND_DISTINCT_ORIGINAL','permission_denied')
    status={'tsa_channel_id':cid,'authentic_ec389_source_pair_count':len(source[cid]['pairs']),
            'signed_archive_head_sha256':None,'signed_head_receipt_sha256':None,
            'signed_snapshot_matches_live_ec389_source':False,
            'claimed_archive_utc':None,'claimed_receipt_utc':None}
    if href is None:
        if source[cid]['pairs']:flag_set[FLAGS[3]]=True
        return status,previous
    head=tr.strict_json(read(href,'signed_independent_archive_head',MAX_SIGNED),
                        'EC390_SIGNED_ARCHIVE_HEAD')
    exact(head,SIGNED_FIELDS,'INDEPENDENT_ARCHIVE_HEAD')
    hclaim=head['claim']
    need(type(hclaim) is dict and hclaim.get('archivist_id') in signers['archivists'],
         'REGISTERED_INDEPENDENT_ARCHIVIST_REQUIRED','permission_denied')
    hclaim=_signed(head,HEAD_SCHEMA,HEAD_CLAIM_SCHEMA,HEAD_CLAIM_FIELDS,
                   signers['archivists'][hclaim['archivist_id']],HEAD_DOMAIN,'ARCHIVE_HEAD')
    pairs=hclaim['ec389_signed_source_pairs']
    need(type(pairs) is list and len(pairs)<=8 and
         all(type(x) is dict and set(x)==PAIR_FIELDS and
             all(tr._sha(s) for s in x.values()) for x in pairs) and
         len({x['ec389_signed_witness_original_sha256'] for x in pairs})==len(pairs) and
         len({x['ec389_signed_custody_original_sha256'] for x in pairs})==len(pairs),
         'SIGNED_ARCHIVE_HEAD_EXACT_ORDERED_SOURCE_PAIR_SHA_LIST_REQUIRED',
         'permission_denied')
    need(hclaim['directory_lineage_id']==lineage and
         hclaim['tsa_channel_id']==cid and
         type(hclaim['epoch_index']) is int and hclaim['epoch_index']==idx and
         hclaim['parent_ec389_canonical_result_sha256']==parent_sha and
         hclaim['ec389_external_witness_archive_original_sha256']==archive_sha and
         hclaim['ec389_parent_derived_inventory_sha256']==inventory_sha and
         type(hclaim['checkpoint_sequence']) is int and hclaim['checkpoint_sequence']==idx+1 and
         tr._sha(href['sha256']) and old338._utc(hclaim['claimed_archived_utc']),
         'SIGNED_HEAD_PARENT_SOURCE_CHANNEL_EPOCH_AND_UTC_REQUIRED',
         'permission_denied')
    prev_head=previous['head'] if previous else ZERO
    if hclaim['previous_signed_archive_head_original_sha256']!=prev_head:
        flag_set[FLAGS[6]]=True
    if previous is not None and (len(pairs)<len(previous['pairs']) or
        pairs[:len(previous['pairs'])]!=previous['pairs']):
        flag_set[FLAGS[6]]=True
    matches=pairs==source[cid]['pairs']
    if not matches:flag_set[FLAGS[4]]=True
    archive_time=old339._time(hclaim['claimed_archived_utc'])
    if (source[cid]['last_deposit'] is not None and
        archive_time<source[cid]['last_deposit']):flag_set[FLAGS[5]]=True
    if (previous is not None and previous['archive_time'] is not None and
            archive_time<previous['archive_time']):
        flag_set[FLAGS[5]]=True
    status.update({'signed_archive_head_sha256':href['sha256'],
        'signed_snapshot_matches_live_ec389_source':matches,
        'signed_snapshot_pair_count':len(pairs),
        'claimed_archive_utc':hclaim['claimed_archived_utc'],
        'signed_snapshot_sha256':sha(canonical.canonical(pairs))})
    if rref is None:
        flag_set[FLAGS[3]]=True
        return status,{'head':href['sha256'],'receipt':previous['receipt'] if previous else ZERO,
                      'pairs':pairs,'archive_time':archive_time,
                      'receipt_time':previous['receipt_time'] if previous else None}
    rec=tr.strict_json(read(rref,'signed_independent_archive_head_receipt',MAX_SIGNED),
                       'EC390_SIGNED_ARCHIVE_RECEIPT')
    exact(rec,SIGNED_FIELDS,'INDEPENDENT_ARCHIVE_HEAD_RECEIPT')
    rclaim=rec['claim']
    need(type(rclaim) is dict and rclaim.get('receipt_attestor_id') in
         signers['receipt_attestors'],
         'REGISTERED_INDEPENDENT_RECEIPT_ATTESTOR_REQUIRED','permission_denied')
    rclaim=_signed(rec,RECEIPT_SCHEMA,RECEIPT_CLAIM_SCHEMA,RECEIPT_CLAIM_FIELDS,
                   signers['receipt_attestors'][rclaim['receipt_attestor_id']],
                   RECEIPT_DOMAIN,'HEAD_RECEIPT')
    need(rclaim['directory_lineage_id']==lineage and
         rclaim['tsa_channel_id']==cid and
         type(rclaim['epoch_index']) is int and rclaim['epoch_index']==idx and
         rclaim['signed_archive_head_original_sha256']==href['sha256'] and
         rclaim['ec389_signed_source_pairs_sha256']==sha(canonical.canonical(pairs)) and
         type(rclaim['receipt_sequence']) is int and rclaim['receipt_sequence']==idx+1 and
         old338._utc(rclaim['claimed_received_utc']),
         'INDEPENDENT_RECEIPT_MUST_SIGN_VERIFIED_HEAD_SOURCE_CHANNEL_EPOCH',
         'permission_denied')
    prev_receipt=previous['receipt'] if previous else ZERO
    if rclaim['previous_signed_receipt_original_sha256']!=prev_receipt:
        flag_set[FLAGS[6]]=True
    receipt_time=old339._time(rclaim['claimed_received_utc'])
    if (receipt_time<archive_time or
        previous is not None and previous['receipt_time'] is not None and
        receipt_time<previous['receipt_time']):flag_set[FLAGS[5]]=True
    status.update({'signed_head_receipt_sha256':rref['sha256'],
                   'claimed_receipt_utc':rclaim['claimed_received_utc']})
    return status,{'head':href['sha256'],'receipt':rref['sha256'],
                  'pairs':pairs,'archive_time':archive_time,'receipt_time':receipt_time}


def _engine(derive,**opts):
    earlier=_inputs(opts,derive)
    real=parent.audit(**earlier)  # CRITICAL: actual unchanged EC389->EC369 work.
    n=len(opts['historical_directory_root_shas']);parent_sha=_parent(real,n)
    pins={};categories={};forbidden=set();cache={}
    def read(ref,label,cap):
        oldfiles.prior.lineage.parent.ref_check(ref,'EC390_'+label)
        path=ref['path']
        need(path not in forbidden,'NO_EC353_SENDER_OR_PARENT_BUNDLE_AS_INDEPENDENT_ORIGINAL',
             'permission_denied')
        if path in cache:
            saved,raw=cache[path]
            need(saved==ref['sha256'] and len(raw)<=cap,
                 'ORIGINAL_PATH_SHA_OR_SIZE_REUSE_INVALID','permission_denied')
            return raw
        raw=oldfiles._read(ref,'ec390_'+label,cap,pins,categories,forbidden)
        cache[path]=(ref['sha256'],raw)
        return raw
    def doc(ref,label,cap):return tr.strict_json(read(ref,label,cap),'EC390_'+label)
    oldref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    newref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    old=doc(oldref,'real_ec389_archive',parent.MAX_BUNDLE)
    new=doc(newref,'ec390_external_archive',MAX_BUNDLE)
    exact(old,parent.BUNDLE_FIELDS,'AUTHENTIC_EC389_ARCHIVE')
    exact(new,BUNDLE_FIELDS,'INDEPENDENT_ARCHIVE_HEAD_BUNDLE')
    need(old['schema']==parent.BUNDLE_SCHEMA and new['schema']==BUNDLE_SCHEMA and
         type(old['epochs']) is list and len(old['epochs'])==n and
         type(new['epochs']) is list and len(new['epochs'])==n and
         real['historical_ec339_external_witness_archive_original_sha256']==oldref['sha256'] and
         new['parent_ec389_canonical_result_sha256']==parent_sha and
         new['ec389_external_witness_archive_original_sha256']==oldref['sha256'] and
         old['claimed_directory_lineage_id']==new['claimed_directory_lineage_id']==
            opts['claimed_historical_directory_lineage_id'],
         'MANDATORY_LIVE_EC389_PARENT_OR_AUTHENTIC_LINEAGE_MISMATCH',
         'permission_denied')
    # An external signature may NOT be read from any EC353 sender-origin label.
    idxref={'path':opts['historical_transparency_archive_bundle_file'],
            'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    sender=doc(idxref,'ec377_sender_index',oldindex.MAX_BUNDLE)
    exact(sender,oldindex.BUNDLE_FIELDS,'EC377_SENDER_INDEX')
    for ep in sender['epochs']:
        sr=ep['ec353_publication_bundle_original']
        label=doc(sr,'sender_label_untrusted',tr.MAX_BUNDLE)
        oldsource._old_sender_labels(label,forbidden)
        forbidden.add(sr['path'])
    forbidden.add(idxref['path'])
    # Protect all ancestor archive *paths* against reuse as newly signed originals.
    protected={v for k,v in opts.items() if k.endswith('_file') and type(v) is str}
    rosterref=old['external_verifier_roster_original']
    pubroster=doc(rosterref,'authentic_ec389_signer_roster',parent.MAX_ROSTER)
    need(rosterref['sha256']==opts[parent.NEW_SCALARS[2]] and
         pubroster['schema']==parent.ROSTER_SCHEMA and
         pubroster['claimed_directory_lineage_id']==new['claimed_directory_lineage_id'],
         'EC389_VERIFIED_WITNESS_CUSTODIAN_ROSTER_MUST_MATCH_PARENT_PIN',
         'permission_denied')
    oldparties=parent._roster(pubroster,rosterref,opts[parent.NEW_SCALARS[2]],read,set())
    existing={x['public_hex'] for x in (*pubroster['witnesses'],*pubroster['custodians'])}
    existing_ids={x['signer_id'] for x in (*pubroster['witnesses'],*pubroster['custodians'])}
    # The genuine EC389 parent already checked old actor/issuer signatures.
    # Reopen their original authorized public-key sources to reject key reuse.
    old388ref={'path':opts[parent.parent.NEW_SCALARS[0]],
               'sha256':opts[parent.parent.NEW_SCALARS[1]]}
    old387ref={'path':opts[parent.parent.parent.NEW_SCALARS[0]],
               'sha256':opts[parent.parent.parent.NEW_SCALARS[1]]}
    old386ref={'path':opts[parent.parent.parent.parent.NEW_SCALARS[0]],
               'sha256':opts[parent.parent.parent.parent.NEW_SCALARS[1]]}
    old388=doc(old388ref,'old_ec388_revocation_original',parent.parent.MAX_BUNDLE)
    old387=doc(old387ref,'old_ec387_rotation_original',parent.parent.parent.MAX_BUNDLE)
    old386=doc(old386ref,'old_ec386_root_original',parent.parent.parent.parent.MAX_BUNDLE)
    for historical,fields,schema in (
        (old388,parent.parent.BUNDLE_FIELDS,parent.parent.BUNDLE_SCHEMA),
        (old387,parent.parent.parent.BUNDLE_FIELDS,parent.parent.parent.BUNDLE_SCHEMA),
        (old386,parent.parent.parent.parent.BUNDLE_FIELDS,
         parent.parent.parent.parent.BUNDLE_SCHEMA)):
        exact(historical,fields,'OLD_AUTHENTIC_ARCHIVE')
        need(historical['schema']==schema and len(historical['epochs'])==n,
             'EC386_EC387_EC388_AUTHENTIC_SOURCE_REQUIRED','permission_denied')
    for epoch388,epoch387,epoch386 in zip(old388['epochs'],old387['epochs'],old386['epochs'],strict=True):
        for row in epoch388['channels']:
            keyref=row['ec338_policy_original']
            if keyref is not None:
                pol=old339.io.parse(read(keyref,'old_ec338_actor_key_policy',old338.MAX_POLICY),
                                    old338.MAX_POLICY)
                for x in pol['actors']:existing.add(x['public_hex'])
        for row in epoch387['channels']:
            keyref=row['ec339_predecessor_authority_roster_original']
            if keyref is not None:
                issuer=old339.io.parse(read(keyref,'old_ec339_issuer_key_roster',old339.MAX_ROSTER),
                                       old339.MAX_ROSTER)
                for x in issuer['issuers']:existing.add(x['issuer_public_hex'])
            for x in row['ec340_original_public_key_sources']:existing.add(x['public_hex'])
        for row in epoch386['channels']:
            for x in row['ec341_signer_public_key_copies']:existing.add(x['public_hex'])
    independent_ref=new['independent_archive_roster_original']
    independent=doc(independent_ref,'independent_signer_roster',MAX_ROSTER)
    need(independent.get('claimed_directory_lineage_id')==new['claimed_directory_lineage_id'],
         'INDEPENDENT_ROSTER_MUST_MATCH_PARENT_LINEAGE','permission_denied')
    parties=_roster(independent,independent_ref,opts[NEW_SCALARS[2]],read,existing_ids,existing)
    forbidden.update(protected)
    forbidden.add(rosterref['path']);forbidden.add(independent_ref['path'])
    # Parent report contains independently reconstructed, signed EC389 per-epoch
    # publication/custody digests. Full reread must match BOTH, not just a count.
    source_epochs=[];flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not real['local_external_signed_revocation_publication_custody_consistent']
    flags[FLAGS[2]]=real[parent.FLAGS[2]]
    for i,epoch in enumerate(old['epochs']):
        data,pubsha,ropsha,count=_source_epoch(epoch,oldparties,read,i,new['claimed_directory_lineage_id'])
        review=real['historical_ec339_external_witness_epoch_reviews'][i]
        # Already-audited, SHA-pinned EC389 source is *not* free to mutate
        # between the live parent audit and this independent receiver replay.
        # A mismatch is a refused TOCTOU/source substitution, not a routine
        # third-party signed contradictory head (which is kept as adverse).
        need(pubsha==review['external_publication_inventory_sha256'] and
             ropsha==review['external_custody_inventory_sha256'] and
             count==review['verified_external_signed_publication_custody_pair_count'],
             'REOPENED_EC389_SIGNED_ORIGINALS_MUST_MATCH_LIVE_PARENT_REPORT',
             'permission_denied')
        source_epochs.append(data)
    reviews=[];inventory=[];previous={};signed_count=0
    for idx,ep in enumerate(new['epochs']):
        exact(ep,EPOCH_FIELDS,'THIRD_PARTY_ARCHIVE_EPOCH')
        need(type(ep['epoch_index']) is int and ep['epoch_index']==idx and
             type(ep['channels']) is list and
             [r.get('tsa_channel_id') for r in ep['channels']]==list(source_epochs[idx]),
             'THIRD_PARTY_CHANNELS_MATCH_AUTHENTIC_EC389_SOURCE_ORDER',
             'permission_denied')
        records=[];heads=[];receipts=[]
        for row in ep['channels']:
            after,before=_channel(row,source_epochs[idx],parties,read,idx,
                  new['claimed_directory_lineage_id'],parent_sha,oldref['sha256'],
                  real['receiver_verified_external_revocation_witness_custody_inventory_sha256'],
                  previous.get(row['tsa_channel_id']),flags)
            records.append(after)
            if after['signed_archive_head_sha256']:
                signed_count+=bool(after['signed_head_receipt_sha256'])
            heads.append({'tsa_channel_id':row['tsa_channel_id'],
                'signed_head_sha256':after['signed_archive_head_sha256'],
                'signed_source_snapshot_sha256':after.get('signed_snapshot_sha256')})
            receipts.append({'tsa_channel_id':row['tsa_channel_id'],
                'signed_receipt_sha256':after['signed_head_receipt_sha256'],
                'signed_head_sha256':after['signed_archive_head_sha256']})
            if before is not None:previous[row['tsa_channel_id']]=before
        headsha=sha(canonical.canonical(heads));recsha=sha(canonical.canonical(receipts))
        c=sum(bool(r['signed_archive_head_sha256'] and r['signed_head_receipt_sha256'])
              for r in records)
        flags[FLAGS[1]]|=(headsha!=opts[NEW_REPEATS[0][0]][idx] or
            recsha!=opts[NEW_REPEATS[1][0]][idx] or
            c<opts[NEW_REPEATS[2][0]][idx])
        flags[FLAGS[3]]|=any(r['authentic_ec389_source_pair_count'] and not
                             (r['signed_archive_head_sha256'] and r['signed_head_receipt_sha256'])
                             for r in records)
        reviews.append({'epoch_index':idx,'genuine_independent_signed_checkpoint_pair_count':c,
            'visible_authentic_ec389_revocation_pair_count':sum(
                r['authentic_ec389_source_pair_count'] for r in records),
            'independent_signed_head_inventory_sha256':headsha,
            'independent_signed_receipt_inventory_sha256':recsha,
            'incomplete_independent_checkpoint_channels':sum(bool(
                r['authentic_ec389_source_pair_count'] and not
                 (r['signed_archive_head_sha256'] and r['signed_head_receipt_sha256']))
                 for r in records)})
        inventory.append({'epoch_index':idx,'verified_third_party_signed_channels':records,
                          'independent_signed_head_inventory_sha256':headsha,
                          'independent_signed_receipt_inventory_sha256':recsha})
    # Late read original signer material and all authenticated archived head/receipt
    # originals AFTER digest production, never merely trusting an initial parse.
    for entry in (*independent['archivists'],*independent['receipt_attestors'],
                  *pubroster['witnesses'],*pubroster['custodians']):
        ref=entry['public_key_original']
        raw=oldfiles._read(ref,'ec390_late_original_key',32,{}, {},set())
        need(len(raw)==32 and raw.hex()==entry['public_hex'] and sha(raw)==ref['sha256'],
             'SIGNED_PUBLIC_KEY_CHANGED_AFTER_VERIFICATION','permission_denied')
    for ref,cap in ((independent_ref,MAX_ROSTER),(rosterref,parent.MAX_ROSTER),
                    (oldref,parent.MAX_BUNDLE),(newref,MAX_BUNDLE)):
        raw=oldfiles._read(ref,'ec390_late_bundle_or_roster',cap,{}, {},set())
        need(sha(raw)==ref['sha256'],'ARCHIVE_OR_ROSTER_CHANGED_AFTER_AUDIT',
             'permission_denied')
    # Reopen every original EC389 signed witness/custody one more time after
    # producing third-party claims, in addition to the mandatory parent reread.
    for ep in old['epochs']:
        for row in ep['channels']:
            for pair in row['external_revocation_publication_and_custody_originals']:
                for key in ('signed_witness_original','signed_custody_original'):
                    ref=pair[key]
                    raw=oldfiles._read(ref,'ec390_late_authentic_ec389_signature',
                                       parent.MAX_SIGNED,{}, {},set())
                    need(sha(raw)==ref['sha256'],
                         'EC389_SIGNED_SOURCE_CHANGED_DURING_THIRD_PARTY_RECEIPT_REPLAY',
                         'permission_denied')
    for ep in new['epochs']:
        for row in ep['channels']:
            for k in ('signed_archive_head_original','signed_head_receipt_original'):
                ref=row[k]
                if ref is not None:
                    raw=oldfiles._read(ref,'ec390_late_signed_original',MAX_SIGNED,{}, {},set())
                    need(sha(raw)==ref['sha256'],
                         'SIGNED_INDEPENDENT_HEAD_OR_RECEIPT_CHANGED_AFTER_CHECK',
                         'permission_denied')
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    derived={'schema':INVENTORY_SCHEMA,
        'live_ec389_to_ec369_parent_canonical_result_sha256':parent_sha,
        'receiver_original_ec389_external_archive_sha256':oldref['sha256'],
        'receiver_original_ec390_independent_archive_sha256':newref['sha256'],
        'receiver_original_independent_roster_sha256':independent_ref['sha256'],
        'claimed_directory_lineage_id':new['claimed_directory_lineage_id'],
        'historical_independent_archive_epoch_reviews':inventory}
    digest=sha(canonical.canonical(derived))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
        'command':'derive-historical-ec339-independent-archive-inventory' if derive else
                  'audit-historical-ec339-independent-archive-heads',
        'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                       OUTCOMES[-1])+'_unresolved',
        'exit_code':2,'offline_unresolved_exit_code':2,
        'verified_live_parent_ec389_canonical_result_sha256':parent_sha,
        'historical_independent_archive_original_sha256':newref['sha256'],
        'receiver_verified_independent_archive_inventory_sha256':digest,
        'genuine_independent_signed_checkpoint_receipt_count':signed_count,
        'historical_independent_archive_epoch_reviews':reviews,
        'local_independent_signed_archive_heads_and_receipts_consistent':local,
        'sender_origin_path_required_or_read':False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
        **flags,**{name:False for name in NEGATIVES},
        **({'unsigned_independent_archive_heads_receipts_inventory':derived,
            'outside_archivist_legal_identity_time_custody_proven':False}
            if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
