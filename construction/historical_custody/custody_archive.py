#!/usr/bin/env python3
"""EC375 receiver-only historic EC356 root/channel/ack original replay.

Every invocation replays the actual production EC374 -> EC369 auditors. Genuine
historic EC356 Ed25519 signatures bind independently SHA-pinned receiver copies
of root references, channel authorizations, and custody acknowledgements to
EC357's already-verified *source-signed* inventory records. Old EC356 sender
paths inside its original UNSIGNED manifest remain untrusted labels and NEVER
become file-read authority. Old EC355->EC337 evidence and EC356/357 canonical
results are not reconstructed. The entire lawful result is exit-2 unresolved.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from gossip import gossip
from custody import custody as ec356
from provenance import provenance as ec357
from publication_accountability import accountability as p370
from historical_archive import archive as p371
from historical_authority import authority_archive as p372
from historical_inclusion import inclusion_archive as p373
from historical_owner import owner_archive as prior

RESULT_SCHEMA='ces.ec375.receiver_historic_ec356_signed_custody_ec357_bridge_unresolved.v1'
DERIVE_SCHEMA='ces.ec375.unsigned_historic_custody_original_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec375.receiver_historic_ec356_signed_custody_denial.v1'
BUNDLE_SCHEMA='ces.ec375.receiver_historic_ec356_custody_original_archive.v1'
INVENTORY_SCHEMA='ces.ec375.receiver_verified_ec356_ec357_custody_original_shas.v1'
MAX_BUNDLE=100_000
MAX_ACKS_PER_CHANNEL=ec356.MAX_PER_CHANNEL
NEW_SCALARS=('historical_custody_archive_bundle_file',
             'expected_historical_custody_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_custody_inventory_sha256',)
NEW_REPEATS=(
 ('historical_custody_a_root_key_shas','--historical-custody-a-root-key-sha256'),
 ('historical_custody_b_root_key_shas','--historical-custody-b-root-key-sha256'),
 ('historical_custody_a_ack_head_shas','--historical-custody-a-ack-head-sha256'),
 ('historical_custody_b_ack_head_shas','--historical-custody-b-ack-head-sha256'),
 ('minimum_historical_custody_a_ack_counts','--minimum-historical-custody-a-ack-count'),
 ('minimum_historical_custody_b_ack_counts','--minimum-historical-custody-b-ack-count'),
)
REPEAT_NAMES=tuple(x for x,_ in NEW_REPEATS)
PARENT_SCALARS=(*p370.prior.SCALARS,*p370.NEW_SCALARS,
                *p371.NEW_SCALARS,*p371.AUDIT_ONLY,
                *p372.NEW_SCALARS,*p372.AUDIT_ONLY,
                *p373.NEW_SCALARS,*p373.AUDIT_ONLY,
                *prior.NEW_SCALARS,*prior.AUDIT_ONLY)
PARENT_REPEATS=(*p370.prior.REPEAT_NAMES,*p370.NEW_REPEAT_NAMES,
                *p371.REPEAT_NAMES,*p372.NEW_REPEAT_NAMES,
                *p373.REPEAT_NAMES,*prior.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec374_canonical_result_sha256',
               'ec374_historical_owner_epoch_bundle_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','ec356_custody_bundle_original','source_a','source_b'}
SOURCE_FIELDS={'root_public_key_original','root_reference_signed_original',
               'channel_public_key_original','channel_authorization_signed_original',
               'acknowledgements','selected_ack_head_sha256'}
ACK_FIELDS={'acknowledgement_signed_original','checkpoint_original',
            'witness_original'}
CHANNEL_FIELDS={'slot','institution_id','channel_id','claimed_organization',
                'root_public_key','root_reference','channel_public_key',
                'channel_authorization','acknowledgements'}
FLAGS=(
 'inherited_ec374_through_ec369_signed_original_dispute_unresolved',
 'external_ec356_custody_root_ack_head_or_inventory_floor_mismatch',
 'historical_ec356_signed_custody_ack_fork_replay_or_equivocation_visible',
 'historical_ec356_original_bytes_or_ec357_signed_inventory_incomplete',
 'historical_ec357_signed_root_revoked_rotated_or_custody_scope_conflict',
 'historical_ec356_custody_cross_epoch_head_or_role_conflict',
 'historical_ec356_self_reported_signature_clock_stale_or_untrusted',
 'ec356_ec357_verified_signature_slice_not_full_old_canonical_ancestry',
)
OUTCOMES=(
 'ec375_inherited_true_receiver_or_owner_signed_dispute',
 'ec375_independent_ec356_root_ack_inventory_retention_disagreement',
 'ec375_genuine_signed_custody_ack_fork_equivocation_or_replay',
 'ec375_old_ack_original_copy_or_source_signed_inventory_missing',
 'ec375_old_source_signed_root_revoke_rotate_or_custody_conflict',
 'ec375_old_custodian_or_ack_head_cross_epoch_disagreement',
 'ec375_old_custody_signed_utc_stale_or_untrusted',
 'ec375_real_ec356_signature_and_ec357_review_bridge_only_not_full_old_parent',
)
NEGATIVES=(
 'old_ec356_canonical_result_recomputed_from_complete_ec355_original_inputs',
 'old_ec357_canonical_result_recomputed_from_complete_ec356_original_inputs',
 'complete_ec365_to_ec337_historical_parent_originals_replayed',
 'ec355_receipt_and_gossip_and_disclosure_originals_truly_replayed',
 'ec356_signed_parent_or_ec357_review_parent_digest_is_a_reproduced_result',
 'old_ec356_unsigned_manifest_original_labels_used_as_receiver_paths',
 'old_ec362_signed_source_copy_labels_or_ec369_sender_paths_read',
 'signed_custody_proves_official_institution_independence_or_physical_site',
 'self_declared_signed_custody_utc_is_independent_tsa',
 'historical_external_sha_pins_prove_global_latest_or_absence_hidden_forks',
 'revoked_ec357_root_or_inherited_dispute_repaired_by_valid_old_ack',
 'network_provider_cas_worm_or_private_signer_invoked',
 'native_powershell_cli_or_old_deep_mock_changed_or_final_accepted',
)


def need(ok,reason,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC375_'+reason,status)


def exact(doc,fields,role):
    need(type(doc) is dict and set(doc)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return prior.sha(raw)


def _inputs(opts,derive):
    parent_keys=set(PARENT_SCALARS)|set(PARENT_REPEATS)
    required=parent_keys|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_EC374_PARENT_AND_EC375_INPUTS_REQUIRED')
    parent={key:opts[key] for key in parent_keys}
    prior._inputs(parent,False)
    p371.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC375_EXTERNALLY_PINNED_RECEIVER_CUSTODY_ARCHIVE')
    need(opts[NEW_SCALARS[0]] is not None and opts[NEW_SCALARS[1]] is not None,
         'INDEPENDENT_HISTORIC_CUSTODY_ARCHIVE_SHA_REQUIRED')
    if not derive:
        need(tr._sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_RETAINED_CUSTODY_INVENTORY_PIN_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    for name in REPEAT_NAMES:
        items=opts[name]
        need(type(items) is list and len(items)==n,
             name.upper()+'_EXACT_HISTORICAL_EPOCH_COVERAGE_REQUIRED')
        if name.startswith('minimum_'):
            need(all(type(value) is int and 0<=value<=MAX_ACKS_PER_CHANNEL for value in items),
                 name.upper()+'_ACK_COUNT_FLOOR_INVALID')
        else:
            need(all(tr._sha(value) for value in items),
                 name.upper()+'_INDEPENDENT_SHA_STREAM_INVALID')
    return parent


def _root_channel(i,slot,old,new,read,known,now):
    """Reopen actual old EC356 public-key + two signed institutional originals.

    Original EC356 manifest paths are never used. The first two equality
    checks join the untrusted old manifest's exact SHA statements to new,
    independent caller-owned receiver copies without opening old labels.
    """
    exact(old,CHANNEL_FIELDS,'OLD_EC356_CHANNEL')
    exact(new,SOURCE_FIELDS,'NEW_EC375_CUSTODY_SOURCE')
    need(old['slot']==slot and all(old[oldkey]['sha256']==new[newkey]['sha256']
        for oldkey,newkey in (
          ('root_public_key','root_public_key_original'),
          ('root_reference','root_reference_signed_original'),
          ('channel_public_key','channel_public_key_original'),
          ('channel_authorization','channel_authorization_signed_original'))),
         'OLD_EC356_UNSIGNED_MANIFEST_SHA_NOT_MATCH_RECEIVER_ORIGINAL',
         'permission_denied')
    root=read(new['root_public_key_original'],'old_ec356_root_public_key',32)
    channel=read(new['channel_public_key_original'],'old_ec356_channel_public_key',32)
    rootsha=sha(root);csha=sha(channel)
    need(len(root)==len(channel)==32 and rootsha!=csha and
         rootsha not in known and csha not in known,
         'HISTORIC_CUSTODY_KEY_LENGTH_OR_SIGNER_ROLE_COLLISION',
         'permission_denied')
    ref=new['root_reference_signed_original']
    rootdoc=ec356._signed(read(ref,'old_ec356_signed_root_reference',ec356.MAX_RECORD),
                          root,ec356.ROOT_DOMAIN,'signature_ed25519_hex',
                          'EC375_TRUE_OLD_ROOT_REF')
    exact(rootdoc,('schema','institution_id','claimed_organization',
          'root_public_key_original_sha256','valid_from_utc','valid_until_utc',
          'signature_ed25519_hex'),'OLD_ROOT_REF')
    begin=tr._utc(rootdoc['valid_from_utc']);end=tr._utc(rootdoc['valid_until_utc'])
    need(rootdoc['schema']==ec356.ROOT_SCHEMA and begin<end and
         rootdoc['root_public_key_original_sha256']==rootsha and
         tr._ident(rootdoc['institution_id']) and
         rootdoc['institution_id']==old['institution_id'] and
         rootdoc['claimed_organization']==old['claimed_organization'] and
         type(rootdoc['claimed_organization']) is str and
         1<=len(rootdoc['claimed_organization'])<=140 and
         rootdoc['claimed_organization']==rootdoc['claimed_organization'].strip(),
         'REAL_ROOT_REFERENCE_OLD_ORIGINAL_ID_OR_VALIDITY_INVALID',
         'permission_denied')
    aref=new['channel_authorization_signed_original']
    auth=ec356._signed(read(aref,'old_ec356_signed_channel_authorization',
                            ec356.MAX_RECORD),root,ec356.AUTH_DOMAIN,
                        'signature_ed25519_hex','EC375_TRUE_OLD_CHANNEL_AUTH')
    exact(auth,('schema','institution_id','channel_id',
          'root_reference_original_sha256','channel_public_key_original_sha256',
          'claimed_physical_site_id','valid_from_utc','valid_until_utc',
          'signature_ed25519_hex'),'OLD_CHANNEL_AUTH')
    astart=tr._utc(auth['valid_from_utc']);aend=tr._utc(auth['valid_until_utc'])
    need(auth['schema']==ec356.AUTH_SCHEMA and
         auth['institution_id']==rootdoc['institution_id'] and
         auth['channel_id']==old['channel_id'] and tr._ident(auth['channel_id']) and
         auth['root_reference_original_sha256']==ref['sha256'] and
         auth['channel_public_key_original_sha256']==csha and
         tr._ident(auth['claimed_physical_site_id']) and
         begin<=astart<aend<=end,
         'TRUE_ROOT_SIGNED_CHANNEL_AUTHORIZATION_INVALID','permission_denied')
    return {'epoch_index':i,'slot':slot,'root_sha':rootsha,'channel_sha':csha,
            'root_original_sha':ref['sha256'],
            'authorization_sha':aref['sha256'],
            'institution_id':rootdoc['institution_id'],
            'channel_id':auth['channel_id'],
            'site_id':auth['claimed_physical_site_id'],
            'root_valid_from':begin,'root_valid_until':end,
            'auth_valid_from':astart,'auth_valid_until':aend,
            'clock':now>end or now>aend,
            'channel_public_key_bytes':channel}


def _acks(i,slot,old,new,actor,read,now):
    oldacks=old['acknowledgements'];newacks=new['acknowledgements']
    need(type(oldacks) is list and type(newacks) is list and
         1<=len(oldacks)==len(newacks)<=MAX_ACKS_PER_CHANNEL,
         'OLD_CUSTODY_MANIFEST_AND_NEW_RECEIVER_ACK_COVERAGE_INVALID',
         'permission_denied')
    old_by_sha={}
    for item in oldacks:
        exact(item,('acknowledgement','checkpoint_original','witness_original'),
              'EC356_OLD_MANIFEST_ACK')
        ref=item['acknowledgement']
        p371.prior._ref(ref)
        need(ref['sha256'] not in old_by_sha,'OLD_MANIFEST_DUPLICATE_ACK_SHA',
             'permission_denied')
        old_by_sha[ref['sha256']]=item
    signed_by_sha={};chain=defaultdict(list);ids=set();nonces=set();rows=[]
    for index,item in enumerate(newacks):
        exact(item,ACK_FIELDS,'EC375_RECEIVER_ACK_REFERENCE')
        signed_ref=item['acknowledgement_signed_original']
        p371.prior._ref(signed_ref)
        olditem=old_by_sha.get(signed_ref['sha256'])
        need(olditem is not None and signed_ref['sha256'] not in signed_by_sha,
             'UNSIGNED_EC356_MANIFEST_SIGNED_ACK_MISSING_OR_DUPLICATE',
             'permission_denied')
        raw=read(signed_ref,'old_ec356_signed_custody_ack',ec356.MAX_RECORD)
        doc=ec356._signed(raw,actor['channel_public_key_bytes'],ec356.ACK_DOMAIN,
                          'signature_ed25519_hex','EC375_TRUE_OLD_CUSTODY_ACK')
        exact(doc,('schema','acknowledgement_id','parent_disclosure_bundle_original_sha256',
                   'gossip_reply_original_sha256','ec355_request_original_sha256',
                   'ec355_receipt_original_sha256','ec355_requested_role','log_id',
                   'checkpoint_original_sha256','witness_original_sha256',
                   'checkpoint_length','witness_length','custody_status',
                   'institution_id','channel_id','channel_authorization_original_sha256',
                   'previous_ack_original_sha256','nonce_hex','acknowledged_utc',
                   'signature_ed25519_hex'),'OLD_SIGNED_CUSTODY_ACK')
        selftime=tr._utc(doc['acknowledged_utc'])
        need(doc['schema']==ec356.ACK_SCHEMA and
             tr._ident(doc['acknowledgement_id']) and
             tr._ident(doc['log_id']) and
             doc['institution_id']==actor['institution_id'] and
             doc['channel_id']==actor['channel_id'] and
             doc['channel_authorization_original_sha256']==actor['authorization_sha'] and
             all(tr._sha(doc[x]) for x in (
                   'parent_disclosure_bundle_original_sha256',
                   'gossip_reply_original_sha256','ec355_request_original_sha256',
                   'ec355_receipt_original_sha256','checkpoint_original_sha256',
                   'witness_original_sha256')) and
             doc['ec355_requested_role'] in ('original_responder','independent_peer') and
             doc['custody_status'] in ('custodied_originals','sha_claim_only','unavailable_claim') and
             (doc['previous_ack_original_sha256']==ec356.GENESIS or
                  tr._sha(doc['previous_ack_original_sha256'])) and
             type(doc['nonce_hex']) is str and gossip.NONCE_RE.fullmatch(doc['nonce_hex']) is not None and
             actor['root_valid_from']<=selftime<=actor['root_valid_until'] and
             actor['auth_valid_from']<=selftime<=actor['auth_valid_until'] and
             selftime<=now,
             'OLD_SIGNED_ACK_REAL_KEY_OR_DOMAIN_VALID_BUT_SCOPE_INVALID',
             'permission_denied')
        need(doc['acknowledgement_id'] not in ids and doc['nonce_hex'] not in nonces,
             'DUPLICATE_SIGNED_ACK_ID_OR_NONCE','permission_denied')
        ids.add(doc['acknowledgement_id']);nonces.add(doc['nonce_hex'])
        for key in ('checkpoint_original','witness_original'):
            legacy=olditem[key]
            fresh=item[key]
            if legacy is None:
                need(fresh is None,'NEW_RECEIVER_ORIGINAL_NOT_PRESENT_IN_OLD_MANIFEST',
                     'permission_denied')
            else:
                p371.prior._ref(legacy)
                need(type(fresh) is dict and fresh.get('sha256')==legacy['sha256'],
                     'RECEIVER_COPY_BYTES_SHA_NOT_OLD_EC356_MANIFEST_SHA',
                     'permission_denied')
        present=doc['custody_status']=='custodied_originals'
        if present:
            need(type(doc['checkpoint_length']) is int and
                 0<doc['checkpoint_length']<=tr.MAX_CHECKPOINT and
                 type(doc['witness_length']) is int and
                 0<doc['witness_length']<=tr.MAX_WITNESS and
                 type(item['checkpoint_original']) is dict and
                 type(item['witness_original']) is dict,
                 'SIGNED_PRESENT_CUSTODY_REQUIRES_MEASURED_RECEIVER_COPIES',
                 'permission_denied')
            for field,cap in (('checkpoint',tr.MAX_CHECKPOINT),
                              ('witness',tr.MAX_WITNESS)):
                copy=read(item[field+'_original'],'old_ec356_'+field+'_copy',cap)
                need(sha(copy)==doc[field+'_original_sha256'] and
                     len(copy)==doc[field+'_length'],
                     'REAL_HISTORIC_ACK_SIGNED_COPY_BYTES_OR_LENGTH_MISMATCH',
                     'permission_denied')
        else:
            need(doc['checkpoint_length'] is None and
                 doc['witness_length'] is None and
                 item['checkpoint_original'] is None and
                 item['witness_original'] is None,
                 'SIGNED_SHA_ONLY_OR_UNAVAILABLE_CANNOT_SMUGGLE_BYTE_COPIES',
                 'permission_denied')
        key=(doc['gossip_reply_original_sha256'],doc['ec355_receipt_original_sha256'])
        chain[(doc['gossip_reply_original_sha256'],doc['previous_ack_original_sha256'])].append(
            signed_ref['sha256'])
        row={'epoch_index':i,'slot':slot,'ack_sha':signed_ref['sha256'],
             'ec355_receipt_sha':doc['ec355_receipt_original_sha256'],
             'ec355_requested_role':doc['ec355_requested_role'],
             'request_sha':doc['ec355_request_original_sha256'],
             'gossip_sha':doc['gossip_reply_original_sha256'],
             'checkpoint_sha':doc['checkpoint_original_sha256'],
             'witness_sha':doc['witness_original_sha256'],
             'checkpoint_length':doc['checkpoint_length'],
             'witness_length':doc['witness_length'],
             'status':doc['custody_status'],
             'acknowledgement_id':doc['acknowledgement_id'],
             'nonce_hex':doc['nonce_hex'],
             'acknowledged_utc':doc['acknowledged_utc'],
             'previous_ack_sha':doc['previous_ack_original_sha256'],
             'channel_id':doc['channel_id'],'site_id':actor['site_id'],
             'claimed_parent_ec355_disclosure_sha':doc[
                                        'parent_disclosure_bundle_original_sha256'],
             'signed_original_bytes_reopened':present}
        rows.append(row)
        signed_by_sha[row['ack_sha']]=row
    need(set(signed_by_sha)==set(old_by_sha),
         'OLD_MANIFEST_ACK_ORIGINALS_NOT_FULLY_REPRESENTED','permission_denied')
    forks=any(len(x)>1 for x in chain.values())
    for digest,row in signed_by_sha.items():
        visited=set();cursor=digest
        while cursor!=ec356.GENESIS:
            need(cursor not in visited and cursor in signed_by_sha,
                 'OLD_SIGNED_ACK_PREDECESSOR_MISSING_OR_CYCLE',
                 'permission_denied')
            visited.add(cursor)
            before=signed_by_sha[cursor]
            parent=before['previous_ack_sha']
            if parent!=ec356.GENESIS:
                need(parent in signed_by_sha and
                     signed_by_sha[parent]['gossip_sha']==before['gossip_sha'] and
                     tr._utc(signed_by_sha[parent]['acknowledged_utc'])<=tr._utc(
                         before['acknowledged_utc']),
                     'SIGNED_OLD_ACK_CROSS_CLAIM_PARENT_OR_TIME_REVERSAL',
                     'permission_denied')
            cursor=parent
    # Multiple independent EC355 gossip claims legitimately have independent
    # signed ACK chains. Detect a fork *within each claim*, not from having
    # two unrelated genesis branches; selected stream head must be terminal
    # within its own claim. Other claims stay explicitly in the inventory.
    by_claim=defaultdict(list)
    for r in rows:by_claim[r['gossip_sha']].append(r)
    endpoints=set()
    for claim,group in by_claim.items():
        need(len(group)<=ec356.MAX_PER_CLAIM_CHANNEL,
             'OLD_EC356_SIGNED_ACKS_EXCEED_PER_CLAIM_LIMIT',
             'permission_denied')
        children={r['previous_ack_sha'] for r in group
                  if r['previous_ack_sha']!=ec356.GENESIS}
        terminals=[r['ack_sha'] for r in group if r['ack_sha'] not in children]
        if len(terminals)!=1:forks=True
        endpoints.update(terminals)
    selected=new['selected_ack_head_sha256']
    need(tr._sha(selected) and selected in signed_by_sha,
         'SELECTED_EC356_ACK_HEAD_NOT_REAL_SIGNED_ORIGINAL','permission_denied')
    if selected not in endpoints:forks=True
    return rows,selected,forks or len({r['claimed_parent_ec355_disclosure_sha'] for r in rows})>1


def _engine(derive,**opts):
    oldopts=_inputs(opts,derive)
    inherited=prior.audit(**oldopts)  # genuine full production EC374→EC369
    need(type(inherited) is dict and inherited.get('schema')==prior.RESULT_SCHEMA and
         inherited.get('exit_code')==2 and
         inherited.get('sender_origin_path_required_or_read') is False,
         'REAL_PRODUCTION_EC374_THROUGH_EC369_AUDIT_REQUIRED','unavailable')
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set()
    def read(ref,role,cap):
        return p372._read(ref,'ec375_'+role,cap,pins,categories,forbidden)
    # Reopen authenticated EC371 old custodian manifests and collect ALL signed
    # old EC362 copy labels plus EC369 sender labels as denylisted paths.
    p373_opts={k:oldopts[k] for k in (
        *p370.prior.SCALARS,*p370.prior.REPEAT_NAMES,
        *p370.NEW_SCALARS,*p370.NEW_REPEAT_NAMES,
        *p371.NEW_SCALARS,*p371.REPEAT_NAMES,*p371.AUDIT_ONLY,
        *p372.NEW_SCALARS,*p372.NEW_REPEAT_NAMES,*p372.AUDIT_ONLY)}
    historic,manifests=p373._open_historical(p373_opts,read,forbidden)
    oldref={'path':opts['historical_owner_epoch_bundle_file'],
            'sha256':opts['expected_historical_owner_epoch_bundle_sha256']}
    oldb=tr.strict_json(read(oldref,'ec374_real_historical_owner_original',
                             prior.MAX_BUNDLE),'EC375_REOPEN_TRUE_EC374_OWNER')
    exact(oldb,prior.BUNDLE_FIELDS,'INHERITED_SIGNED_OWNER_ARCHIVE')
    need(oldb['schema']==prior.BUNDLE_SCHEMA and
         oldb['claimed_directory_lineage_id']==opts[
                                   'claimed_historical_directory_lineage_id'],
         'ACTUAL_EC374_OWNER_ARCHIVE_PARENT_ID_DISAGREES','permission_denied')
    newref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    newb=tr.strict_json(read(newref,'ec375_new_receiver_historic_custody_archive',
                             MAX_BUNDLE),'EC375_RECEIVER_CUSTODY_ARCHIVE')
    exact(newb,BUNDLE_FIELDS,'EC375_RECEIVER_CUSTODY_ARCHIVE')
    parent_digest=sha(canonical.canonical(inherited))
    need(newb['schema']==BUNDLE_SCHEMA and
         newb['parent_ec374_canonical_result_sha256']==parent_digest and
         newb['ec374_historical_owner_epoch_bundle_original_sha256']==oldref['sha256']
         and newb['claimed_directory_lineage_id']==opts[
                                   'claimed_historical_directory_lineage_id'],
         'NEW_EC375_ARCHIVE_NOT_BOUND_TO_REAL_EC374_PARENT_AND_ORIGINAL',
         'permission_denied')
    epochs=newb['epochs'];olds=oldb['epochs']
    need(type(epochs) is list and len(epochs)==len(olds)==len(historic['epochs'])
         and 1<=len(epochs)<=p371.MAX_EPOCHS,
         'EC375_CUSTODY_ARCHIVE_EPOCHS_NOT_MATCH_LIVE_RECEIVER')
    flags={flag:False for flag in FLAGS}
    flags[FLAGS[0]]=not inherited['local_pinned_historical_owner_reviewer_slice_consistent']
    # Reuse inherited, already signature-verified owner + reviewer role hashes,
    # and caller-retained current + historical external signer hashes. Historic
    # old EC372 issuer/root/witness/custodian keys are replayed by EC374.
    blocked=set(opts['institution_root_public_key_shas']+
        opts['witness_public_key_shas']+opts['historical_directory_root_shas']+
        [opts['expected_sender_public_key_sha256'],
         opts['expected_receiver_public_key_sha256'],
         opts['expected_publisher_public_key_sha256'],
         opts['expected_publication_observer_public_key_sha256']])
    for row in inherited['historical_owner_source_epoch_reviews']:
        blocked.update((row['owner_sha'],row['source_reviewer_sha']))
        if row['selected_reviewer_sha']:blocked.add(row['selected_reviewer_sha'])
    # Signed EC372 old issuer/root/witness originals must not be repurposed.
    ab=tr.strict_json(read({'path':opts['historical_authority_bundle_file'],
         'sha256':opts['expected_historical_authority_bundle_sha256']},
         'inherited_ec372_signer_roles',p372.MAX_BUNDLE),
         'EC375_REOPEN_EC372_SIGNER_ROLES')
    exact(ab,p372.BUNDLE_FIELDS,'TRUE_EC372_SIGNER_ROLES')
    need(ab['schema']==p372.BUNDLE_SCHEMA and len(ab['epochs'])==len(epochs),
         'EC372_SIGNER_ROLE_EPOCH_COUNT_DISAGREES','permission_denied')
    for aepoch in ab['epochs']:
        exact(aepoch,p372.EPOCH_FIELDS,'EC372_SIGNED_ANCESTOR_EPOCH')
        for slot in ('a','b'):
            src=aepoch['source_'+slot]
            exact(src,p372.SOURCE_FIELDS,'EC372_SIGNED_ISSUER_ROOT_ROLE')
            blocked.update(src[k]['sha256'] for k in (
                'authority_root_public_key_original',
                'origin_witness_public_key_original','issuer_public_key_original'))
    for epoch in historic['epochs']:
        blocked.update(epoch['source_'+slot+'_custodian_public_key_original']['sha256']
                       for slot in ('a','b'))
    for epoch in oldb['epochs']:
        for slot in ('a','b'):
            src=epoch['source_'+slot]
            exact(src,prior.SOURCE_FIELDS,'OLD_EC374_ALL_REVIEWER_SIGNER_ROLES')
            for event in src['reviewer_epoch_events']:
                exact(event,prior.EVENT_PIN_FIELDS,'OLD_EC358_VERIFIED_EVENT_ROLE')
                # The live EC374 auditor already verified each signature and
                # old signed event; reopen exactly those original bytes here
                # solely to prevent *previous*, retired reviewer key reuse.
                raw=read(event['event_original'],'old_ec358_reviewer_key_roles',
                         prior.ec358.MAX_EVENT)
                signed=tr.strict_json(raw,'EC375_REOPEN_REAL_EC358_SIGNING_KEY_ROLES')
                exact(signed,prior.ec358.EVENT_FIELDS,'TRUE_EC358_SIGNED_EVENT_ROLES')
                for field in ('previous_reviewer_public_key_original_sha256',
                              'current_reviewer_public_key_original_sha256'):
                    if signed[field] is not None:blocked.add(signed[field])
    rows=[];old_claims=[];seen_roles={}
    for i,entry in enumerate(epochs):
        exact(entry,EPOCH_FIELDS,'EC375_CUSTODY_EPOCH')
        need(type(entry['epoch_index']) is int and entry['epoch_index']==i,
             'EC375_RECEIVER_ARCHIVE_EPOCH_NOT_CONTIGUOUS')
        oldepoch=olds[i]
        exact(oldepoch,prior.EPOCH_FIELDS,'OLD_EC374_HISTORICAL_OWNER_EPOCH')
        need(oldepoch['epoch_index']==i,
             'OLD_EC374_OWNER_EPOCH_NOT_CONTIGUOUS','permission_denied')
        oldcustref=entry['ec356_custody_bundle_original']
        oldcust=tr.strict_json(read(oldcustref,'historic_unsigned_ec356_manifest',
                                  ec356.MAX_BUNDLE),'EC375_TRUE_OLD_EC356_BUNDLE')
        exact(oldcust,('schema','channels'),'REAL_OLD_EC356_CUSTODY_MANIFEST')
        need(oldcust['schema']==ec356.BUNDLE_SCHEMA and
             type(oldcust['channels']) is list and len(oldcust['channels'])==2,
             'OLD_EC356_ORIGINAL_CHANNELS_MUST_BE_BOTH_PRESENT',
             'permission_denied')
        channels={}
        # NEVER read the old EC356 manifest's embedded paths. They may be
        # sender-controlled or original physical-custodian path labels.
        for item in oldcust['channels']:
            exact(item,CHANNEL_FIELDS,'EC356_UNSIGNED_OLD_CHANNEL')
            slot=item['slot']
            need(slot in ('a','b') and slot not in channels,
                 'OLD_EC356_CHANNEL_SLOTS_REQUIRE_EXACT_A_AND_B','permission_denied')
            channels[slot]=item
            for k in ('root_public_key','root_reference','channel_public_key',
                      'channel_authorization'):
                p371.prior._ref(item[k]);forbidden.add(item[k]['path'])
            for oldack in item['acknowledgements']:
                exact(oldack,('acknowledgement','checkpoint_original','witness_original'),
                      'EC356_OLD_CHANNEL_ACK_REFERENCE')
                for ref in oldack.values():
                    if ref is not None:
                        p371.prior._ref(ref);forbidden.add(ref['path'])
        need(set(channels)=={'a','b'},'EC356_MISSING_HISTORIC_CHANNEL',
             'permission_denied')
        epoch_recovered=[];signed_review_views=[]
        used_id=set();used_root=set();used_channel=set()
        for slot in ('a','b'):
            source=oldepoch['source_'+slot]
            exact(source,prior.SOURCE_FIELDS,'TRUE_EC374_HISTORIC_OWNER_SOURCE')
            need(source['signed_ec356_custody_bundle_original_sha256']==oldcustref['sha256'],
                 'GENUINE_EC357_SOURCE_REVIEW_SIGNED_WRONG_EC356_ORIGINAL_SHA',
                 'permission_denied')
            review_pub=read(source['source_review_public_key_original'],
                            'ec357_true_source_reviewer_key',32)
            review_raw=read(source['source_review_signed_original'],
                            'ec357_true_signed_source_review',ec357.MAX_SOURCE)
            review,_,_=ec357._review(review_raw,review_pub)
            need(review['ec356_custody_bundle_original_sha256']==oldcustref['sha256']
                 and review['parent_ec356_canonical_result_sha256']==source[
                    'signed_parent_ec356_canonical_result_sha256'],
                 'EC357_REAL_SIGNED_PARENT_RESULT_OR_BUNDLE_SHA_CHANGED',
                 'permission_denied')
            signed_review_views.append((slot,review))
            new=entry['source_'+slot]
            actual=_root_channel(i,slot,channels[slot],new,read,blocked,now)
            need(actual['institution_id'] not in used_id and
                 actual['root_sha'] not in used_root and
                 actual['channel_sha'] not in used_channel and
                 actual['root_sha']!=actual['channel_sha'],
                 'HISTORIC_TWO_CUSTODY_CHANNELS_SAME_INSTITUTION_OR_SIGNER',
                 'permission_denied')
            used_id.add(actual['institution_id']);used_root.add(actual['root_sha'])
            used_channel.add(actual['channel_sha'])
            for k in ('root_sha','channel_sha'):
                identity=actual[k]
                used=seen_roles.setdefault(identity,slot)
                need(used==slot,
                     'HISTORIC_CUSTODY_SIGNER_REUSED_ACROSS_SOURCE_CHANNELS',
                     'permission_denied')
            ackrows,selected,fork=_acks(i,slot,channels[slot],new,actual,read,now)
            allack=Counter((r['ec355_receipt_sha'],r['checkpoint_sha'],r['witness_sha'],
                            r['checkpoint_length'],r['witness_length'])
                           for r in ackrows if r['status']=='custodied_originals')
            # Signature-backed EC357 inventory is itself an assertion. Verify
            # every claimed present row against a genuine signed EC356 ACK
            # AND the bytes of two receiver-held originals, not only SHA text.
            inventory=[r for r in review['inventory_records'] if r['slot']==slot]
            missing=False;conflict=False
            for rec in inventory:
                signature_tuple=(rec['ec355_receipt_original_sha256'],
                   rec['checkpoint_original_sha256'],rec['witness_original_sha256'],
                   rec['checkpoint_length'],rec['witness_length'])
                if (rec['availability']=='present' and allack[signature_tuple]==0):
                    conflict=True
                if rec['availability']=='unavailable' and allack[signature_tuple]>0:
                    conflict=True
                if rec['declared_site_id']!=actual['site_id']:
                    conflict=True
            for r in ackrows:
                if r['status']=='custodied_originals' and not any(
                    item['availability']=='present' and
                    (item['ec355_receipt_original_sha256'],item['checkpoint_original_sha256'],
                     item['witness_original_sha256'],item['checkpoint_length'],
                     item['witness_length'])==(
                        r['ec355_receipt_sha'],r['checkpoint_sha'],r['witness_sha'],
                        r['checkpoint_length'],r['witness_length'])
                    for item in inventory):
                    missing=True
            if not inventory or any(r['status']!='custodied_originals' for r in ackrows):
                missing=True
            roots=[r for r in review['root_records'] if r['slot']==slot]
            if len(roots)!=1:
                missing=True
            else:
                root=roots[0]
                if (root['root_public_key_original_sha256']!=actual['root_sha'] or
                    root['institution_id']!=actual['institution_id'] or
                    root['declared_physical_site_id']!=actual['site_id']):
                    conflict=True
                if root['root_state']!='active':flags[FLAGS[4]]=True
            if conflict:flags[FLAGS[4]]=True
            if missing:flags[FLAGS[3]]=True
            if fork:flags[FLAGS[2]]=True
            if actual['clock']:flags[FLAGS[6]]=True
            if (actual['root_sha']!=opts['historical_custody_'+slot+'_root_key_shas'][i]
                or selected!=opts['historical_custody_'+slot+'_ack_head_shas'][i]
                or len(ackrows)<opts[
                     'minimum_historical_custody_'+slot+'_ack_counts'][i]):
                flags[FLAGS[1]]=True
            recovered={'epoch_index':i,'slot':slot,
                'ec356_bundle_original_sha':oldcustref['sha256'],
                'ec357_review_signed_original_sha':source[
                     'source_review_signed_original']['sha256'],
                'ec357_signed_parent_ec356_result_sha':source[
                     'signed_parent_ec356_canonical_result_sha256'],
                'root_public_key_sha':actual['root_sha'],
                'root_reference_signed_original_sha':actual['root_original_sha'],
                'channel_public_key_sha':actual['channel_sha'],
                'channel_authorization_signed_original_sha':actual[
                     'authorization_sha'],
                'institution_id':actual['institution_id'],
                'channel_id':actual['channel_id'],'declared_site_id':actual['site_id'],
                'ack_original_shas':sorted(r['ack_sha'] for r in ackrows),
                'selected_ack_head_sha':selected,
                'verified_signed_ack_count':len(ackrows),
                'actual_copied_pair_count':sum(r['signed_original_bytes_reopened']
                                              for r in ackrows),
                'ec357_signed_inventory_row_count':len(inventory),
                'signed_root_review_missing_or_conflicting':conflict or len(roots)!=1,
                'signed_inventory_missing_or_conflicting':missing or conflict,
                'signed_ack_fork':fork}
            rows.append(recovered);epoch_recovered.append((actual,ackrows))
            old_claims.append((i,slot,source['signed_parent_ec356_canonical_result_sha256'],
                                   oldcustref['sha256']))
        (a,aacks),(b,backs)=epoch_recovered
        need(len({a['root_sha'],a['channel_sha'],b['root_sha'],b['channel_sha']})==4,
             'INDEPENDENT_HISTORIC_CHANNEL_ROOT_AND_ACK_KEY_ROLES_REQUIRED',
             'permission_denied')
        all_signed_acks=aacks+backs
        need(len({r['acknowledgement_id'] for r in all_signed_acks})==len(all_signed_acks)
             and len({r['nonce_hex'] for r in all_signed_acks})==len(all_signed_acks),
             'TWO_CHANNEL_SIGNED_ACK_IDENTIFIER_OR_NONCE_REPLAY',
             'permission_denied')
        # Each EC357 signed source review can testify about BOTH historic
        # custody slots. The owner-layer audit verifies that its signature is
        # real, but the new custody layer must check EVERY signed cross-slot
        # claim against the actual old EC356 channel signature + original
        # copies. Otherwise a revoked B root or a conflicting B inventory row
        # signed by reviewer A could be lost when A's own row was consistent.
        by_slot={'a':(a,aacks),'b':(b,backs)}
        root_testimonies=defaultdict(set)
        inventory_testimonies=defaultdict(set)
        for reviewer_slot,review in signed_review_views:
            for root in review['root_records']:
                actor,_=by_slot[root['slot']]
                root_testimonies[root['slot']].add(tuple(sorted(root.items())))
                if (root['root_state']!='active' or
                    root['institution_id']!=actor['institution_id'] or
                    root['root_public_key_original_sha256']!=actor['root_sha'] or
                    root['declared_physical_site_id']!=actor['site_id']):
                    flags[FLAGS[4]]=True
            for rec in review['inventory_records']:
                actor,verified_acks=by_slot[rec['slot']]
                evidence=(rec['ec355_receipt_original_sha256'],
                          rec['checkpoint_original_sha256'],
                          rec['witness_original_sha256'],
                          rec['checkpoint_length'],rec['witness_length'])
                inventory_testimonies[(rec['slot'],rec[
                    'ec355_receipt_original_sha256'])].add(tuple(sorted(rec.items())))
                matched=any((row['ec355_receipt_sha'],row['checkpoint_sha'],
                             row['witness_sha'],row['checkpoint_length'],
                             row['witness_length'])==evidence and
                             row['status']=='custodied_originals'
                            for row in verified_acks)
                if (rec['declared_site_id']!=actor['site_id'] or
                    (rec['availability']=='present')!=matched):
                    flags[FLAGS[4]]=True
        if (any(len(x)>1 for x in root_testimonies.values()) or
            any(len(x)>1 for x in inventory_testimonies.values())):
            flags[FLAGS[4]]=True
        # Signed EC357 source a and source b may disagree about the custody
        # state; never select the convenient one or mark both validated.
        if a['site_id']==b['site_id'] or a['institution_id']==b['institution_id']:
            flags[FLAGS[4]]=True
        if old_claims[-1][2:]!=old_claims[-2][2:]:
            flags[FLAGS[4]]=True
        # Independently signed same old EC355 original SHA but different real
        # copied data is conflicting source evidence, not silent quorum.
        per_receipt=defaultdict(set)
        for row in aacks+backs:
            if row['status']=='custodied_originals':
                per_receipt[row['ec355_receipt_sha']].add((row['checkpoint_sha'],
                                                             row['witness_sha']))
        if any(len(values)>1 for values in per_receipt.values()):flags[FLAGS[4]]=True
        # Historic EC356's core quorum is two differently signed EC355
        # requested-role receipts of the SAME checkpoint + witness bytes.
        # We recover that signed assertion and true copy-byte equality here,
        # but cannot authenticate the old EC355 roles without its originals.
        paired=any(
           x['status']=='custodied_originals' and
           y['status']=='custodied_originals' and
           x['checkpoint_sha']==y['checkpoint_sha'] and
           x['witness_sha']==y['witness_sha'] and
           x['gossip_sha']==y['gossip_sha'] and
           x['ec355_receipt_sha']!=y['ec355_receipt_sha'] and
           x['ec355_requested_role']!=y['ec355_requested_role']
           for x in aacks for y in backs)
        if not paired:flags[FLAGS[3]]=True
    for slot in ('a','b'):
        for before,after in zip([r for r in rows if r['slot']==slot],
                                [r for r in rows if r['slot']==slot][1:]):
            if (before['root_public_key_sha']!=after['root_public_key_sha'] or
                before['channel_public_key_sha']!=after['channel_public_key_sha'] or
                before['institution_id']!=after['institution_id'] or
                before['channel_id']!=after['channel_id'] or
                before['ec356_bundle_original_sha']!=after['ec356_bundle_original_sha'] or
                before['ec357_signed_parent_ec356_result_sha']!=after[
                    'ec357_signed_parent_ec356_result_sha']):
                flags[FLAGS[5]]=True
            if before['selected_ack_head_sha']!=after['selected_ack_head_sha'] and \
               before['selected_ack_head_sha'] not in after['ack_original_shas']:
                flags[FLAGS[5]]=True
    need(not set(pins).intersection(forbidden),
         'HISTORIC_EC356_OR_EC362_OR_EC369_SOURCE_LABEL_READ',
         'permission_denied')
    tsa._check_late(pins)
    ec357._late_identity_check(pins,set())
    flags[FLAGS[-1]]=True
    inventory={'schema':INVENTORY_SCHEMA,
         'verified_live_parent_ec374_canonical_result_sha256':parent_digest,
         'ec374_owner_epoch_original_sha256':oldref['sha256'],
         'receiver_ec375_historical_custody_archive_original_sha256':newref['sha256'],
         'claimed_historical_directory_lineage_id':opts[
                                   'claimed_historical_directory_lineage_id'],
         'receiver_verified_ec356_ec357_source_rows':[
          {k:r[k] for k in (
              'epoch_index','slot','ec356_bundle_original_sha',
              'ec357_review_signed_original_sha','ec357_signed_parent_ec356_result_sha',
              'root_public_key_sha','root_reference_signed_original_sha',
              'channel_public_key_sha','channel_authorization_signed_original_sha',
              'institution_id','channel_id','declared_site_id','ack_original_shas',
              'selected_ack_head_sha','verified_signed_ack_count',
              'actual_copied_pair_count','ec357_signed_inventory_row_count')}
          for r in rows]}
    digest=sha(canonical.canonical(inventory))
    if not derive and opts[AUDIT_ONLY[0]]!=digest:flags[FLAGS[1]]=True
    local=not any(flags[key] for key in FLAGS[:-1])
    status=next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),
                OUTCOMES[-1])+'_unresolved'
    doc={'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
         'command':('derive-historical-custody-inventory' if derive else
                    'audit-historical-custody-archive'),
         'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
         'historical_custody_archive_bundle_original_sha256':newref['sha256'],
         'verified_live_parent_ec374_canonical_result_sha256':parent_digest,
         'receiver_verified_historical_custody_inventory_sha256':digest,
         'verified_real_ec356_root_signed_reference_count':len(rows),
         'verified_real_ec356_root_signed_channel_authorization_count':len(rows),
         'verified_real_ec356_channel_signed_acknowledgement_count':sum(
                r['verified_signed_ack_count'] for r in rows),
         'verified_real_old_ec356_original_copy_pair_count':sum(
                r['actual_copied_pair_count'] for r in rows),
         'historical_custody_source_epoch_reviews':[
            {k:r[k] for k in (
              'epoch_index','slot','root_public_key_sha','channel_public_key_sha',
              'selected_ack_head_sha','verified_signed_ack_count',
              'actual_copied_pair_count','ec357_signed_inventory_row_count',
              'signed_root_review_missing_or_conflicting',
              'signed_inventory_missing_or_conflicting','signed_ack_fork')}
            for r in rows],
         'local_pinned_historical_custody_signatures_and_source_inventory_consistent':local,
         'sender_origin_path_required_or_read':False,
         'ec365_to_ec337_full_parent_original_replay_performed':False,
         **flags,**{key:False for key in NEGATIVES}}
    if derive:
        doc['unsigned_verified_historical_custody_inventory']=inventory
        doc['caller_external_inventory_pin_created_or_certified']=False
    return doc


def audit(**opts):return _engine(False,**opts)


def derive_inventory(**opts):return _engine(True,**opts)
