#!/usr/bin/env python3
"""EC357: offline, signed, externally IMPORTED source reviews for EC356 custody.

Trust boundary: two caller-SHA-pinned source signing keys prove only that their
actual private keys signed the presented assertions. No local computation can
authenticate their real-world owners, legal independence or physical custody.
This layer never repairs EC356/EC355 ancestry, signs, fetches or writes remotely.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from datetime import timedelta
import hashlib
import os

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec356_custody import custody as prior

RESULT_SCHEMA='ces.ec357.offline_imported_institution_provenance_unresolved.v1'
DENIAL_SCHEMA='ces.ec357.offline_imported_institution_provenance_denial.v1'
HANDOFF_SCHEMA='ces.ec357.unsigned_institution_provenance_handoff.v1'
BUNDLE_SCHEMA='ces.ec357.pinned_source_review_bundle.v1'
SOURCE_SCHEMA='ces.ec357.source_signed_root_and_custody_inventory.v1'
SOURCE_DOMAIN=b'CES/EC357/ImportedRootCustodyReview/v1\x00'
MAX_BUNDLE=36_000
MAX_SOURCE=48_000
MAX_INVENTORY=48
MAX_AGE=timedelta(days=30)
OUTCOMES=(
    'ec357_parent_ec356_cross_role_original_custody_unresolved',
    'ec357_two_caller_pinned_source_reviews_missing',
    'ec357_signed_root_revocation_or_rotation_visible',
    'ec357_signed_institution_root_site_or_source_identity_conflicts_visible',
    'ec357_signed_custody_inventory_conflicts_with_verified_originals',
    'ec357_signed_original_inventory_or_copied_bytes_incomplete',
    'ec357_stale_or_future_self_reported_source_reviews_visible',
    'ec357_two_signed_source_reviews_locally_consistent_external_authentication_unproven',
)
NEGATIVES=(
    'caller_source_sha_pins_prove_real_external_identity',
    'two_signed_source_reviews_prove_independent_legal_institutions',
    'copy_path_or_signed_site_proves_physical_external_custody',
    'source_review_time_proves_trusted_utc',
    'active_source_review_overrides_revoked_or_rotated_root',
    'source_reviews_repair_ec356_or_ec355_parent_proof',
    'source_reviews_prove_global_log_head_or_fork_absence',
    'audit_uses_network_or_system_trust_store',
    'audit_signs_keys_or_writes_provider_cas_worm',
    'production_ec317_ec318_and_final_acceptance_proven',
)

def need(condition,code,status='invalid_input'):
    if condition is not True:raise errors.AnchorError('EC357_'+code,status)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def _obj(raw,role):return tr.strict_json(raw,'EC357_'+role)

def _exact(obj,fields,role):need(type(obj) is dict and set(obj)==set(fields),role+'_EXACT_FIELDS_REQUIRED')

def _pin(pair,role):
    _exact(pair,('path','sha256'),role+'_PIN')
    need(type(pair['path']) is str and tr._sha(pair['sha256']),role+'_PIN_FORMAT')


def _all_pins(obj,paths):
    """Accumulate nested pinned originals in authenticated old manifests."""
    if type(obj) is dict:
        if set(obj)=={'path','sha256'} and type(obj['path']) is str and tr._sha(obj['sha256']):
            paths.add(obj['path'])
        for value in obj.values():_all_pins(value,paths)
    elif type(obj) is list:
        for value in obj:_all_pins(value,paths)


def _parent_files(inputs,manifest,oldpins):
    """Reopen parent manifests and exclude *nested* prior originals, not only
    top-level input paths, from being reused as claimed external copies.
    """
    paths={inputs['custody_bundle_file']}
    for key,value in inputs.items():
        if key.endswith('_file') and type(value) is str:paths.add(value)
        if key.endswith('_files') and type(value) is list:
            paths.update(v for v in value if type(v) is str)
    _all_pins(manifest,paths)
    for file_key,sha_key,cap,kind in (
        ('publication_bundle_file','expected_publication_bundle_sha256',
         tr.MAX_BUNDLE,'EC353_PUBLICATION'),
        ('gossip_bundle_file','expected_gossip_bundle_sha256',
         prior.gossip.MAX_BUNDLE,'EC354_GOSSIP'),
        ('checkpoint_disclosure_bundle_file','expected_checkpoint_disclosure_bundle_sha256',
         prior.prior.MAX_BUNDLE,'EC355_DISCLOSURE')):
        original=prior._inherited({'path':inputs[file_key],'sha256':inputs[sha_key]},
                                  kind,cap,oldpins)
        _all_pins(_obj(original,kind),paths)
    # EC352 and earlier caller pins, including signed role references nested
    # in the original old ceremony, are included in alias prohibitions.
    paths.update(prior.gossip.reg352._all_parent_files(inputs))
    return paths


def _late_identity_check(newpins,oldpaths):
    """Recheck file type, symlink ancestry and inode independence at exit.
    No local check can make this a transactional filesystem snapshot.
    """
    old_ids=set()
    for path in oldpaths:
        try:
            st=os.stat(path,follow_symlinks=False)
            old_ids.add((st.st_dev,st.st_ino))
        except OSError:pass  # Parent auditors check their required originals.
    seen=set()
    for path in newpins:
        p=Path(path)
        need(not any(node.is_symlink() for node in (p,*p.parents)),
             'LATE_SOURCE_SYMLINK_ANCESTOR_DENIED','permission_denied')
        try:
            st=os.stat(path,follow_symlinks=False)
        except OSError as exc:
            raise errors.AnchorError('EC357_LATE_SOURCE_ORIGINAL_STAT_UNAVAILABLE',
                                     'unavailable') from exc
        ident=(st.st_dev,st.st_ino)
        need(ident not in old_ids and ident not in seen,
             'LATE_SOURCE_ORIGINAL_INODE_ALIAS_DENIED','permission_denied')
        seen.add(ident)


def _parent(original_inputs):
    result=prior.audit(**original_inputs)   # Genuine EC356 -> EC355 -> EC337 replay.
    need(result.get('schema')==prior.RESULT_SCHEMA and
         result.get('actual_ec355_through_ec337_signed_originals_replayed') is True and
         result.get('exit_code')==2,
         'PARENT_REAL_SIGNED_ORIGINAL_REPLAY_REQUIRED','permission_denied')
    return result


def _index(parent):
    expected={}
    for claim in parent['claim_custody_evidence']:
        for slot in ('a','b'):
            for row in claim['channel_'+slot+'_acknowledgements']:
                original=row['verified_originals']
                if original is None:continue
                key=(slot,row['ec355_receipt_original_sha256'])
                need(key not in expected,'PARENT_DUPLICATE_CUSTODY_ROLE','permission_denied')
                expected[key]={
                    'slot':slot,'ec355_receipt_original_sha256':key[1],
                    'checkpoint_original_sha256':original['checkpoint_sha256'],
                    'checkpoint_length':original['checkpoint_length'],
                    'witness_original_sha256':original['witness_sha256'],
                    'witness_length':original['witness_length'],
                    'role':original['ec355_requested_role'],
                }
    return expected


def _review(raw,pub):
    doc=prior._signed(raw,pub,SOURCE_DOMAIN,'signature_ed25519_hex','EC357_SOURCE_REVIEW')
    _exact(doc,('schema','source_id','source_authority_public_key_original_sha256',
                'ec356_custody_bundle_original_sha256',
                'parent_ec356_canonical_result_sha256','issued_utc','expires_utc',
                'root_records','inventory_records','signature_ed25519_hex'),
           'SOURCE_REVIEW')
    need(doc['schema']==SOURCE_SCHEMA and tr._ident(doc['source_id']) and
         type(doc['root_records']) is list and len(doc['root_records'])<=2 and
         type(doc['inventory_records']) is list and len(doc['inventory_records'])<=MAX_INVENTORY,
         'SOURCE_SCHEMA_OR_BOUNDS')
    issued=tr._utc(doc['issued_utc']);expires=tr._utc(doc['expires_utc'])
    need(issued<expires,'SOURCE_VALIDITY_INTERVAL_INVALID','permission_denied')
    for row in doc['root_records']:
        _exact(row,('slot','institution_id','claimed_legal_entity_id',
                    'root_public_key_original_sha256','root_state',
                    'replacement_root_public_key_sha256','root_state_effective_utc',
                    'declared_physical_site_id'),'SOURCE_ROOT_ROW')
        need(row['slot'] in ('a','b') and tr._ident(row['institution_id']) and
             tr._ident(row['claimed_legal_entity_id']) and
             tr._ident(row['declared_physical_site_id']) and
             tr._sha(row['root_public_key_original_sha256']) and
             row['root_state'] in ('active','revoked','rotated'),
             'SIGNED_ROOT_ROW_FORMAT_INVALID')
        if row['root_state']=='active':
            need(row['replacement_root_public_key_sha256'] is None and
                 row['root_state_effective_utc'] is None,
                 'ACTIVE_ROOT_CANNOT_HAVE_REPLACEMENT_OR_REVOCATION')
        else:
            replaced=row['replacement_root_public_key_sha256']
            need((replaced is None if row['root_state']=='revoked'
                  else tr._sha(replaced) and replaced!=row['root_public_key_original_sha256'])
                 and type(row['root_state_effective_utc']) is str and
                 tr._utc(row['root_state_effective_utc'])<=expires,
                 'SIGNED_REVOKED_OR_ROTATED_ROOT_SCOPE_INVALID')
    need(len({r['slot'] for r in doc['root_records']})==len(doc['root_records']),
         'SIGNED_ROOT_SLOT_DUPLICATE','permission_denied')
    for row in doc['inventory_records']:
        _exact(row,('slot','ec355_receipt_original_sha256',
                    'checkpoint_original_sha256','checkpoint_length',
                    'witness_original_sha256','witness_length','declared_site_id',
                    'availability'),'SOURCE_INVENTORY_ROW')
        need(row['slot'] in ('a','b') and
             all(tr._sha(row[k]) for k in ('ec355_receipt_original_sha256',
                  'checkpoint_original_sha256','witness_original_sha256')) and
             all(type(row[k]) is int and 0<row[k]<=tr.MAX_CHECKPOINT+tr.MAX_WITNESS
                 for k in ('checkpoint_length','witness_length')) and
             tr._ident(row['declared_site_id']) and
             row['availability'] in ('present','unavailable'),
             'SIGNED_INVENTORY_ROW_FORMAT_INVALID')
    need(len({(r['slot'],r['ec355_receipt_original_sha256'])
              for r in doc['inventory_records']})==len(doc['inventory_records']),
         'SIGNED_INVENTORY_ROLE_DUPLICATE','permission_denied')
    return doc,issued,expires


def checklist(**custody_inputs):
    parent=_parent(custody_inputs)
    expected=_index(parent)
    return {'schema':HANDOFF_SCHEMA,'command':'derive-provenance-review-handoff',
            'status':'caller_must_obtain_two_offline_signed_independent_source_reviews_unresolved',
            'exit_code':2,'case_id':parent['case_id'],
            'actual_ec356_through_ec337_originals_replayed':True,
            'parent_ec356_canonical_result_sha256':sha(canonical.canonical(parent)),
            'parent_custody_bundle_original_sha256':custody_inputs[
                 'expected_custody_bundle_sha256'],
            'required_ec356_verified_originals':list(expected.values()),
            'externally_authenticated_source_identity_and_physical_custody_unproven':True,
            'offline_unresolved_exit_code':2,**{n:False for n in NEGATIVES}}


def audit(*,provenance_review_evaluation_utc,
          provenance_review_bundle_file=None,expected_provenance_review_bundle_sha256=None,
          source_a_authority_public_key_file=None,
          expected_source_a_authority_public_key_sha256=None,
          source_b_authority_public_key_file=None,
          expected_source_b_authority_public_key_sha256=None,**custody_inputs):
    evaluated=tr._utc(provenance_review_evaluation_utc)
    need(evaluated>=tr._utc(custody_inputs['two_channel_custody_evaluation_utc']),
         'REVIEW_EVALUATION_BEFORE_EC356','permission_denied')
    parent=_parent(custody_inputs)
    parent_sha=sha(canonical.canonical(parent))
    expected=_index(parent)
    root_channels={row['slot']:row for row in parent['channel_establishments']}
    original_bundle={'path':custody_inputs['custody_bundle_file'],
                     'sha256':custody_inputs['expected_custody_bundle_sha256']}
    oldpins={}
    manifest=_obj(prior._inherited(original_bundle,'EC356_CUSTODY_MANIFEST',
                                    prior.MAX_BUNDLE,oldpins),'EC356_CUSTODY_MANIFEST')
    _exact(manifest,('schema','channels'),'PARENT_CUSTODY_MANIFEST')
    need(manifest['schema']==prior.BUNDLE_SCHEMA and type(manifest['channels']) is list,
         'PARENT_CUSTODY_MANIFEST_SCHEMA_INVALID','permission_denied')
    oldpaths=_parent_files(custody_inputs,manifest,oldpins)
    for channel in manifest['channels']:
        for name,cap in (('root_public_key',32),('root_reference',prior.MAX_RECORD),
                         ('channel_public_key',32),('channel_authorization',prior.MAX_RECORD)):
            prior._inherited(channel[name],'EC356_'+name.upper(),cap,oldpins)
        for entry in channel['acknowledgements']:
            prior._inherited(entry['acknowledgement'],'EC356_ACK',prior.MAX_RECORD,oldpins)
            for name,cap in (('checkpoint_original',tr.MAX_CHECKPOINT),
                             ('witness_original',tr.MAX_WITNESS)):
                if entry[name] is not None:
                    prior._inherited(entry[name],'EC356_'+name.upper(),cap,oldpins)

    bundle_pair=(provenance_review_bundle_file,expected_provenance_review_bundle_sha256)
    need((bundle_pair==(None,None)) or
         (type(bundle_pair[0]) is str and tr._sha(bundle_pair[1])),
         'BUNDLE_FILE_AND_SHA_MUST_BE_PAIRED')
    source_args={
        'a':(source_a_authority_public_key_file,expected_source_a_authority_public_key_sha256),
        'b':(source_b_authority_public_key_file,expected_source_b_authority_public_key_sha256),
    }
    for pair in source_args.values():
        need(pair==(None,None) or (type(pair[0]) is str and tr._sha(pair[1])),
             'SOURCE_PUBLIC_KEY_FILE_AND_SHA_MUST_BE_PAIRED')
    submitted=[(slot,pair) for slot,pair in source_args.items() if pair!=(None,None)]
    if len(submitted)==2:
        need(submitted[0][1][0]!=submitted[1][1][0] and
             submitted[0][1][1]!=submitted[1][1][1],
             'SOURCES_REQUIRE_TWO_DIFFERENT_CALLER_PINS','permission_denied')
    pins={};reviews={};source_entries=[]
    if bundle_pair!=(None,None):
        doc=_obj(prior._new({'path':bundle_pair[0],'sha256':bundle_pair[1]},
                 'SOURCE_BUNDLE',MAX_BUNDLE,pins,oldpaths),'SOURCE_BUNDLE')
        _exact(doc,('schema','sources'),'SOURCE_BUNDLE')
        need(doc['schema']==BUNDLE_SCHEMA and type(doc['sources']) is list and
             len(doc['sources'])<=2,'SOURCE_BUNDLE_SCHEMA_OR_SIZE_INVALID')
        source_entries=doc['sources']
    collisions=False;conflicts=False;missing=False;revoked=False;stale=False
    source_rows=[];all_roots=[];all_inventory=[];oldrolekeyhashes={
        r[k] for r in root_channels.values() for k in (
        'root_public_key_original_sha256','channel_public_key_original_sha256')}
    # Never reinterpret an EC353 log, witness or EC354 auditor signing key as
    # an independent external source reviewer. Those parent public keys are
    # reopened and SHA checked; the EC356 result itself already authenticates
    # their signature roles.
    publication=_obj(prior._inherited({'path':custody_inputs['publication_bundle_file'],
              'sha256':custody_inputs['expected_publication_bundle_sha256']},
              'EC353_KEY_ROLE_MANIFEST',tr.MAX_BUNDLE,oldpins),'EC353_KEY_ROLES')
    gossip=_obj(prior._inherited({'path':custody_inputs['gossip_bundle_file'],
              'sha256':custody_inputs['expected_gossip_bundle_sha256']},
              'EC354_KEY_ROLE_MANIFEST',prior.gossip.MAX_BUNDLE,oldpins),'EC354_KEY_ROLES')
    for record in publication['logs']:
        for field in ('log_public_key','witness_public_key'):
            raw=prior._inherited(record[field],'EC353_ROLE_KEY',32,oldpins)
            oldrolekeyhashes.add(sha(raw))
    for record in gossip['auditors']:
        raw=prior._inherited(record['auditor_public_key'],
                             'EC354_AUDITOR_ROLE_KEY',32,oldpins)
        oldrolekeyhashes.add(sha(raw))
    used_authority_keys=set();source_ids=set();source_slots=set()
    for entry in source_entries:
        _exact(entry,('slot','source_authority_public_key','signed_source_review',
                      'inventory_copies'),'SOURCE_ENTRY')
        slot=entry['slot']
        need(slot in source_args and slot not in source_slots,'SOURCE_SLOT_DUPLICATE_OR_UNKNOWN')
        source_slots.add(slot)
        pair=source_args[slot]
        need(pair!=(None,None),'MISSING_SEPARATELY_CALLER_PINNED_SOURCE_AUTHORITY',
             'permission_denied')
        keypin={'path':pair[0],'sha256':pair[1]}
        need(entry['source_authority_public_key']==keypin,
             'SOURCE_AUTHORITY_MUST_EQUAL_EXPLICIT_CALLER_PIN','permission_denied')
        raw_key=prior._new(keypin,'SOURCE_'+slot+'_PUBKEY',32,pins,oldpaths)
        key_sha=sha(raw_key)
        need(key_sha not in used_authority_keys and key_sha not in oldrolekeyhashes,
             'SOURCE_SIGNER_KEY_REUSES_PARENT_OR_OTHER_SOURCE_ROLE',
             'permission_denied')
        used_authority_keys.add(key_sha)
        review_pin=entry['signed_source_review']
        raw=prior._new(review_pin,'SOURCE_'+slot+'_SIGNATURE',MAX_SOURCE,pins,oldpaths)
        signed,issued,expires=_review(raw,raw_key)
        need(signed['source_authority_public_key_original_sha256']==keypin['sha256']
             and signed['ec356_custody_bundle_original_sha256']==original_bundle['sha256']
             and signed['parent_ec356_canonical_result_sha256']==parent_sha,
             'SIGNATURE_MUST_BIND_ACTUAL_EC356_REPLAY_AND_SOURCE_KEY',
             'permission_denied')
        need(signed['source_id'] not in source_ids,
             'SIGNED_SOURCE_ID_DUPLICATE','permission_denied')
        source_ids.add(signed['source_id'])
        if (issued>evaluated or expires<evaluated or evaluated-issued>MAX_AGE):stale=True
        if signed['source_id'] in {r['institution_id'] for r in root_channels.values()}:
            collisions=True
        for root in signed['root_records']:
            original=root_channels.get(root['slot'])
            correct=bool(original and root['institution_id']==original['institution_id'] and
                         root['root_public_key_original_sha256']==original[
                            'root_public_key_original_sha256'] and
                         root['declared_physical_site_id']==original['claimed_physical_site_id'])
            if not correct:collisions=True
            if root['root_state']!='active':revoked=True
            all_roots.append((slot,root))
        root_slots={r['slot'] for r in signed['root_records']}
        if root_slots!={'a','b'}:missing=True
        inv={(r['slot'],r['ec355_receipt_original_sha256']):r
             for r in signed['inventory_records']}
        presented=entry['inventory_copies']
        need(type(presented) is list and len(presented)<=MAX_INVENTORY,
             'SOURCE_COPIED_INVENTORY_BOUNDS_INVALID')
        copy_index={}
        for item in presented:
            _exact(item,('slot','ec355_receipt_original_sha256',
                         'checkpoint_original','witness_original'),'PRESENTED_SOURCE_COPY')
            key=(item['slot'],item['ec355_receipt_original_sha256'])
            need(item['slot'] in ('a','b') and tr._sha(key[1]) and key not in copy_index,
                 'COPIED_SOURCE_INVENTORY_DUPLICATE_OR_INVALID')
            copy_index[key]=item
            need(key in inv and inv[key]['availability']=='present',
                 'COPIED_BYTES_WITHOUT_SIGNED_PRESENT_INVENTORY',
                 'permission_denied')
        inventory_out=[]
        for key,record in inv.items():
            original=expected.get(key)
            consistent=(original is not None and all(record[n]==original[n]
                       for n in ('checkpoint_original_sha256','checkpoint_length',
                                  'witness_original_sha256','witness_length')) and
                        original['slot']==record['slot'])
            root=root_channels.get(record['slot'])
            if root and record['declared_site_id']!=root['claimed_physical_site_id']:
                collisions=True
            if not consistent:conflicts=True
            item=copy_index.get(key)
            has_bytes=record['availability']=='present' and item is not None
            if record['availability']=='present' and item is None:missing=True
            if record['availability']=='unavailable' and item is not None:
                need(False,'UNAVAILABLE_SOURCE_MUST_NOT_PRESENT_FILES',
                     'permission_denied')
            if record['availability']=='unavailable':missing=True
            if has_bytes:
                data=[]
                for name,cap,shafield,lengthfield in (
                    ('checkpoint_original',tr.MAX_CHECKPOINT,'checkpoint_original_sha256',
                     'checkpoint_length'),
                    ('witness_original',tr.MAX_WITNESS,'witness_original_sha256',
                     'witness_length')):
                    _pin(item[name],'COPIED_'+name.upper())
                    b=prior._new(item[name],'SOURCE_'+slot+'_COPIED_'+name.upper(),
                                 cap,pins,oldpaths)
                    need(sha(b)==record[shafield] and len(b)==record[lengthfield],
                         'PRESENTED_COPY_NOT_EQUAL_SIGNED_INVENTORY_SHA_AND_LENGTH',
                         'permission_denied')
                    data.append(b)
            evidence={'slot':record['slot'],'ec355_receipt_original_sha256':key[1],
                      'availability':record['availability'],
                      'presented_actual_new_original_bytes':has_bytes,
                      'matches_parent_ec356_verified_original':consistent,
                      'checkpoint_original_sha256':record['checkpoint_original_sha256'],
                      'checkpoint_length':record['checkpoint_length'],
                      'witness_original_sha256':record['witness_original_sha256'],
                      'witness_length':record['witness_length'],
                      'declared_site_id_as_signed_claim':record['declared_site_id']}
            inventory_out.append(evidence)
            all_inventory.append((slot,record))
        if set(inv)!=set(expected):missing=True
        source_rows.append({'slot':slot,'source_id_as_signed_claim':signed['source_id'],
                            'authority_public_key_original_sha256':key_sha,
                            'source_review_original_sha256':review_pin['sha256'],
                            'issued_utc_as_signed_claim':signed['issued_utc'],
                            'expires_utc_as_signed_claim':signed['expires_utc'],
                            'declared_root_records':signed['root_records'],
                            'inventory_evidence':inventory_out})
        reviews[slot]=signed

    if len(reviews)<2:missing=True
    root_by_slot=defaultdict(list)
    for source_slot,record in all_roots:root_by_slot[record['slot']].append((source_slot,record))
    for target_slot,records in root_by_slot.items():
        if len(records)==2:
            a,b=(r for _,r in records)
            fields=('institution_id','claimed_legal_entity_id',
                    'root_public_key_original_sha256','root_state',
                    'replacement_root_public_key_sha256',
                    'root_state_effective_utc','declared_physical_site_id')
            if any(a[k]!=b[k] for k in fields):collisions=True
    # Signed declarations of *two* distinct institutions which use one same
    # alleged legal identity or same site are a contradiction, not proof.
    for signed in reviews.values():
        records=signed['root_records']
        if len(records)==2 and (records[0]['claimed_legal_entity_id']==records[1]['claimed_legal_entity_id'] or
                                records[0]['declared_physical_site_id']==records[1]['declared_physical_site_id']):
            collisions=True
    inventory_by_key=defaultdict(list)
    for source_slot,row in all_inventory:
        inventory_by_key[(row['slot'],row['ec355_receipt_original_sha256'])].append(row)
    for key,records in inventory_by_key.items():
        if len(records)==2 and any(records[0][field]!=records[1][field] for field in (
            'checkpoint_original_sha256','checkpoint_length','witness_original_sha256',
            'witness_length','availability','declared_site_id')):
            conflicts=True
    # EC356 manifest, authentic old root/channel/ack and all newly imported
    # signed source originals must remain byte-identical through decision return.
    tsa._check_late(oldpins)
    tsa._check_late(pins)
    _late_identity_check(pins,oldpaths)
    parent_good=(parent['two_channel_cross_role_exact_original_quorum_for_all_claims']
                 and len(root_channels)==2 and all(row['outcome']==prior.OUTCOMES[-1]
                          for row in parent['channel_evidence']))
    if not parent_good:outcome=OUTCOMES[0]
    elif len(reviews)<2:outcome=OUTCOMES[1]
    elif revoked:outcome=OUTCOMES[2]
    elif collisions:outcome=OUTCOMES[3]
    elif conflicts:outcome=OUTCOMES[4]
    elif missing:outcome=OUTCOMES[5]
    elif stale:outcome=OUTCOMES[6]
    else:outcome=OUTCOMES[7]
    rows=[{'tsa_channel_id':item['tsa_channel_id'],
           'parent_ec356_outcome':item['outcome'],'outcome':outcome}
          for item in parent['channel_evidence']]
    return {'schema':RESULT_SCHEMA,'command':'audit-institution-provenance',
            'status':outcome+'_unresolved','exit_code':2,'case_id':parent['case_id'],
            'actual_ec356_through_ec337_originals_replayed':True,
            'parent_ec356_canonical_result_sha256':parent_sha,
            'parent_custody_bundle_original_sha256':original_bundle['sha256'],
            'source_review_bundle_original_sha256':bundle_pair[1],
            'review_evaluation_utc_as_caller_claim':provenance_review_evaluation_utc,
            'source_review_count':len(reviews),
            'verified_ec356_custody_original_count':len(expected),
            'source_establishments':source_rows,
            'signed_revocation_or_rotation_visible':revoked,
            'signed_root_identity_or_source_collision_visible':collisions,
            'signed_inventory_conflicts_with_ec356_or_other_source_visible':conflicts,
            'missing_source_root_record_or_original_copy_visible':missing,
            'stale_or_future_self_claimed_source_utc_visible':stale,
            'both_source_copies_match_ec356_parent_for_all_signed_eligible_receipts':bool(
                len(reviews)==2 and expected and parent_good and not (
                    revoked or collisions or conflicts or missing or stale)),
            'externally_authenticated_source_identity_and_physical_custody_unproven':True,
            'channel_evidence':rows,
            'outcome_counts':{x:sum(r['outcome']==x for r in rows) for x in OUTCOMES},
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}
