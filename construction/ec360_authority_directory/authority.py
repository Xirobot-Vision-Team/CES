#!/usr/bin/env python3
"""EC360: bounded, offline, *claim-scoped* authority/revocation/directory evidence.

All new roots, origin witnesses, and directory keys are caller-pinned. Their
signatures prove control of those keys, not an official issuance source. Every
lawful result (including a locally coherent one) remains unresolved/exit 2.
Never fetch, sign, derive private keys, use ambient trust stores, or write CAS.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec359_owner_distribution import distribution as previous

RESULT_SCHEMA = 'ces.ec360.offline_authority_revocation_directory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec360.offline_authority_revocation_directory_denial.v1'
HANDOFF_SCHEMA = 'ces.ec360.unsigned_authority_revocation_handoff.v1'
BUNDLE_SCHEMA = 'ces.ec360.authority_revocation_directory_bundle.v1'
ORIGIN_SCHEMA = 'ces.ec360.offline_anchor_origin_witness_claim.v1'
DELEGATION_SCHEMA = 'ces.ec360.root_signed_issuer_delegation.v1'
SNAPSHOT_SCHEMA = 'ces.ec360.root_signed_revocation_inventory.v1'
DIRECTORY_SCHEMA = 'ces.ec360.directory_signed_checkpoint.v1'
TARGET_SCOPE = previous.SCOPE
ORIGIN_DOMAIN = b'CES/EC360/AnchorOriginWitness/v1\x00'
DELEGATION_DOMAIN = b'CES/EC360/AuthorityDelegation/v1\x00'
SNAPSHOT_DOMAIN = b'CES/EC360/AuthorityRevocations/v1\x00'
DIRECTORY_DOMAIN = b'CES/EC360/DirectoryCheckpoint/v1\x00'
MAX_BUNDLE = 32_000
MAX_ORIGINAL = 8_000
MAX_SNAPSHOTS = 5
MAX_DIRECTORY_LEAVES = 64
MAX_AUTH_SPAN = timedelta(days=180)
MAX_SNAPSHOT_SPAN = timedelta(days=14)
MAX_ORIGIN_SPAN = timedelta(days=180)
MAX_DIRECTORY_SPAN = timedelta(days=7)
MAX_EVALUATION_LAG = timedelta(days=7)
MAX_LIST = 8

ORIGIN_FIELDS = {'schema', 'slot', 'authority_id', 'claimed_jurisdiction',
                 'origin_reference_id', 'root_public_key_original_sha256',
                 'delegation_original_sha256', 'origin_witness_public_key_original_sha256',
                 'observed_utc', 'expires_utc', 'signature_witness_ed25519_hex'}
DELEGATION_FIELDS = {'schema', 'slot', 'authority_id', 'root_public_key_original_sha256',
                     'issuer_public_key_original_sha256', 'issuer_id_as_signed_claim',
                     'owner_public_key_original_sha256', 'parent_owner_head_event_sha256',
                     'parent_distribution_head_original_sha256',
                     'parent_ec359_canonical_result_sha256',
                     'authorized_jurisdictions', 'authorized_scopes',
                     'valid_from_utc', 'expires_utc', 'signature_root_ed25519_hex'}
SNAPSHOT_FIELDS = {'schema', 'slot', 'authority_id', 'root_public_key_original_sha256',
                   'delegation_original_sha256', 'scope', 'sequence',
                   'previous_snapshot_original_sha256', 'inventory_issuer_key_shas',
                   'revoked_issuer_key_shas', 'issued_utc', 'valid_until_utc',
                   'signature_root_ed25519_hex'}
DIRECTORY_FIELDS = {'schema', 'directory_id', 'directory_public_key_original_sha256',
                    'tree_size', 'root_sha256', 'issued_utc', 'expires_utc',
                    'signature_directory_ed25519_hex'}

OUTCOMES = (
    'ec360_parent_ec359_signed_distribution_not_locally_continuous',
    'ec360_external_authority_material_or_caller_saved_head_not_furnished',
    'ec360_valid_signed_delegation_excludes_scope_jurisdiction_or_issuer',
    'ec360_signed_revocation_or_inventory_gap_visible',
    'ec360_signed_revocation_snapshot_fork_or_authority_identity_collision',
    'ec360_caller_saved_revocation_or_directory_rollback_visible',
    'ec360_signed_origin_delegation_snapshot_or_directory_clock_untrusted',
    'ec360_independent_directory_signed_inclusion_not_furnished',
    'ec360_locally_verifiable_authority_and_directory_official_origin_unproven',
)
NEGATIVES = (
    'caller_pinned_root_or_witness_is_officially_authenticated',
    'signed_origin_reference_is_verified_government_or_public_registry',
    'root_delegation_proves_real_issuer_legal_authority',
    'two_independent_root_keys_prove_distinct_legal_organizations',
    'signed_inventory_proves_globally_complete_revocation',
    'signed_directory_checkpoint_proves_latest_global_log_head',
    'issuer_or_witness_signed_utc_is_trusted_historical_time',
    'signed_local_directory_repairs_parent_crypto_or_custody_failure',
    'offline_auditor_fetches_urls_or_ambient_os_trust_stores',
    'offline_auditor_signs_or_writes_provider_cas_worm',
    'native_powershell_or_deep_mock_or_final_acceptance_proven',
)


def need(ok, code, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC360_' + code, status)


def exact(doc, fields, name):
    need(type(doc) is dict and set(doc) == set(fields), name + '_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return previous.sha(raw)


def sig(doc, sig_field, pub, domain, name):
    signature = doc[sig_field]
    need(type(signature) is str and tr.SIG_RE.fullmatch(signature) is not None,
         name + '_SIGNATURE_FORMAT_INVALID')
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(
            bytes.fromhex(signature), domain + canonical.canonical(
                {k: v for k, v in doc.items() if k != sig_field}))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise errors.AnchorError('EC360_' + name + '_TRUE_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def sorted_sha_array(value, name, *, include=None):
    need(type(value) is list and len(value) <= MAX_LIST and
         all(tr._sha(x) for x in value) and value == sorted(set(value)),
         name + '_BOUNDED_SORTED_DISTINCT_SHA_REQUIRED')
    if include is not None:
        return include in value
    return True


def sorted_ids(value, name):
    need(type(value) is list and 1 <= len(value) <= 4 and
         all(tr._ident(x) for x in value) and value == sorted(set(value)),
         name + '_BOUNDED_SORTED_DISTINCT_IDENTIFIERS_REQUIRED')


def window(start, end, limit, name):
    first, last = tr._utc(start), tr._utc(end)
    need(first < last and last - first <= limit,
         name + '_TIME_WINDOW_OUT_OF_BOUNDS', 'permission_denied')
    return first, last


def utc_untrusted(now, start, end, max_lag):
    return start > now or end < now or now - start > max_lag


def outer_pin(path, digest, role):
    need((path, digest) == (None, None) or
         (type(path) is str and tr._sha(digest)), role + '_EXTERNAL_PAIR_INVALID')


def parent_boundary(inputs):
    """Replay already occurred; reopen every furnished parent issuer/key/record.

    Inherited originals can already be listed as old nested paths; do not
    mistakenly route them through the *new* file loader, which rejects them.
    """
    pins, paths, keys = previous._prior_boundary(inputs)
    file=inputs.get('distribution_bundle_file')
    digest=inputs.get('expected_distribution_bundle_sha256')
    if file is not None and digest is not None:
        inherited=previous.parent.parent.prior._inherited
        raw=inherited({'path':file,'sha256':digest},'EC360_PARENT_BUNDLE',
                      previous.MAX_BUNDLE,pins)
        paths.add(file)
        doc=tr.strict_json(raw,'EC360_PARENT_DISTRIBUTION_BUNDLE')
        exact(doc,('schema','sources'),'PARENT_DISTRIBUTION_BUNDLE')
        need(doc['schema']==previous.BUNDLE_SCHEMA,'PARENT_DISTRIBUTION_BUNDLE_INVALID')
        for source in doc['sources']:
            for item,cap,role in [
                (source['distributor_public_key'],32,'parent_issuer'),
                *[(rec,previous.MAX_RECORD,'parent_record') for rec in source['records']]]:
                old=inherited(item,'EC360_OLD_'+role.upper(),cap,pins)
                paths.add(item['path'])
                if role=='parent_issuer':keys.add(sha(old))
    return pins,paths,keys


def load(pin, role, cap, files, oldpaths, categories, kind):
    return previous._load(pin, role, cap, files, oldpaths, categories, kind)


def key_file(path, digest, name, files, oldpaths, categories, seen):
    raw = load({'path':path, 'sha256':digest}, name, 32,
               files, oldpaths, categories, 'key_' + name)
    need(len(raw) == 32 and digest not in seen,
         'NEW_ROLE_KEY_MUST_BE_DISTINCT_' + name, 'permission_denied')
    seen.add(digest)
    return raw


def validate_delegation(raw, root, slot, root_sha, parent_sha, issuer):
    doc = tr.strict_json(raw, 'EC360_DELEGATION')
    exact(doc, DELEGATION_FIELDS, 'DELEGATION')
    need(doc['schema'] == DELEGATION_SCHEMA and doc['slot'] == slot and
         tr._ident(doc['authority_id']) and doc['root_public_key_original_sha256'] == root_sha and
         doc['issuer_public_key_original_sha256'] == issuer['issuer_public_key_original_sha256'] and
         doc['issuer_id_as_signed_claim'] == issuer['issuer_id_as_signed_claim'] and
         doc['owner_public_key_original_sha256'] == issuer['parent_owner_public_key_original_sha256'] and
         doc['parent_owner_head_event_sha256'] == issuer['parent_owner_head_event_sha256'] and
         doc['parent_distribution_head_original_sha256'] == issuer[
             'expected_distribution_head_sha256_as_caller_pin'] and
         doc['parent_ec359_canonical_result_sha256'] == parent_sha,
         'ROOT_DELEGATION_MUST_BIND_TRUE_EC359_ISSUER_OWNER_AND_HEAD', 'permission_denied')
    sorted_ids(doc['authorized_jurisdictions'], 'DELEGATION_JURISDICTIONS')
    sorted_ids(doc['authorized_scopes'], 'DELEGATION_SCOPES')
    start, expiry = window(doc['valid_from_utc'], doc['expires_utc'],
                           MAX_AUTH_SPAN, 'DELEGATION')
    sig(doc, 'signature_root_ed25519_hex', root, DELEGATION_DOMAIN, 'DELEGATION_ROOT')
    return doc, start, expiry


def validate_origin(raw, witness, slot, witness_sha, delegation_sha, root_sha, auth_id):
    doc = tr.strict_json(raw, 'EC360_WITNESSED_ORIGIN')
    exact(doc, ORIGIN_FIELDS, 'ORIGIN')
    need(doc['schema'] == ORIGIN_SCHEMA and doc['slot'] == slot and
         doc['authority_id'] == auth_id and tr._ident(doc['claimed_jurisdiction']) and
         tr._ident(doc['origin_reference_id']) and
         doc['root_public_key_original_sha256'] == root_sha and
         doc['delegation_original_sha256'] == delegation_sha and
         doc['origin_witness_public_key_original_sha256'] == witness_sha,
         'ORIGIN_WITNESS_MUST_BIND_PINNED_ROOT_AND_DELEGATION', 'permission_denied')
    start, expiry = window(doc['observed_utc'], doc['expires_utc'],
                           MAX_ORIGIN_SPAN, 'ORIGIN')
    sig(doc, 'signature_witness_ed25519_hex', witness, ORIGIN_DOMAIN, 'ORIGIN_WITNESS')
    return doc, start, expiry


def validate_snapshot(raw, root, slot, root_sha, delegation_sha, auth_id):
    doc = tr.strict_json(raw, 'EC360_REVOCATION_SNAPSHOT')
    exact(doc, SNAPSHOT_FIELDS, 'REVOCATION_SNAPSHOT')
    need(doc['schema'] == SNAPSHOT_SCHEMA and doc['slot'] == slot and
         doc['authority_id'] == auth_id and
         doc['root_public_key_original_sha256'] == root_sha and
         doc['delegation_original_sha256'] == delegation_sha and
         doc['scope'] == TARGET_SCOPE and
         type(doc['sequence']) is int and 0 <= doc['sequence'] < MAX_SNAPSHOTS and
         (doc['previous_snapshot_original_sha256'] is None or
          tr._sha(doc['previous_snapshot_original_sha256'])) and
         ((doc['sequence'] == 0) == (doc['previous_snapshot_original_sha256'] is None)),
         'REVOCATION_SNAPSHOT_PARENT_OR_SCOPE_INVALID', 'permission_denied')
    sorted_sha_array(doc['inventory_issuer_key_shas'], 'REVOCATION_INVENTORY')
    sorted_sha_array(doc['revoked_issuer_key_shas'], 'REVOKED_ISSUERS')
    need(set(doc['revoked_issuer_key_shas']).issubset(doc['inventory_issuer_key_shas']),
         'REVOCATION_INVENTORY_MUST_INCLUDE_ALL_REVOKED_SHA', 'permission_denied')
    start, expiry = window(doc['issued_utc'], doc['valid_until_utc'],
                           MAX_SNAPSHOT_SPAN, 'REVOCATION_SNAPSHOT')
    sig(doc, 'signature_root_ed25519_hex', root, SNAPSHOT_DOMAIN, 'REVOCATION_ROOT')
    return doc, start, expiry


def snapshot_history(records, head, floor, evaluation, issuer_sha):
    children = defaultdict(list)
    origins=[]; ids=set()
    for digest, (doc, _, _) in records.items():
        prev = doc['previous_snapshot_original_sha256']
        if prev is None:origins.append(digest)
        else:children[prev].append(digest)
    anomaly = len(origins) > 1 or any(len(x) > 1 for x in children.values())
    revoked = False;coverage_missing = False;stale = False
    for digest, (doc, start, end) in records.items():
        prev = doc['previous_snapshot_original_sha256']
        if prev is not None:
            need(prev in records, 'REVOCATION_SIGNED_PREDECESSOR_MISSING', 'permission_denied')
            old, old_start, _ = records[prev]
            need(doc['sequence'] == old['sequence'] + 1,
                 'REVOCATION_SEQUENCE_NOT_MONOTONE', 'permission_denied')
            if start < old_start or not set(old['revoked_issuer_key_shas']).issubset(
                    doc['revoked_issuer_key_shas']):
                anomaly=True
        if issuer_sha in doc['revoked_issuer_key_shas']:
            revoked=True  # Any visible root-signed revocation blocks authorization.
        # Every supplied signed record must cover claimed issuer: no branch can be hidden.
        if issuer_sha not in doc['inventory_issuer_key_shas']:
            coverage_missing=True
        seen=set();current=digest
        while current is not None:
            need(current not in seen, 'REVOCATION_SIGNED_HISTORY_CYCLE', 'permission_denied')
            seen.add(current)
            current=records[current][0]['previous_snapshot_original_sha256']
    endpoints=[x for x in records if not children.get(x)]
    if len(endpoints)>1:anomaly=True
    if head is not None:
        need(head in records,'CALLER_PINNED_REVOCATION_HEAD_NOT_FURNISHED', 'permission_denied')
    selected=records.get(head)
    missing=selected is None or floor is None
    rollback=False
    seq=None
    if selected is not None:
        doc,frm,to=selected
        seq=doc['sequence']
        rollback=bool(children.get(head) or (floor is not None and seq < floor))
        stale=utc_untrusted(evaluation,frm,to,MAX_EVALUATION_LAG)
    return {'selected':selected, 'selected_sequence':seq, 'endpoints':len(endpoints),
            'fork':anomaly, 'revoked':revoked, 'coverage_missing':coverage_missing,
            'stale':stale, 'rollback':rollback, 'missing':missing}


def directory_checkpoint(raw, public, sha_public, eval_time):
    doc=tr.strict_json(raw,'EC360_DIRECTORY_CHECKPOINT')
    exact(doc,DIRECTORY_FIELDS,'DIRECTORY_CHECKPOINT')
    need(doc['schema']==DIRECTORY_SCHEMA and tr._ident(doc['directory_id']) and
         doc['directory_public_key_original_sha256']==sha_public and
         type(doc['tree_size']) is int and 1<=doc['tree_size']<=MAX_DIRECTORY_LEAVES and
         tr._sha(doc['root_sha256']), 'DIRECTORY_SIGNED_CHECKPOINT_INVALID',
         'permission_denied')
    start,end=window(doc['issued_utc'],doc['expires_utc'],MAX_DIRECTORY_SPAN,'DIRECTORY')
    sig(doc,'signature_directory_ed25519_hex',public,DIRECTORY_DOMAIN,'DIRECTORY_SIGNER')
    return doc,utc_untrusted(eval_time,start,end,MAX_EVALUATION_LAG)


def check_proofs(inclusions, originals, checkpoint):
    need(type(inclusions) is list and len(inclusions)==len(originals),
         'DIRECTORY_INCLUSION_LIST_INCOMPLETE_OR_OVERSIZED')
    indexed=set();ok=True
    for item in inclusions:
        exact(item,('original_sha256','leaf_index','audit_path_sha256'),
              'DIRECTORY_INCLUSION')
        digest=item['original_sha256'];index=item['leaf_index'];path=item['audit_path_sha256']
        need(tr._sha(digest) and digest in originals and digest not in indexed and
             type(index) is int and 0<=index<checkpoint['tree_size'] and
             type(path) is list and len(path)<=7 and all(tr._sha(h) for h in path),
             'DIRECTORY_INCLUSION_PROOF_SHAPE_OR_ORIGINAL_MISMATCH')
        indexed.add(digest)
        # Parent EC353 RFC6962 verifier handles non-perfect trees and rejects
        # redundant, missing or wrongly oriented proofs; hash the true raw file.
        if not tr.verify_inclusion(tr.leaf_hash(originals[digest]),index,
                  checkpoint['tree_size'],bytes.fromhex(checkpoint['root_sha256']),
                  [bytes.fromhex(h) for h in path]):
            ok=False
    return ok and indexed==set(originals)


def checklist(**distribution_inputs):
    p=previous.checklist(**distribution_inputs)
    return {
        'schema':HANDOFF_SCHEMA,'command':'derive-authority-directory-handoff',
        'status':'caller_must_supply_separately_authenticated_offline_roots_revocation_and_directory_evidence_unresolved',
        'exit_code':2,'case_id':p['case_id'],
        'actual_ec359_through_ec337_signed_originals_replayed':True,
        'ec359_parent_handoff_schema':p['schema'],
        'required_chain_external_inputs':['authority root pins a/b','origin witness pins a/b',
           'root-signed scope-constrained delegation originals',
           'root-signed monotone revocation snapshots + caller-saved head and minimum sequence',
           'independently pinned directory signing key and checkpoint',
           'RFC6962 inclusion paths for both current delegation and revocation head per source'],
        'origin_and_official_legal_identity_still_not_authenticated':True,
        'offline_unresolved_exit_code':2,
        **{key:False for key in NEGATIVES},
    }


def audit(*, authority_evaluation_utc,
          authority_bundle_file=None,expected_authority_bundle_sha256=None,
          authority_a_root_public_key_file=None,expected_authority_a_root_public_key_sha256=None,
          authority_b_root_public_key_file=None,expected_authority_b_root_public_key_sha256=None,
          origin_a_witness_public_key_file=None,expected_origin_a_witness_public_key_sha256=None,
          origin_b_witness_public_key_file=None,expected_origin_b_witness_public_key_sha256=None,
          minimum_a_revocation_sequence=None,minimum_b_revocation_sequence=None,
          expected_a_revocation_head_sha256=None,expected_b_revocation_head_sha256=None,
          directory_public_key_file=None,expected_directory_public_key_sha256=None,
          directory_checkpoint_file=None,expected_directory_checkpoint_sha256=None,
          minimum_directory_tree_size=None,expected_directory_head_sha256=None,
          **distribution_inputs):
    now=tr._utc(authority_evaluation_utc)
    need(now >= tr._utc(distribution_inputs['distribution_evaluation_utc']),
         'AUTHORITY_EVALUATION_PRECEDES_EC359', 'permission_denied')
    # No shortcut: each EC360 audit truly replays EC359, and hence EC358..EC337.
    prior=previous.audit(**distribution_inputs)
    need(prior['schema']==previous.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec358_through_ec337_signed_originals_replayed'] is True,
         'PARENT_REAL_EC359_THROUGH_EC337_REPLAY_REQUIRED', 'permission_denied')
    psha=sha(canonical.canonical(prior))
    oldpins,oldpaths,oldkeys=parent_boundary(distribution_inputs)
    source_rows={r['slot']:r for r in prior['distribution_establishments']}
    root_pins={'a':(authority_a_root_public_key_file,expected_authority_a_root_public_key_sha256),
               'b':(authority_b_root_public_key_file,expected_authority_b_root_public_key_sha256)}
    origin_pins={'a':(origin_a_witness_public_key_file,expected_origin_a_witness_public_key_sha256),
                 'b':(origin_b_witness_public_key_file,expected_origin_b_witness_public_key_sha256)}
    heads={'a':expected_a_revocation_head_sha256,'b':expected_b_revocation_head_sha256}
    floors={'a':minimum_a_revocation_sequence,'b':minimum_b_revocation_sequence}
    for slot in ('a','b'):
        for name,pin in (('ROOT',root_pins[slot]),('ORIGIN_WITNESS',origin_pins[slot])):
            outer_pin(*pin,name+'_'+slot)
        need(heads[slot] is None or tr._sha(heads[slot]),
             'REVOCATION_HEAD_PIN_' +slot.upper()+'_INVALID')
        need(floors[slot] is None or
             (type(floors[slot]) is int and 0<=floors[slot]<MAX_SNAPSHOTS),
             'REVOCATION_MINIMUM_'+slot.upper()+'_INVALID')
    for name,pin in (('AUTHORITY_BUNDLE',(authority_bundle_file,expected_authority_bundle_sha256)),
                     ('DIRECTORY_PUBLIC_KEY',(directory_public_key_file,expected_directory_public_key_sha256)),
                     ('DIRECTORY_CHECKPOINT',(directory_checkpoint_file,expected_directory_checkpoint_sha256))):
        outer_pin(*pin,name)
    need(minimum_directory_tree_size is None or
         (type(minimum_directory_tree_size) is int and 1<=minimum_directory_tree_size<=64),
         'DIRECTORY_MINIMUM_TREE_SIZE_INVALID')
    need(expected_directory_head_sha256 is None or tr._sha(expected_directory_head_sha256),
         'DIRECTORY_HEAD_CALLER_PIN_INVALID')
    needs_dir=(directory_public_key_file is not None or directory_checkpoint_file is not None)
    need(not needs_dir or (directory_public_key_file is not None and
                            directory_checkpoint_file is not None),
         'DIRECTORY_KEY_AND_CHECKPOINT_BOTH_REQUIRED')
    newpins,categories={},{}
    entries=[]
    if authority_bundle_file is not None:
        raw=load({'path':authority_bundle_file,'sha256':expected_authority_bundle_sha256},
                 'AUTHORITY_BUNDLE',MAX_BUNDLE,newpins,oldpaths,categories,'manifest')
        doc=tr.strict_json(raw,'EC360_AUTHORITY_BUNDLE')
        exact(doc,('schema','sources'),'AUTHORITY_BUNDLE')
        need(doc['schema']==BUNDLE_SCHEMA and type(doc['sources']) is list and
             len(doc['sources'])<=2,'AUTHORITY_BUNDLE_SCHEMA_OR_COUNT_INVALID')
        entries=doc['sources']
    seenkeys=set(oldkeys);seen_slots=set();seen_auth_ids=set()
    reviews=[];new_source_originals={};flags={
        'missing':False,'excluded':False,'revoked_or_coverage_gap':False,
        'fork_or_collision':False,'rollback':False,'stale':False,
        'directory_missing':False,
    }
    for entry in entries:
        exact(entry,('slot','authority_root_public_key','origin_witness_public_key',
                     'origin_original','delegation_original',
                     'revocation_snapshot_originals','directory_inclusions'),
              'AUTHORITY_SOURCE')
        slot=entry['slot']
        need(slot in ('a','b') and slot not in seen_slots,
             'AUTHORITY_SLOT_DUPLICATE_OR_UNKNOWN','permission_denied')
        seen_slots.add(slot)
        need(slot in source_rows,'AUTHORITY_SOURCE_MISSING_TRUE_PARENT_ISSUER',
             'permission_denied')
        root_input=root_pins[slot];origin_input=origin_pins[slot]
        need(root_input!=(None,None) and origin_input!=(None,None),
             'ROOT_AND_WITNESS_MUST_BE_EXTERNALLY_PINNED','permission_denied')
        need(entry['authority_root_public_key']=={'path':root_input[0], 'sha256':root_input[1]} and
             entry['origin_witness_public_key']=={'path':origin_input[0], 'sha256':origin_input[1]},
             'ROLE_KEYS_MUST_MATCH_SEPARATE_CALLER_PINS','permission_denied')
        root=key_file(*root_input,'AUTHORITY_ROOT_'+slot,newpins,oldpaths,categories,seenkeys)
        witness=key_file(*origin_input,'ORIGIN_WITNESS_'+slot,newpins,oldpaths,categories,seenkeys)
        delegation_raw=load(entry['delegation_original'],'ROOT_DELEGATION',MAX_ORIGINAL,
                            newpins,oldpaths,categories,'delegation')
        delegate_sha=sha(delegation_raw)
        delegate,dstart,dend=validate_delegation(delegation_raw,root,slot,root_input[1],
                                                  psha,source_rows[slot])
        origin_raw=load(entry['origin_original'],'WITNESSED_ORIGIN',MAX_ORIGINAL,
                        newpins,oldpaths,categories,'origin')
        origin,ostart,oend=validate_origin(origin_raw,witness,slot,origin_input[1],
                    delegate_sha,root_input[1],delegate['authority_id'])
        need(type(entry['revocation_snapshot_originals']) is list and
             len(entry['revocation_snapshot_originals'])<=MAX_SNAPSHOTS,
             'REVOCATION_SNAPSHOTS_OVER_BOUND')
        records={};originals={delegate_sha:delegation_raw}
        for pin in entry['revocation_snapshot_originals']:
            snap_raw=load(pin,'REVOCATION_ORIGINAL',MAX_ORIGINAL,newpins,
                          oldpaths,categories,'revocation')
            digest=sha(snap_raw)
            need(digest not in records,'REPEATED_REVOCATION_ORIGINAL','permission_denied')
            records[digest]=validate_snapshot(snap_raw,root,slot,root_input[1],
                                             delegate_sha,delegate['authority_id'])
        history=snapshot_history(records,heads[slot],floors[slot],now,
                    source_rows[slot]['issuer_public_key_original_sha256'])
        if history['selected'] is not None:
            # Open the selected SHA-pinned original again, not a JSON reconstruction.
            selpin=next(p for p in entry['revocation_snapshot_originals']
                        if p['sha256']==heads[slot])
            originals[heads[slot]]=load(selpin,'SELECTED_REVOCATION_ORIGINAL',MAX_ORIGINAL,
                                         newpins,oldpaths,categories,'revocation')
        new_source_originals[slot]=originals
        authorized=(TARGET_SCOPE in delegate['authorized_scopes'] and
                    origin['claimed_jurisdiction'] in delegate['authorized_jurisdictions'])
        fresh=not utc_untrusted(now,dstart,dend,MAX_EVALUATION_LAG) and not utc_untrusted(
                         now,ostart,oend,MAX_EVALUATION_LAG)
        flags['excluded'] |= not authorized
        flags['revoked_or_coverage_gap'] |= (history['revoked'] or history['coverage_missing'])
        flags['fork_or_collision'] |= (history['fork'] or
                                      delegate['authority_id'] in seen_auth_ids)
        seen_auth_ids.add(delegate['authority_id'])
        flags['rollback'] |= history['rollback']
        flags['stale'] |= (not fresh or history['stale'])
        flags['missing'] |= history['missing']
        reviews.append({
            'slot':slot,'authority_id_as_root_signed_claim':delegate['authority_id'],
            'claimed_jurisdiction_as_witness_claim':origin['claimed_jurisdiction'],
            'origin_reference_id_unverified':origin['origin_reference_id'],
            'authority_root_public_key_sha256':root_input[1],
            'origin_witness_public_key_sha256':origin_input[1],
            'delegation_original_sha256':delegate_sha,
            'origin_original_sha256':sha(origin_raw),
            'parent_issuer_public_key_sha256':source_rows[slot]['issuer_public_key_original_sha256'],
            'signed_scope_and_jurisdiction_included':authorized,
            'visible_signed_revocation':history['revoked'],
            'signed_issuer_inventory_coverage_missing':history['coverage_missing'],
            'signed_snapshot_history_fork_or_revocation_conflict':history['fork'],
            'caller_saved_snapshot_rollback':history['rollback'],
            'signed_clock_anomaly':not fresh or history['stale'],
            'minimum_sequence_as_caller_pin':floors[slot],
            'selected_revocation_head_sha256':heads[slot],
            'selected_revocation_sequence':history['selected_sequence'],
            'observed_signed_snapshot_count':len(records),
            'observed_snapshot_endpoint_count':history['endpoints'],
            'directory_inclusion_valid':False,
            'unverified_authoritative_origin':True,
        })
    if len(seen_slots)!=2:flags['missing']=True
    directory_good=False;directory_sha=None;directory_tree_size=None
    if needs_dir:
        logkey=key_file(directory_public_key_file,expected_directory_public_key_sha256,
                        'DIRECTORY_LOG',newpins,oldpaths,categories,seenkeys)
        cpraw=load({'path':directory_checkpoint_file,'sha256':expected_directory_checkpoint_sha256},
                 'DIRECTORY_CHECKPOINT',MAX_ORIGINAL,newpins,oldpaths,categories,'checkpoint')
        cp,cp_stale=directory_checkpoint(cpraw,logkey,
                                      expected_directory_public_key_sha256,now)
        directory_sha=sha(cpraw);directory_tree_size=cp['tree_size']
        flags['stale'] |= cp_stale
        # Caller-retained immutable checkpoint hash + monotone minimum are
        # stronger local anti-rollback bounds than the bundle-selected head.
        if expected_directory_head_sha256 is None or minimum_directory_tree_size is None:
            flags['missing']=True
        else:
            flags['rollback'] |= (expected_directory_head_sha256!=directory_sha or
                                  cp['tree_size']<minimum_directory_tree_size)
        for entry in entries:
            slot=entry['slot']
            if len(new_source_originals[slot])!=2:
                continue
            valid=check_proofs(entry['directory_inclusions'],new_source_originals[slot],cp)
            if not valid:flags['directory_missing']=True
            next(r for r in reviews if r['slot']==slot)['directory_inclusion_valid']=valid
        directory_good=(len(reviews)==2 and all(r['directory_inclusion_valid'] for r in reviews))
        if not directory_good:flags['directory_missing']=True
    else:
        flags['directory_missing']=True
        # A bundle cannot claim directory publication without a signed checkpoint.
        for entry in entries:
            need(entry['directory_inclusions']==[],
                 'DIRECTORY_INCLUSION_WITHOUT_REAL_SIGNED_CHECKPOINT',
                 'permission_denied')
    # Second read of all original file bytes + path/inode/ancestor boundaries.
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    previous.parent.parent._late_identity_check(newpins,oldpaths)
    parent_good=(prior['two_issuer_signed_distributions_locally_match_ec358_owner'] is True and
                 prior['distribution_review_count']==2 and
                 all(row['outcome']==previous.OUTCOMES[-1]
                     for row in prior['channel_evidence']))
    sources_coherent=bool(parent_good and len(reviews)==2 and
             not any(flags[x] for x in ('missing','excluded','revoked_or_coverage_gap',
                                        'fork_or_collision','rollback','stale')))
    directory_coherent=bool(sources_coherent and directory_good and
                            not flags['directory_missing'])
    if not parent_good:outcome=OUTCOMES[0]
    elif flags['missing']:outcome=OUTCOMES[1]
    elif flags['excluded']:outcome=OUTCOMES[2]
    elif flags['revoked_or_coverage_gap']:outcome=OUTCOMES[3]
    elif flags['fork_or_collision']:outcome=OUTCOMES[4]
    elif flags['rollback']:outcome=OUTCOMES[5]
    elif flags['stale']:outcome=OUTCOMES[6]
    elif flags['directory_missing']:outcome=OUTCOMES[7]
    else:outcome=OUTCOMES[8]
    evidence=[{'tsa_channel_id':r['tsa_channel_id'],
               'parent_ec359_outcome':r['outcome'],'outcome':outcome}
               for r in prior['channel_evidence']]
    return {
       'schema':RESULT_SCHEMA,'command':'audit-authority-directory',
       'status':outcome+'_unresolved','exit_code':2,'case_id':prior['case_id'],
       'actual_ec359_through_ec337_signed_originals_replayed':True,
       'parent_ec359_canonical_result_sha256':psha,
       'authority_bundle_original_sha256':expected_authority_bundle_sha256,
       'authority_evaluation_utc_as_caller_claim':authority_evaluation_utc,
       'authority_reviews':reviews,'authority_review_count':len(reviews),
       'directory_checkpoint_original_sha256':directory_sha,
       'directory_tree_size_as_signed_claim':directory_tree_size,
       'external_authority_material_missing':flags['missing'],
       'valid_signatures_but_scope_jurisdiction_issuer_excluded':flags['excluded'],
       'signed_issuer_revocation_or_coverage_gap_visible':flags['revoked_or_coverage_gap'],
       'signed_revocation_fork_or_authority_identity_collision':flags['fork_or_collision'],
       'caller_pinned_revocation_or_directory_rollback':flags['rollback'],
       'signed_utc_claim_stale_or_future':flags['stale'],
       'independent_signed_directory_inclusion_missing_or_invalid':flags['directory_missing'],
       'two_sources_scope_and_revocation_locally_coherent':sources_coherent,
       'two_sources_directory_inclusion_locally_verified':directory_coherent,
       'official_trust_anchor_origin_legal_identity_trusted_time_and_global_revocation_unproven':True,
       'channel_evidence':evidence,
       'outcome_counts':{o:sum(r['outcome']==o for r in evidence) for o in OUTCOMES},
       'offline_unresolved_exit_code':2,
       **{k:False for k in NEGATIVES},
    }
