#!/usr/bin/env python3
"""EC316 two-role, externally pinned offline checkpoints of genuine EC315 replay.

One certificate per EC315 delivery prefix, signed by *two distinct public keys*
over the same domain-separated source commitment. All parent certificates have
independently pinned whole bytes and all of their original EC315/312 signatures
are replayed through the current ledger at every verification, not accepted
from old unsigned reports. A certificate is NOT a physical CAS commit or proof
that public keys are held by different people or that external pins are WORM.

The separate offline signer commands are deliberately NOT console privileges.
"""
from __future__ import annotations

import hmac
import os
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from receiver_ack import ack as receiver
from registrar_epochs import epochs
from delivery_ledger import ledger as ledger

CLAIM_SCHEMA = 'ces.ec316.dual_custodian_cas_checkpoint_claim.v1'
VOTE_SCHEMA = 'ces.ec316.dual_custodian_cas_checkpoint_vote.v1'
CERT_SCHEMA = 'ces.ec316.dual_custodian_cas_checkpoint_certificate.v1'
CHAIN_SCHEMA = 'ces.ec316.dual_custodian_cas_checkpoint_chain.v1'
RESULT_SCHEMA = 'ces.ec316.dual_custodian_cas_checkpoint_result.v1'
DENIAL_SCHEMA = 'ces.ec316.dual_custodian_cas_checkpoint_denial.v1'
MAX_DOCUMENT_BYTES = 25_000
MAX_CERTIFICATES = 4
ROLES = ('a', 'b')
DOMAIN = {
    'a': b'CES/EC316/SignedOriginalCheckpoint/CustodianA/v1\0',
    'b': b'CES/EC316/SignedOriginalCheckpoint/CustodianB/v1\0',
}
CLAIM_FIELDS = frozenset({
    'schema', 'sequence', 'cas_authority_id', 'cas_authority_public_hex',
    'cas_store_namespace_id', 'expected_registry_id',
    'custodian_a_id', 'custodian_a_public_hex',
    'custodian_b_id', 'custodian_b_public_hex',
    'ledger_outer_manifest_raw_sha256', 'delivery_original_raw_sha256',
    'verified_originals_commitment_sha256', 'bounded_candidate_sha256',
    'previous_certificate_original_raw_sha256',
    'previous_delivery_original_raw_sha256',
    'previous_verified_originals_commitment_sha256',
    'external_unique_challenge_sha256',
})
TRUST_FIELDS = frozenset({
    'custodian_a_id', 'custodian_a_public_hex',
    'custodian_b_id', 'custodian_b_public_hex',
})
VOTE_FIELDS = frozenset({
    'schema', 'role', 'claim_original_raw_sha256',
    'custodian_id', 'custodian_public_hex', 'signature_ed25519',
})
CERT_FIELDS = frozenset({'schema', 'claim', 'votes'})
CHAIN_FIELDS = frozenset({'schema', 'ledger_manifest_file',
                          'expected_ledger_manifest_sha256', 'certificates'})
REF_FIELDS = frozenset({'sequence', 'certificate_file',
                        'expected_certificate_sha256', 'ledger_manifest_file',
                        'expected_ledger_manifest_sha256'})


def need(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise a.AnchorError('EC316_' + reason, status)


def _sha(value: Any) -> bool:
    return (type(value) is str and b.HEX64.fullmatch(value) is not None and
            value != '0' * 64)


def _id(value: Any) -> bool:
    return type(value) is str and receiver.ID.fullmatch(value) is not None


def _trust(trust: dict, *, authority: str | None = None) -> dict:
    a.exact(trust, TRUST_FIELDS, 'EC316_EXACT_EXTERNAL_TWO_CUSTODIAN_TRUST_REQUIRED')
    keys = [trust['custodian_' + role + '_public_hex'] for role in ROLES]
    identities = [trust['custodian_' + role + '_id'] for role in ROLES]
    need(all(_id(identity) for identity in identities) and len(set(identities)) == 2,
         'CUSTODIAN_IDS_MUST_BE_VALID_AND_DISTINCT', 'invalid_input')
    need(all(a.valid_pub(key) for key in keys) and len(set(keys)) == 2,
         'TWO_DIFFERENT_VALID_ED25519_CUSTODIAN_PUBLIC_KEYS_REQUIRED', 'invalid_input')
    if authority is not None:
        need(authority not in keys,
             'CUSTODIANS_CANNOT_REUSE_KNOWN_CAS_AUTHORITY_SIGNING_KEY')
    return trust


def _ref(path: str, sha: str, label: str) -> None:
    need(ledger.mesh._path(path) and _sha(sha),
         label + '_PRIVATE_ABSOLUTE_PATH_AND_EXTERNAL_RAW_SHA_REQUIRED', 'invalid_input')


def _read(path: str, sha: str) -> dict:
    _ref(path, sha, 'DOCUMENT')
    doc = epochs._owner_private_read(path, sha)
    need(len(b.canonical(doc)) <= MAX_DOCUMENT_BYTES,
         'DOCUMENT_EXCEEDS_BOUND', 'invalid_input')
    return doc


def _read_unpinned_vote(path: str) -> dict:
    # The only unpinned input is a signed vote whose key, exact claim SHA and
    # Ed25519 signature must be checked. It is not allowed to read arbitrary
    # files or follow links just because the vote itself is not SHA-pinned.
    target = b._private_parent(path)
    before = os.lstat(target)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'VOTE_OWNER_0600_SINGLE_REGULAR_LINK_REQUIRED')
    raw = io._open_regular(path, MAX_DOCUMENT_BYTES, private=True)
    after = os.lstat(target)
    need(tuple(getattr(before, k) for k in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')) ==
         tuple(getattr(after, k) for k in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
         'VOTE_CHANGED_DURING_READ', 'unavailable')
    doc = io.parse(raw, MAX_DOCUMENT_BYTES)
    need(hmac.compare_digest(raw, b.canonical(doc)), 'VOTE_NOT_CANONICAL_LF_JSON')
    return doc


def _chain_structure(doc: dict) -> list[dict]:
    a.exact(doc, CHAIN_FIELDS, 'EC316_CHAIN_FIELDS_INVALID')
    need(doc['schema'] == CHAIN_SCHEMA, 'CHAIN_SCHEMA_INVALID', 'invalid_input')
    _ref(doc['ledger_manifest_file'], doc['expected_ledger_manifest_sha256'],
         'CHAIN_LEDGER')
    entries = doc['certificates']
    need(type(entries) is list and 1 <= len(entries) <= MAX_CERTIFICATES,
         'CHAIN_MUST_HAVE_ONE_TO_FOUR_CERTIFICATES', 'invalid_input')
    seen = set()
    for number, entry in enumerate(entries, 1):
        a.exact(entry, REF_FIELDS, 'EC316_CHAIN_CERTIFICATE_REFERENCE_FIELDS_INVALID')
        need(type(entry['sequence']) is int and entry['sequence'] == number,
             'CHAIN_SEQUENCE_MUST_BE_CONTIGUOUS_FROM_ONE', 'invalid_input')
        _ref(entry['certificate_file'], entry['expected_certificate_sha256'],
             'CHAIN_CERTIFICATE')
        _ref(entry['ledger_manifest_file'], entry['expected_ledger_manifest_sha256'],
             'HISTORICAL_ORIGINAL_LEDGER')
        need(entry['expected_certificate_sha256'] not in seen,
             'DUPLICATE_CERTIFICATE_WHOLE_RAW_SHA', 'invalid_input')
        seen.add(entry['expected_certificate_sha256'])
    return entries


def _claim_structure(claim: dict, trust: dict) -> None:
    a.exact(claim, CLAIM_FIELDS, 'EC316_CHECKPOINT_CLAIM_FIELDS_INVALID')
    need(claim['schema'] == CLAIM_SCHEMA, 'CLAIM_SCHEMA_INVALID', 'invalid_input')
    need(type(claim['sequence']) is int and
         1 <= claim['sequence'] <= MAX_CERTIFICATES,
         'CLAIM_SEQUENCE_INVALID', 'invalid_input')
    need(all(claim[k] == v for k, v in trust.items()),
         'SIGNED_CUSTODIAN_TRUST_DIFFERS_FROM_EXTERNAL_PINS')
    need(_id(claim['cas_authority_id']) and
         a.valid_pub(claim['cas_authority_public_hex']) and
         _id(claim['cas_store_namespace_id']) and
         _id(claim['expected_registry_id']),
         'SIGNED_CAS_IDENTITY_INVALID', 'invalid_input')
    _trust(trust, authority=claim['cas_authority_public_hex'])
    need(all(_sha(claim[key]) for key in (
         'ledger_outer_manifest_raw_sha256', 'delivery_original_raw_sha256',
         'verified_originals_commitment_sha256', 'bounded_candidate_sha256',
         'external_unique_challenge_sha256')),
         'EXACT_NONZERO_SHA_COMMITMENTS_REQUIRED', 'invalid_input')
    prev = ('previous_certificate_original_raw_sha256',
            'previous_delivery_original_raw_sha256',
            'previous_verified_originals_commitment_sha256')
    if claim['sequence'] == 1:
        need(all(claim[k] == 'GENESIS' for k in prev),
             'GENESIS_REQUIRES_THREE_EXPLICIT_GENESIS_PREDECESSORS')
    else:
        need(all(_sha(claim[k]) for k in prev),
             'APPEND_REQUIRES_THREE_PREDECESSOR_SHA_PINS')


def _vote_check(vote: dict, role: str, claim: dict, trust: dict) -> None:
    a.exact(vote, VOTE_FIELDS, 'EC316_SIGNED_VOTE_FIELDS_INVALID')
    need(vote['schema'] == VOTE_SCHEMA and vote['role'] == role,
         'VOTE_SCHEMA_OR_ROLE_INVALID')
    need(vote['custodian_id'] == trust['custodian_' + role + '_id'] and
         vote['custodian_public_hex'] == trust['custodian_' + role + '_public_hex'] and
         vote['claim_original_raw_sha256'] == b.digest(b.canonical(claim)),
         'SIGNER_OR_CLAIM_PIN_NOT_EQUAL_EXTERNALLY_FROZEN_CLAIM')
    signature = vote['signature_ed25519']
    need(type(signature) is str and a.SIG.fullmatch(signature) is not None,
         'SIGNATURE_NOT_64_BYTE_LOWERCASE_HEX')
    try:
        io.pub_from_hex(trust['custodian_' + role + '_public_hex']).verify(
            bytes.fromhex(signature), DOMAIN[role] + a.canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise a.AnchorError('EC316_INDEPENDENT_CUSTODIAN_' + role.upper() +
                            '_ED25519_SIGNATURE_INVALID') from exc


def _certificate_check(doc: dict, trust: dict) -> dict:
    a.exact(doc, CERT_FIELDS, 'EC316_CERTIFICATE_FIELDS_INVALID')
    need(doc['schema'] == CERT_SCHEMA, 'CERTIFICATE_SCHEMA_INVALID', 'invalid_input')
    claim = doc['claim']
    _claim_structure(claim, trust)
    votes = a.exact(doc['votes'], set(ROLES), 'EC316_EXACTLY_TWO_CUSTODIAN_VOTES_REQUIRED')
    for role in ROLES:
        _vote_check(votes[role], role, claim, trust)
    return claim


def _replay(ledger_file: str, ledger_sha: str, previous_claim: dict | None) -> dict:
    _ref(ledger_file, ledger_sha, 'LATEST_LEDGER')
    options = {}
    if previous_claim is not None:
        options = {'expected_prior_delivery_sha256':
                       previous_claim['delivery_original_raw_sha256'],
                   'expected_prior_originals_commitment_sha256':
                       previous_claim['verified_originals_commitment_sha256']}
    report = ledger.evaluate(manifest_file=ledger_file,
                             expected_manifest_sha256=ledger_sha, **options)
    need(report['exit_code'] == 0 and report['status'] == ledger.SUCCESS and
         report['first_failing_append_prefix_sequence'] is None,
         'CONFLICTING_OR_DISCONNECTED_SIGNED_ORIGINALS_MUST_NOT_BE_CERTIFIED')
    need(report['bounded_candidate_only_if_every_prefix_valid'] is not None,
         'NO_FULLY_REPLAYED_BOUNDED_SIGNED_CANDIDATE')
    return report


def _verify_doc_chain(doc: dict, trust: dict, ledger_file: str,
                      ledger_sha: str, *, latest_external_pin: str,
                      expected_latest_challenge_sha256: str | None = None) -> dict:
    entries = _chain_structure(doc)
    need(doc['ledger_manifest_file'] == ledger_file and
         doc['expected_ledger_manifest_sha256'] == ledger_sha,
         'CHAIN_LATEST_LEDGER_LOCATION_AND_RAW_SHA_NOT_EQUAL_CALLER_PINS')
    need(entries[-1]['expected_certificate_sha256'] == latest_external_pin,
         'LATEST_CERTIFICATE_NOT_EQUAL_INDEPENDENT_OFF_CHAIN_RAW_SHA_PIN')
    previous_sha = 'GENESIS'
    previous: dict | None = None
    claims: list[dict] = []
    seen_challenges = set()
    final_report = None
    for entry in entries:
        cert = _read(entry['certificate_file'], entry['expected_certificate_sha256'])
        claim = _certificate_check(cert, trust)
        need(claim['sequence'] == entry['sequence'] and
             claim['previous_certificate_original_raw_sha256'] == previous_sha,
             'SIGNED_CHECKPOINT_SEQUENCE_OR_PARENT_CERTIFICATE_SHA_BROKEN')
        need(claim['external_unique_challenge_sha256'] not in seen_challenges,
             'SIGNED_CHECKPOINT_CHALLENGE_REUSED_IN_HISTORY')
        seen_challenges.add(claim['external_unique_challenge_sha256'])
        if previous is not None:
            need(claim['previous_delivery_original_raw_sha256'] ==
                 previous['delivery_original_raw_sha256'] and
                 claim['previous_verified_originals_commitment_sha256'] ==
                 previous['verified_originals_commitment_sha256'],
                 'SIGNED_CHECKPOINT_PREVIOUS_TIP_OR_SOURCE_PREFIX_BROKEN')
            for field in ('cas_authority_id', 'cas_authority_public_hex',
                          'cas_store_namespace_id', 'expected_registry_id'):
                need(claim[field] == previous[field],
                     'SIGNED_CAS_AUTHORITY_OR_NAMESPACE_CHANGED_IN_HISTORY')
        # Important: don't trust a signed *claim* about an old candidate.
        # Pin and re-open EACH original EC315 historical root, then replay its
        # own EC312->294 genuine signed originals and compare its *own* bounded
        # candidate, not merely the latest manifest's cumulative commitment.
        need(claim['ledger_outer_manifest_raw_sha256'] ==
             entry['expected_ledger_manifest_sha256'],
             'CERTIFICATE_ORIGINAL_LEDGER_SHA_NOT_EQUAL_PINNED_HISTORY')
        report = _replay(entry['ledger_manifest_file'],
                         entry['expected_ledger_manifest_sha256'], previous)
        need(report['delivery_count'] == claim['sequence'] and
             report['checkpoint_tip_delivery_original_raw_sha256'] ==
                 claim['delivery_original_raw_sha256'] and
             report['checkpoint_cumulative_replayed_originals_commitment_sha256'] ==
                 claim['verified_originals_commitment_sha256'] and
             report['bounded_candidate_only_if_every_prefix_valid'] ==
                 claim['bounded_candidate_sha256'],
             'SIGNED_CHECKPOINT_NOT_EQUAL_ITS_OWN_FRESH_FULL_ORIGINAL_REPLAY')
        for field in ('cas_authority_id', 'cas_authority_public_hex',
                      'cas_store_namespace_id', 'expected_registry_id'):
            need(claim[field] == report[field],
                 'SIGNED_CAS_IDENTITY_NOT_EQUAL_ITS_OWN_VERIFIED_LEDGER')
        previous, previous_sha = claim, entry['expected_certificate_sha256']
        claims.append(claim)
        final_report = report
    if expected_latest_challenge_sha256 is not None:
        need(_sha(expected_latest_challenge_sha256),
             'VALID_EXTERNALLY_FROZEN_LATEST_CHALLENGE_REQUIRED', 'invalid_input')
        need(claims[-1]['external_unique_challenge_sha256'] ==
             expected_latest_challenge_sha256,
             'SIGNED_LATEST_CHALLENGE_NOT_EQUAL_INDEPENDENT_EXTERNAL_PIN')
    need(entries[-1]['ledger_manifest_file'] == ledger_file and
         entries[-1]['expected_ledger_manifest_sha256'] == ledger_sha,
         'LATEST_CERTIFICATE_ORIGINAL_LEDGER_SOURCE_NOT_EQUAL_CALLER_PIN')
    report = final_report
    # Every old signed candidate was recomputed against its own pinned original
    # ledger manifest, not inferred from a later unrelated final graph.
    return {
        'status': 'two_offline_custodian_signatures_and_all_original_prefixes_verified',
        'exit_code': 0,
        'checkpoint_count': len(claims),
        'latest_certificate_original_raw_sha256': previous_sha,
        'latest_delivery_original_raw_sha256':
            report['checkpoint_tip_delivery_original_raw_sha256'],
        'latest_verified_originals_commitment_sha256':
            report['checkpoint_cumulative_replayed_originals_commitment_sha256'],
        'latest_bounded_candidate_sha256':
            report['bounded_candidate_only_if_every_prefix_valid'],
        'all_ec315_prefixes_and_ec312_to_ec294_originals_replayed': True,
        'independent_external_public_key_pins_supplied': True,
        'off_chain_latest_certificate_sha_pin_compared': True,
        'actual_separate_human_custody_or_public_key_authority_proven': False,
        'actual_external_worm_anchor_or_linearizable_cas_latest_proven': False,
        'business_or_external_store_write_performed': False,
    }


def verify(*, chain_file: str, expected_chain_sha256: str,
           ledger_manifest_file: str, expected_ledger_manifest_sha256: str,
           trust: dict, expected_latest_certificate_sha256: str,
           expected_latest_challenge_sha256: str | None = None) -> dict:
    _trust(trust)
    need(_sha(expected_latest_certificate_sha256),
         'INDEPENDENT_LATEST_CERTIFICATE_SHA_REQUIRED', 'invalid_input')
    doc = _read(chain_file, expected_chain_sha256)
    result = _verify_doc_chain(doc, trust, ledger_manifest_file,
                               expected_ledger_manifest_sha256,
                               latest_external_pin=expected_latest_certificate_sha256,
                               expected_latest_challenge_sha256=
                                   expected_latest_challenge_sha256)
    result['chain_original_raw_sha256'] = expected_chain_sha256
    result['latest_ledger_original_raw_sha256'] = expected_ledger_manifest_sha256
    return result


def _create_claim(*, ledger_manifest_file: str,
                  expected_ledger_manifest_sha256: str, trust: dict,
                  external_unique_challenge_sha256: str,
                  prior_chain_file: str | None,
                  expected_prior_chain_sha256: str | None,
                  expected_prior_certificate_sha256: str) -> dict:
    _trust(trust)
    need(_sha(external_unique_challenge_sha256),
         'FRESH_EXTERNAL_CHALLENGE_SHA_REQUIRED', 'invalid_input')
    previous = None
    if expected_prior_certificate_sha256 == 'GENESIS':
        need(prior_chain_file is None and expected_prior_chain_sha256 is None,
             'GENESIS_MUST_NOT_SUPPLY_PRIOR_CHAIN', 'invalid_input')
    else:
        need(_sha(expected_prior_certificate_sha256) and
             prior_chain_file is not None and
             _sha(expected_prior_chain_sha256),
             'APPEND_REQUIRES_INDEPENDENT_PREVIOUS_CERT_AND_CHAIN_PINS',
             'invalid_input')
        prior = _read(prior_chain_file, expected_prior_chain_sha256)
        refs = _chain_structure(prior)
        need(refs[-1]['expected_certificate_sha256'] ==
             expected_prior_certificate_sha256,
             'EXTERNAL_PREVIOUS_CERTIFICATE_SHA_DIFFERS_FROM_PRIOR_CHAIN')
        # The old chain is not consumed as a trusted PASS report: verify both
        # Ed25519 signatures for every old cert plus OLD genuine EC315 originals.
        _verify_doc_chain(prior, trust, prior['ledger_manifest_file'],
                          prior['expected_ledger_manifest_sha256'],
                          latest_external_pin=expected_prior_certificate_sha256)
        prev_cert = _read(refs[-1]['certificate_file'],
                          refs[-1]['expected_certificate_sha256'])
        previous = _certificate_check(prev_cert, trust)
    report = _replay(ledger_manifest_file, expected_ledger_manifest_sha256, previous)
    seq = report['delivery_count']
    need(seq == (1 if previous is None else previous['sequence'] + 1),
         'NEW_LEDGER_MUST_APPEND_EXACTLY_ONE_SIGNED_CERTIFICATE_PREFIX')
    if previous is not None:
        before = report['each_append_prefix_full_original_signed_replay'][-2]
        need(before['delivery_original_raw_sha256'] ==
             previous['delivery_original_raw_sha256'] and
             before['cumulative_replayed_originals_commitment_sha256'] ==
             previous['verified_originals_commitment_sha256'],
             'PRIOR_SIGNED_SOURCE_PREFIX_CHANGED_IN_NEW_LEDGER')
        need(previous['external_unique_challenge_sha256'] !=
             external_unique_challenge_sha256,
             'NEW_CHALLENGE_REUSES_PREVIOUS')
        for field in ('cas_authority_id', 'cas_authority_public_hex',
                      'cas_store_namespace_id', 'expected_registry_id'):
            need(report[field] == previous[field],
                 'NEW_SIGNED_CAS_IDENTITY_MISMATCHES_OLD_CERTIFICATE')
        # Earlier challenges are also rejected in _verify_doc_chain. Require
        # distinct challenge from ALL ancestors, not only the latest one.
        for ref in refs:
            past = _read(ref['certificate_file'], ref['expected_certificate_sha256'])
            need(past['claim']['external_unique_challenge_sha256'] !=
                 external_unique_challenge_sha256,
                 'NEW_CHALLENGE_REUSES_AN_OLDER_SIGNED_CHECKPOINT')
    _trust(trust, authority=report['cas_authority_public_hex'])
    return {
        'schema': CLAIM_SCHEMA,
        'sequence': seq,
        'cas_authority_id': report['cas_authority_id'],
        'cas_authority_public_hex': report['cas_authority_public_hex'],
        'cas_store_namespace_id': report['cas_store_namespace_id'],
        'expected_registry_id': report['expected_registry_id'],
        **trust,
        'ledger_outer_manifest_raw_sha256': expected_ledger_manifest_sha256,
        'delivery_original_raw_sha256':
            report['checkpoint_tip_delivery_original_raw_sha256'],
        'verified_originals_commitment_sha256':
            report['checkpoint_cumulative_replayed_originals_commitment_sha256'],
        'bounded_candidate_sha256':
            report['bounded_candidate_only_if_every_prefix_valid'],
        'previous_certificate_original_raw_sha256': (
            expected_prior_certificate_sha256),
        'previous_delivery_original_raw_sha256': (
            'GENESIS' if previous is None else
            previous['delivery_original_raw_sha256']),
        'previous_verified_originals_commitment_sha256': (
            'GENESIS' if previous is None else
            previous['verified_originals_commitment_sha256']),
        'external_unique_challenge_sha256': external_unique_challenge_sha256,
    }


def _intended_claim(claim_file: str, expected_claim_sha256: str,
                   context: dict) -> dict:
    saved = _read(claim_file, expected_claim_sha256)
    _claim_structure(saved, context['trust'])
    generated = _create_claim(**context)
    need(saved == generated and
         expected_claim_sha256 == b.digest(b.canonical(generated)),
         'PREPARED_CLAIM_DIFFERS_FROM_CURRENT_FULL_SIGNED_ORIGINAL_REPLAY')
    return saved


def prepare(*, out: str, **context: Any) -> dict:
    claim = _create_claim(**context)
    store.store(out, claim, MAX_DOCUMENT_BYTES)
    return {
        'status': 'checkpoint_claim_prepared_after_all_genuine_origins_replayed',
        'exit_code': 0, 'sequence': claim['sequence'],
        'claim_raw_sha256': b.digest(b.canonical(claim)),
        'delivery_original_raw_sha256': claim['delivery_original_raw_sha256'],
        'verified_originals_commitment_sha256':
            claim['verified_originals_commitment_sha256'],
    }


def sign(*, claim_file: str, expected_claim_sha256: str,
         role: str, private_key_file: str, out: str, **context: Any) -> dict:
    need(role in ROLES, 'ONLY_TWO_FIXED_CUSTODIAN_ROLES_ALLOWED', 'invalid_input')
    claim = _intended_claim(claim_file, expected_claim_sha256, context)
    key = io.private_from_file(private_key_file)
    public_hex = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    need(public_hex == context['trust']['custodian_' + role + '_public_hex'],
         'PRIVATE_KEY_DOES_NOT_MATCH_EXTERNALLY_PINNED_ROLE')
    vote = {
        'schema': VOTE_SCHEMA,
        'role': role,
        'claim_original_raw_sha256': expected_claim_sha256,
        'custodian_id': context['trust']['custodian_' + role + '_id'],
        'custodian_public_hex': public_hex,
        'signature_ed25519': key.sign(DOMAIN[role] + a.canonical(claim)).hex(),
    }
    _vote_check(vote, role, claim, context['trust'])
    store.store(out, vote, MAX_DOCUMENT_BYTES)
    return {'status': 'one_offline_role_signed_after_fresh_original_replay',
            'exit_code': 0, 'role': role,
            'claim_raw_sha256': expected_claim_sha256,
            'vote_raw_sha256': b.digest(b.canonical(vote))}


def assemble(*, claim_file: str, expected_claim_sha256: str,
             custodian_a_vote_file: str, custodian_b_vote_file: str,
             out: str, **context: Any) -> dict:
    claim = _intended_claim(claim_file, expected_claim_sha256, context)
    votes = {role: _read_unpinned_vote(file) for role, file in (
        ('a', custodian_a_vote_file), ('b', custodian_b_vote_file))}
    cert = {'schema': CERT_SCHEMA, 'claim': claim, 'votes': votes}
    _certificate_check(cert, context['trust'])
    store.store(out, cert, MAX_DOCUMENT_BYTES)
    return {
        'status': 'two_distinct_signed_roles_assembled_after_fresh_origin_replay',
        'exit_code': 0, 'sequence': claim['sequence'],
        'certificate_raw_sha256': b.digest(b.canonical(cert)),
        'claim_raw_sha256': expected_claim_sha256,
    }


def seal_chain(*, certificate_file: str, expected_certificate_sha256: str,
               out: str, **context: Any) -> dict:
    cert = _read(certificate_file, expected_certificate_sha256)
    claim = _certificate_check(cert, context['trust'])
    current = _create_claim(**context)
    need(claim == current,
         'NEW_DOUBLE_SIGNED_CERTIFICATE_NOT_EQUAL_LATEST_REPLAYED_ORIGINALS')
    existing = []
    if context['prior_chain_file'] is not None:
        previous = _read(context['prior_chain_file'],
                         context['expected_prior_chain_sha256'])
        existing = _chain_structure(previous)
    refs = [*existing, {
        'sequence': claim['sequence'],
        'certificate_file': certificate_file,
        'expected_certificate_sha256': expected_certificate_sha256,
        'ledger_manifest_file': context['ledger_manifest_file'],
        'expected_ledger_manifest_sha256':
            context['expected_ledger_manifest_sha256'],
    }]
    doc = {
        'schema': CHAIN_SCHEMA,
        'ledger_manifest_file': context['ledger_manifest_file'],
        'expected_ledger_manifest_sha256':
            context['expected_ledger_manifest_sha256'],
        'certificates': refs,
    }
    _verify_doc_chain(doc, context['trust'], context['ledger_manifest_file'],
                      context['expected_ledger_manifest_sha256'],
                      latest_external_pin=expected_certificate_sha256,
                      expected_latest_challenge_sha256=
                          context['external_unique_challenge_sha256'])
    store.store(out, doc, MAX_DOCUMENT_BYTES)
    return {
        'status': 'full_dual_signed_certificate_chain_sealed_with_all_prefix_replay',
        'exit_code': 0, 'checkpoint_count': len(refs),
        'chain_raw_sha256': b.digest(b.canonical(doc)),
        'latest_certificate_raw_sha256': expected_certificate_sha256,
    }
