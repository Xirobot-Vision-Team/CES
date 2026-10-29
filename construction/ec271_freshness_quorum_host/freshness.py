#!/usr/bin/env python3
"""EC271: short-lived, two-independent-witness, chained governance seals.

This is a signature and local admission protocol. The witness times are signed
claims, NOT a remote trusted clock or a cross-reboot nonrollbackable store.
Private witness signing keys are used only in offline command paths.
"""
from __future__ import annotations

import hmac
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec263_offline_anchor_host import checkpoint as cp
from ec266_source_provenance_host import provenance as prov
from ec268_root_handover_host import handover as rot
from ec269_emergency_recovery_host import recovery as rec
from ec270_recovery_closure_host import closure as rat

SCHEMA = 'ces.ec271.two_of_three_fresh_governance_seal.v1'
CHAIN_SCHEMA = 'ces.ec271.signed_freshness_chain.v1'
PURPOSE = 'INDEPENDENT_SHORT_LIVED_RECOVERY_GOVERNANCE_FRESHNESS'
DOMAIN = b'CES/EC271/two-of-three-freshness/v1\x00'
ZERO = '0' * 64
MAX_LIFETIME = 900
MAX_WITNESS_SPAN = 120
MAX_CHAIN = 256
MAX_RECEIPT = 4096
MAX_CONFIG = 65536
FIELDS = frozenset({
    'schema', 'purpose', 'closure_sha256', 'governance_sha256',
    'governance_epoch', 'recovered_root_public_sha256',
    'sequence', 'previous_receipt_sha256', 'not_before_unix',
    'expires_at_unix', 'witness_public_sha256', 'nonce',
})
APPROVAL = frozenset({'public_sha256', 'observed_at_unix', 'signature_ed25519'})
ENTRY = frozenset({'receipt_path', 'receipt_sha256'})


class FreshnessError(rat.ClosureError):
    """A fixed-denial exception without source bytes or secret information."""


def deny(reason: str) -> None:
    raise FreshnessError(reason)


def _fields(doc: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if type(doc) is not dict or doc.get('schema') != SCHEMA or set(doc) not in (
            FIELDS, FIELDS | {'approvals'}):
        deny('EC271_RECEIPT_SCHEMA_INVALID')
    if doc['purpose'] != PURPOSE:
        deny('EC271_RECEIPT_PURPOSE_INVALID')
    for field in ('closure_sha256', 'governance_sha256',
                  'recovered_root_public_sha256', 'previous_receipt_sha256'):
        rec._sha(doc[field])
    epoch = rec._integer(doc['governance_epoch'], 2, 2**31-1, 'EC271_EPOCH_INVALID')
    seq = rec._integer(doc['sequence'], 1, 2**31-1, 'EC271_SEQUENCE_INVALID')
    if (seq == 1) != (doc['previous_receipt_sha256'] == ZERO):
        deny('EC271_GENESIS_OR_PREDECESSOR_INVALID')
    start = rec._integer(doc['not_before_unix'], 1, 2**40, 'EC271_WINDOW_INVALID')
    stop = rec._integer(doc['expires_at_unix'], 1, 2**40, 'EC271_WINDOW_INVALID')
    if stop <= start or stop - start > MAX_LIFETIME:
        deny('EC271_WINDOW_TOO_LONG_OR_REVERSED')
    pins = doc['witness_public_sha256']
    if (type(pins) is not list or len(pins) != 3 or
            any(type(v) is not str or cp.SHA_RE.fullmatch(v) is None for v in pins) or
            pins != sorted(set(pins))):
        deny('EC271_EXACTLY_THREE_DISTINCT_WITNESSES_REQUIRED')
    if type(doc['nonce']) is not str or cp.NONCE_RE.fullmatch(doc['nonce']) is None:
        deny('EC271_NONCE_INVALID')
    votes = doc.get('approvals', [])
    if 'approvals' in doc and (type(votes) is not list or not 1 <= len(votes) <= 2):
        deny('EC271_APPROVALS_INVALID')
    observed = []
    voters = []
    for v in votes:
        if (type(v) is not dict or set(v) != APPROVAL or
                type(v['public_sha256']) is not str or
                cp.SHA_RE.fullmatch(v['public_sha256']) is None or
                type(v['signature_ed25519']) is not str or
                prov.SIGNATURE_RE.fullmatch(v['signature_ed25519']) is None):
            deny('EC271_APPROVAL_FIELDS_INVALID')
        ts = rec._integer(v['observed_at_unix'], 1, 2**40,
                          'EC271_WITNESS_OBSERVATION_INVALID')
        if not start <= ts < stop:
            deny('EC271_WITNESS_TIME_OUTSIDE_SEAL_WINDOW')
        observed.append(ts)
        voters.append(v['public_sha256'])
    if (voters != sorted(set(voters)) or any(pin not in pins for pin in voters)):
        deny('EC271_WITNESSES_DUPLICATE_OUT_OF_ORDER_OR_UNKNOWN')
    if observed and (observed != sorted(observed) or
                     observed[-1] - observed[0] > MAX_WITNESS_SPAN):
        deny('EC271_WITNESS_OBSERVATIONS_TOO_FAR_APART')
    return {k: doc[k] for k in FIELDS}, votes


def _witness_keys(witness_public_keys: tuple[tuple[str, str], ...] | list[tuple[str, str]],
                  forbidden_signers: tuple[str, ...] = ()) -> dict[str, bytes]:
    if type(witness_public_keys) not in (tuple, list) or len(witness_public_keys) != 3:
        deny('EC271_THREE_PINNED_WITNESS_PUBLIC_KEYS_REQUIRED')
    result: dict[str, bytes] = {}
    paths = set()
    excluded = set(map(rec._sha, forbidden_signers))
    for path, sha in witness_public_keys:
        sha = rec._sha(sha)
        normalized = prov._path(path)
        if sha in excluded or sha in result or normalized in paths:
            deny('EC271_WITNESS_REUSED_OR_FORBIDDEN')
        paths.add(normalized)
        result[sha] = rec._public(normalized, sha)
    return result


def _signature_message(core: dict, prior: list[dict], pin: str, observed: int) -> bytes:
    # Each signer commits to the FULL preceding signature stage, in order.
    return DOMAIN + prov._canonical({
        'claim': core, 'prior_approvals': prior,
        'signer_public_sha256': pin, 'observed_at_unix': observed,
    })


def _votes(doc: dict[str, Any], keys: dict[str, bytes], require_quorum: bool) -> tuple[dict, list]:
    core, votes = _fields(doc)
    if core['witness_public_sha256'] != sorted(keys):
        deny('EC271_WITNESS_ROSTER_MISMATCH')
    if require_quorum and len(votes) != 2:
        deny('EC271_TWO_INDEPENDENT_SIGNATURES_REQUIRED')
    for i, vote in enumerate(votes):
        rec._signature(keys[vote['public_sha256']],
                       _signature_message(core, votes[:i], vote['public_sha256'],
                                          vote['observed_at_unix']),
                       vote['signature_ed25519'], 'EC271_WITNESS_SIGNATURE_INVALID')
    return core, votes


def _read_verified(path: str, sha: str, keys: dict[str, bytes],
                   *, complete: bool = True) -> tuple[dict, str]:
    raw, doc = rec._read(path, MAX_RECEIPT)
    rec._check_pin(raw, sha, 'EC271_RECEIPT_SHA256_PIN_MISMATCH')
    _votes(doc, keys, complete)
    return doc, prov._digest(raw)


def _chain_entries(path: str, sha: str) -> list[dict[str, str]]:
    raw, obj = rec._read(path, MAX_CONFIG)
    rec._check_pin(raw, sha, 'EC271_CHAIN_CONFIG_SHA256_PIN_MISMATCH')
    if (type(obj) is not dict or set(obj) != {'schema', 'entries'} or
            obj['schema'] != CHAIN_SCHEMA or type(obj['entries']) is not list or
            not 1 <= len(obj['entries']) <= MAX_CHAIN):
        deny('EC271_CHAIN_CONFIG_INVALID')
    paths: set[str] = set()
    entries = []
    for entry in obj['entries']:
        if type(entry) is not dict or set(entry) != ENTRY:
            deny('EC271_CHAIN_ENTRY_INVALID')
        path_name = prov._path(entry['receipt_path'])
        sha_pin = rec._sha(entry['receipt_sha256'])
        if path_name in paths:
            deny('EC271_CHAIN_DUPLICATE_RECEIPT_PATH')
        paths.add(path_name)
        entries.append({'receipt_path': path_name, 'receipt_sha256': sha_pin})
    return entries


def _prior(doc: dict[str, Any], previous: dict[str, Any] | None, previous_pin: str) -> None:
    if previous is None:
        if doc['sequence'] != 1 or doc['previous_receipt_sha256'] != ZERO:
            deny('EC271_GENESIS_PREDECESSOR_REQUIRED')
        return
    if (doc['sequence'] != previous['sequence'] + 1 or
            doc['previous_receipt_sha256'] != previous_pin or
            doc['closure_sha256'] != previous['closure_sha256'] or
            doc['recovered_root_public_sha256'] != previous['recovered_root_public_sha256'] or
            doc['witness_public_sha256'] != previous['witness_public_sha256']):
        deny('EC271_SIGNED_CHAIN_PREDECESSOR_INVALID')
    if doc['governance_epoch'] == previous['governance_epoch']:
        if doc['governance_sha256'] != previous['governance_sha256']:
            deny('EC271_SAME_EPOCH_GOVERNANCE_DRIFT')
    elif doc['governance_epoch'] != previous['governance_epoch'] + 1:
        deny('EC271_GOVERNANCE_EPOCH_GAP_OR_REWIND')
    if (doc['not_before_unix'] < previous['not_before_unix'] or
            doc['not_before_unix'] < previous['approvals'][-1]['observed_at_unix']):
        deny('EC271_FRESHNESS_TIME_REWIND')


def _authority(*, historic: dict[str, Any],
               governance_policy: str, governance_policy_sha256: str,
               continuation_chain: str | None, continuation_chain_sha256: str | None,
               witness_public_keys: tuple[tuple[str, str], ...],
               forbidden_signers: tuple[str, ...]) -> tuple[dict, dict[str, bytes]]:
    """Every signer revalidates EC270 historic closure and full signed governance."""
    closure = rat.verify_closure(**historic)
    root_bytes = rec._public(historic['recovered_root_public'],
                             historic['recovered_root_public_sha256'])
    anchor = rot._signed_governance(historic['anchor_governance'],
                                    historic['anchor_governance_sha256'], root_bytes)
    if (continuation_chain is None) != (continuation_chain_sha256 is None):
        deny('EC271_CONTINUATION_PIN_PAIR_REQUIRED')
    entries = [] if continuation_chain is None else rot._read_continuation(
        continuation_chain, continuation_chain_sha256)
    forbidden = set(map(rec._sha, forbidden_signers))
    forbidden |= {historic['old_root_public_sha256'],
                  historic['recovered_root_public_sha256'],
                  historic['witness_public_sha256']}
    forbidden |= {pin for _, pin in historic['council_public_keys']}
    # Includes every active and revoked role in signed epoch history.
    old = rot._signed_governance(historic['old_governance'],
                                 historic['old_governance_sha256'],
                                 rec._public(historic['old_root_public'],
                                             historic['old_root_public_sha256']))
    prev, prev_pin = anchor, historic['anchor_governance_sha256']
    for policy in [old, anchor]:
        forbidden.update(policy['role_public_sha256'].values())
        forbidden.update(policy['revoked_public_sha256'])
    for entry in entries:
        nxt = rot._signed_governance(entry['governance_policy'],
                                    entry['governance_policy_sha256'], root_bytes)
        rot._transition(prev, nxt, prev_pin)
        forbidden.update(nxt['role_public_sha256'].values())
        forbidden.update(nxt['revoked_public_sha256'])
        prev, prev_pin = nxt, entry['governance_policy_sha256']
    if (prev_pin != rec._sha(governance_policy_sha256) or
            prov._path(governance_policy) != (prov._path(
                entries[-1]['governance_policy']) if entries else
                prov._path(historic['anchor_governance']))):
        deny('EC271_CURRENT_GOVERNANCE_NOT_LAST_SIGNED_EPOCH')
    keys = _witness_keys(witness_public_keys, tuple(forbidden))
    if closure['ratified_recovery_epoch'] != anchor['epoch']:
        deny('EC271_CLOSURE_ANCHOR_EPOCH_INVALID')
    return prev, keys


def _context(*, historic: dict[str, Any], governance_policy: str,
             governance_policy_sha256: str, continuation_chain: str | None,
             continuation_chain_sha256: str | None,
             witness_public_keys: tuple[tuple[str, str], ...],
             forbidden_signers: tuple[str, ...],
             previous_receipt: str | None, previous_receipt_sha256: str | None,
             doc: dict[str, Any]) -> dict[str, bytes]:
    current, keys = _authority(
        historic=historic, governance_policy=governance_policy,
        governance_policy_sha256=governance_policy_sha256,
        continuation_chain=continuation_chain,
        continuation_chain_sha256=continuation_chain_sha256,
        witness_public_keys=witness_public_keys, forbidden_signers=forbidden_signers)
    if (doc['closure_sha256'] != historic['closure_certificate_sha256'] or
            doc['governance_sha256'] != governance_policy_sha256 or
            doc['governance_epoch'] != current['epoch'] or
            doc['recovered_root_public_sha256'] != historic['recovered_root_public_sha256']):
        deny('EC271_SIGNED_GOVERNANCE_OR_CLOSURE_BINDING_MISMATCH')
    if (previous_receipt is None) != (previous_receipt_sha256 is None):
        deny('EC271_PREVIOUS_RECEIPT_PIN_PAIR_REQUIRED')
    earlier = None
    if previous_receipt is not None:
        earlier, _ = _read_verified(previous_receipt, previous_receipt_sha256, keys)
    _prior(doc, earlier, previous_receipt_sha256 or ZERO)
    # Current signed EC267 policy is authoritative over this freshness interval.
    if (doc['not_before_unix'] < current['not_before_unix'] or
            doc['expires_at_unix'] > current['expires_at_unix']):
        deny('EC271_SEAL_OUTSIDE_SIGNED_GOVERNANCE_WINDOW')
    return keys


def prepare_freshness(*, historic: dict[str, Any], governance_policy: str,
                      governance_policy_sha256: str,
                      witness_public_keys: tuple[tuple[str, str], ...],
                      sequence: int, not_before_unix: int, expires_at_unix: int,
                      output: str, previous_receipt: str | None = None,
                      previous_receipt_sha256: str | None = None,
                      continuation_chain: str | None = None,
                      continuation_chain_sha256: str | None = None,
                      forbidden_signers: tuple[str, ...] = ()) -> dict[str, Any]:
    keys = _witness_keys(witness_public_keys)
    current = rot._signed_governance(governance_policy, governance_policy_sha256,
        rec._public(historic['recovered_root_public'],historic['recovered_root_public_sha256']))
    doc = {
        'schema': SCHEMA, 'purpose': PURPOSE,
        'closure_sha256': historic['closure_certificate_sha256'],
        'governance_sha256': rec._sha(governance_policy_sha256),
        'governance_epoch': current['epoch'],
        'recovered_root_public_sha256': historic['recovered_root_public_sha256'],
        'sequence': sequence,
        'previous_receipt_sha256': previous_receipt_sha256 or ZERO,
        'not_before_unix': not_before_unix, 'expires_at_unix': expires_at_unix,
        'witness_public_sha256': sorted(keys), 'nonce': os.urandom(16).hex(),
    }
    _fields(doc)
    _context(historic=historic, governance_policy=governance_policy,
        governance_policy_sha256=governance_policy_sha256,
        continuation_chain=continuation_chain,
        continuation_chain_sha256=continuation_chain_sha256,
        witness_public_keys=witness_public_keys, forbidden_signers=forbidden_signers,
        previous_receipt=previous_receipt,
        previous_receipt_sha256=previous_receipt_sha256, doc=doc)
    pin = rec._save(output, doc, 'EC271_NEW_FRESHNESS_PROPOSAL_REQUIRED')
    return {'status':'partial','exit_code':2,'proposal_sha256':pin,
            'sequence':sequence,'requires_two_independent_witness_signatures':True,
            'trusted_external_time_or_antirollback_verified':False}


def sign_freshness(*, historic: dict[str, Any], governance_policy: str,
                   governance_policy_sha256: str,
                   witness_public_keys: tuple[tuple[str, str], ...],
                   input_path: str, input_sha256: str, signing_key: str,
                   expected_public_sha256: str, output: str,
                   previous_receipt: str | None = None,
                   previous_receipt_sha256: str | None = None,
                   continuation_chain: str | None = None,
                   continuation_chain_sha256: str | None = None,
                   forbidden_signers: tuple[str, ...] = ()) -> dict[str, Any]:
    raw, doc = rec._read(input_path, MAX_RECEIPT)
    rec._check_pin(raw, input_sha256, 'EC271_SIGNER_INPUT_PIN_MISMATCH')
    core, _ = _fields(doc)
    keys = _context(historic=historic, governance_policy=governance_policy,
        governance_policy_sha256=governance_policy_sha256,
        continuation_chain=continuation_chain,
        continuation_chain_sha256=continuation_chain_sha256,
        witness_public_keys=witness_public_keys, forbidden_signers=forbidden_signers,
        previous_receipt=previous_receipt,
        previous_receipt_sha256=previous_receipt_sha256, doc=doc)
    _core, votes = _votes(doc, keys, False)
    if len(votes) >= 2:
        deny('EC271_QUORUM_ALREADY_COMPLETE')
    pin = rec._sha(expected_public_sha256)
    if pin not in keys or (votes and pin <= votes[-1]['public_sha256']):
        deny('EC271_SIGNER_NOT_IN_INCREASING_WITNESS_QUORUM')
    observed = int(time.time())
    if not core['not_before_unix'] <= observed < core['expires_at_unix']:
        deny('EC271_SIGNING_OUTSIDE_FRESHNESS_WINDOW')
    vote = {'public_sha256':pin, 'observed_at_unix':observed,
            'signature_ed25519':rec._sign(signing_key, pin,
                _signature_message(core, votes, pin, observed))}
    signed = {**core,'approvals':[*votes,vote]}
    _votes(signed,keys,False)
    if len(prov._canonical(signed)) > MAX_RECEIPT:
        deny('EC271_RECEIPT_TOO_LARGE')
    digest = rec._save(output, signed, 'EC271_NEW_SIGNED_STAGE_REQUIRED')
    return {'status':'partial','exit_code':2,'signed_freshness_sha256':digest,
            'completed_witnesses':len(signed['approvals']),
            'quorum_complete':len(signed['approvals'])==2,
            'must_independently_pin_output':True}


def _verified_history(entries: list[dict[str, str]],
                      keys: dict[str, bytes]) -> list[dict[str, Any]]:
    """Reopen and authenticate *every* certificate, never just the last.

    A valid last signature alone does not establish an append-only prefix.
    This common verifier is used both at issuance and at host admission.
    """
    previous = None
    previous_pin = ZERO
    result: list[dict[str, Any]] = []
    for entry in entries:
        doc, _ = _read_verified(entry['receipt_path'], entry['receipt_sha256'], keys)
        _prior(doc, previous, previous_pin)
        result.append(doc)
        previous, previous_pin = doc, entry['receipt_sha256']
    return result


def append_chain(*, receipt: str, receipt_sha256: str,
                 witness_public_keys: tuple[tuple[str, str], ...], output: str,
                 previous_chain: str | None = None,
                 previous_chain_sha256: str | None = None) -> dict[str, Any]:
    keys = _witness_keys(witness_public_keys)
    new, _ = _read_verified(receipt, receipt_sha256, keys)
    if (previous_chain is None) != (previous_chain_sha256 is None):
        deny('EC271_PREVIOUS_CHAIN_PIN_PAIR_REQUIRED')
    existing = ([] if previous_chain is None else
                _chain_entries(previous_chain, previous_chain_sha256))
    if len(existing) >= MAX_CHAIN:
        deny('EC271_MAX_FRESHNESS_CHAIN_REACHED')
    if any(entry['receipt_path'] == prov._path(receipt) for entry in existing):
        deny('EC271_RECEIPT_ALREADY_IN_CHAIN')
    predecessor = _verified_history(existing, keys)
    _prior(new, predecessor[-1] if predecessor else None,
           existing[-1]['receipt_sha256'] if existing else ZERO)
    doc = {'schema': CHAIN_SCHEMA, 'entries':[
        *existing,{'receipt_path':prov._path(receipt),'receipt_sha256':rec._sha(receipt_sha256)}]}
    if len(prov._canonical(doc)) > MAX_CONFIG:
        deny('EC271_CHAIN_CONFIG_TOO_LARGE')
    digest = rec._save(output,doc,'EC271_NEW_CHAIN_CONFIG_REQUIRED')
    return {'status':'partial','exit_code':2,'chain_sha256':digest,
            'sequence':new['sequence'],'chain_length':len(doc['entries']),
            'operator_must_independently_pin_chain':True}


def verify_chain(*, chain: str, chain_sha256: str,
                 witness_public_keys: tuple[tuple[str, str], ...],
                 closure_sha256: str, recovered_root_public_sha256: str,
                 allowed_governance_epochs: dict[int, str],
                 current_governance_sha256: str, current_governance_epoch: int,
                 minimum_sequence: int, expected_previous_receipt_sha256: str,
                 effective_now: float | None = None,
                 forbidden_signers: tuple[str, ...] = ()) -> dict[str, Any]:
    keys = _witness_keys(witness_public_keys, forbidden_signers)
    entries = _chain_entries(chain, chain_sha256)
    floor = rec._integer(minimum_sequence,1,2**31-1,'EC271_SEQUENCE_FLOOR_REQUIRED')
    docs = _verified_history(entries, keys)
    for doc in docs:
        if (doc['closure_sha256'] != rec._sha(closure_sha256) or
                doc['recovered_root_public_sha256'] != rec._sha(recovered_root_public_sha256) or
                doc['governance_sha256'] != allowed_governance_epochs.get(doc['governance_epoch'])):
            deny('EC271_RECEIPT_NOT_IN_AUTHENTICATED_EC267_HISTORY')
    prior = docs[-1]
    if prior['sequence'] < floor:
        deny('EC271_OPERATOR_SEQUENCE_FLOOR_NOT_MET')
    expected_prev = entries[-2]['receipt_sha256'] if len(entries) > 1 else ZERO
    if rec._sha(expected_previous_receipt_sha256) != expected_prev:
        deny('EC271_OPERATOR_PREDECESSOR_PIN_MISMATCH')
    if (prior['governance_sha256'] != rec._sha(current_governance_sha256) or
            prior['governance_epoch'] != current_governance_epoch):
        deny('EC271_FRESHNESS_SEAL_NOT_FOR_CURRENT_GOVERNANCE')
    if effective_now is not None:
        if not prior['not_before_unix'] <= effective_now < prior['expires_at_unix']:
            deny('EC271_QUORUM_SEAL_EXPIRED_OR_NOT_YET_VALID')
        if max(v['observed_at_unix'] for v in prior['approvals']) > effective_now + 30:
            deny('EC271_WITNESS_TIME_UNREASONABLY_FUTURE')
    return {
        'status':'partial','exit_code':2,'reason_code':
            'EC271_PINNED_TWO_WITNESS_LOCAL_FRESHNESS_VERIFIED',
        'freshness_sequence':prior['sequence'],
        'freshness_expires_at_unix':prior['expires_at_unix'],
        'freshness_signed_witnesses':len(prior['approvals']),
        'freshness_chain_length':len(entries),
        'trusted_external_time_verified':False,
        'external_nonrollbackable_epoch_escrow_verified':False,
    }
