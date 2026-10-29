#!/usr/bin/env python3
"""EC272: authenticated, bounded rollover of EC271 two-witness receipt chains.

A checkpoint is a two-witness signed attestation that the COMPLETE preceding
EC271 segment was verified when the checkpoint was created and signed. Runtime
reopens/checks each signed checkpoint and the SHA-pinned segment manifests, but
only the *live* segment's individual receipts. This is an explicit change in
historical revalidation policy, not an independent WORM, clock, or antirollback
proof. Secrets are read only by the offline `sign_checkpoint` operation.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from source_provenance_host import provenance as prov
from emergency_recovery_host import recovery as rec
from freshness_quorum_host import freshness as fresh

SCHEMA = 'ces.ec272.two_witness_ratified_segment_checkpoint.v1'
PURPOSE = 'CHECKPOINT_FULLY_VERIFIED_EC271_SEGMENT_AND_ROLLOVER'
DOMAIN = b'CES/EC272/ratified-freshness-segment/v1\x00'
MAX_CHECKPOINTS = 16
MAX_CERT = 16000
ZERO = fresh.ZERO
FIELDS = frozenset({
    'schema', 'purpose', 'checkpoint_number', 'previous_checkpoint_path',
    'previous_checkpoint_sha256', 'segment_path', 'segment_sha256',
    'segment_length', 'first_receipt_sha256', 'first_receipt',
    'last_receipt_sha256', 'last_receipt', 'closure_sha256',
    'recovered_root_public_sha256', 'witness_public_sha256', 'nonce',
})
APPROVAL = fresh.APPROVAL


class RolloverError(fresh.FreshnessError):
    """A bounded error reason, never containing signing material or source bytes."""


def deny(code: str) -> None:
    raise RolloverError(code)


def _signed_bytes(doc: dict[str, Any]) -> bytes:
    return prov._canonical(doc)


def _digest_doc(doc: dict[str, Any]) -> str:
    # EC266 canonical JSON includes the newline; identical to its disk bytes.
    return prov._digest(_signed_bytes(doc))


def _message(core: dict[str, Any], earlier_votes: list[dict],
             pin: str, observed: int) -> bytes:
    return DOMAIN + prov._canonical({
        'checkpoint': core, 'prior_approvals': earlier_votes,
        'signer_public_sha256': pin, 'observed_at_unix': observed,
    })


def _fields(doc: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if (type(doc) is not dict or doc.get('schema') != SCHEMA or
            set(doc) not in (FIELDS, FIELDS | {'approvals'}) or
            doc.get('purpose') != PURPOSE):
        deny('EC272_CHECKPOINT_SCHEMA_INVALID')
    num = rec._integer(doc['checkpoint_number'], 1, MAX_CHECKPOINTS,
                       'EC272_CHECKPOINT_LIMIT_INVALID')
    if (doc['previous_checkpoint_path'] is None) != (
            doc['previous_checkpoint_sha256'] == ZERO):
        deny('EC272_PREVIOUS_CHECKPOINT_PAIR_INVALID')
    if (num == 1) != (doc['previous_checkpoint_path'] is None):
        deny('EC272_CHECKPOINT_GENESIS_INVALID')
    rec._sha(doc['previous_checkpoint_sha256'])
    if doc['previous_checkpoint_path'] is not None:
        prov._path(doc['previous_checkpoint_path'])
    segment_path = prov._path(doc['segment_path'])
    if segment_path == doc['previous_checkpoint_path']:
        deny('EC272_CHECKPOINT_PATH_REUSED')
    for field in ('segment_sha256', 'first_receipt_sha256', 'last_receipt_sha256',
                  'closure_sha256', 'recovered_root_public_sha256'):
        rec._sha(doc[field])
    length = rec._integer(doc['segment_length'], 1, fresh.MAX_CHAIN,
                          'EC272_SEGMENT_LENGTH_INVALID')
    pins = doc['witness_public_sha256']
    if (type(pins) is not list or len(pins) != 3 or
            any(type(v) is not str or fresh.cp.SHA_RE.fullmatch(v) is None
                for v in pins) or pins != sorted(set(pins))):
        deny('EC272_THREE_DISTINCT_WITNESSES_REQUIRED')
    if type(doc['nonce']) is not str or fresh.cp.NONCE_RE.fullmatch(doc['nonce']) is None:
        deny('EC272_NONCE_INVALID')
    for name in ('first_receipt', 'last_receipt'):
        _core, votes = fresh._fields(doc[name])
        if len(votes) != 2:
            deny('EC272_EMBEDDED_RECEIPT_QUORUM_REQUIRED')
        if doc[name]['witness_public_sha256'] != pins:
            deny('EC272_EMBEDDED_RECEIPT_ROSTER_MISMATCH')
        if doc[name]['closure_sha256'] != doc['closure_sha256'] or \
                doc[name]['recovered_root_public_sha256'] != doc['recovered_root_public_sha256']:
            deny('EC272_EMBEDDED_RECEIPT_ROOT_MISMATCH')
        if _digest_doc(doc[name]) != doc[name + '_sha256']:
            deny('EC272_EMBEDDED_RECEIPT_SHA256_MISMATCH')
    first = doc['first_receipt']; last = doc['last_receipt']
    if last['sequence'] != first['sequence'] + length - 1:
        deny('EC272_SEGMENT_SEQUENCE_GAP')
    if length == 1 and first != last:
        deny('EC272_ONE_RECEIPT_SEGMENT_MISMATCH')
    if length > 1 and first['sequence'] >= last['sequence']:
        deny('EC272_SEGMENT_ORDER_INVALID')
    approvals = doc.get('approvals', [])
    if 'approvals' in doc and (type(approvals) is not list or not 1 <= len(approvals) <= 2):
        deny('EC272_APPROVAL_COUNT_INVALID')
    voters = []
    seen_at = []
    for vote in approvals:
        if (type(vote) is not dict or set(vote) != APPROVAL or
                type(vote['public_sha256']) is not str or
                fresh.cp.SHA_RE.fullmatch(vote['public_sha256']) is None or
                type(vote['signature_ed25519']) is not str or
                prov.SIGNATURE_RE.fullmatch(vote['signature_ed25519']) is None):
            deny('EC272_APPROVAL_FIELDS_INVALID')
        when = rec._integer(vote['observed_at_unix'], 1, 2**40,
                            'EC272_APPROVAL_OBSERVATION_INVALID')
        if (not last['not_before_unix'] <= when < last['expires_at_unix'] or
                when < last['approvals'][-1]['observed_at_unix']):
            deny('EC272_CHECKPOINT_SIGNED_OUTSIDE_LAST_LIVE_SEAL')
        voters.append(vote['public_sha256'])
        seen_at.append(when)
    if voters != sorted(set(voters)) or any(pin not in pins for pin in voters):
        deny('EC272_APPROVERS_UNKNOWN_DUPLICATE_OR_UNORDERED')
    if (seen_at != sorted(seen_at) or
            (seen_at and seen_at[-1] - seen_at[0] > fresh.MAX_WITNESS_SPAN)):
        deny('EC272_CHECKPOINT_WITNESS_CLOCK_DISAGREEMENT')
    return {key: doc[key] for key in FIELDS}, approvals


def _votes(doc: dict[str, Any], keys: dict[str, bytes],
           require_quorum: bool) -> tuple[dict, list]:
    core, votes = _fields(doc)
    if core['witness_public_sha256'] != sorted(keys):
        deny('EC272_CHECKPOINT_WITNESS_ROSTER_MISMATCH')
    if require_quorum and len(votes) != 2:
        deny('EC272_CHECKPOINT_TWO_SIGNATURES_REQUIRED')
    # The embedded endpoint signatures are reverified, even for sealed history.
    fresh._votes(core['first_receipt'], keys, True)
    fresh._votes(core['last_receipt'], keys, True)
    for idx, vote in enumerate(votes):
        rec._signature(keys[vote['public_sha256']],
                       _message(core, votes[:idx], vote['public_sha256'],
                                vote['observed_at_unix']),
                       vote['signature_ed25519'],
                       'EC272_CHECKPOINT_SIGNATURE_INVALID')
    return core, votes


def _checked_config(path: str, sha: str) -> list[dict[str, str]]:
    return fresh._chain_entries(prov._path(path), rec._sha(sha))


def _read_checkpoint(path: str, sha: str, keys: dict[str, bytes],
                     *, complete: bool = True) -> dict[str, Any]:
    raw, doc = rec._read(path, MAX_CERT)
    rec._check_pin(raw, sha, 'EC272_CHECKPOINT_SHA256_PIN_MISMATCH')
    _votes(doc, keys, complete)
    return doc


def _check_member_roots(doc: dict[str, Any], closure_sha256: str,
                        root_sha256: str, allowed_epochs: dict[int, str]) -> None:
    if (doc['closure_sha256'] != closure_sha256 or
            doc['recovered_root_public_sha256'] != root_sha256 or
            doc['governance_sha256'] != allowed_epochs.get(doc['governance_epoch'])):
        deny('EC272_RECEIPT_NOT_IN_SIGNED_GOVERNANCE_HISTORY')


def _walk_checkpoints(*, checkpoint: str, checkpoint_sha256: str,
                      keys: dict[str, bytes], closure_sha256: str,
                      root_sha256: str, allowed_epochs: dict[int, str]
                      ) -> tuple[dict[str, Any], list[str]]:
    """Verify every ratified checkpoint, not old raw receipt bodies.

    Each certificate is independently SHA pinned and carries signed first/last
    receipts. It ratifies a complete segment which was fully reopened and
    checked *at issuance*. At runtime intermediate historical receipt bodies
    are NOT reopened (this is a deliberate, documented trust boundary).
    """
    pending: list[tuple[str, str, dict[str, Any]]] = []
    visited: set[str] = set()
    path, sha = prov._path(checkpoint), rec._sha(checkpoint_sha256)
    while True:
        if path in visited or len(pending) >= MAX_CHECKPOINTS:
            deny('EC272_CHECKPOINT_CYCLE_OR_LIMIT')
        visited.add(path)
        doc = _read_checkpoint(path, sha, keys)
        pending.append((path, sha, doc))
        previous_path = doc['previous_checkpoint_path']
        if previous_path is None:
            break
        path, sha = prov._path(previous_path), rec._sha(doc['previous_checkpoint_sha256'])
    previous = None
    previous_sha = ZERO
    previous_cert_sha = ZERO
    all_paths: list[str] = []
    for i, (path, sha, doc) in enumerate(reversed(pending), 1):
        if doc['checkpoint_number'] != i:
            deny('EC272_CHECKPOINT_NUMBER_GAP')
        if i > 1 and (doc['previous_checkpoint_sha256'] != previous_cert_sha or
                      prov._path(doc['previous_checkpoint_path']) != all_paths[-2]):
            deny('EC272_CHECKPOINT_PREDECESSOR_INVALID')
        entries = _checked_config(doc['segment_path'], doc['segment_sha256'])
        if len(entries) != doc['segment_length'] or \
                entries[0]['receipt_sha256'] != doc['first_receipt_sha256'] or \
                entries[-1]['receipt_sha256'] != doc['last_receipt_sha256']:
            deny('EC272_CHECKPOINT_SEALED_SEGMENT_MISMATCH')
        if (entries[0]['receipt_path'] in (path, doc['segment_path']) or
                entries[-1]['receipt_path'] in (path, doc['segment_path'])):
            deny('EC272_SEALED_SEGMENT_PATH_COLLISION')
        first, last = doc['first_receipt'], doc['last_receipt']
        fresh._prior(first, previous, previous_sha if previous is not None else ZERO)
        _check_member_roots(first, closure_sha256, root_sha256, allowed_epochs)
        _check_member_roots(last, closure_sha256, root_sha256, allowed_epochs)
        previous, previous_sha = last, doc['last_receipt_sha256']
        previous_cert_sha = sha
        all_paths.extend([path, prov._path(doc['segment_path'])])
    return pending[0][2], all_paths


def _full_segment(*, entries: list[dict[str, str]], keys: dict[str, bytes],
                  previous: dict[str, Any] | None, previous_sha: str,
                  closure_sha256: str, root_sha256: str,
                  allowed_epochs: dict[int, str]) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    cursor, pin = previous, previous_sha
    for entry in entries:
        doc, _ = fresh._read_verified(entry['receipt_path'],
                                      entry['receipt_sha256'], keys)
        fresh._prior(doc, cursor, pin)
        _check_member_roots(doc, closure_sha256, root_sha256, allowed_epochs)
        docs.append(doc)
        cursor, pin = doc, entry['receipt_sha256']
    return docs


def _authority(*, historic: dict[str, Any], governance_policy: str,
               governance_policy_sha256: str,
               continuation_chain: str | None, continuation_chain_sha256: str | None,
               witness_public_keys: tuple[tuple[str, str], ...],
               forbidden_signers: tuple[str, ...]) -> tuple[dict, dict, dict[str, bytes]]:
    current, keys = fresh._authority(
        historic=historic, governance_policy=governance_policy,
        governance_policy_sha256=governance_policy_sha256,
        continuation_chain=continuation_chain,
        continuation_chain_sha256=continuation_chain_sha256,
        witness_public_keys=witness_public_keys,
        forbidden_signers=forbidden_signers)
    # The parent authority establishes every signature/transition, not just pins.
    from root_handover_host import handover as rot
    root = rec._public(historic['recovered_root_public'],
                       historic['recovered_root_public_sha256'])
    anchor = rot._signed_governance(historic['anchor_governance'],
                                    historic['anchor_governance_sha256'], root)
    epochs = {anchor['epoch']: historic['anchor_governance_sha256']}
    for item in ([] if continuation_chain is None else
                 rot._read_continuation(continuation_chain,continuation_chain_sha256)):
        doc = rot._signed_governance(item['governance_policy'],
                                    item['governance_policy_sha256'],root)
        epochs[doc['epoch']] = item['governance_policy_sha256']
    return current, epochs, keys


def _check_live_now(doc: dict[str, Any]) -> None:
    current = int(time.time())
    if not doc['not_before_unix'] <= current < doc['expires_at_unix']:
        deny('EC272_CHECKPOINT_CEREMONY_OUTSIDE_LIVE_SEAL')
    if doc['approvals'][-1]['observed_at_unix'] > current + 30:
        deny('EC272_SEAL_WITNESS_OBSERVED_IN_FUTURE')


def _proposed(*, segment: str, segment_sha256: str,
              checkpoint: str | None, checkpoint_sha256: str | None,
              keys: dict[str, bytes], closure_sha256: str, root_sha256: str,
              allowed_epochs: dict[int, str]) -> tuple[dict, dict]:
    if (checkpoint is None) != (checkpoint_sha256 is None):
        deny('EC272_PREVIOUS_CHECKPOINT_PAIR_REQUIRED')
    previous = None
    previous_sha = ZERO
    number = 1
    prev_path = None
    if checkpoint is not None:
        latest, _ = _walk_checkpoints(checkpoint=checkpoint,
            checkpoint_sha256=checkpoint_sha256, keys=keys,
            closure_sha256=closure_sha256, root_sha256=root_sha256,
            allowed_epochs=allowed_epochs)
        previous, previous_sha = latest['last_receipt'], latest['last_receipt_sha256']
        number = latest['checkpoint_number'] + 1
        prev_path = prov._path(checkpoint)
    if number > MAX_CHECKPOINTS:
        deny('EC272_MAX_SIGNED_CHECKPOINTS_REACHED')
    entries = _checked_config(segment,segment_sha256)
    if prev_path and prev_path == prov._path(segment):
        deny('EC272_CHECKPOINT_SEGMENT_COLLISION')
    docs = _full_segment(entries=entries, keys=keys, previous=previous,
        previous_sha=previous_sha, closure_sha256=closure_sha256,
        root_sha256=root_sha256, allowed_epochs=allowed_epochs)
    result = {
        'schema':SCHEMA,'purpose':PURPOSE,'checkpoint_number':number,
        'previous_checkpoint_path':prev_path,
        'previous_checkpoint_sha256':checkpoint_sha256 or ZERO,
        'segment_path':prov._path(segment), 'segment_sha256':rec._sha(segment_sha256),
        'segment_length':len(entries),
        'first_receipt_sha256':entries[0]['receipt_sha256'],
        'first_receipt':docs[0],
        'last_receipt_sha256':entries[-1]['receipt_sha256'],
        'last_receipt':docs[-1],
        'closure_sha256':rec._sha(closure_sha256),
        'recovered_root_public_sha256':rec._sha(root_sha256),
        'witness_public_sha256':sorted(keys),'nonce':os.urandom(16).hex(),
    }
    _fields(result)
    return result, docs[-1]


def prepare_checkpoint(*, historic: dict[str, Any], governance_policy: str,
                       governance_policy_sha256: str,
                       witness_public_keys: tuple[tuple[str,str], ...],
                       segment: str, segment_sha256: str, output: str,
                       previous_checkpoint: str | None = None,
                       previous_checkpoint_sha256: str | None = None,
                       continuation_chain: str | None = None,
                       continuation_chain_sha256: str | None = None,
                       forbidden_signers: tuple[str, ...] = ()) -> dict:
    current, epochs, keys = _authority(historic=historic,
        governance_policy=governance_policy,
        governance_policy_sha256=governance_policy_sha256,
        continuation_chain=continuation_chain,
        continuation_chain_sha256=continuation_chain_sha256,
        witness_public_keys=witness_public_keys, forbidden_signers=forbidden_signers)
    doc, last = _proposed(segment=segment,segment_sha256=segment_sha256,
        checkpoint=previous_checkpoint,checkpoint_sha256=previous_checkpoint_sha256,
        keys=keys,closure_sha256=historic['closure_certificate_sha256'],
        root_sha256=historic['recovered_root_public_sha256'],allowed_epochs=epochs)
    if last['governance_sha256'] != governance_policy_sha256 or \
            last['governance_epoch'] != current['epoch']:
        deny('EC272_CHECKPOINT_LAST_SEAL_NOT_CURRENT_GOVERNANCE')
    _check_live_now(last)
    pin=rec._save(output, doc, 'EC272_NEW_CHECKPOINT_PROPOSAL_REQUIRED')
    return {'status':'partial','exit_code':2,'checkpoint_proposal_sha256':pin,
            'checkpoint_number':doc['checkpoint_number'],
            'last_sealed_sequence':last['sequence'],
            'requires_two_independent_witness_signatures':True}


def sign_checkpoint(*, historic: dict[str, Any], governance_policy: str,
                    governance_policy_sha256: str,
                    witness_public_keys: tuple[tuple[str,str], ...],
                    input_path: str, input_sha256: str, signing_key: str,
                    expected_public_sha256: str, output: str,
                    continuation_chain: str | None = None,
                    continuation_chain_sha256: str | None = None,
                    forbidden_signers: tuple[str, ...] = ()) -> dict:
    raw, doc = rec._read(input_path, MAX_CERT)
    rec._check_pin(raw, input_sha256, 'EC272_SIGNER_STAGE_SHA256_MISMATCH')
    core, votes = _fields(doc)
    if len(votes) >= 2:
        deny('EC272_CHECKPOINT_ALREADY_COMPLETE')
    current, epochs, keys = _authority(historic=historic,
        governance_policy=governance_policy,
        governance_policy_sha256=governance_policy_sha256,
        continuation_chain=continuation_chain,
        continuation_chain_sha256=continuation_chain_sha256,
        witness_public_keys=witness_public_keys, forbidden_signers=forbidden_signers)
    # Do not trust only a previous proposal's assertion: revalidate full segment
    # at EACH signing stage, including its historic predecessor checkpoints.
    expected, last = _proposed(segment=core['segment_path'],
        segment_sha256=core['segment_sha256'],
        checkpoint=core['previous_checkpoint_path'],
        checkpoint_sha256=(None if core['previous_checkpoint_path'] is None else
                           core['previous_checkpoint_sha256']),
        keys=keys, closure_sha256=historic['closure_certificate_sha256'],
        root_sha256=historic['recovered_root_public_sha256'],allowed_epochs=epochs)
    expected['nonce'] = core['nonce']
    if expected != core:
        deny('EC272_STAGE_CONTEXT_CHANGED')
    if last['governance_sha256'] != governance_policy_sha256 or \
            last['governance_epoch'] != current['epoch']:
        deny('EC272_CHECKPOINT_LAST_SEAL_NOT_CURRENT_GOVERNANCE')
    _votes(doc, keys, False)
    _check_live_now(last)
    pin = rec._sha(expected_public_sha256)
    if pin not in keys or (votes and pin <= votes[-1]['public_sha256']):
        deny('EC272_SIGNER_NOT_IN_INCREASING_QUORUM')
    observed=int(time.time())
    signed_vote={'public_sha256':pin,'observed_at_unix':observed,
                 'signature_ed25519':rec._sign(signing_key,pin,
                    _message(core,votes,pin,observed))}
    signed={**core,'approvals':[*votes,signed_vote]}
    _votes(signed,keys,False)
    if len(_signed_bytes(signed)) > MAX_CERT:
        deny('EC272_CHECKPOINT_TOO_LARGE')
    digest=rec._save(output,signed,'EC272_NEW_SIGNED_STAGE_REQUIRED')
    return {'status':'partial','exit_code':2,'signed_checkpoint_sha256':digest,
            'checkpoint_number':core['checkpoint_number'],
            'completed_witnesses':len(signed['approvals']),
            'quorum_complete':len(signed['approvals'])==2,
            'operator_must_independently_pin_checkpoint':True}


def append_segment(*, checkpoint: str, checkpoint_sha256: str,
                   segment_receipt: str, segment_receipt_sha256: str,
                   witness_public_keys: tuple[tuple[str,str], ...],
                   closure_sha256: str, recovered_root_public_sha256: str,
                   allowed_governance_epochs: dict[int,str], output: str,
                   previous_segment: str | None = None,
                   previous_segment_sha256: str | None = None,
                   forbidden_signers: tuple[str,...] = ()) -> dict:
    keys=fresh._witness_keys(witness_public_keys,forbidden_signers)
    last,_=_walk_checkpoints(checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256,keys=keys,
        closure_sha256=rec._sha(closure_sha256),
        root_sha256=rec._sha(recovered_root_public_sha256),
        allowed_epochs=allowed_governance_epochs)
    if (previous_segment is None) != (previous_segment_sha256 is None):
        deny('EC272_PREVIOUS_LIVE_SEGMENT_PAIR_REQUIRED')
    entries=[] if previous_segment is None else _checked_config(
        previous_segment,previous_segment_sha256)
    if len(entries) >= fresh.MAX_CHAIN:
        deny('EC272_LIVE_SEGMENT_MAX_256_REACHED')
    if any(p['receipt_path']==prov._path(segment_receipt) for p in entries):
        deny('EC272_DUPLICATE_LIVE_RECEIPT')
    prev=last['last_receipt']
    prev_sha=last['last_receipt_sha256']
    if entries:
        docs=_full_segment(entries=entries,keys=keys,previous=prev,
            previous_sha=prev_sha,closure_sha256=closure_sha256,
            root_sha256=recovered_root_public_sha256,
            allowed_epochs=allowed_governance_epochs)
        prev,prev_sha=docs[-1],entries[-1]['receipt_sha256']
    new,_=fresh._read_verified(segment_receipt,segment_receipt_sha256,keys)
    fresh._prior(new,prev,prev_sha)
    _check_member_roots(new,closure_sha256,recovered_root_public_sha256,
                        allowed_governance_epochs)
    doc={'schema':fresh.CHAIN_SCHEMA, 'entries':[
        *entries,{'receipt_path':prov._path(segment_receipt),
                  'receipt_sha256':rec._sha(segment_receipt_sha256)}]}
    if len(prov._canonical(doc))>fresh.MAX_CONFIG:
        deny('EC272_LIVE_SEGMENT_CONFIG_TOO_LARGE')
    pin=rec._save(output,doc,'EC272_NEW_SEGMENT_CONFIG_REQUIRED')
    return {'status':'partial','exit_code':2,'segment_sha256':pin,
            'freshness_sequence':new['sequence'],
            'segment_length':len(doc['entries']),
            'checkpoint_sha256':rec._sha(checkpoint_sha256)}


def verify_tail(*, checkpoint: str, checkpoint_sha256: str,
                segment: str, segment_sha256: str,
                witness_public_keys: tuple[tuple[str,str], ...],
                closure_sha256: str, recovered_root_public_sha256: str,
                allowed_governance_epochs: dict[int,str],
                current_governance_sha256: str,current_governance_epoch: int,
                minimum_sequence: int,expected_previous_receipt_sha256: str,
                minimum_checkpoint_number: int,
                effective_now: float | None,
                forbidden_signers: tuple[str,...] = ()) -> tuple[dict,list[str]]:
    keys=fresh._witness_keys(witness_public_keys, forbidden_signers)
    last,paths=_walk_checkpoints(checkpoint=checkpoint,
        checkpoint_sha256=checkpoint_sha256, keys=keys,
        closure_sha256=rec._sha(closure_sha256),
        root_sha256=rec._sha(recovered_root_public_sha256),
        allowed_epochs=allowed_governance_epochs)
    floor=rec._integer(minimum_checkpoint_number,1,MAX_CHECKPOINTS,
                       'EC272_CHECKPOINT_FLOOR_INVALID')
    if last['checkpoint_number'] < floor:
        deny('EC272_OPERATOR_CHECKPOINT_FLOOR_NOT_MET')
    entries=_checked_config(segment,segment_sha256)
    if prov._path(segment) in paths:
        deny('EC272_LIVE_SEGMENT_REUSES_SEALED_CHECKPOINT_PATH')
    docs=_full_segment(entries=entries, keys=keys,
        previous=last['last_receipt'],previous_sha=last['last_receipt_sha256'],
        closure_sha256=closure_sha256,root_sha256=recovered_root_public_sha256,
        allowed_epochs=allowed_governance_epochs)
    newest=docs[-1]
    minimum=rec._integer(minimum_sequence,1,2**31-1,'EC272_SEQUENCE_FLOOR_INVALID')
    if newest['sequence'] < minimum:
        deny('EC272_OPERATOR_SEQUENCE_FLOOR_NOT_MET')
    predecessor=entries[-2]['receipt_sha256'] if len(entries)>1 else last['last_receipt_sha256']
    if rec._sha(expected_previous_receipt_sha256)!=predecessor:
        deny('EC272_OPERATOR_PREDECESSOR_PIN_MISMATCH')
    if (newest['governance_sha256'] != rec._sha(current_governance_sha256) or
            newest['governance_epoch'] != current_governance_epoch):
        deny('EC272_LIVE_SEGMENT_NOT_CURRENT_GOVERNANCE')
    if effective_now is not None:
        if not newest['not_before_unix'] <= effective_now < newest['expires_at_unix']:
            deny('EC272_LIVE_SEAL_EXPIRED_OR_NOT_YET_VALID')
        if newest['approvals'][-1]['observed_at_unix'] > effective_now+30:
            deny('EC272_LIVE_WITNESS_UNREASONABLY_FUTURE')
    report={'status':'partial','exit_code':2,
        'reason_code':'EC272_SIGNED_SEGMENT_ROLLOVER_LOCAL_VERIFIED',
        'freshness_sequence':newest['sequence'],
        'freshness_expires_at_unix':newest['expires_at_unix'],
        'freshness_signed_witnesses':len(newest['approvals']),
        'freshness_chain_length':len(entries),
        'sealed_checkpoint_number':last['checkpoint_number'],
        'sealed_checkpoint_sha256':rec._sha(checkpoint_sha256),
        'sealed_segment_member_readback_at_runtime':False,
        'sealed_checkpoint_witnesses_ratified':2,
        'trusted_external_time_verified':False,
        'external_nonrollbackable_epoch_escrow_verified':False}
    return report,paths


def referenced_checkpoint_paths(*, checkpoint: str, checkpoint_sha256: str,
                               witness_public_keys: tuple[tuple[str,str], ...]
                               ) -> list[str]:
    """Signed certificate/manifest paths for collision/protected-tree checks."""
    keys=fresh._witness_keys(witness_public_keys)
    result=[]
    visited=set()
    path,pin=prov._path(checkpoint),rec._sha(checkpoint_sha256)
    while True:
        if path in visited or len(visited)>=MAX_CHECKPOINTS:
            deny('EC272_CHECKPOINT_PATH_CYCLE_OR_LIMIT')
        visited.add(path)
        doc=_read_checkpoint(path,pin,keys)
        result.extend([path,prov._path(doc['segment_path'])])
        if doc['previous_checkpoint_path'] is None:
            break
        path,pin=prov._path(doc['previous_checkpoint_path']),rec._sha(
            doc['previous_checkpoint_sha256'])
    return result
