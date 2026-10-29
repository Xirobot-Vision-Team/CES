#!/usr/bin/env python3
"""EC349: audit separately presented signed SHA anchors and time witnesses.

Only accepts public keys, externally supplied SHA pins and original private
files. This module NEVER signs, writes, fetches hidden files or contacts a
provider. A cryptographically verified time claim is NOT a trusted UTC clock;
two locally fabricated keys are NOT externally independent institutions.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec338_independent_custody import ceremony
from ec339_offline_authority import authority as old
from ec343_hold_receipts import timeline as prior
from ec348_external_custody import custody as inherited

DIRECTORY_SCHEMA = 'ces.ec349.ed25519_out_of_band_channel_directory.v1'
DIRECTORY_CLAIM = 'ces.ec349.out_of_band_channel_directory_claim.v1'
RECEIPT_SCHEMA = 'ces.ec349.ed25519_channel_sha_anchor_receipt.v1'
RECEIPT_CLAIM = 'ces.ec349.channel_sha_anchor_receipt_claim.v1'
TIME_SCHEMA = 'ces.ec349.ed25519_independent_time_witness_claim.v1'
TIME_CLAIM = 'ces.ec349.independent_time_witness_claim.v1'
RESULT_SCHEMA = 'ces.ec349.dual_channel_sha_time_audit_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec349.dual_channel_sha_time_audit_denial.v1'
D_DIRECTORY = b'CES/EC349/IndependentChannelDirectory/v1\0'
D_RECEIPT = b'CES/EC349/OutOfBandSHAReceipt/v1\0'
D_TIME = b'CES/EC349/IndependentReceiptTimeWitness/v1\0'
UNPINNED = inherited.UNPINNED
MAX_CHANNELS = 2
MAX_SEQUENCES = 3
MAX_RECEIPTS = 12  # 2 channels x 3 versions x at most 2 siblings
MAX_TIMES = MAX_RECEIPTS
MAX_WITNESS_RECEIPT_SKEW_SECONDS = 300
MAX_CHANNEL_TIME_DIFFERENCE_SECONDS = 300
KINDS = ('capture_claim', 'renewal_claim', 'revocation_claim')
DIR_FIELDS = frozenset({
    'schema', 'case_id', 'ec348_inputs_canonical_sha256',
    'ec348_verified_result_canonical_sha256',
    'ec348_keeper_directory_original_raw_sha256', 'channel_id',
    'channel_role', 'root_authority', 'receipt_actor', 'time_actor',
    'valid_from_utc', 'valid_until_utc', 'scope',
    'no_independence_or_trusted_clock_authority'
})
RECEIPT_FIELDS = frozenset({
    'schema', 'case_id', 'ec348_inputs_canonical_sha256',
    'ec348_verified_result_canonical_sha256',
    'channel_id', 'channel_directory_original_raw_sha256',
    'receipt_signer_id', 'receipt_signer_public_hex',
    'receipt_signer_organization_id', 'keeper_visible_heads',
    'keeper_signed_originals', 'statement_kind', 'sequence',
    'previous_statement_file', 'previous_statement_original_raw_sha256',
    'statement_nonce_sha256', 'claimed_received_utc', 'expires_utc',
    'scope', 'no_remote_custody_or_external_time_authority'
})
TIME_FIELDS = frozenset({
    'schema', 'case_id', 'channel_id',
    'channel_directory_original_raw_sha256',
    'receipt_original_raw_sha256', 'receipt_sequence',
    'time_actor_id', 'time_actor_public_hex', 'time_actor_organization_id',
    'time_provenance_kind', 'claimed_observed_utc',
    'uncertainty_seconds', 'time_nonce_sha256', 'scope',
    'not_a_trusted_utc_or_legal_timestamp'
})
OUTCOMES = (
    'channel_receipt_not_presented',
    'channel_signed_receipt_fork_no_winner',
    'channel_signed_revocation_not_physical_erasure',
    'channel_receipt_ancestry_not_wholly_out_of_band_pinned',
    'channel_latest_time_witness_missing_or_unpinned',
    'channel_signed_time_claim_gap_or_disagreement',
    'channel_receipt_expired_or_signed_ancestry_time_gap',
    'inherited_ec348_keeper_history_unresolved',
    'channel_pinned_signature_and_time_claims_match_not_independence',
)
PRIORITY = (1, 2, 0, 3, 4, 5, 6, 7, 8)
NEGATIVES = (
    'two_local_or_declared_signers_prove_two_independent_institutions',
    'caller_supplied_channel_sha_pins_prove_external_out_of_band_custody',
    'signature_on_time_claim_proves_trusted_utc_or_receipt_delivery_time',
    'claimed_time_uncertainty_proves_a_calibrated_physical_clock',
    'claimed_root_organization_proves_independent_private_key_control',
    'one_visible_latest_head_proves_absence_of_hidden_signed_forks',
    'signed_revocation_erases_previous_offsite_originals',
    'listed_signed_originals_prove_long_term_physical_durability',
    'remote_provider_cas_worm_freeze_release_or_readback_executed',
    'ec317_ec318_unmocked_and_final_acceptance_proven',
)


def need(ok: Any, reason: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC349_' + reason, status)


def _elapsed(first: str, last: str) -> float:
    return (old._time(last) - old._time(first)).total_seconds()


def _keeper_heads(report: dict) -> list[dict]:
    """Freeze every visible EC348 head, including forks and missing keepers."""
    return [{k: row[k] for k in (
        'custodian_id', 'subject_receiver_id', 'signed_receipt_count',
        'signed_head_original_raw_sha256s',
        'multiple_signed_heads_are_unresolved_forks',
        'latest_single_head_kind',
        'latest_head_entire_history_caller_sha_pins_present',
        'signed_keeper_ancestry_has_self_reported_expiry_gap',
        'latest_single_head_ledger_original_raw_sha256',
        'outcome')} for row in report['keeper_outcomes']]


def _keeper_originals(inputs: dict) -> list[dict]:
    # UNPINNED is preserved as an independently unpinned claim; even if its
    # bytes are available locally, the calculated raw SHA is NOT a new pin.
    return [{'whole_original_raw_sha256': sha if sha != UNPINNED else prior.digest(path),
             'independently_furnished_sha_pin_present': sha != UNPINNED}
            for path, sha in zip(inputs['keeper_receipt_files'],
                                 inputs['keeper_receipt_shas'], strict=True)]


def _replay(ec348_inputs: dict) -> dict:
    need(set(ec348_inputs) == inherited.PARENT_KEYS | {
        'external_evaluation_utc', 'keeper_directory_file',
        'expected_keeper_directory_sha256',
        'expected_directory_root_public_hex',
        'keeper_receipt_files', 'keeper_receipt_shas',
        'presented_keeper_ids', 'presented_ledger_files',
        'presented_ledger_shas', 'presented_copy_snapshot_files',
        'presented_copy_ack_set_files'},
        'EXACT_FULL_EC348_SOURCE_INPUTS_REQUIRED')
    report = inherited.audit_external_custody(**ec348_inputs)
    need(report['exit_code'] == 2 and
         report['ec347_full_signed_source_and_readback_replayed'] is True and
         report['directory_signature_verified'] is True,
         'REAL_EC348_TO_EC337_SIGNED_ORIGINAL_REPLAY_REQUIRED', 'permission_denied')
    original_roster = prior.roster(ec348_inputs['roster_file'],
                                   ec348_inputs['expected_roster_sha256'])
    old_governance = inherited.governance._governance(
        ec348_inputs['governance_roster_file'],
        ec348_inputs['expected_governance_roster_sha256'])
    directory_doc = prior.read(ec348_inputs['keeper_directory_file'],
                               ec348_inputs['expected_keeper_directory_sha256'],
                               'REPLAYED_EC348_DIRECTORY')
    return {'inputs': ec348_inputs, 'report': report,
            'source_sha': case.sha(reg.canonical(ec348_inputs)),
            'result_sha': case.sha(reg.canonical(report)),
            'keepers': _keeper_heads(report),
            'originals': _keeper_originals(ec348_inputs),
            'old_actors': [directory_doc['claim']['directory_authority'],
                           *directory_doc['claim']['custodians'],
                           original_roster['change_proposer'],
                           original_roster['change_approver'],
                           *original_roster['receivers'],
                           old_governance['initiator'],
                           old_governance['external_approver'],
                           *old_governance['reviewers']]}


def derive_handoff(**ec348_inputs) -> dict:
    """Unsigned recipe for third parties; intentionally no signing API."""
    ctx = _replay(ec348_inputs)
    return {'schema': 'ces.ec349.unsigned_dual_channel_handoff.v1',
            'status': 'requires_two_separately_furnished_anchor_and_time_channels',
            'exit_code': 2, 'case_id': ctx['report']['case_id'],
            'ec348_inputs_canonical_sha256': ctx['source_sha'],
            'ec348_verified_result_canonical_sha256': ctx['result_sha'],
            'keeper_visible_heads': ctx['keepers'],
            'keeper_signed_originals': ctx['originals'],
            'unverified_external_channel_count': 2,
            'offline_unresolved_exit_code': 2,
            **{key: False for key in NEGATIVES}}


def _directory(path: str, sha: str, root_public: str, ctx: dict,
               pins: dict[str, str]) -> dict:
    prior.pin(pins, path, sha)
    doc = prior.read(path, sha, 'INDEPENDENTLY_SHA_PINNED_CHANNEL_DIRECTORY')
    claim = doc.get('claim') if type(doc) is dict else None
    need(type(claim) is dict and set(claim) == DIR_FIELDS and
         claim.get('schema') == DIRECTORY_CLAIM and
         claim.get('case_id') == ctx['report']['case_id'] and
         claim.get('ec348_inputs_canonical_sha256') == ctx['source_sha'] and
         claim.get('ec348_verified_result_canonical_sha256') == ctx['result_sha'] and
         claim.get('ec348_keeper_directory_original_raw_sha256') ==
             ctx['inputs']['expected_keeper_directory_sha256'] and
         claim.get('channel_role') == 'independent_out_of_band_sha_anchor_claim' and
         claim.get('scope') == 'bounded_offline_sha_anchor_and_time_witness_only' and
         claim.get('no_independence_or_trusted_clock_authority') is True and
         ceremony._id(claim.get('channel_id')),
         'CHANNEL_DIRECTORY_MUST_BIND_EXACT_REAL_EC348_SOURCE')
    for actor_name in ('root_authority', 'receipt_actor', 'time_actor'):
        need(inherited._actor(claim.get(actor_name)),
             'CHANNEL_DIRECTORY_NEEDS_THREE_DISTINCT_EXPLICIT_ACTORS')
    need(prior.same(root_public, claim['root_authority']['public_hex']),
         'EXTERNALLY_PINNED_CHANNEL_ROOT_PUBLIC_MISMATCH')
    need(ceremony._utc(claim.get('valid_from_utc')) and
         ceremony._utc(claim.get('valid_until_utc')) and
         _elapsed(ctx['inputs']['external_evaluation_utc'],
                  claim['valid_from_utc']) >= 0 and
         _elapsed(claim['valid_from_utc'], claim['valid_until_utc']) >= 0,
         'CHANNEL_SIGNED_VALIDITY_WINDOW_INVALID')
    prior._signed(doc, DIRECTORY_SCHEMA, D_DIRECTORY,
                  root_public, 'EC349_CHANNEL_DIRECTORY')
    return claim


def _receipt(path: str, sha_arg: str, directory: dict, directory_sha: str,
             ctx: dict, pins: dict[str, str]) -> tuple[str, dict, bool, str]:
    pinned = sha_arg != UNPINNED
    sha = sha_arg if pinned else prior.digest(path)
    prior.pin(pins, path, sha)
    doc = prior.read(path, sha, 'CHANNEL_SIGNED_ANCHOR_RECEIPT')
    c = doc.get('claim') if type(doc) is dict else None
    actor = directory['receipt_actor']
    need(type(c) is dict and set(c) == RECEIPT_FIELDS and
         c.get('schema') == RECEIPT_CLAIM and
         c.get('case_id') == ctx['report']['case_id'] and
         c.get('ec348_inputs_canonical_sha256') == ctx['source_sha'] and
         c.get('ec348_verified_result_canonical_sha256') == ctx['result_sha'] and
         c.get('channel_directory_original_raw_sha256') == directory_sha and
         c.get('channel_id') == directory['channel_id'] and
         all(c.get(k) == actor[v] for k, v in (
             ('receipt_signer_id', 'signer_id'),
             ('receipt_signer_public_hex', 'public_hex'),
             ('receipt_signer_organization_id', 'organization_id'))) and
         c.get('keeper_visible_heads') == ctx['keepers'] and
         c.get('keeper_signed_originals') == ctx['originals'],
         'CHANNEL_RECEIPT_MUST_BIND_ALL_EC348_KEEPER_HEADS_AND_ORIGINALS')
    kind, sequence = c.get('statement_kind'), c.get('sequence')
    need(kind in KINDS and type(sequence) is int and 1 <= sequence <= MAX_SEQUENCES and
         ((sequence == 1 and kind == KINDS[0]) or
          (sequence > 1 and kind in KINDS[1:])) and
         ceremony._sha(c.get('statement_nonce_sha256')) and
         ceremony._utc(c.get('claimed_received_utc')) and
         ceremony._utc(c.get('expires_utc')) and
         _elapsed(directory['valid_from_utc'], c['claimed_received_utc']) >= 0 and
         _elapsed(c['claimed_received_utc'],ctx['evaluation_utc']) >= 0 and
         _elapsed(c['claimed_received_utc'], c['expires_utc']) >= 0 and
         _elapsed(c['expires_utc'], directory['valid_until_utc']) >= 0 and
         c.get('scope') == 'signed_out_of_band_keeper_heads_claim_only' and
         c.get('no_remote_custody_or_external_time_authority') is True,
         'CHANNEL_RECEIPT_VERSION_NONCE_OR_SIGNED_CLAIM_TIME_INVALID')
    if sequence == 1:
        need(c.get('previous_statement_file') is None and
             c.get('previous_statement_original_raw_sha256') is None,
             'FIRST_ANCHOR_RECEIPT_HAS_NO_PREDECESSOR')
    else:
        need(type(c.get('previous_statement_file')) is str and
             ceremony._sha(c.get('previous_statement_original_raw_sha256')) and
             c['previous_statement_file'] != path,
             'ANCHOR_SUCCESSOR_REQUIRES_EXPLICIT_SHA_PINNED_PREDECESSOR')
    prior._signed(doc, RECEIPT_SCHEMA, D_RECEIPT, actor['public_hex'],
                  'EC349_CHANNEL_RECEIPT')
    return sha, c, pinned, doc['signature_ed25519']


def _time(path: str, sha_arg: str, directories: dict, receipts: dict,
          ctx: dict, pins: dict[str, str]) -> tuple[str, dict, bool, str]:
    pinned = sha_arg != UNPINNED
    sha = sha_arg if pinned else prior.digest(path)
    prior.pin(pins, path, sha)
    doc = prior.read(path, sha, 'INDEPENDENT_TIME_WITNESS_ORIGINAL')
    c = doc.get('claim') if type(doc) is dict else None
    need(type(c) is dict and set(c) == TIME_FIELDS and
         c.get('schema') == TIME_CLAIM and
         c.get('case_id') == ctx['report']['case_id'] and
         type(c.get('channel_id')) is str and
         c['channel_id'] in directories and
         ceremony._sha(c.get('receipt_original_raw_sha256')),
         'TIME_WITNESS_NEEDS_EXPLICIT_PRESENTED_CHANNEL_RECEIPT')
    directory_sha, directory = directories[c['channel_id']]
    owner = receipts.get(c['receipt_original_raw_sha256'])
    actor = directory['time_actor']
    need(owner is not None and owner[2]['channel_id'] == c['channel_id'] and
         c.get('channel_directory_original_raw_sha256') == directory_sha and
         c.get('receipt_sequence') == owner[2]['sequence'] and
         all(c.get(k) == actor[v] for k, v in (
             ('time_actor_id', 'signer_id'),
             ('time_actor_public_hex', 'public_hex'),
             ('time_actor_organization_id', 'organization_id'))) and
         c.get('time_provenance_kind') == 'separately_signed_local_clock_claim' and
         ceremony._utc(c.get('claimed_observed_utc')) and
         type(c.get('uncertainty_seconds')) is int and
         0 <= c['uncertainty_seconds'] <= 3600 and
         ceremony._sha(c.get('time_nonce_sha256')) and
         _elapsed(directory['valid_from_utc'], c['claimed_observed_utc']) >= 0 and
         _elapsed(c['claimed_observed_utc'],ctx['evaluation_utc']) >= 0 and
         _elapsed(c['claimed_observed_utc'], directory['valid_until_utc']) >= 0 and
         c.get('scope') == 'receipt_sha_time_provenance_claim_only' and
         c.get('not_a_trusted_utc_or_legal_timestamp') is True,
         'TIME_WITNESS_ROLE_BINDING_OR_SIGNED_PROVENANCE_INVALID')
    prior._signed(doc, TIME_SCHEMA, D_TIME, actor['public_hex'],
                  'EC349_SEPARATE_TIME_WITNESS')
    return sha, c, pinned, doc['signature_ed25519']


def audit_dual_anchors(*, dual_evaluation_utc: str,
                       channel_directory_files: list[str],
                       channel_directory_shas: list[str],
                       channel_root_public_hexes: list[str],
                       channel_receipt_files: list[str],
                       channel_receipt_shas: list[str],
                       time_witness_files: list[str],
                       time_witness_shas: list[str],
                       **ec348_inputs) -> dict:
    """Read-only; always exit 2 on well-formed cryptographically checked inputs."""
    need(ceremony._utc(dual_evaluation_utc) and
         ceremony._utc(ec348_inputs.get('external_evaluation_utc')) and
         _elapsed(ec348_inputs['external_evaluation_utc'],dual_evaluation_utc) >= 0,
         'CHANNEL_EVALUATION_MUST_FOLLOW_EC348')
    arrays = (channel_directory_files, channel_directory_shas,
              channel_root_public_hexes, channel_receipt_files,
              channel_receipt_shas, time_witness_files, time_witness_shas)
    need(all(type(x) is list for x in arrays) and
         len(channel_directory_files) == len(channel_directory_shas) ==
             len(channel_root_public_hexes) == MAX_CHANNELS and
         len(channel_receipt_files) == len(channel_receipt_shas) <= MAX_RECEIPTS and
         len(time_witness_files) == len(time_witness_shas) <= MAX_TIMES and
         all(type(p) is str for p in (*channel_directory_files,
             *channel_receipt_files, *time_witness_files)) and
         all(ceremony._sha(s) for s in channel_directory_shas) and
         all(type(k) is str and len(k)==64 and
             all(ch in '0123456789abcdef' for ch in k)
             for k in channel_root_public_hexes) and
         all(ceremony._sha(s) or s == UNPINNED for s in
             (*channel_receipt_shas, *time_witness_shas)),
         'EXACT_TWO_SEPARATELY_SHA_PINNED_DIRECTORIES_AND_BOUNDED_ORIGINALS_REQUIRED')
    new_paths = [*channel_directory_files, *channel_receipt_files,
                 *time_witness_files]
    old_paths = {v for k,v in ec348_inputs.items()
                 if k.endswith('_file') and type(v) is str}
    old_paths.update(v for k, vals in ec348_inputs.items()
                     if k.endswith('_files') and type(vals) is list for v in vals)
    need(len(set(new_paths)) == len(new_paths) and
         not set(new_paths).intersection(old_paths),
         'NEW_ANCHOR_OR_WITNESS_PATH_CANNOT_REUSE_OLD_ORIGINAL_OR_EACH_OTHER')
    ctx = _replay(ec348_inputs)
    ctx['evaluation_utc'] = dual_evaluation_utc
    pins: dict[str, str] = {}
    directories: dict[str, tuple[str, dict]] = {}
    actors = list(ctx['old_actors'])
    for path, sha, pub in zip(channel_directory_files,
                              channel_directory_shas,
                              channel_root_public_hexes, strict=True):
        c = _directory(path, sha, pub, ctx, pins)
        need(c['channel_id'] not in directories,
             'CHANNEL_ID_MUST_BE_DISTINCT')
        directories[c['channel_id']] = (sha,c)
        actors.extend(c[k] for k in ('root_authority','receipt_actor','time_actor'))
    need(list(directories) == sorted(directories),
         'TWO_CHANNEL_DIRECTORIES_MUST_BE_IN_CANONICAL_ID_ORDER')
    # Key, signer ID and claimed legal-organization labels may not be recycled
    # across either channel or the earlier registered EC348 actors.
    for key in ('public_hex','signer_id','organization_id'):
        need(len({a[key] for a in actors}) == len(actors),
             'CHANNEL_ROOT_RECEIPT_TIME_ACTOR_REUSE_OR_SELF_ATTESTATION_DENIED')
    sigs: set[str] = set()
    # Inherited EC348 receipts may be explicitly UNPINNED but still signed.
    # Carry forward the complete EC345 + EC346 nonce inventory; EC348's own
    # replay already checked those, but *new* signatures must not reuse them.
    nonces: set[str] = inherited.parent._parent_nonces(ec348_inputs, {})
    for p,s in zip(ec348_inputs['keeper_receipt_files'],
                   ec348_inputs['keeper_receipt_shas'],strict=True):
        actual = s if s != UNPINNED else prior.digest(p)
        nonces.add(prior.read(p,actual,'REPLAYED_EC348_RECEIPT')['claim']['statement_nonce_sha256'])
    for p,s in zip(ec348_inputs['readback_challenge_files'],
                   ec348_inputs['readback_challenge_shas'],strict=True):
        nonces.add(prior.read(p,s,'REPLAYED_EC347_CHALLENGE')['claim']['challenge_nonce_sha256'])
    for p,s in zip(ec348_inputs['readback_response_files'],
                   ec348_inputs['readback_response_shas'],strict=True):
        nonces.add(prior.read(p,s,'REPLAYED_EC347_RESPONSE')['claim']['response_nonce_sha256'])
    receipts: dict[str, tuple[str, str, dict, bool]] = {}
    channel_events: dict[str, list[tuple[str,str,dict,bool]]] = defaultdict(list)
    channel_order = list(directories)
    previous_order = (-1, -1, '')
    per_version: dict[tuple[str,int],int] = defaultdict(int)
    for path, sha_arg in zip(channel_receipt_files,channel_receipt_shas,strict=True):
        # Determine ownership from signed original, then verify against the
        # pinned directory; never use a signed path to discover predecessor.
        sha = sha_arg if sha_arg != UNPINNED else prior.digest(path)
        unsigned = prior.read(path, sha, 'CHANNEL_RECEIPT_FOR_OWNER_SELECTION')
        claim = unsigned.get('claim') if type(unsigned) is dict else None
        need(type(claim) is dict and claim.get('channel_id') in directories,
             'RECEIPT_OWNER_MUST_BE_ONE_OF_TWO_PINNED_CHANNELS')
        directory_sha, directory = directories[claim['channel_id']]
        sha, claim, pinned, sig = _receipt(path,sha_arg,directory,
                                           directory_sha,ctx,pins)
        order = (channel_order.index(claim['channel_id']),claim['sequence'],sha)
        need(order > previous_order, 'CHANNEL_RECEIPTS_MUST_BE_CANONICALLY_SORTED')
        previous_order = order
        per_version[(claim['channel_id'],claim['sequence'])] += 1
        need(per_version[(claim['channel_id'],claim['sequence'])] <= 2,
             'CHANNEL_MAX_TWO_SIGNED_SIBLINGS_AT_EACH_SEQUENCE')
        need(sha not in receipts and sig not in sigs and
             claim['statement_nonce_sha256'] not in nonces,
             'DUPLICATE_SIGNED_RECEIPT_OR_REPLAY_NONCE_DENIED')
        nonces.add(claim['statement_nonce_sha256']); sigs.add(sig)
        if claim['sequence'] > 1:
            pred = receipts.get(claim['previous_statement_original_raw_sha256'])
            need(pred is not None and pred[0] == claim['previous_statement_file'] and
                 pred[2]['channel_id'] == claim['channel_id'] and
                 pred[2]['sequence']+1 == claim['sequence'] and
                 pred[2]['statement_kind'] != KINDS[2] and
                 _elapsed(pred[2]['claimed_received_utc'],
                          claim['claimed_received_utc']) >= 0,
                 'CONTIGUOUS_SIGNED_SAME_CHANNEL_PREDECESSOR_REQUIRED')
        receipts[sha]=(path,sha,claim,pinned)
        channel_events[claim['channel_id']].append((path,sha,claim,pinned))
    # A time witness must bind to an *explicitly supplied* signed receipt and
    # can never legitimize a receipt not already in this audited list.
    times: dict[str, tuple[str,dict,bool]] = {}
    prev_time_order = (-1,-1,'')
    for path,sha_arg in zip(time_witness_files,time_witness_shas,strict=True):
        sha = sha_arg if sha_arg != UNPINNED else prior.digest(path)
        unsigned = prior.read(path,sha,'WITNESS_FOR_OWNER_SELECTION')
        raw = unsigned.get('claim') if type(unsigned) is dict else None
        need(type(raw) is dict and raw.get('channel_id') in directories,
             'TIME_WITNESS_OWNER_MUST_BE_ONE_OF_TWO_CHANNELS')
        actual,claim,pinned,sig = _time(path,sha_arg,directories,receipts,ctx,pins)
        order = (channel_order.index(claim['channel_id']),
                 claim['receipt_sequence'],claim['receipt_original_raw_sha256'])
        need(order > prev_time_order and
             claim['receipt_original_raw_sha256'] not in times and
             sig not in sigs and claim['time_nonce_sha256'] not in nonces,
             'DUPLICATE_TIME_WITNESS_OR_NONCANONICAL_ORDER_OR_NONCE')
        prev_time_order=order
        sigs.add(sig);nonces.add(claim['time_nonce_sha256'])
        times[claim['receipt_original_raw_sha256']] = (actual,claim,pinned)
    # Retest *all new signed originals* after completing the whole replay.
    prior.late(pins)
    rows=[]
    selected_time_claims=[]
    inherited_uncertain = any(row['outcome'] != inherited.OUTCOMES[7]
                              for row in ctx['report']['keeper_outcomes'])
    for channel_id in channel_order:
        _,directory = directories[channel_id]
        events=channel_events[channel_id]
        consumed={e[2]['previous_statement_original_raw_sha256']
                  for e in events if e[2]['sequence'] > 1}
        heads=[x for x in events if x[1] not in consumed]
        fork=len(heads)>1
        head=heads[0] if len(heads)==1 else None
        ancestry_pinned = False
        ancestry_expiry_gap = False
        witness=None
        gap=None
        expired=False
        if head:
            ancestry_pinned = True
            walk=head
            while True:
                ancestry_pinned = ancestry_pinned and walk[3]
                prev_sha=walk[2]['previous_statement_original_raw_sha256']
                if prev_sha is None:break
                ancestor=receipts[prev_sha]
                if _elapsed(ancestor[2]['expires_utc'],
                            walk[2]['claimed_received_utc']) > 0:
                    ancestry_expiry_gap=True
                walk=ancestor
            expired=(_elapsed(head[2]['expires_utc'],dual_evaluation_utc)>0 or
                     _elapsed(directory['valid_until_utc'],dual_evaluation_utc)>0)
            if head[1] in times:
                ts,doc,pinned=times[head[1]]
                gap=_elapsed(head[2]['claimed_received_utc'],
                             doc['claimed_observed_utc'])
                witness={'time_witness_original_raw_sha256':ts,
                         'time_witness_independently_pinned':pinned,
                         'time_provenance_kind':doc['time_provenance_kind'],
                         'claim_received_utc':head[2]['claimed_received_utc'],
                         'witness_claimed_observed_utc':doc['claimed_observed_utc'],
                         'claimed_uncertainty_seconds':doc['uncertainty_seconds'],
                         'signed_claim_gap_seconds':gap,
                         'signed_claims_agree_within_claimed_uncertainty':
                             abs(gap) <= doc['uncertainty_seconds']}
        if not events: outcome=OUTCOMES[0]
        elif fork: outcome=OUTCOMES[1]
        elif head[2]['statement_kind']==KINDS[2]: outcome=OUTCOMES[2]
        elif not ancestry_pinned: outcome=OUTCOMES[3]
        elif witness is None or not witness['time_witness_independently_pinned']:
            outcome=OUTCOMES[4]
        elif abs(gap) > min(witness['claimed_uncertainty_seconds'],
                            MAX_WITNESS_RECEIPT_SKEW_SECONDS):
            outcome=OUTCOMES[5]
        elif expired or ancestry_expiry_gap: outcome=OUTCOMES[6]
        elif inherited_uncertain: outcome=OUTCOMES[7]
        else: outcome=OUTCOMES[8]
        if witness is not None and head is not None:
            selected_time_claims.append((channel_id,head[1],witness))
        rows.append({
            'channel_id':channel_id, 'signed_receipt_count':len(events),
            'visible_signed_head_original_raw_sha256s':[r[1] for r in heads],
            'multiple_signed_heads_no_winner':fork,
            'latest_head_kind':head[2]['statement_kind'] if head else None,
            'latest_head_ancestry_all_externally_pinned':ancestry_pinned,
            'signed_ancestry_has_self_reported_expiry_gap':ancestry_expiry_gap,
            'channel_or_latest_receipt_claimed_expired':expired,
            'latest_time_witness':witness,
            'outcome':outcome})
    compared=[]
    # Keep peer mismatch separate, even if another more urgent condition was
    # already found. Two self-reported timestamps need not be the same clock.
    if len(selected_time_claims)==2:
        a,b=selected_time_claims
        difference=abs(_elapsed(a[2]['witness_claimed_observed_utc'],
                                b[2]['witness_claimed_observed_utc']))
        compared=[{'left_channel_id':a[0], 'right_channel_id':b[0],
                   'absolute_claimed_utc_difference_seconds':difference,
                   'within_five_minute_claim_comparison_window':
                       difference <= MAX_CHANNEL_TIME_DIFFERENCE_SECONDS,
                   'peer_time_comparison_is_not_trusted_utc':True}]
        if difference > MAX_CHANNEL_TIME_DIFFERENCE_SECONDS:
            for row in rows:
                if row['outcome'] == OUTCOMES[8]:
                    row['outcome'] = OUTCOMES[5]
    counts={k:sum(row['outcome']==k for row in rows) for k in OUTCOMES}
    status=next(OUTCOMES[i] for i in PRIORITY if counts[OUTCOMES[i]])+'_unresolved'
    return {'schema':RESULT_SCHEMA, 'command':'audit-dual-anchors',
        'status':status,'exit_code':2,'case_id':ctx['report']['case_id'],
        'ec348_inputs_canonical_sha256':ctx['source_sha'],
        'ec348_verified_result_canonical_sha256':ctx['result_sha'],
        'ec348_full_signed_source_replayed':True,
        'two_channel_directory_signatures_verified':True,
        'channel_directory_original_raw_sha256s':channel_directory_shas,
        'channel_root_public_hexes_as_caller_pinned':channel_root_public_hexes,
        'channel_receipt_count':len(channel_receipt_files),
        'time_witness_original_count':len(time_witness_files),
        'channel_outcomes':rows,'outcome_counts':counts,
        'cross_channel_signed_time_comparison':compared,
        'ec348_keeper_heads_still_unresolved':inherited_uncertain,
        'all_external_identity_physical_sha_custody_and_trusted_time_not_proven':True,
        'offline_unresolved_exit_code':2,
        **{key:False for key in NEGATIVES}}
