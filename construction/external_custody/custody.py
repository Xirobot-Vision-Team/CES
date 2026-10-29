#!/usr/bin/env python3
"""EC348: verify independently *supplied* SHA-pinned keeper originals.

No private key lives here, no copy is created, no network ledger is queried.
An independently pinned digest is a caller-supplied input, not evidence that
an external organization, independent machine or trusted clock actually exists.
All EC347 originals are replayed before a newer assertion is considered.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from independent_custody import ceremony
from offline_authority import authority as old
from hold_receipts import timeline as prior
from conflict_hold import hold as governance
from disclosure_custody import custody as copies
from readback_challenge import readback as parent

DIRECTORY_SCHEMA = 'ces.ec348.ed25519_external_keeper_directory.v1'
DIRECTORY_CLAIM = 'ces.ec348.external_keeper_directory_claim.v1'
RECEIPT_SCHEMA = 'ces.ec348.ed25519_keeper_whole_original_receipt.v1'
RECEIPT_CLAIM = 'ces.ec348.keeper_whole_original_receipt_claim.v1'
LEDGER_SCHEMA = 'ces.ec348.keeper_inventory_raw_original.v1'
RESULT_SCHEMA = 'ces.ec348.bounded_external_custody_import_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec348.bounded_external_custody_import_denial.v1'
D_DIRECTORY = b'CES/EC348/ExternalKeeperDirectory/v1\0'
D_RECEIPT = b'CES/EC348/ExternalKeeperInventoryReceipt/v1\0'
MAX_KEEPERS = 4
MAX_VERSIONS = 3
MAX_RECEIPTS = MAX_KEEPERS * MAX_VERSIONS * 2  # includes one signed sibling per version
UNPINNED = 'UNPINNED'
STORE, RENEW, REVOKE = 'store_claim', 'renewal_claim', 'revocation_claim'
KINDS = (STORE, RENEW, REVOKE)
PARENT_KEYS = parent.PARENT_KEYS | {
    'readback_evaluation_utc', 'readback_challenge_files',
    'readback_challenge_shas', 'readback_response_files',
    'readback_response_shas', 'presented_receiver_ids',
    'presented_snapshot_files', 'presented_ack_set_files'
}
D_FIELDS = frozenset({
    'schema', 'case_id', 'ec347_audit_inputs_canonical_sha256',
    'ec347_latest_challenge_original_raw_sha256',
    'source_snapshot_original_raw_sha256', 'source_ack_set_original_raw_sha256',
    'directory_authority', 'custodians', 'valid_from_utc', 'valid_until_utc',
    'scope', 'no_physical_or_external_identity_authority'
})
K_FIELDS = frozenset({'signer_id','public_hex','organization_id',
                      'ledger_id','subject_receiver_id'})
R_FIELDS = frozenset({
    'schema', 'case_id', 'ec347_audit_inputs_canonical_sha256',
    'directory_original_raw_sha256', 'custodian_id', 'custodian_public_hex',
    'custodian_organization_id', 'ledger_id', 'subject_receiver_id',
    'latest_ec347_round', 'latest_challenge_original_raw_sha256',
    'latest_receiver_reply_original_raw_sha256', 'whole_original_inventory',
    'claimed_snapshot_original_raw_sha256', 'claimed_snapshot_byte_length',
    'claimed_ack_set_original_raw_sha256', 'claimed_ack_set_byte_length',
    'ledger_original_raw_sha256', 'statement_kind', 'sequence',
    'previous_statement_file', 'previous_statement_original_raw_sha256',
    'statement_nonce_sha256', 'reported_utc', 'expires_utc', 'scope',
    'no_actual_site_custody_or_remote_authority'
})
L_FIELDS = frozenset({
    'schema', 'case_id', 'ec347_audit_inputs_canonical_sha256',
    'custodian_id', 'subject_receiver_id', 'ledger_id',
    'statement_kind', 'sequence', 'whole_original_inventory',
    'claimed_snapshot_original_raw_sha256', 'claimed_snapshot_byte_length',
    'claimed_ack_set_original_raw_sha256', 'claimed_ack_set_byte_length'
})
OUTCOMES = (
    'no_keeper_receipt_presented',
    'keeper_current_receipt_missing_external_sha_pin',
    'keeper_signed_versions_fork',
    'keeper_signed_revocation',
    'keeper_directory_or_receipt_expired',
    'keeper_signed_bytes_differ_from_receiver',
    'keeper_explicit_retest_changed_since_signed_receipt',
    'keeper_signed_receipt_matches_receiver_unproven',
    'keepers_share_same_claimed_ledger_original_not_independent',
)
STATUS_PRIORITY = (
    OUTCOMES[2], OUTCOMES[6], OUTCOMES[3], OUTCOMES[4],
    OUTCOMES[1], OUTCOMES[5], OUTCOMES[0], OUTCOMES[8], OUTCOMES[7],
)
STATUS_SUFFIX = '_unresolved'
NEGATIVES = (
    'local_signature_verification_proves_institutional_identity',
    'caller_supplied_pins_prove_independently_custodied_external_shas',
    'distinct_keys_or_ledger_ids_prove_distinct_machines',
    'self_reported_signed_expiry_is_a_trusted_clock',
    'claim_of_ledger_sha_proves_external_ledger_exists',
    'signed_revocation_erases_any_bytes_or_remote_storage',
    'same_file_or_ledger_label_proves_multi_party_independence',
    'fresh_local_copy_retest_proves_long_term_offsite_durability',
    'partial_presentation_proves_global_latest_or_no_hidden_fork',
    'remote_provider_cas_worm_or_legal_action_executed',
    'ec317_ec318_unmocked_and_final_acceptance_proven',
)


def need(ok: Any, name: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC348_' + name, status)


def _actor(a: dict) -> bool:
    return governance._actor(a)


def _inventory(context: dict, subject: str) -> list[dict]:
    """The exact *complete* old challenge/reply SHA list is never abbreviated."""
    latest = context['latest'].get(subject)
    need(latest is not None and latest['response_kind'] == parent.MEASURED,
         'CUSTODIAN_SUBJECT_NEEDS_LATEST_VERIFIED_MEASURED_EC347_REPLY')
    inp = context['inputs']
    entries = [
        ('ec345_source_snapshot', context['report']['source_snapshot_original_raw_sha256']),
        ('ec345_source_ack_set', context['report']['source_ack_set_original_raw_sha256']),
    ]
    entries += [(f'older_pinned_{key}', inp[key]) for key in (
        'expected_manifest_sha256', 'expected_current_root_sha256',
        'expected_governance_roster_sha256', 'expected_review_manifest_sha256',
        'expected_approval_sha256', 'expected_roster_sha256',
        'expected_head_snapshot_sha256', 'expected_head_ack_set_sha256',
        'expected_directory_sha256', 'expected_checkpoint_sha256')]
    for kind, key in (('ec344_signed_view','view_shas'),
                      ('ec345_signed_disclosure_challenge','challenge_shas'),
                      ('ec345_signed_disclosure_response','response_shas'),
                      ('ec346_signed_receiver_copy','observation_shas')):
        entries += [(f'{kind}_{i}', x) for i,x in enumerate(inp[key],start=1)]
    entries += [(f'ec347_challenge_round_{i}', s) for i, s in
                enumerate(inp['readback_challenge_shas'], start=1)]
    entries += [(f'ec347_signed_reply_{i}', s) for i, s in
                enumerate(inp['readback_response_shas'], start=1)]
    entries += [
        ('subject_latest_signed_snapshot', latest['signed_snapshot_raw_sha256']),
        ('subject_latest_signed_ack_set', latest['signed_ack_set_raw_sha256']),
    ]
    return [{'name': name, 'whole_original_sha256': sha} for name, sha in entries]


def _context(inputs: dict) -> dict:
    need(set(inputs) == PARENT_KEYS,
         'EXACT_FULL_EC347_AUDIT_INPUTS_REQUIRED')
    audit = parent.audit_readbacks(**inputs)
    need(audit['exit_code'] == 2 and
         audit['ec345_through_ec346_original_signed_history_replayed'] is True,
         'REAL_EC347_AND_ALL_EARLIER_ORIGINALS_MUST_REPLAY', 'permission_denied')
    roster = prior.roster(inputs['roster_file'], inputs['expected_roster_sha256'])
    old_governance = governance._governance(inputs['governance_roster_file'],
                                            inputs['expected_governance_roster_sha256'])
    latest_round = audit['challenge_round_count']
    latest = {row['receiver_id']: row for row in
              audit['per_receiver_round_outcomes']
              if row['round_number'] == latest_round}
    return {'inputs': inputs, 'report': audit, 'roster': roster,
            'old_governance': old_governance, 'latest': latest,
            'context_sha': case.sha(reg.canonical(inputs))}


def derive_checklist(**ec347_inputs) -> dict:
    """Safe public payload recipe for an external registrar; never signs it."""
    ctx = _context(ec347_inputs)
    return {'schema': 'ces.ec348.unsigned_external_custody_handoff.v1',
            'status': 'unsigned_handoff_requires_independent_institutional_review',
            'exit_code': 2, 'ec347_audit_inputs_canonical_sha256': ctx['context_sha'],
            'case_id': ctx['report']['case_id'],
            'latest_challenge_original_raw_sha256':
                ec347_inputs['readback_challenge_shas'][-1],
            'audience_receiver_ids': ctx['report']['latest_challenge_audience_receiver_ids'],
            'eligible_receiver_inventories': [
                {'receiver_id': rid, 'whole_original_inventory': _inventory(ctx, rid)}
                for rid, row in ctx['latest'].items()
                if row['response_kind'] == parent.MEASURED],
            'unanswered_or_unavailable_receiver_ids': [
                rid for rid, row in ctx['latest'].items()
                if row['response_kind'] != parent.MEASURED],
            'offline_unresolved_exit_code': 2,
            **{k: False for k in NEGATIVES}}


def _directory(path: str, sha: str, root_public: str, ctx: dict,
               pins: dict[str, str]) -> dict:
    prior.pin(pins, path, sha)
    doc = prior.read(path, sha, 'EC348_EXPLICITLY_SHA_PINNED_DIRECTORY')
    c = doc.get('claim') if type(doc) is dict else None
    rep = ctx['report']
    need(type(c) is dict and set(c) == D_FIELDS and
         c.get('schema') == DIRECTORY_CLAIM and
         c.get('case_id') == rep['case_id'] and
         c.get('ec347_audit_inputs_canonical_sha256') == ctx['context_sha'] and
         c.get('ec347_latest_challenge_original_raw_sha256') ==
             ctx['inputs']['readback_challenge_shas'][-1] and
         c.get('source_snapshot_original_raw_sha256') ==
             rep['source_snapshot_original_raw_sha256'] and
         c.get('source_ack_set_original_raw_sha256') ==
             rep['source_ack_set_original_raw_sha256'] and
         c.get('scope') == 'independently_furnished_offline_keeper_sha_inventory_only' and
         c.get('no_physical_or_external_identity_authority') is True,
         'DIRECTORY_MUST_BIND_VERIFIED_EC347_ALL_ORIGINALS')
    head = c.get('directory_authority')
    keepers = c.get('custodians')
    need(_actor(head) and prior.same(head['public_hex'], root_public) and
         type(keepers) is list and
         2 <= len(keepers) <= MAX_KEEPERS and
         all(type(k) is dict and set(k) == K_FIELDS and
             _actor({x:k[x] for x in ('signer_id','public_hex','organization_id')}) and
             ceremony._id(k['ledger_id']) and
             ceremony._id(k['subject_receiver_id']) for k in keepers),
         'SEPARATE_EXTERNALLY_SUPPLIED_ROOT_AND_KEEPER_ROSTER_REQUIRED')
    all_old = [ctx['roster']['change_proposer'], ctx['roster']['change_approver'],
               *ctx['roster']['receivers'], ctx['old_governance']['initiator'],
               ctx['old_governance']['external_approver'],
               *ctx['old_governance']['reviewers']]
    actors = [head, *keepers, *all_old]
    for field in ('public_hex', 'signer_id', 'organization_id'):
        need(len({a[field] for a in actors}) == len(actors),
             'ROOT_KEEPER_MUST_NOT_RECYCLE_ANY_EC343_ROLE_KEY_ID_OR_ORG')
    need(len({k['ledger_id'] for k in keepers}) == len(keepers) and
         [k['subject_receiver_id'] for k in keepers] ==
             rep['latest_challenge_audience_receiver_ids'],
         'ONE_INDEPENDENT_KEEPER_ROSTER_SLOT_PER_CHALLENGED_RECEIVER_REQUIRED')
    need(ceremony._utc(c.get('valid_from_utc')) and
         ceremony._utc(c.get('valid_until_utc')) and
         old._time(c['valid_from_utc']) >= old._time(ctx['inputs']['readback_evaluation_utc']) and
         old._time(c['valid_from_utc']) <= old._time(c['valid_until_utc']),
         'DIRECTORY_UTC_WINDOW_INVALID')
    need(old._time(ctx['evaluation_utc']) >= old._time(c['valid_from_utc']),
         'EXTERNAL_AUDIT_CANNOT_PRECEDE_DIRECTORY_VALIDITY_START')
    prior._signed(doc, DIRECTORY_SCHEMA, D_DIRECTORY,
                  root_public, 'EC348_EXTERNAL_DIRECTORY')
    return c


def _ledger_fields(claim: dict) -> dict:
    return {'schema': LEDGER_SCHEMA,
            **{k: claim[k] for k in (
                'case_id','ec347_audit_inputs_canonical_sha256',
                'custodian_id','subject_receiver_id','ledger_id',
                'statement_kind','sequence','whole_original_inventory',
                'claimed_snapshot_original_raw_sha256','claimed_snapshot_byte_length',
                'claimed_ack_set_original_raw_sha256','claimed_ack_set_byte_length')}}


def _receipt(path: str, sha_arg: str, ctx: dict, directory: dict,
             directory_sha: str, pins: dict[str,str]) -> tuple[str, dict, bool, str]:
    pinned = sha_arg != UNPINNED
    sha = sha_arg if pinned else prior.digest(path)
    prior.pin(pins, path, sha)
    doc = prior.read(path, sha, 'EC348_EXTERNAL_SIGNED_KEEPER_RECEIPT')
    c = doc.get('claim') if type(doc) is dict else None
    need(type(c) is dict and set(c) == R_FIELDS and
         c.get('schema') == RECEIPT_CLAIM and
         c.get('case_id') == ctx['report']['case_id'] and
         c.get('ec347_audit_inputs_canonical_sha256') == ctx['context_sha'] and
         c.get('directory_original_raw_sha256') == directory_sha and
         c.get('latest_ec347_round') == ctx['report']['challenge_round_count'] and
         c.get('latest_challenge_original_raw_sha256') ==
             ctx['inputs']['readback_challenge_shas'][-1],
         'KEEPER_RECEIPT_MUST_BIND_FULL_PINNED_EC347_CONTEXT')
    actor = next((a for a in directory['custodians']
                  if a['signer_id'] == c.get('custodian_id')), None)
    need(actor is not None and all(c.get(k) == v for k,v in (
        ('custodian_public_hex',actor['public_hex']),
        ('custodian_organization_id',actor['organization_id']),
        ('ledger_id',actor['ledger_id']),
        ('subject_receiver_id',actor['subject_receiver_id']))),
        'KEEPER_SIGNER_AND_SUBJECT_MUST_MATCH_PINNED_DIRECTORY')
    subject = actor['subject_receiver_id']
    latest = ctx['latest'].get(subject)
    need(latest is not None and latest['response_kind'] == parent.MEASURED and
         c.get('latest_receiver_reply_original_raw_sha256') ==
             latest['response_original_raw_sha256'] and
         c.get('whole_original_inventory') == _inventory(ctx, subject),
         'KEEPER_INVENTORY_MUST_MATCH_REAL_SIGNED_MEASURED_RECEIVER_HISTORY')
    kind, seq = c.get('statement_kind'), c.get('sequence')
    need(kind in KINDS and type(seq) is int and 1 <= seq <= MAX_VERSIONS and
         (seq == 1 and kind == STORE or seq > 1 and kind in (RENEW, REVOKE)) and
         ceremony._sha(c.get('ledger_original_raw_sha256')) and
         ceremony._sha(c.get('statement_nonce_sha256')) and
         ceremony._utc(c.get('reported_utc')) and
         ceremony._utc(c.get('expires_utc')) and
         old._time(directory['valid_from_utc']) <= old._time(c['reported_utc']) <=
             old._time(ctx['evaluation_utc']) and
         old._time(c['reported_utc']) <= old._time(c['expires_utc']) <=
             old._time(directory['valid_until_utc']) and
         c.get('scope') == 'keeper_signed_local_sha_inventory_claim_not_independent_site_proof' and
         c.get('no_actual_site_custody_or_remote_authority') is True,
         'KEEPER_KIND_SEQUENCE_LEDGER_SHA_EXPIRY_OR_NONCE_INVALID')
    fields = ('claimed_snapshot_original_raw_sha256','claimed_snapshot_byte_length',
              'claimed_ack_set_original_raw_sha256','claimed_ack_set_byte_length')
    if kind == REVOKE:
        need(all(c[x] is None for x in fields),
             'REVOKED_KEEPER_MAY_NOT_CLAIM_CURRENT_CONTENT_BYTES')
    else:
        need(all(ceremony._sha(c[x]) for x in fields if x.endswith('sha256')) and
             all(type(c[x]) is int and 0 < c[x] <= copies.MAX_COPY_BYTES
                 for x in fields if x.endswith('length')),
             'STORE_OR_RENEWAL_CLAIMS_REQUIRE_TWO_COMPLETE_SHA_LENGTHS')
    if seq == 1:
        need(c.get('previous_statement_file') is None and
             c.get('previous_statement_original_raw_sha256') is None,
             'FIRST_KEEPER_STATEMENT_MUST_HAVE_NO_PREDECESSOR')
    else:
        need(type(c.get('previous_statement_file')) is str and
             ceremony._sha(c.get('previous_statement_original_raw_sha256')) and
             c['previous_statement_file'] != path,
             'KEEPER_SUCCESSOR_REQUIRES_EXPLICIT_OLD_WHOLE_SHA')
    prior._signed(doc, RECEIPT_SCHEMA, D_RECEIPT,
                  actor['public_hex'], 'EC348_EXTERNAL_KEEPER_RECEIPT')
    return sha, c, pinned, doc['signature_ed25519']


def audit_external_custody(*, external_evaluation_utc: str,
                           keeper_directory_file: str,
                           expected_keeper_directory_sha256: str,
                           expected_directory_root_public_hex: str,
                           keeper_receipt_files: list[str],
                           keeper_receipt_shas: list[str],
                           presented_keeper_ids: list[str],
                           presented_ledger_files: list[str],
                           presented_ledger_shas: list[str],
                           presented_copy_snapshot_files: list[str],
                           presented_copy_ack_set_files: list[str],
                           **ec347_inputs) -> dict:
    """Read-only import; a successful signature never promotes external reality."""
    need(ceremony._utc(external_evaluation_utc) and
         ceremony._utc(ec347_inputs.get('readback_evaluation_utc')) and
         old._time(external_evaluation_utc) >=
             old._time(ec347_inputs['readback_evaluation_utc']),
         'EXTERNAL_EVALUATION_MUST_FOLLOW_EC347')
    array = (keeper_receipt_files, keeper_receipt_shas,
             presented_keeper_ids, presented_ledger_files, presented_ledger_shas,
             presented_copy_snapshot_files, presented_copy_ack_set_files)
    need(all(type(x) is list for x in array) and
         len(keeper_receipt_files) == len(keeper_receipt_shas) <= MAX_RECEIPTS and
         len(presented_keeper_ids) == len(presented_ledger_files) ==
         len(presented_ledger_shas) == len(presented_copy_snapshot_files) ==
         len(presented_copy_ack_set_files) <= MAX_KEEPERS and
         all(type(p) is str for p in keeper_receipt_files) and
         len(set(keeper_receipt_files)) == len(keeper_receipt_files) and
         len(set(presented_keeper_ids)) == len(presented_keeper_ids) and
         all(ceremony._sha(x) or x == UNPINNED for x in keeper_receipt_shas) and
         all(ceremony._sha(x) for x in presented_ledger_shas),
         'BOUNDED_PINNED_OR_EXPLICITLY_UNPINNED_RECEIPT_ARRAYS_REQUIRED')
    ctx = _context(ec347_inputs)
    ctx['evaluation_utc'] = external_evaluation_utc
    # Collect *every* original read by the EC347 audit, not just receipt paths.
    inherited_paths = {v for k,v in ec347_inputs.items()
                       if k.endswith('_file') and isinstance(v,str)}
    inherited_paths.update(p for k,v in ec347_inputs.items()
                           if k.endswith('_files') and isinstance(v,list) for p in v)
    checkpoint=prior.read(ec347_inputs['checkpoint_file'],
                          ec347_inputs['expected_checkpoint_sha256'],
                          'EC348_ALREADY_REPLAYED_CHECKPOINT')
    selected=[x for x in checkpoint['announcements']
              if x['item_id']==ec347_inputs['item_id']]
    need(len(selected)==1, 'ONE_REPLAYED_SOURCE_PAIR_REQUIRED')
    old_bytes=(selected[0]['snapshot_file'],selected[0]['ack_set_file'])
    inherited_paths.update(old_bytes)
    # EC346/347 signed copy *paths* are never rediscovered or opened here.
    # Exclude aliases even if the EC347 auditor did not explicitly present them.
    for fk,sk in (('observation_files','observation_shas'),
                  ('readback_response_files','readback_response_shas')):
        for p,s in zip(ec347_inputs[fk],ec347_inputs[sk], strict=True):
            claim=prior.read(p,s,'EC348_PREVIOUS_SIGNED_COPY_PATH')['claim']
            inherited_paths.add(claim['copy_snapshot_file'])
            inherited_paths.add(claim['copy_ack_set_file'])
    pins: dict[str,str] = {}
    newer_paths = ([keeper_directory_file, *keeper_receipt_files,
                    *presented_ledger_files, *presented_copy_snapshot_files,
                    *presented_copy_ack_set_files])
    need(len(set(newer_paths)) == len(newer_paths) and
         not (set(newer_paths) & inherited_paths),
         'KEEPER_AND_PRESENTED_BYTE_PATHS_MUST_NOT_ALIAS_ANY_OLD_ORIGINALS')
    directory = _directory(keeper_directory_file,
         expected_keeper_directory_sha256, expected_directory_root_public_hex,
         ctx, pins)
    # No hidden scan of the directory's claimed ledger ids or host labels.
    keeper_order = [k['signer_id'] for k in directory['custodians']]
    known = {}
    receipt_rows = defaultdict(list)
    nonce_old = parent._parent_nonces(ec347_inputs, {})
    # All old nonce-bearing signed originals were verified by audit_readbacks.
    for p,s in zip(ec347_inputs['readback_challenge_files'],
                   ec347_inputs['readback_challenge_shas'], strict=True):
        nonce_old.add(prior.read(p,s,'EC348_PARENT_CHALLENGE_NONCE')['claim']['challenge_nonce_sha256'])
    for p,s in zip(ec347_inputs['readback_response_files'],
                   ec347_inputs['readback_response_shas'], strict=True):
        nonce_old.add(prior.read(p,s,'EC348_PARENT_RESPONSE_NONCE')['claim']['response_nonce_sha256'])
    # Check every signed original, even ones later in canonical receipt order.
    all_receipt_original_shas = {x if x != UNPINNED else prior.digest(p)
                                 for p,x in zip(keeper_receipt_files,
                                                keeper_receipt_shas,strict=True)}
    older_original_shas = {v for k,v in ec347_inputs.items()
                           if k.endswith('_sha256') and ceremony._sha(v)}
    older_original_shas.update(x for k,v in ec347_inputs.items()
                               if k.endswith('_shas') and type(v) is list
                               for x in v if ceremony._sha(x))
    forbidden_ledger_references = (all_receipt_original_shas | older_original_shas |
                                   {expected_keeper_directory_sha256})
    signatures = set()
    version_counts = defaultdict(int)
    order_key = (-1, -1, '')
    for path, sha_arg in zip(keeper_receipt_files, keeper_receipt_shas, strict=True):
        sha, claim, pinned, sig = _receipt(path, sha_arg, ctx, directory,
                                          expected_keeper_directory_sha256, pins)
        key = (keeper_order.index(claim['custodian_id']), claim['sequence'], sha)
        need(key > order_key, 'KEEPER_RECEIPTS_MUST_BE_IN_CANONICAL_ORDER')
        order_key = key
        version_counts[(claim['custodian_id'], claim['sequence'])] += 1
        need(version_counts[(claim['custodian_id'], claim['sequence'])] <= 2,
             'AT_MOST_TWO_VISIBLE_SIGNED_SIBLINGS_PER_KEEPER_VERSION')
        need(sig not in signatures and claim['statement_nonce_sha256'] not in nonce_old,
             'REPEATED_KEEPER_SIGNATURE_OR_NONCE_DENIED')
        signatures.add(sig)
        nonce_old.add(claim['statement_nonce_sha256'])
        need(claim['ledger_original_raw_sha256'] not in forbidden_ledger_references and
             claim['ledger_original_raw_sha256'] not in (
                 ctx['report']['source_snapshot_original_raw_sha256'],
                 ctx['report']['source_ack_set_original_raw_sha256']),
             'LEDGER_CLAIM_CANNOT_SELF_LOOP_TO_EXISTING_SIGNED_ORIGINAL')
        if claim['sequence'] > 1:
            prev = known.get(claim['previous_statement_file'])
            need(prev is not None and prev[0] == claim['previous_statement_original_raw_sha256'] and
                 prev[1]['custodian_id'] == claim['custodian_id'] and
                 prev[1]['subject_receiver_id'] == claim['subject_receiver_id'] and
                 prev[1]['sequence']+1 == claim['sequence'] and
                 prev[1]['statement_kind'] != REVOKE and
                 old._time(prev[1]['reported_utc']) <= old._time(claim['reported_utc']),
                 'SUCCESSOR_NEEDS_EXPLICIT_PREVIOUS_SAME_KEEPER_SIGNED_ORIGINAL')
        known[path] = (sha, claim, pinned, sig)
        receipt_rows[claim['custodian_id']].append((path, sha, claim, pinned))
    for keeper_id in keeper_order:
        need(sum(v for (who,_),v in version_counts.items() if who==keeper_id) <= 2*MAX_VERSIONS,
             'KEEPER_SIGNED_HISTORY_MUST_STAY_WITHIN_THREE_VERSIONS')
    presented = dict(zip(presented_keeper_ids,
                     zip(presented_ledger_files, presented_ledger_shas,
                         presented_copy_snapshot_files, presented_copy_ack_set_files,
                         strict=True), strict=True))
    need(presented_keeper_ids == [x for x in keeper_order if x in presented],
         'EXPLICIT_KEEPER_PRESENTATIONS_MUST_BE_CANONICAL')
    result_rows = []
    all_ledger_shas = defaultdict(set)
    for keeper in directory['custodians']:
        kid = keeper['signer_id']
        events = receipt_rows[kid]
        subsequent = {x[2]['previous_statement_original_raw_sha256']
                      for x in events if x[2]['sequence'] > 1}
        heads = [x for x in events if x[1] not in subsequent]
        is_fork = len(heads) > 1
        head = heads[0] if len(heads) == 1 else None
        if head is not None:
            all_ledger_shas[head[2]['ledger_original_raw_sha256']].add(kid)
        signed_compare = None
        signed_source_compare = None
        ancestry_pinned = False
        # A later claimed renewal cannot silently repair an earlier expiry.
        # UTC comes from signers, not a trusted clock; this is a bounded
        # *claim continuity* check rather than external physical custody proof.
        ancestry_self_reported_expiry_gap = False
        if head is not None:
            walk=head
            ancestry_pinned=True
            while walk is not None:
                ancestry_pinned = ancestry_pinned and walk[3]
                ancestor_file=walk[2]['previous_statement_file']
                if ancestor_file is None:
                    break
                ancestor=known[ancestor_file]
                if old._time(walk[2]['reported_utc']) > old._time(ancestor[1]['expires_utc']):
                    ancestry_self_reported_expiry_gap = True
                walk=(ancestor_file,*ancestor[:3])
        retest = None
        if kid in presented:
            need(head is not None and head[2]['statement_kind'] != REVOKE,
                 'CANNOT_PICK_A_FORK_OR_REVOKED_HEAD_TO_RETEST')
            lp, ls, snap, ack = presented[kid]
            need(ls == head[2]['ledger_original_raw_sha256'],
                 'EXPLICIT_EXTERNAL_LEDGER_SHA_MUST_MATCH_SIGNED_HEAD')
            ledger = prior.read(lp, ls, 'EC348_EXPLICIT_WHOLE_LEDGER_ORIGINAL')
            need(type(ledger) is dict and ledger == _ledger_fields(head[2]),
                 'PRESENTED_LEDGER_WHOLE_ORIGINAL_CONTENT_MISMATCH')
            local = copies._copy_fields(snap, ack, allow_source=old_bytes)
            for p, sha in ((lp,ls),
                           (snap,local['copy_snapshot_original_raw_sha256']),
                           (ack,local['copy_ack_set_original_raw_sha256'])):
                prior.pin(pins,p,sha)
            matches = all(local[k] == head[2][v] for k,v in (
                ('copy_snapshot_original_raw_sha256','claimed_snapshot_original_raw_sha256'),
                ('copy_snapshot_byte_length','claimed_snapshot_byte_length'),
                ('copy_ack_set_original_raw_sha256','claimed_ack_set_original_raw_sha256'),
                ('copy_ack_set_byte_length','claimed_ack_set_byte_length')))
            retest = {'explicit_ledger_original_read_and_sha_verified': True,
                      'actual_copy_snapshot_original_raw_sha256':
                          local['copy_snapshot_original_raw_sha256'],
                      'actual_copy_ack_set_original_raw_sha256':
                          local['copy_ack_set_original_raw_sha256'],
                      'actual_copy_snapshot_byte_length': local['copy_snapshot_byte_length'],
                      'actual_copy_ack_set_byte_length': local['copy_ack_set_byte_length'],
                      'matches_signed_keeper_claimed_bytes': matches,
                      'matches_ec345_verified_source': all(local[k] ==
                          ctx['report'][n] for k,n in (
                              ('copy_snapshot_original_raw_sha256','source_snapshot_original_raw_sha256'),
                              ('copy_ack_set_original_raw_sha256','source_ack_set_original_raw_sha256')))}
        if head is not None and head[2]['statement_kind'] != REVOKE:
            latest = ctx['latest'][keeper['subject_receiver_id']]
            signed_compare = (
                head[2]['claimed_snapshot_original_raw_sha256'] ==
                    latest['signed_snapshot_raw_sha256'] and
                head[2]['claimed_ack_set_original_raw_sha256'] ==
                    latest['signed_ack_set_raw_sha256'])
            signed_source_compare = (
                head[2]['claimed_snapshot_original_raw_sha256'] ==
                    ctx['report']['source_snapshot_original_raw_sha256'] and
                head[2]['claimed_ack_set_original_raw_sha256'] ==
                    ctx['report']['source_ack_set_original_raw_sha256'])
        if not events:
            outcome = OUTCOMES[0]
        elif is_fork:
            outcome = OUTCOMES[2]
        elif head[2]['statement_kind'] == REVOKE:
            outcome = OUTCOMES[3]
        elif retest is not None and not retest['matches_signed_keeper_claimed_bytes']:
            outcome = OUTCOMES[6]
        elif (old._time(ctx['evaluation_utc']) > old._time(directory['valid_until_utc']) or
              old._time(ctx['evaluation_utc']) > old._time(head[2]['expires_utc']) or
              ancestry_self_reported_expiry_gap):
            outcome = OUTCOMES[4]
        elif not ancestry_pinned:
            outcome = OUTCOMES[1]
        elif not signed_compare or not signed_source_compare:
            outcome = OUTCOMES[5]
        else:
            outcome = OUTCOMES[7]
        result_rows.append({
            'custodian_id': kid, 'subject_receiver_id': keeper['subject_receiver_id'],
            'claimed_ledger_id_not_independent_evidence': keeper['ledger_id'],
            'signed_receipt_count': len(events),
            'signed_head_original_raw_sha256s': [x[1] for x in heads],
            'multiple_signed_heads_are_unresolved_forks': is_fork,
            'latest_single_head_kind': head[2]['statement_kind'] if head else None,
            'latest_head_entire_history_caller_sha_pins_present': ancestry_pinned,
            'signed_keeper_ancestry_has_self_reported_expiry_gap':
                ancestry_self_reported_expiry_gap,
            'latest_single_head_ledger_original_raw_sha256':
                head[2]['ledger_original_raw_sha256'] if head else None,
            'signed_keeper_bytes_match_latest_receiver': signed_compare,
            'signed_keeper_bytes_match_verified_ec345_source': signed_source_compare,
            'local_explicit_retest': retest, 'outcome': outcome})
    # Identical ledger original across separate alleged keepers cannot establish
    # independent copies; this is a *visible downgrade*, not proof of collusion.
    shared = sorted(x for x,ids in all_ledger_shas.items() if len(ids) > 1)
    for row in result_rows:
        row['shares_same_ledger_original_with_another_keeper'] = (
            row['latest_single_head_ledger_original_raw_sha256'] in shared)
        if row['shares_same_ledger_original_with_another_keeper'] and row['outcome'] == OUTCOMES[7]:
            row['outcome']=OUTCOMES[8]
    prior.late(pins)
    counts = {out: sum(row['outcome'] == out for row in result_rows) for out in OUTCOMES}
    status = next(o for o in STATUS_PRIORITY if counts[o]) + STATUS_SUFFIX
    return {'schema': RESULT_SCHEMA, 'command': 'audit-external-custody',
            'status': status, 'exit_code': 2,
            'case_id': ctx['report']['case_id'],
            'ec347_audit_inputs_canonical_sha256': ctx['context_sha'],
            'ec347_full_signed_source_and_readback_replayed': True,
            'keeper_directory_original_raw_sha256': expected_keeper_directory_sha256,
            'externally_asserted_root_public_hex': expected_directory_root_public_hex,
            'directory_signature_verified': True,
            'directory_reported_expired_at_evaluation':
                old._time(ctx['evaluation_utc']) > old._time(directory['valid_until_utc']),
            'keeper_count': len(keeper_order), 'receipt_count': len(keeper_receipt_files),
            'explicitly_presented_ledger_and_copy_pair_count': len(presented),
            'keeper_outcomes': result_rows, 'outcome_counts': counts,
            'shared_ledger_original_raw_sha256s': shared,
            'external_evaluation_utc': external_evaluation_utc,
            'external_physical_identity_pin_provenance_clock_and_site_all_not_proven': True,
            'offline_unresolved_exit_code': 2,
            **{k: False for k in NEGATIVES}}
