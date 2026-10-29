#!/usr/bin/env python3
"""EC340: old/new role cross-signatures plus independently pinned root observation.

This is one hop (legacy EC339 root = epoch 1 -> successor epoch 2). Every
receipt verified by this module is a cryptographic statement, NOT authoritative
proof of the legal institution, global newest root, revoked registry or clock.
Only the standalone issuer/witness candidate subcommands can write files.
"""
from __future__ import annotations

from datetime import timedelta
import hmac
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec338_independent_custody import ceremony
from ec339_offline_authority import authority as old

ROLES = old.ROLES
SIDES = ('old', 'new')
ROOT_SCHEMA = 'ces.ec340.issuer_successor_epoch_roster.v1'
EDGE_CLAIM_SCHEMA = 'ces.ec340.role_scoped_dual_root_edge_claim.v1'
EDGE_SCHEMA = 'ces.ec340.ed25519_root_edge_signature.v1'
OBSERVER_ROOT_SCHEMA = 'ces.ec340.independent_root_observer_trust.v1'
OBSERVER_CLAIM_SCHEMA = 'ces.ec340.challenged_root_retirement_observation_claim.v1'
OBSERVER_SCHEMA = 'ces.ec340.ed25519_root_retirement_observation.v1'
RESULT_SCHEMA = 'ces.ec340.issuer_root_rotation_full_replay_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec340.issuer_root_rotation_denial.v1'
ROOT_FIELDS = frozenset({'schema','transfer_id','policy_original_raw_sha256',
    'predecessor_roster_original_raw_sha256','epoch','rotation_id',
    'rotation_nonce_sha256','effective_utc','issuers',
    'old_root_retired_from_effective_utc','external_successor_root_trust_required'})
EDGE_FIELDS = frozenset({'schema','successor_roster_original_raw_sha256',
    'predecessor_roster_original_raw_sha256','role','side','issuer_id',
    'issuer_public_hex','rotation_id','rotation_nonce_sha256','epoch','effective_utc'})
OBSERVER_ROOT_FIELDS = frozenset({'schema','transfer_id',
    'policy_original_raw_sha256','observer_id','observer_organization_id',
    'observer_public_hex','independent_out_of_band_approval_required'})
OBSERVATION_FIELDS = frozenset({'schema','predecessor_roster_original_raw_sha256',
    'successor_roster_original_raw_sha256','observer_trust_original_raw_sha256',
    'edge_signature_original_raw_sha256s','rotation_id','rotation_nonce_sha256',
    'epoch','verifier_challenge_sha256','observed_utc','expires_utc',
    'predecessor_root_state','successor_root_state'})
EDGE_KEYS = tuple((side,role) for side in SIDES for role in ROLES)
MAX_JSON = 12_000
NEGATIVES = (
    'cross_signatures_prove_legally_authorized_institutions',
    'observer_signature_proves_real_revocation_register_completeness',
    'observer_claimed_utc_or_operator_utc_is_independently_trusted_time',
    'operator_minimum_epoch_and_root_pin_prove_global_latest_epoch',
    'historical_ec339_grants_authorize_new_epoch_signatures_or_actions',
    'four_independent_physical_issuers_and_observer_persons_verified',
    'old_unmocked_ec294_to_ec336_production_history_verified',
    'external_provider_cas_worm_actual_nonexecution_latest_winner_proven',
    'any_business_or_remote_persist_write_performed',
)


def need(value: Any, reason: str, status: str='permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC340_' + reason, status)


def _read(path: str, sha: str, label: str) -> dict:
    doc, _ = old._read_json(path,sha,MAX_JSON,label)
    return doc


def _same(a: Any, b: Any) -> bool:
    return type(a) is str and type(b) is str and hmac.compare_digest(a,b)


def _private_key_public(path: str) -> tuple[Any,str]:
    key = io.private_from_file(path)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex()
    return key,pub


def _load_context(policy_file: str, expected_policy_sha256: str,
                  authority_roster_file: str,
                  expected_authority_roster_sha256: str) -> tuple[dict,dict]:
    policy = _read(policy_file,expected_policy_sha256,'LEGACY_POLICY')
    need(type(policy.get('original_roots')) is dict,
         'LEGACY_POLICY_ROOTS_REQUIRED','invalid_input')
    ceremony._policy_validate(policy,policy['original_roots'])
    roots = old._load_roster(authority_roster_file,
                              expected_authority_roster_sha256,
                              policy,expected_policy_sha256)
    return policy,roots


def _validate_successor(doc: dict, old_roster: dict, old_sha: str,
                        policy: dict, policy_sha: str) -> None:
    need(type(doc) is dict and set(doc)==ROOT_FIELDS and
         doc.get('schema')==ROOT_SCHEMA and
         doc.get('transfer_id')==policy['transfer_id'] and
         doc.get('policy_original_raw_sha256')==policy_sha and
         doc.get('predecessor_roster_original_raw_sha256')==old_sha and
         type(doc.get('epoch')) is int and doc['epoch']==2 and
         ceremony._id(doc.get('rotation_id')) and
         ceremony._sha(doc.get('rotation_nonce_sha256')) and
         ceremony._utc(doc.get('effective_utc')) and
         doc.get('old_root_retired_from_effective_utc') is True and
         doc.get('external_successor_root_trust_required') is True,
         'SUCCESSOR_ROOT_EPOCH2_MUST_BIND_ORIGINAL_POLICY_AND_OLD_ROOT',
         'invalid_input')
    roots = doc.get('issuers')
    need(type(roots) is list and len(roots)==4,
         'FOUR_SUCCESSOR_ROLE_ROOTS_REQUIRED','invalid_input')
    for idx, issuer in enumerate(roots):
        need(type(issuer) is dict and set(issuer)==old.ISSUER_FIELDS and
             issuer.get('role')==ROLES[idx] and
             ceremony._id(issuer.get('issuer_id')) and
             anchor.valid_pub(issuer.get('issuer_public_hex')) and
             issuer.get('subject_organization_id')==
                    policy['actors'][idx]['organization_id'],
             'SUCCESSOR_KEY_ID_ROLE_OR_ORGANIZATION_MISMATCH','invalid_input')
    old_issuers=old_roster['issuers']
    old_ids={x['issuer_id'] for x in old_issuers}
    old_pubs={x['issuer_public_hex'] for x in old_issuers}
    new_ids={x['issuer_id'] for x in roots}
    new_pubs={x['issuer_public_hex'] for x in roots}
    actor_pubs={x['public_hex'] for x in policy['actors']}
    need(len(new_ids)==len(new_pubs)==4 and
         not (new_ids & old_ids) and not (new_pubs & old_pubs) and
         not (new_pubs & actor_pubs),
         'ROOT_ROTATION_MUST_USE_EIGHT_DISTINCT_ISSUER_IDS_KEYS_AND_NO_ACTOR_KEY',
         'invalid_input')


def _load_successor(path: str, sha: str, old_roster: dict, old_sha: str,
                    policy: dict, policy_sha: str) -> dict:
    doc=_read(path,sha,'SUCCESSOR_ROOT')
    _validate_successor(doc,old_roster,old_sha,policy,policy_sha)
    return doc


def _edge_claim(side: str, role: str, new_doc: dict, old_doc: dict,
                old_sha: str, new_sha: str) -> dict:
    need(side in SIDES and role in ROLES,'SIGNED_EDGE_ROLE_SIDE_REQUIRED','invalid_input')
    i=ROLES.index(role)
    issuer=(old_doc if side=='old' else new_doc)['issuers'][i]
    return {'schema':EDGE_CLAIM_SCHEMA,'successor_roster_original_raw_sha256':new_sha,
            'predecessor_roster_original_raw_sha256':old_sha,
            'role':role,'side':side,'issuer_id':issuer['issuer_id'],
            'issuer_public_hex':issuer['issuer_public_hex'],
            'rotation_id':new_doc['rotation_id'],
            'rotation_nonce_sha256':new_doc['rotation_nonce_sha256'],
            'epoch':2,'effective_utc':new_doc['effective_utc']}


def _domain(side: str, role: str) -> bytes:
    need(side in SIDES and role in ROLES,'EDGE_DOMAIN_ROLE_REQUIRED','invalid_input')
    return ('CES/EC340/IssuerRootHandoff/'+side+'/'+role+'/v1\0').encode('ascii')


def _verify_edge(path: str, sha: str, side: str, role: str,
                 new_doc: dict, old_doc: dict, old_sha: str,
                 new_sha: str) -> None:
    doc=_read(path,sha,'SIGNED_EDGE_'+side.upper()+'_'+role.upper())
    claim=_edge_claim(side,role,new_doc,old_doc,old_sha,new_sha)
    need(type(doc) is dict and set(doc)==old.SIGNED_FIELDS and
         doc.get('schema')==EDGE_SCHEMA and doc.get('claim')==claim and
         type(doc.get('signature_ed25519')) is str and
         anchor.SIG.fullmatch(doc['signature_ed25519']) is not None,
         'EDGE_EXACT_CLAIM_AND_ED25519_SIGNATURE_REQUIRED','invalid_input')
    try:
        io.pub_from_hex(claim['issuer_public_hex']).verify(
            bytes.fromhex(doc['signature_ed25519']),
            _domain(side,role)+reg.canonical(claim))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise anchor.AnchorError('EC340_ISSUER_ROOT_CROSS_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _edge_inputs(edge_files: dict, edge_shas: dict) -> tuple[list[str],list[str]]:
    need(type(edge_files) is dict and type(edge_shas) is dict and
         set(edge_files)==set(EDGE_KEYS) and set(edge_shas)==set(EDGE_KEYS),
         'EXACT_EIGHT_OLD_AND_NEW_ROLE_SIGNED_EDGES_REQUIRED','invalid_input')
    paths=[edge_files[k] for k in EDGE_KEYS]
    shas=[edge_shas[k] for k in EDGE_KEYS]
    need(all(ceremony._sha(s) for s in shas) and len(set(shas))==8,
         'EIGHT_DISTINCT_WHOLE_SIGNED_EDGE_SHA_REQUIRED','invalid_input')
    return paths,shas


def _edge_vector(edge_shas: dict) -> list[dict]:
    return [{'side':side,'role':role,'original_raw_sha256':edge_shas[(side,role)]}
            for side,role in EDGE_KEYS]


def _verify_edges(edge_files: dict, edge_shas: dict,
                  successor: dict, predecessor: dict,
                  predecessor_sha: str, successor_sha: str) -> None:
    _edge_inputs(edge_files,edge_shas)
    for side,role in EDGE_KEYS:
        _verify_edge(edge_files[(side,role)],edge_shas[(side,role)],
                     side,role,successor,predecessor,predecessor_sha,successor_sha)


def _load_observer_root(path: str, sha: str, policy: dict, policy_sha: str,
                        predecessor: dict, successor: dict) -> dict:
    doc=_read(path,sha,'INDEPENDENT_OBSERVER_ROOT')
    need(type(doc) is dict and set(doc)==OBSERVER_ROOT_FIELDS and
         doc.get('schema')==OBSERVER_ROOT_SCHEMA and
         doc.get('transfer_id')==policy['transfer_id'] and
         doc.get('policy_original_raw_sha256')==policy_sha and
         ceremony._id(doc.get('observer_id')) and
         ceremony._id(doc.get('observer_organization_id')) and
         anchor.valid_pub(doc.get('observer_public_hex')) and
         doc.get('independent_out_of_band_approval_required') is True,
         'OBSERVER_EXTERNAL_ROOT_FIELDS_AND_POLICY_BINDING_REQUIRED',
         'invalid_input')
    old_new=[*predecessor['issuers'],*successor['issuers']]
    need(doc['observer_public_hex'] not in
           {i['issuer_public_hex'] for i in old_new} and
         doc['observer_public_hex'] not in
           {a['public_hex'] for a in policy['actors']} and
         doc['observer_id'] not in {i['issuer_id'] for i in old_new} and
         doc['observer_organization_id'] not in
           {a['organization_id'] for a in policy['actors']},
         'OBSERVER_KEY_ID_OR_ORG_MUST_BE_DECLARED_INDEPENDENT',
         'invalid_input')
    return doc


def _observe_claim(*, predecessor_sha: str, successor_sha: str,
                   witness_sha: str, edge_shas: dict, new_doc: dict,
                   verifier_challenge_sha256: str, observed_utc: str,
                   expires_utc: str) -> dict:
    need(ceremony._sha(verifier_challenge_sha256),
         'FRESH_OUT_OF_BAND_CHALLENGE_REQUIRED','invalid_input')
    old._interval(observed_utc,expires_utc,timedelta(hours=24),
                  'OBSERVATION_VALIDITY_MUST_NOT_EXCEED_24H')
    need(old._time(new_doc['effective_utc'])<=old._time(observed_utc),
         'CANNOT_ATTEST_ROOT_RETIRED_BEFORE_EFFECTIVE_UTC','invalid_input')
    return {'schema':OBSERVER_CLAIM_SCHEMA,
            'predecessor_roster_original_raw_sha256':predecessor_sha,
            'successor_roster_original_raw_sha256':successor_sha,
            'observer_trust_original_raw_sha256':witness_sha,
            'edge_signature_original_raw_sha256s':_edge_vector(edge_shas),
            'rotation_id':new_doc['rotation_id'],
            'rotation_nonce_sha256':new_doc['rotation_nonce_sha256'],
            'epoch':2,'verifier_challenge_sha256':verifier_challenge_sha256,
            'observed_utc':observed_utc,'expires_utc':expires_utc,
            'predecessor_root_state':'retired',
            'successor_root_state':'active'}


def _verify_observation(path: str, sha: str, observer: dict,
                        expected: dict, root_evaluation_utc: str) -> None:
    doc=_read(path,sha,'SIGNED_ROOT_OBSERVATION')
    need(type(doc) is dict and set(doc)==old.SIGNED_FIELDS and
         doc.get('schema')==OBSERVER_SCHEMA and doc.get('claim')==expected and
         type(doc.get('signature_ed25519')) is str and
         anchor.SIG.fullmatch(doc['signature_ed25519']) is not None,
         'OBSERVER_EXACT_RETIREMENT_CURRENT_ROOT_AND_CHALLENGE_REQUIRED',
         'invalid_input')
    need(old._time(expected['observed_utc'])<=old._time(root_evaluation_utc)
         <old._time(expected['expires_utc']),
         'OBSERVER_STATUS_EXPIRED_OR_FUTURE_AT_OPERATOR_ROOT_EVALUATION',
         'permission_denied')
    try:
        io.pub_from_hex(observer['observer_public_hex']).verify(
            bytes.fromhex(doc['signature_ed25519']),
            b'CES/EC340/IndependentRootRetirementObservation/v1\0'+
            reg.canonical(expected))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise anchor.AnchorError('EC340_OBSERVER_STATUS_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _late(paths: list[str], shas: list[str]) -> None:
    for p,sha in zip(paths,shas):
        need(_same(case.sha(reg._private_read(p,MAX_JSON,'EC340_LATE_PIN')),sha),
             'ORIGINAL_SOURCE_CHANGED_DURING_ROOT_AUDIT')


def _paths(*paths: str) -> None:
    old._path_set(list(paths))


def create_successor_roster(*, out: str, policy_file: str,
                            expected_policy_sha256: str,
                            authority_roster_file: str,
                            expected_authority_roster_sha256: str,
                            issuer_config_file: str,
                            expected_issuer_config_sha256: str,
                            rotation_id: str, rotation_nonce_sha256: str,
                            effective_utc: str) -> dict:
    """Create an unsigned successor candidate; never self-approve its SHA."""
    _paths(out,policy_file,authority_roster_file,issuer_config_file)
    policy,old_roster=_load_context(policy_file,expected_policy_sha256,
                                    authority_roster_file,
                                    expected_authority_roster_sha256)
    cfg=_read(issuer_config_file,expected_issuer_config_sha256,'ISSUER_INPUT_CONFIG')
    need(type(cfg) is dict and set(cfg)=={'issuers'},
         'EXACT_ISSUER_CONFIG_REQUIRED','invalid_input')
    doc={'schema':ROOT_SCHEMA,'transfer_id':policy['transfer_id'],
         'policy_original_raw_sha256':expected_policy_sha256,
         'predecessor_roster_original_raw_sha256':expected_authority_roster_sha256,
         'epoch':2,'rotation_id':rotation_id,
         'rotation_nonce_sha256':rotation_nonce_sha256,
         'effective_utc':effective_utc,'issuers':cfg['issuers'],
         'old_root_retired_from_effective_utc':True,
         'external_successor_root_trust_required':True}
    _validate_successor(doc,old_roster,expected_authority_roster_sha256,
                        policy,expected_policy_sha256)
    sha=old._write_and_check(out,doc,[policy_file,authority_roster_file,
                                        issuer_config_file],late_recheck=lambda: _late(
           [policy_file,authority_roster_file,issuer_config_file],
           [expected_policy_sha256,expected_authority_roster_sha256,
            expected_issuer_config_sha256]))
    return _candidate('create-roster','successor_root_original_raw_sha256_local_untrusted',sha)


def sign_edge(*, out: str, private_key_file: str, side: str, role: str,
              policy_file: str, expected_policy_sha256: str,
              authority_roster_file: str, expected_authority_roster_sha256: str,
              successor_roster_file: str, expected_successor_roster_sha256: str) -> dict:
    _paths(out,private_key_file,policy_file,authority_roster_file,
           successor_roster_file)
    policy,predecessor=_load_context(policy_file,expected_policy_sha256,
                                     authority_roster_file,
                                     expected_authority_roster_sha256)
    successor=_load_successor(successor_roster_file,expected_successor_roster_sha256,
                              predecessor,expected_authority_roster_sha256,
                              policy,expected_policy_sha256)
    claim=_edge_claim(side,role,successor,predecessor,
                      expected_authority_roster_sha256,
                      expected_successor_roster_sha256)
    key,pub=_private_key_public(private_key_file)
    need(_same(pub,claim['issuer_public_hex']),
         'PRIVATE_KEY_MUST_MATCH_PINNED_SIDE_AND_ROLE_ROOT')
    doc={'schema':EDGE_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(_domain(side,role)+reg.canonical(claim)).hex()}
    sha=old._write_and_check(out,doc,[private_key_file,policy_file,
          authority_roster_file,successor_roster_file],late_recheck=lambda: _late(
          [policy_file,authority_roster_file,successor_roster_file],
          [expected_policy_sha256,expected_authority_roster_sha256,
           expected_successor_roster_sha256]))
    return _candidate('sign-edge','edge_signature_original_raw_sha256_local_untrusted',
                      sha,side=side,role=role)


def issue_observation(*, out: str, private_key_file: str,
                      policy_file: str, expected_policy_sha256: str,
                      authority_roster_file: str,
                      expected_authority_roster_sha256: str,
                      successor_roster_file: str,
                      expected_successor_roster_sha256: str,
                      observer_roster_file: str,
                      expected_observer_roster_sha256: str,
                      edge_files: dict, edge_shas: dict,
                      verifier_challenge_sha256: str,
                      observed_utc: str, expires_utc: str) -> dict:
    edge_paths,sha_list=_edge_inputs(edge_files,edge_shas)
    all_paths=[out,private_key_file,policy_file,authority_roster_file,
               successor_roster_file,observer_roster_file,*edge_paths]
    _paths(*all_paths)
    policy,predecessor=_load_context(policy_file,expected_policy_sha256,
                                     authority_roster_file,
                                     expected_authority_roster_sha256)
    successor=_load_successor(successor_roster_file,expected_successor_roster_sha256,
                              predecessor,expected_authority_roster_sha256,
                              policy,expected_policy_sha256)
    witness=_load_observer_root(observer_roster_file,expected_observer_roster_sha256,
                                policy,expected_policy_sha256,
                                predecessor,successor)
    _verify_edges(edge_files,edge_shas,successor,predecessor,
                  expected_authority_roster_sha256,expected_successor_roster_sha256)
    claim=_observe_claim(predecessor_sha=expected_authority_roster_sha256,
        successor_sha=expected_successor_roster_sha256,
        witness_sha=expected_observer_roster_sha256,edge_shas=edge_shas,
        new_doc=successor,verifier_challenge_sha256=verifier_challenge_sha256,
        observed_utc=observed_utc,expires_utc=expires_utc)
    key,pub=_private_key_public(private_key_file)
    need(_same(pub,witness['observer_public_hex']),
         'OBSERVER_PRIVATE_KEY_MUST_MATCH_INDEPENDENT_PINNED_KEY')
    doc={'schema':OBSERVER_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(
             b'CES/EC340/IndependentRootRetirementObservation/v1\0'+
             reg.canonical(claim)).hex()}
    sources=all_paths[2:]
    shas=[expected_policy_sha256,expected_authority_roster_sha256,
          expected_successor_roster_sha256,expected_observer_roster_sha256,*sha_list]
    _late(sources,shas)
    sha=old._write_and_check(out,doc,all_paths[1:],late_recheck=lambda: _late(
        sources,shas))
    return _candidate('issue-observation',
                      'root_observation_original_raw_sha256_local_untrusted',sha)


def _candidate(command: str, field: str, sha: str, **details: Any) -> dict:
    return {'schema':RESULT_SCHEMA,'command':command,'exit_code':2,
            'status':'owner_private_local_candidate_not_independently_trusted',
            field:sha,**details,
            'external_root_and_witness_trust_still_required':True,
            **{field:False for field in NEGATIVES}}


def verify_rotation(*, policy_file: str, expected_policy_sha256: str,
                    authority_roster_file: str,
                    expected_authority_roster_sha256: str,
                    successor_roster_file: str,
                    expected_successor_roster_sha256: str,
                    expected_current_root_sha256: str,
                    expected_current_root_epoch: int,
                    observer_roster_file: str,
                    expected_observer_roster_sha256: str,
                    root_observation_file: str,
                    expected_root_observation_sha256: str,
                    edge_files: dict, edge_shas: dict,
                    root_evaluation_utc: str,
                    verifier_challenge_sha256: str,
                    **ec339_base: str) -> dict:
    """Verify exactly one historical EC339 epoch-1 -> epoch-2 root transition.

    Never authorize using legacy grants at/after successor effective_utc;
    this command attests only separately pinned *historical* EC339 material.
    """
    edge_paths,sha_list=_edge_inputs(edge_files,edge_shas)
    paths=[policy_file,authority_roster_file,successor_roster_file,
           observer_roster_file,root_observation_file,*edge_paths]
    _paths(*paths)
    need(type(expected_current_root_epoch) is int and
         expected_current_root_epoch==2,
         'INDEPENDENT_CURRENT_ROOT_EPOCH_MUST_EQUAL_TWO_FOR_ONE_HOP',
         'invalid_input')
    need(ceremony._sha(expected_current_root_sha256) and
         _same(expected_current_root_sha256,expected_successor_roster_sha256),
         'EXTERNAL_CURRENT_ROOT_PIN_MUST_MATCH_SUCCESSOR_OR_REJECT_ROLLBACK',
         'invalid_input')
    need(ceremony._sha(verifier_challenge_sha256),
         'INDEPENDENT_CHALLENGE_SHA_REQUIRED','invalid_input')
    root_eval=old._time(root_evaluation_utc)
    historical_eval=old._time(ec339_base['evaluation_utc'])
    need(root_eval>=historical_eval,'ROOT_AUDIT_MUST_NOT_PRECEDE_HISTORICAL_EC339',
         'invalid_input')
    policy,predecessor=_load_context(policy_file,expected_policy_sha256,
                                     authority_roster_file,
                                     expected_authority_roster_sha256)
    successor=_load_successor(successor_roster_file,expected_successor_roster_sha256,
                              predecessor,expected_authority_roster_sha256,
                              policy,expected_policy_sha256)
    effective=old._time(successor['effective_utc'])
    need(historical_eval<effective<=root_eval,
         'HISTORICAL_EC339_MUST_PREDATE_RETIRED_ROOT_EFFECTIVE_TIME',
         'permission_denied')
    witness=_load_observer_root(observer_roster_file,expected_observer_roster_sha256,
                                policy,expected_policy_sha256,
                                predecessor,successor)
    _verify_edges(edge_files,edge_shas,successor,predecessor,
                  expected_authority_roster_sha256,expected_successor_roster_sha256)
    observation=_read(root_observation_file,expected_root_observation_sha256,
                      'SIGNED_ROOT_OBSERVATION')
    need(type(observation) is dict and type(observation.get('claim')) is dict,
         'STRICT_ROOT_OBSERVATION_CLAIM_REQUIRED','invalid_input')
    cl=observation['claim']
    need(set(cl)==OBSERVATION_FIELDS and
         ceremony._utc(cl.get('observed_utc')) and
         ceremony._utc(cl.get('expires_utc')),
         'SIGNED_OBSERVATION_HAS_EXACT_TIME_AND_SCHEMA','invalid_input')
    expected=_observe_claim(predecessor_sha=expected_authority_roster_sha256,
        successor_sha=expected_successor_roster_sha256,
        witness_sha=expected_observer_roster_sha256,
        edge_shas=edge_shas,new_doc=successor,
        verifier_challenge_sha256=verifier_challenge_sha256,
        observed_utc=cl['observed_utc'],expires_utc=cl['expires_utc'])
    _verify_observation(root_observation_file,expected_root_observation_sha256,
                        witness,expected,root_evaluation_utc)
    # After rejecting false/stale/cross-signed roots, really replay EC339.
    # Legacy file paths and signature domains remain entirely untouched.
    inherited=old.verify_authority(policy_file=policy_file,
              expected_policy_sha256=expected_policy_sha256,
              authority_roster_file=authority_roster_file,
              expected_authority_roster_sha256=expected_authority_roster_sha256,
              verifier_challenge_sha256=verifier_challenge_sha256,
              **ec339_base)
    need(inherited.get('schema')==old.RESULT_SCHEMA and
         inherited.get('exit_code')==2 and
         inherited.get('status')==
           'four_role_issuer_grants_and_challenged_status_verified_local_unresolved' and
         inherited.get('issuer_approved_role_count')==4 and
         inherited.get('active_status_signed_count')==4 and
         inherited.get('ec338_four_signed_receipts_verified') is True and
         inherited.get('ec337_complete_archive_and_nested_originals_verified') is True and
         all(inherited.get(f) is False for f in old.FALSE_FIELDS),
         'REAL_EC339_TO_EC337_FULL_REPLAY_REQUIRED')
    # A historical actor's *self-declared* receipt time after retirement must
    # never be presented as a pre-rotation receipt, regardless of signature.
    receipt_shas=[]; receipt_files=[]
    for r in ROLES:
        rfile=ec339_base[r+'_receipt_file']
        rsha=ec339_base['expected_'+r+'_receipt_sha256']
        receipt=_read(rfile,rsha,'HISTORICAL_RECEIPT_'+r.upper())
        need(old._time(receipt['claim']['signer_reported_utc'])<effective,
             'OLD_ISSUER_RECEIPT_SELF_DECLARED_AFTER_RETIREMENT')
        receipt_files.append(rfile);receipt_shas.append(rsha)
    _late(paths,[expected_policy_sha256,expected_authority_roster_sha256,
                 expected_successor_roster_sha256,expected_observer_roster_sha256,
                 expected_root_observation_sha256,*sha_list])
    _late(receipt_files,receipt_shas)
    # No EC339 grant/status may be swapped during the additional EC340 work.
    # The EC337 transport ZIP also gets a fresh whole-file check after all
    # inherited original/nested verification (this is not a new CAS write).
    old_files=[ec339_base[role+'_'+kind+'_file'] for role in ROLES
               for kind in ('grant','status')]
    old_shas=[ec339_base['expected_'+role+'_'+kind+'_sha256'] for role in ROLES
              for kind in ('grant','status')]
    _late(old_files,old_shas)
    need(_same(ceremony.transport._sha_path(ec339_base['bundle_file']),
               ec339_base['expected_bundle_sha256']),
         'LATE_EC337_WHOLE_TRANSPORT_ZIP_CHANGED')
    # EC339 already rechecked all originals and nested archive members.
    # Refresh the two distinct epoch roots immediately before returning.
    _late([authority_roster_file,successor_roster_file],
          [expected_authority_roster_sha256,expected_successor_roster_sha256])
    return {'schema':RESULT_SCHEMA,'command':'verify-rotation',
            'status':'historical_old_epoch_and_cross_signed_successor_locally_verified_unresolved',
            'exit_code':2,'transfer_id':policy['transfer_id'],
            'policy_original_raw_sha256':expected_policy_sha256,
            'predecessor_roster_original_raw_sha256':expected_authority_roster_sha256,
            'successor_roster_original_raw_sha256':expected_successor_roster_sha256,
            'external_current_root_sha256':expected_current_root_sha256,
            'external_current_root_epoch':2,
            'observer_trust_original_raw_sha256':expected_observer_roster_sha256,
            'root_observation_original_raw_sha256':expected_root_observation_sha256,
            'edge_signature_original_raw_sha256s':_edge_vector(edge_shas),
            'historical_ec339_evaluation_utc':ec339_base['evaluation_utc'],
            'successor_effective_utc':successor['effective_utc'],
            'operator_root_evaluation_utc':root_evaluation_utc,
            'verifier_challenge_sha256':verifier_challenge_sha256,
            'eight_separate_old_new_ed25519_signatures_verified':True,
            'independent_observer_challenged_signed_retirement_verified':True,
            'root_epoch_and_current_sha_external_rollback_floor_checked':True,
            'historical_ec339_to_ec337_original_full_replay_verified':True,
            'historical_ec339_not_accepted_as_new_epoch_authorization':True,
            'new_eleven_original_sha_pins_plus_21_old_sha_required':True,
            'offline_unresolved_exit_code':2,
            **{field:False for field in NEGATIVES}}
