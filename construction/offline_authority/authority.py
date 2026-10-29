#!/usr/bin/env python3
"""EC339 externally pinned, locally verifiable issuer authority evidence.

A SHA-pinned issuer roster is an OUT-OF-BAND trust input. Each of four issuer
keys signs one actor's grant and one role/grant/challenge-bound status assertion.
Neither a SHA nor an issuer signature verifies the legal reality of an institution,
the completeness of a revocation database or the existence of a trusted clock.
All accepted audits remain exit 2 / unresolved, including after genuine EC338
four-receipt verification and full EC337 original nested ZIP inspection.

Crucial ordering: issue grants BEFORE creating the immutable EC338 policy, whose
actor.authorization_reference_sha256 equals the corresponding whole signed
grant SHA. Grants therefore bind the transfer and original bundle, NOT the
EC338 policy SHA (that would create a circular whole-file hash dependency).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hmac
import os
import stat
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from finding_query_host import protocol as io
from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from dual_channel_receipt import receipt as prior
from independent_custody import ceremony

ROLES = ceremony.ROLES
ROSTER_SCHEMA = 'ces.ec339.externally_pinned_role_issuer_roster.v1'
GRANT_CLAIM_SCHEMA = 'ces.ec339.role_issuer_authorization_grant_claim.v1'
GRANT_SCHEMA = 'ces.ec339.ed25519_role_issuer_authorization_grant.v1'
STATUS_CLAIM_SCHEMA = 'ces.ec339.challenged_role_grant_status_claim.v1'
STATUS_SCHEMA = 'ces.ec339.ed25519_role_grant_revocation_status.v1'
RESULT_SCHEMA = 'ces.ec339.four_role_issuer_grant_and_revocation_audit_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec339.role_issuer_evidence_denial.v1'
ROSTER_FIELDS = frozenset({'schema','transfer_id','policy_original_raw_sha256',
                           'issuers','external_issuer_trust_and_rotation_required'})
ISSUER_FIELDS = frozenset({'role','issuer_id','issuer_public_hex',
                           'subject_organization_id'})
GRANT_FIELDS = frozenset({'schema','transfer_id','bundle_original_raw_sha256',
                          'role','issuer_id','grant_id','actor_id','organization_id',
                          'subject_public_hex','issued_utc','not_before_utc',
                          'not_after_utc'})
STATUS_FIELDS = frozenset({'schema','transfer_id','role','issuer_id','grant_id',
                           'grant_original_raw_sha256','verifier_challenge_sha256',
                           'state','as_of_utc','expires_utc','revoked_effective_utc'})
SIGNED_FIELDS = frozenset({'schema','claim','signature_ed25519'})
MAX_ROSTER = 12_000
MAX_SIGNED = 10_000
MAX_GRANT_LIFETIME = timedelta(days=366)
MAX_STATUS_LIFETIME = timedelta(hours=24)
FALSE_FIELDS = (
    'issuer_roster_whole_sha_self_certifies_real_issuer_authority',
    'issuer_signature_proves_actual_revocation_database_completeness',
    'operator_supplied_evaluation_utc_is_a_trusted_clock',
    'challenge_hash_alone_proves_real_time_or_latest_issuer_status',
    'signed_claims_prove_four_actual_independent_people_or_physical_custody',
    'ec336_unmocked_complete_old_signed_history_replayed_by_this_command',
    'remote_cas_worm_actual_nonexecution_latest_winner_proven',
    'any_external_provider_or_cas_write_performed',
)


def need(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC339_' + reason, status)


def _time(value: Any) -> datetime:
    need(ceremony._utc(value), 'STRICT_UTC_SECONDS_REQUIRED', 'invalid_input')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def _interval(start: str, end: str, maximum: timedelta, reason: str) -> None:
    left, right = _time(start), _time(end)
    need(left < right and right-left <= maximum, reason, 'invalid_input')


def _actor_fields(role: Any, actor_id: Any, org: Any, public_hex: Any,
                  issuer_id: Any, grant_id: Any) -> None:
    need(role in ROLES and ceremony._id(actor_id) and ceremony._id(org) and
         ceremony._id(issuer_id) and ceremony._id(grant_id) and
         anchor.valid_pub(public_hex),
         'ROLE_ACTOR_ORGANIZATION_ISSUER_GRANT_AND_PUBLIC_REQUIRED', 'invalid_input')


def _domain(kind: str, role: str) -> bytes:
    need(kind in ('Grant','Status') and role in ROLES,
         'ONLY_ROLE_SEPARATED_ISSUER_DOMAINS', 'invalid_input')
    return (b'CES/EC339/Issuer' + kind.encode('ascii') + b'/' +
            role.encode('ascii') + b'/v1\0')


def _read_json(path: str, expected_sha: str, limit: int, label: str) -> tuple[dict, bytes]:
    need(ceremony._sha(expected_sha), label+'_INDEPENDENT_RAW_SHA_REQUIRED',
         'invalid_input')
    raw=reg._private_read(path,limit,'EC339_'+label)
    need(hmac.compare_digest(case.sha(raw),expected_sha),
         label+'_NOT_EQUAL_INDEPENDENT_WHOLE_SHA')
    doc=io.parse(raw,limit)
    need(raw == reg.raw_doc(doc) and type(doc) is dict,
         label+'_MUST_BE_CANONICAL_EXACT_LF_JSON', 'invalid_input')
    return doc,raw


def _load_roster(path: str, sha: str, policy: dict, policy_sha: str) -> dict:
    roster,_=_read_json(path,sha,MAX_ROSTER,'ISSUER_ROSTER')
    need(set(roster)==ROSTER_FIELDS and roster.get('schema')==ROSTER_SCHEMA and
         roster.get('transfer_id')==policy['transfer_id'] and
         roster.get('policy_original_raw_sha256')==policy_sha and
         roster.get('external_issuer_trust_and_rotation_required') is True,
         'EXTERNALLY_ROOTED_ROSTER_MUST_BIND_EXACT_EC338_POLICY', 'invalid_input')
    issuers=roster.get('issuers')
    need(type(issuers) is list and len(issuers)==4,
         'FOUR_ORDERED_ISSUER_ROOTS_REQUIRED', 'invalid_input')
    actors=policy['actors']
    for i, issuer in enumerate(issuers):
        need(type(issuer) is dict and set(issuer)==ISSUER_FIELDS and
             issuer.get('role')==ROLES[i] and
             ceremony._id(issuer.get('issuer_id')) and
             anchor.valid_pub(issuer.get('issuer_public_hex')) and
             issuer.get('subject_organization_id')==actors[i]['organization_id'],
             'ISSUER_ROLE_KEY_OR_PERMITTED_ORGANIZATION_MISMATCH', 'invalid_input')
    need(len({item['issuer_public_hex'] for item in issuers})==4 and
         len({item['issuer_id'] for item in issuers})==4 and
         not ({item['issuer_public_hex'] for item in issuers} &
              {actor['public_hex'] for actor in actors}),
         'FOUR_DISTINCT_ISSUER_KEYS_MUST_NOT_BE_ROLE_SIGNER_KEYS', 'invalid_input')
    return roster


def _verify_sig(doc: dict, schema: str, claim_schema: str,
                public_hex: str, domain: bytes, kind: str) -> dict:
    need(type(doc) is dict and set(doc)==SIGNED_FIELDS and
         doc.get('schema')==schema and
         type(doc.get('claim')) is dict and
         doc['claim'].get('schema')==claim_schema and
         type(doc.get('signature_ed25519')) is str and
         anchor.SIG.fullmatch(doc['signature_ed25519']) is not None,
         kind+'_SIGNED_CANONICAL_FIELDS_REQUIRED', 'invalid_input')
    try:
        io.pub_from_hex(public_hex).verify(
            bytes.fromhex(doc['signature_ed25519']),
            domain+reg.canonical(doc['claim']))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise anchor.AnchorError('EC339_'+kind+'_ED25519_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return doc['claim']


def _grant_claim(claim: dict, issuer: dict, actor: dict, policy: dict) -> None:
    need(type(claim) is dict and set(claim)==GRANT_FIELDS and
         claim.get('schema')==GRANT_CLAIM_SCHEMA and
         claim.get('transfer_id')==policy['transfer_id'] and
         claim.get('bundle_original_raw_sha256')==
            policy['original_roots']['bundle_original_raw_sha256'] and
         claim.get('role')==actor['role']==issuer['role'] and
         claim.get('issuer_id')==issuer['issuer_id'] and
         ceremony._id(claim.get('grant_id')) and
         claim.get('actor_id')==actor['actor_id'] and
         claim.get('organization_id')==actor['organization_id'] and
         claim.get('subject_public_hex')==actor['public_hex'],
         'GRANT_CANNOT_BIND_TO_OTHER_ACTOR_ROLE_ISSUER_OR_BUNDLE', 'invalid_input')
    _interval(claim.get('not_before_utc'),claim.get('not_after_utc'),
              MAX_GRANT_LIFETIME,'GRANT_VALIDITY_WINDOW_INVALID')
    when=_time(claim.get('issued_utc'))
    need(when<=_time(claim['not_after_utc']),
         'GRANT_ISSUED_AFTER_ITS_EXPIRATION', 'invalid_input')


def _load_grant(path: str, sha: str, issuer: dict,
                actor: dict, policy: dict) -> dict:
    need(hmac.compare_digest(sha,actor['authorization_reference_sha256']),
         'EC338_ACTOR_AUTHORIZATION_REFERENCE_NOT_SIGNED_GRANT_WHOLE_SHA')
    doc,_=_read_json(path,sha,MAX_SIGNED,'SIGNED_GRANT_'+actor['role'].upper())
    claim=_verify_sig(doc,GRANT_SCHEMA,GRANT_CLAIM_SCHEMA,
                      issuer['issuer_public_hex'],_domain('Grant',actor['role']),
                      'GRANT')
    _grant_claim(claim,issuer,actor,policy)
    return claim


def _status_claim(claim: dict, issuer: dict, grant: dict, grant_sha: str,
                  challenge_sha: str, evaluation_utc: str) -> None:
    need(type(claim) is dict and set(claim)==STATUS_FIELDS and
         claim.get('schema')==STATUS_CLAIM_SCHEMA and
         claim.get('transfer_id')==grant['transfer_id'] and
         claim.get('role')==grant['role']==issuer['role'] and
         claim.get('issuer_id')==issuer['issuer_id'] and
         claim.get('grant_id')==grant['grant_id'] and
         claim.get('grant_original_raw_sha256')==grant_sha and
         claim.get('verifier_challenge_sha256')==challenge_sha and
         claim.get('state') in ('active','revoked'),
         'STATUS_MUST_BIND_ISSUER_ROLE_GRANT_AND_VERIFIER_CHALLENGE',
         'invalid_input')
    _interval(claim.get('as_of_utc'),claim.get('expires_utc'),
              MAX_STATUS_LIFETIME,'STATUS_WINDOW_MUST_BE_AT_MOST_24H')
    when=_time(evaluation_utc)
    need(_time(claim['as_of_utc'])<=when<_time(claim['expires_utc']),
         'STATUS_WINDOW_NOT_VALID_AT_OPERATOR_EVALUATION_UTC', 'invalid_input')
    revoked=claim.get('revoked_effective_utc')
    need((claim['state']=='active' and revoked is None) or
         (claim['state']=='revoked' and ceremony._utc(revoked)),
         'SIGNED_REVOCATION_STATE_AND_EFFECTIVE_TIME_INCONSISTENT',
         'invalid_input')
    # Conservative: any signed revoked report fails, even future-dated.
    need(claim['state']=='active','ISSUER_SIGNED_GRANT_REVOKED')


def _load_status(path: str, sha: str, issuer: dict, grant: dict,
                 grant_sha: str, challenge_sha: str,
                 evaluation_utc: str) -> dict:
    doc,_=_read_json(path,sha,MAX_SIGNED,'SIGNED_STATUS_'+issuer['role'].upper())
    claim=_verify_sig(doc,STATUS_SCHEMA,STATUS_CLAIM_SCHEMA,
                      issuer['issuer_public_hex'],_domain('Status',issuer['role']),
                      'STATUS')
    _status_claim(claim,issuer,grant,grant_sha,challenge_sha,evaluation_utc)
    return claim


def _path_set(paths: list[str]) -> None:
    need(all(type(p) is str and reg.original._valid_path(p) for p in paths) and
         len(set(paths))==len(paths),
         'EACH_ORIGINAL_SOURCE_MUST_USE_DISTINCT_NORMALIZED_ABSOLUTE_PATH',
         'invalid_input')


def _role_map(names: list[str], shas: list[str]) -> dict[str,str]:
    return dict(zip(ROLES,shas))


def _late_pin(paths: list[str], shas: list[str], labels: list[str]) -> None:
    for path,sha,label in zip(paths,shas,labels):
        limit=MAX_ROSTER if label in ('POLICY','ROSTER') else MAX_SIGNED
        raw=reg._private_read(path,limit,'EC339_LATE_'+label)
        need(hmac.compare_digest(case.sha(raw),sha),
             'LATE_'+label+'_WHOLE_RAW_SHA_CHANGED')


def _core_args(*, authority_roster_file: str, expected_authority_roster_sha256: str,
               grant_files: list[str], grant_shas: list[str],
               status_files: list[str], status_shas: list[str],
               evaluation_utc: str, verifier_challenge_sha256: str,
               **base: str) -> dict:
    need(ceremony._sha(verifier_challenge_sha256),
         'EXTERNALLY_CHOSEN_NONZERO_FRESH_CHALLENGE_REQUIRED','invalid_input')
    _time(evaluation_utc)
    need(len(grant_files)==len(grant_shas)==len(status_files)==len(status_shas)==4 and
         all(ceremony._sha(s) for s in [expected_authority_roster_sha256,
                                         *grant_shas,*status_shas]),
         'NINE_ADDITIONAL_EXPLICIT_WHOLE_SHA_PINS_REQUIRED', 'invalid_input')
    receipt_files=[base[r+'_receipt_file'] for r in ROLES]
    receipt_shas=[base['expected_'+r+'_receipt_sha256'] for r in ROLES]
    paths=[base['policy_file'],base['bundle_file'],*receipt_files,
           authority_roster_file,*grant_files,*status_files]
    _path_set(paths)
    # Call genuine EC338 original verifier, including genuine EC337 whole ZIP
    # and all old nested ZIP member checks. Never accept its claimed success
    # without the expected complete local semantics / all negative flags.
    result=ceremony.verify_chain(**base)
    need(result.get('schema')==ceremony.RESULT_SCHEMA and
         result.get('status')==
            'four_role_pinned_local_signature_and_original_bytes_verified_unresolved' and
         result.get('exit_code')==2 and
         result.get('signature_count_verified')==4 and
         result.get('ec337_complete_archive_and_nested_originals_verified') is True and
         result.get('whole_receipt_external_sha_and_previous_raw_sha_chain_verified') is True and
         all(result.get(field) is False for field in ceremony.FALSE_FIELDS),
         'INHERITED_EC338_FULL_VERIFICATION_NOT_PROVEN')
    roots=ceremony._roots({k:base[k] for _,k in ceremony.ROOT_MAP})
    policy,_=ceremony._load_policy(base['policy_file'],base['expected_policy_sha256'],roots)
    roster=_load_roster(authority_roster_file,expected_authority_roster_sha256,
                        policy,base['expected_policy_sha256'])
    prev=ceremony.ZERO
    grant_ids=set()
    for index,role in enumerate(ROLES):
        actor=policy['actors'][index]
        issuer=roster['issuers'][index]
        receipt,raw=ceremony._load_receipt(receipt_files[index],receipt_shas[index],
             policy,base['expected_policy_sha256'],index,prev)
        prev=case.sha(raw)
        grant=_load_grant(grant_files[index],grant_shas[index],issuer,actor,policy)
        need(grant['grant_id'] not in grant_ids,
             'GRANT_ID_REUSED_ACROSS_FOUR_ISSUERS','invalid_input')
        grant_ids.add(grant['grant_id'])
        start,end=_time(grant['not_before_utc']),_time(grant['not_after_utc'])
        need(start<=_time(evaluation_utc)<end,
             'GRANT_NOT_VALID_AT_EVALUATION_UTC')
        # Reported receipt time is a signed *claim*, not a trusted clock.
        need(start<=_time(receipt['claim']['signer_reported_utc'])<end,
             'SIGNED_RECEIPT_DECLARED_TIME_OUTSIDE_ISSUER_GRANT_WINDOW')
        _load_status(status_files[index],status_shas[index],issuer,grant,
                     grant_shas[index],verifier_challenge_sha256,evaluation_utc)
    _late_pin([base['policy_file'],*receipt_files,authority_roster_file,
               *grant_files,*status_files],
              [base['expected_policy_sha256'],*receipt_shas,
               expected_authority_roster_sha256,*grant_shas,*status_shas],
              ['POLICY',*('RECEIPT_'+r.upper() for r in ROLES),'ROSTER',
               *('GRANT_'+r.upper() for r in ROLES),
               *('STATUS_'+r.upper() for r in ROLES)])
    need(ceremony.transport._sha_path(base['bundle_file'])==base['expected_bundle_sha256'],
         'LATE_EC337_ARCHIVE_WHOLE_SHA_CHANGED')
    return {'schema':RESULT_SCHEMA,'command':'verify-authority',
            'status':'four_role_issuer_grants_and_challenged_status_verified_local_unresolved',
            'exit_code':2,'transfer_id':policy['transfer_id'],
            'policy_original_raw_sha256':base['expected_policy_sha256'],
            'authority_roster_original_raw_sha256':expected_authority_roster_sha256,
            'bundle_original_raw_sha256':base['expected_bundle_sha256'],
            'receipt_original_raw_sha256s':_role_map(receipt_files,receipt_shas),
            'grant_original_raw_sha256s':_role_map(grant_files,grant_shas),
            'status_original_raw_sha256s':_role_map(status_files,status_shas),
            'evaluation_utc':evaluation_utc,
            'verifier_challenge_sha256':verifier_challenge_sha256,
            'issuer_approved_role_count':4,'active_status_signed_count':4,
            'ec338_four_signed_receipts_verified':True,
            'ec337_complete_archive_and_nested_originals_verified':True,
            'declared_receipt_times_within_grant_windows':True,
            'issuer_sig_and_grant_actor_role_key_bound':True,
            'signed_status_challenge_and_time_window_verified':True,
            'external_custody_of_all_twenty_one_raw_sha_pins_required':True,
            'ec336_old_signed_history_must_run_separately':True,
            'offline_unresolved_exit_code':2,
            **{key:False for key in FALSE_FIELDS}}


def verify_authority(*, authority_roster_file: str,
                     expected_authority_roster_sha256: str,
                     sender_grant_file: str, expected_sender_grant_sha256: str,
                     carrier_grant_file: str, expected_carrier_grant_sha256: str,
                     receiver_grant_file: str, expected_receiver_grant_sha256: str,
                     witness_grant_file: str, expected_witness_grant_sha256: str,
                     sender_status_file: str, expected_sender_status_sha256: str,
                     carrier_status_file: str, expected_carrier_status_sha256: str,
                     receiver_status_file: str, expected_receiver_status_sha256: str,
                     witness_status_file: str, expected_witness_status_sha256: str,
                     evaluation_utc: str, verifier_challenge_sha256: str,
                     **base: str) -> dict:
    """Read-only complete EC338+339 audit; never returns exit 0/real-world approval."""
    return _core_args(authority_roster_file=authority_roster_file,
                      expected_authority_roster_sha256=expected_authority_roster_sha256,
                      grant_files=[sender_grant_file,carrier_grant_file,
                                   receiver_grant_file,witness_grant_file],
                      grant_shas=[expected_sender_grant_sha256,
                                  expected_carrier_grant_sha256,
                                  expected_receiver_grant_sha256,
                                  expected_witness_grant_sha256],
                      status_files=[sender_status_file,carrier_status_file,
                                    receiver_status_file,witness_status_file],
                      status_shas=[expected_sender_status_sha256,
                                   expected_carrier_status_sha256,
                                   expected_receiver_status_sha256,
                                   expected_witness_status_sha256],
                      evaluation_utc=evaluation_utc,
                      verifier_challenge_sha256=verifier_challenge_sha256,**base)


def _write_and_check(out: str, doc: dict, paths: list[str],
                     late_recheck: Callable[[],None] | None = None) -> str:
    _path_set([out,*paths])
    raw=reg.raw_doc(doc)
    need(len(raw)<=MAX_SIGNED,'SIGNED_RECORD_EXCEEDS_BYTE_BUDGET','invalid_input')
    prior._write_exclusive(out,raw)
    try:
        # Capture OUR newly created inode before any later check: do not unlink
        # an unrelated replacement file when a local actor races the issuer.
        created=os.lstat(out)
    except OSError as exc:
        raise anchor.AnchorError('EC339_POSTWRITE_INODE_NOT_AVAILABLE',
                                 'unavailable') from exc
    try:
        observed=reg._private_read(out,MAX_SIGNED,'EC339_NEW_ISSUER_OUTPUT')
        need(observed==raw,'NEW_ISSUER_OUTPUT_CHANGED_AFTER_WRITE')
        if late_recheck is not None:
            late_recheck()
    except Exception:
        # Best effort only: this is not a multi-file atomic commit.
        try:
            now=os.lstat(out)
            if (stat.S_ISREG(now.st_mode) and now.st_nlink==1 and
                now.st_dev==created.st_dev and now.st_ino==created.st_ino and
                now.st_uid==os.geteuid() and stat.S_IMODE(now.st_mode)==0o600 and
                reg._private_read(out,MAX_SIGNED,'EC339_FAILED_ISSUE_OUTPUT')==raw):
                os.unlink(out)
        except (OSError,ValueError,anchor.AnchorError,io.HostError):
            pass
        raise
    return case.sha(raw)


def issue_grant(*, out: str, private_key_file: str,
                role: str, issuer_id: str, grant_id: str,
                transfer_id: str, bundle_original_raw_sha256: str,
                actor_id: str, organization_id: str, subject_public_hex: str,
                issued_utc: str, not_before_utc: str, not_after_utc: str) -> dict:
    """Issuer signs a future EC338 policy's authorization-reference whole original.

    The issuer's own real-world authority is a separate external prerequisite.
    """
    _actor_fields(role,actor_id,organization_id,subject_public_hex,issuer_id,grant_id)
    need(ceremony._id(transfer_id) and ceremony._sha(bundle_original_raw_sha256),
         'VALID_TRANSFER_AND_EXTERNAL_ORIGINAL_BUNDLE_ROOT_REQUIRED','invalid_input')
    _interval(not_before_utc,not_after_utc,MAX_GRANT_LIFETIME,
              'GRANT_VALIDITY_WINDOW_INVALID')
    need(_time(issued_utc)<=_time(not_after_utc),
         'GRANT_ISSUED_AFTER_EXPIRATION','invalid_input')
    _path_set([out,private_key_file])
    key=io.private_from_file(private_key_file)
    issuer_pub=key.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex()
    need(issuer_pub!=subject_public_hex,
         'ISSUER_MUST_NOT_BE_ITS_OWN_ROLE_SIGNER')
    claim={'schema':GRANT_CLAIM_SCHEMA,'transfer_id':transfer_id,
           'bundle_original_raw_sha256':bundle_original_raw_sha256,
           'role':role,'issuer_id':issuer_id,'grant_id':grant_id,
           'actor_id':actor_id,'organization_id':organization_id,
           'subject_public_hex':subject_public_hex,
           'issued_utc':issued_utc,'not_before_utc':not_before_utc,
           'not_after_utc':not_after_utc}
    doc={'schema':GRANT_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(_domain('Grant',role)+reg.canonical(claim)).hex()}
    sha=_write_and_check(out,doc,[private_key_file])
    return {'schema':RESULT_SCHEMA,'command':'issue-grant','exit_code':2,
            'status':'local_issuer_signed_grant_candidate_untrusted_until_external_authority',
            'role':role,'issuer_public_hex_local_untrusted':issuer_pub,
            'grant_original_raw_sha256_local_untrusted':sha,
            'must_embed_grant_sha_in_future_ec338_policy':True,
            'external_trust_in_issuer_key_must_be_entrusted_separately':True,
            'offline_unresolved_exit_code':2,
            **{field:False for field in FALSE_FIELDS}}


def issue_status(*, out: str, private_key_file: str, role: str,
                 policy_file: str, expected_policy_sha256: str,
                 authority_roster_file: str,
                 expected_authority_roster_sha256: str,
                 grant_file: str, expected_grant_sha256: str,
                 verifier_challenge_sha256: str, state: str,
                 as_of_utc: str, expires_utc: str,
                 revoked_effective_utc: str | None = None) -> dict:
    """Issuer locally signs one freshly challenged grant-status statement.

    It does NOT examine a remote revocation registry, clock or original bundle.
    The issuer must check those external facts using its actual procedures.
    """
    need(role in ROLES and ceremony._sha(verifier_challenge_sha256) and
         state in ('active','revoked'),
         'VALID_ROLE_CHALLENGE_AND_EXPLICIT_STATUS_REQUIRED','invalid_input')
    _interval(as_of_utc,expires_utc,MAX_STATUS_LIFETIME,
              'STATUS_WINDOW_MUST_BE_AT_MOST_24H')
    need((state=='active' and revoked_effective_utc is None) or
         (state=='revoked' and ceremony._utc(revoked_effective_utc)),
         'REVOCATION_EFFECTIVE_UTC_REQUIRED_ONLY_FOR_REVOKED','invalid_input')
    paths=[out,private_key_file,policy_file,authority_roster_file,grant_file]
    _path_set(paths)
    policy,_=_read_json(policy_file,expected_policy_sha256,MAX_ROSTER,'POLICY')
    need(type(policy.get('original_roots')) is dict,
         'POLICY_ORIGINAL_ROOTS_REQUIRED','invalid_input')
    ceremony._policy_validate(policy,policy['original_roots'])
    roster=_load_roster(authority_roster_file,expected_authority_roster_sha256,
                        policy,expected_policy_sha256)
    i=ROLES.index(role)
    issuer=roster['issuers'][i]
    grant=_load_grant(grant_file,expected_grant_sha256,issuer,policy['actors'][i],policy)
    need(_time(grant['not_before_utc'])<=_time(as_of_utc)<_time(grant['not_after_utc']),
         'STATUS_TIME_OUTSIDE_SIGNED_GRANT_VALIDITY')
    key=io.private_from_file(private_key_file)
    pub=key.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex()
    need(hmac.compare_digest(pub,issuer['issuer_public_hex']),
         'LOCAL_ISSUER_PRIVATE_KEY_DOES_NOT_MATCH_PINNED_ROSTER')
    claim={'schema':STATUS_CLAIM_SCHEMA,'transfer_id':policy['transfer_id'],
           'role':role,'issuer_id':issuer['issuer_id'],
           'grant_id':grant['grant_id'],
           'grant_original_raw_sha256':expected_grant_sha256,
           'verifier_challenge_sha256':verifier_challenge_sha256,
           'state':state,'as_of_utc':as_of_utc,'expires_utc':expires_utc,
           'revoked_effective_utc':revoked_effective_utc}
    doc={'schema':STATUS_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(_domain('Status',role)+reg.canonical(claim)).hex()}
    # A locally issued status is only a candidate. It is not independently
    # pinned until obtained from the specified separate trust channel.
    _late_pin([policy_file,authority_roster_file,grant_file],
              [expected_policy_sha256,expected_authority_roster_sha256,
               expected_grant_sha256],['POLICY','ROSTER','GRANT_'+role.upper()])
    sha=_write_and_check(out,doc,paths[1:],late_recheck=lambda: _late_pin(
        [policy_file,authority_roster_file,grant_file],
        [expected_policy_sha256,expected_authority_roster_sha256,
         expected_grant_sha256],['POLICY','ROSTER','GRANT_'+role.upper()]))
    return {'schema':RESULT_SCHEMA,'command':'issue-status','exit_code':2,
            'status':'local_issuer_signed_challenged_status_candidate_untrusted',
            'role':role,'state':state,
            'status_original_raw_sha256_local_untrusted':sha,
            'challenge_is_operator_supplied_not_trusted_clock':True,
            'external_status_sha_custody_still_required':True,
            'offline_unresolved_exit_code':2,
            **{field:False for field in FALSE_FIELDS}}
