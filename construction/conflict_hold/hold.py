#!/usr/bin/env python3
"""EC342: signed offline conflict hold, distinct reviewers, and approval.

Only an externally pinned EC341 manifest and a separately pinned governance
roster can select a reported, genuinely signed sibling conflict. Every new
original is canonical, whole-file hashed, and cryptographically domain-separated.
A local 'hold' is *not* an executed freeze, grant, global winner, or legal act.
"""
from __future__ import annotations

from datetime import timedelta
import hmac
from typing import Any

from cryptography.exceptions import InvalidSignature

from finding_query_host import protocol as io
from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from independent_custody import ceremony
from offline_authority import authority as old
from issuer_root_rotation import rotation as rotation
from root_lineage import lineage as lineage

GOVERNANCE_SCHEMA = 'ces.ec342.externally_pinned_conflict_governance_roster.v1'
HOLD_CLAIM_SCHEMA = 'ces.ec342.both_successor_hold_request_claim.v1'
HOLD_SCHEMA = 'ces.ec342.ed25519_initiator_hold_request.v1'
REVIEW_CLAIM_SCHEMA = 'ces.ec342.independent_hold_review_claim.v1'
REVIEW_SCHEMA = 'ces.ec342.ed25519_hold_review.v1'
REVIEW_MANIFEST_SCHEMA = 'ces.ec342.externally_pinned_review_set.v1'
APPROVAL_CLAIM_SCHEMA = 'ces.ec342.approval_of_exact_review_set_claim.v1'
APPROVAL_SCHEMA = 'ces.ec342.ed25519_external_approval_claim.v1'
RESULT_SCHEMA = 'ces.ec342.offline_conflict_hold_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec342.offline_conflict_hold_denial.v1'
MAX_REVIEWERS = 5
MAX_JSON = 64000
ACTOR_FIELDS = frozenset({'signer_id', 'public_hex', 'organization_id'})
GOVERNANCE_FIELDS = frozenset({
    'schema', 'case_id', 'case_nonce_sha256', 'transfer_id',
    'policy_original_raw_sha256', 'lineage_manifest_original_raw_sha256',
    'current_root_original_raw_sha256', 'current_root_epoch',
    'minimum_acceptable_epoch', 'current_root_evaluation_utc',
    'parent_epoch', 'parent_root_original_raw_sha256',
    'selected_successor_original_raw_sha256',
    'alternative_successor_original_raw_sha256',
    'initiator', 'reviewers', 'required_support_quorum', 'external_approver',
    'external_approval_required', 'remote_freeze_not_performed'})
HOLD_BASE_FIELDS = (
    'case_id', 'case_nonce_sha256', 'parent_epoch',
    'parent_root_original_raw_sha256',
    'selected_successor_original_raw_sha256',
    'alternative_successor_original_raw_sha256')
ROOT_BINDINGS = (
    ('lineage_manifest_original_raw_sha256', 'expected_manifest_sha256'),
    ('current_root_original_raw_sha256', 'expected_current_root_sha256'),
    ('current_root_epoch', 'expected_current_root_epoch'),
    ('minimum_acceptable_epoch', 'minimum_acceptable_epoch'),
    ('current_root_evaluation_utc', 'current_root_evaluation_utc'))
LINEAGE_KEYS = ('manifest_file', 'expected_manifest_sha256',
    'expected_current_root_sha256', 'expected_current_root_epoch',
    'minimum_acceptable_epoch', 'current_root_evaluation_utc')
REVIEW_MANIFEST_FIELDS = frozenset({'schema','hold_file',
    'expected_hold_sha256','attestations'})
REVIEW_REF_FIELDS = frozenset({'file','sha256'})
GAPS = (
    'global_unreported_sibling_fork_completeness_unknown',
    'real_legal_institutional_signer_identity_unproven',
    'actual_remote_cas_worm_freeze_nonexecution_unproven',
    'independently_trusted_wall_clock_and_revocation_unproven',
    'institutional_pin_custody_and_approval_authority_unproven')
NEGATIVES = (
    'hold_or_approval_is_remote_freeze_or_provider_write',
    'review_quorum_confers_issuer_root_or_legal_authority',
    'approver_key_self_certifies_real_external_institution',
    'signers_are_proven_physically_or_organizationally_independent',
    'actual_global_latest_epoch_or_all_forks_discovered',
    'signed_case_selects_a_fork_winner',
    'claimed_utc_is_a_trusted_external_clock',
    'old_ec317_ec318_deep_mock_is_real_production_chain',
    'external_cas_worm_nonexecution_or_revocation_verified',
    'any_remote_or_business_persist_write_performed')
DOMAIN_HOLD = b'CES/EC342/OfflineSiblingHoldRequest/v1\0'
DOMAIN_REVIEW = b'CES/EC342/IndependentConflictHoldReview/v1\0'
DOMAIN_APPROVAL = b'CES/EC342/ExternalHoldReviewApproval/v1\0'


def need(value: Any, reason: str, status: str='permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC342_' + reason, status)


def _same(a: Any, b: Any) -> bool:
    return type(a) is str and type(b) is str and hmac.compare_digest(a,b)


def _sha(path: str) -> str:
    return case.sha(reg._private_read(path,lineage.MAX_MANIFEST_BYTES,'EC342_ORIGINAL'))


def _read(path: str, sha: str, label: str, limit: int=MAX_JSON) -> dict:
    doc,_=old._read_json(path,sha,limit,'EC342_'+label)
    return doc


def _actor(doc: Any) -> bool:
    return (type(doc) is dict and set(doc)==ACTOR_FIELDS and
            ceremony._id(doc.get('signer_id')) and
            ceremony._id(doc.get('organization_id')) and
            anchor.valid_pub(doc.get('public_hex')))


def _governance(path: str, sha: str) -> dict:
    gov=_read(path,sha,'GOVERNANCE')
    need(type(gov) is dict and set(gov)==GOVERNANCE_FIELDS and
         gov.get('schema')==GOVERNANCE_SCHEMA and
         ceremony._id(gov.get('case_id')) and
         ceremony._id(gov.get('transfer_id')) and
         all(ceremony._sha(gov.get(k)) for k in (
           'case_nonce_sha256','policy_original_raw_sha256',
           'lineage_manifest_original_raw_sha256',
           'current_root_original_raw_sha256',
           'parent_root_original_raw_sha256',
           'selected_successor_original_raw_sha256',
           'alternative_successor_original_raw_sha256')) and
         gov.get('selected_successor_original_raw_sha256')!=
           gov.get('alternative_successor_original_raw_sha256') and
         type(gov.get('parent_epoch')) is int and
         type(gov.get('current_root_epoch')) is int and
         type(gov.get('minimum_acceptable_epoch')) is int and
         1<=gov['parent_epoch']<gov['current_root_epoch']<=lineage.MAX_EPOCH and
         2<=gov['minimum_acceptable_epoch']<=gov['current_root_epoch'] and
         ceremony._utc(gov.get('current_root_evaluation_utc')) and
         _actor(gov.get('initiator')) and
         _actor(gov.get('external_approver')) and
         gov.get('external_approval_required') is True and
         gov.get('remote_freeze_not_performed') is True and
         type(gov.get('reviewers')) is list and
         3<=len(gov['reviewers'])<=MAX_REVIEWERS and
         type(gov.get('required_support_quorum')) is int and
         3<=gov['required_support_quorum']<=len(gov['reviewers']) and
         all(_actor(x) for x in gov['reviewers']),
         'EXACT_SEPARATELY_ENTRUSTED_GOVERNANCE_ROSTER_REQUIRED',
         'invalid_input')
    actors=[gov['initiator'],*gov['reviewers'],gov['external_approver']]
    for field in ACTOR_FIELDS:
        need(len({x[field] for x in actors})==len(actors),
             'INITIATOR_REVIEWERS_APPROVER_MUST_HAVE_DISTINCT_IDS_KEYS_AND_ORGS',
             'invalid_input')
    return gov


def _lineage_args(**kwargs) -> dict:
    return {k:kwargs[k] for k in LINEAGE_KEYS}


def _trusted_case(gov: dict, lineage_args: dict) -> tuple[dict,dict]:
    for field, arg in ROOT_BINDINGS:
        need(gov[field]==lineage_args[arg],
             'GOVERNANCE_MUST_BIND_INDEPENDENT_LINEAGE_ROOT_EPOCH_FLOOR_TIME',
             'invalid_input')
    result=lineage.verify_lineage(**lineage_args)
    need(result.get('exit_code')==2 and
         result.get('status')=='conflict_unresolved' and
         result.get('historical_ec340_to_ec337_real_original_replay_verified') is True and
         result.get('only_supplied_externally_pinned_forks_examined') is True and
         result.get('policy_original_raw_sha256')==
             gov['policy_original_raw_sha256'],
         'FULL_SIGNED_LINEAGE_AND_A_VISIBLE_FORK_REQUIRED')
    matches=[x for x in result['fork_conflicts'] if
        x.get('parent_epoch')==gov['parent_epoch'] and
        x.get('parent_roster_original_raw_sha256')==
            gov['parent_root_original_raw_sha256'] and
        x.get('selected_successor_original_raw_sha256')==
            gov['selected_successor_original_raw_sha256'] and
        x.get('alternative_successor_original_raw_sha256')==
            gov['alternative_successor_original_raw_sha256']]
    need(len(matches)==1,
         'GOVERNANCE_MUST_SELECT_ONE_ACTUALLY_VERIFIED_SIGNED_SIBLING_PAIR')
    manifest=_read(lineage_args['manifest_file'],
                   lineage_args['expected_manifest_sha256'], 'LINEAGE_MANIFEST',
                   lineage.MAX_MANIFEST_BYTES)
    policy=_read(manifest['context']['policy_file'],
                 manifest['context']['expected_policy_sha256'], 'POLICY')
    need(gov['transfer_id']==policy['transfer_id'],
         'GOVERNANCE_MUST_BIND_EXACT_HISTORICAL_TRANSFER', 'invalid_input')
    # Cryptographically verified lineage roots/observations are inspected only
    # *after* lineage.verify_lineage has checked their original SHA and signatures.
    # This is a textual separation check, NOT proof of physical independence.
    actors=[gov['initiator'],*gov['reviewers'],gov['external_approver']]
    reserved_ids=set()
    reserved_pubs=set()
    reserved_orgs=set()
    def collect(items: list[dict]):
        for x in items:
            for key in ('issuer_id','observer_id','actor_id'):
                if type(x.get(key)) is str:
                    reserved_ids.add(x[key])
            for key in ('issuer_public_hex','observer_public_hex','public_hex'):
                if type(x.get(key)) is str:
                    reserved_pubs.add(x[key])
            for key in ('organization_id','subject_organization_id',
                        'observer_organization_id'):
                if type(x.get(key)) is str:
                    reserved_orgs.add(x[key])
    collect(policy['actors'])
    legacy=_read(manifest['context']['authority_roster_file'],
                 manifest['context']['expected_authority_roster_sha256'],
                 'ORIGINAL_ISSUER_ROSTER')
    collect(legacy['issuers'])
    for hop in [*manifest['hops'],*(x['hop'] for x in manifest['forks'])]:
        root=_read(hop['successor_roster_file'],
                   hop['expected_successor_roster_sha256'], 'OBSERVED_ROOT')
        observer=_read(hop['observer_roster_file'],
                       hop['expected_observer_roster_sha256'], 'OBSERVED_WITNESS')
        collect(root['issuers']);collect([observer])
    need(all(x['signer_id'] not in reserved_ids and
             x['public_hex'] not in reserved_pubs and
             x['organization_id'] not in reserved_orgs for x in actors),
         'GOVERNANCE_ROLE_COLLIDES_WITH_SIGNED_LINEAGE_ISSUER_OBSERVER_OR_ACTOR',
         'invalid_input')
    return result,manifest


def _hold_claim(gov: dict, gov_sha: str, challenge_sha: str,
                issued_utc: str, expires_utc: str) -> dict:
    need(ceremony._sha(challenge_sha),
         'INDEPENDENT_HOLD_CHALLENGE_SHA_REQUIRED','invalid_input')
    old._interval(issued_utc,expires_utc,timedelta(hours=24),
                  'HOLD_WINDOW_MAX_24_HOURS')
    need(old._time(issued_utc)>=old._time(gov['current_root_evaluation_utc']),
         'HOLD_ISSUED_BEFORE_ROOT_EVALUATION','invalid_input')
    return {'schema':HOLD_CLAIM_SCHEMA,
        'governance_roster_original_raw_sha256':gov_sha,
        **{k:gov[k] for k in HOLD_BASE_FIELDS},
        'lineage_manifest_original_raw_sha256':
             gov['lineage_manifest_original_raw_sha256'],
        'current_root_original_raw_sha256':
             gov['current_root_original_raw_sha256'],
        'current_root_epoch':gov['current_root_epoch'],
        'minimum_acceptable_epoch':gov['minimum_acceptable_epoch'],
        'current_root_evaluation_utc':gov['current_root_evaluation_utc'],
        'initiator_id':gov['initiator']['signer_id'],
        'initiator_public_hex':gov['initiator']['public_hex'],
        'initiator_organization_id':gov['initiator']['organization_id'],
        'hold_challenge_sha256':challenge_sha,
        'issued_utc':issued_utc, 'expires_utc':expires_utc,
        'requested_action':'request_hold_both_seen_sibling_successors_only',
        'evidence_gaps':list(GAPS),
        'external_governance_and_approval_still_required':True,
        'remote_freeze_not_executed':True,
        'no_winner_declared':True}


def _verify_signed(doc: dict, schema: str, domain: bytes, pub: str,
                   reason: str) -> None:
    need(type(doc) is dict and set(doc)=={'schema','claim','signature_ed25519'} and
         doc.get('schema')==schema and type(doc.get('claim')) is dict and
         type(doc.get('signature_ed25519')) is str and
         anchor.SIG.fullmatch(doc['signature_ed25519']) is not None,
         reason+'_STRUCTURE_AND_SIGNATURE_REQUIRED', 'invalid_input')
    try:
        io.pub_from_hex(pub).verify(bytes.fromhex(doc['signature_ed25519']),
                                    domain+reg.canonical(doc['claim']))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise anchor.AnchorError('EC342_'+reason+'_ED25519_INVALID',
                                 'permission_denied') from exc


def _load_hold(path: str, sha: str, gov: dict, gov_sha: str) -> dict:
    doc=_read(path,sha,'HOLD')
    need(type(doc) is dict and type(doc.get('claim')) is dict,
         'HOLD_SIGNED_CLAIM_REQUIRED','invalid_input')
    claim=doc['claim']
    need(ceremony._utc(claim.get('issued_utc')) and
         ceremony._utc(claim.get('expires_utc')),
         'HOLD_SIGNED_WINDOW_REQUIRED','invalid_input')
    expected=_hold_claim(gov,gov_sha,claim.get('hold_challenge_sha256'),
                         claim['issued_utc'],claim['expires_utc'])
    need(claim==expected,'HOLD_REQUEST_MUST_BIND_EXACT_GOVERNANCE_AND_EVIDENCE_GAPS',
         'invalid_input')
    _verify_signed(doc,HOLD_SCHEMA,DOMAIN_HOLD,
                   gov['initiator']['public_hex'],'HOLD_INITIATOR')
    return claim


def _review_claim(gov: dict,gov_sha: str,hold_sha: str,hold: dict,
                  actor: dict,decision: str,reviewer_reported_utc: str) -> dict:
    need(decision in ('support_hold','object_to_hold') and
         ceremony._utc(reviewer_reported_utc),
         'EXACT_REVIEW_DECISION_AND_UTC_REQUIRED','invalid_input')
    need(old._time(hold['issued_utc'])<=old._time(reviewer_reported_utc)<
         old._time(hold['expires_utc']),
         'REVIEW_MUST_BE_IN_SIGNED_HOLD_WINDOW', 'invalid_input')
    return {'schema':REVIEW_CLAIM_SCHEMA,
        'governance_roster_original_raw_sha256':gov_sha,
        'hold_original_raw_sha256':hold_sha,'case_id':gov['case_id'],
        'reviewer_id':actor['signer_id'],'reviewer_public_hex':actor['public_hex'],
        'reviewer_organization_id':actor['organization_id'],
        'decision':decision,'reviewer_reported_utc':reviewer_reported_utc,
        'hold_challenge_sha256':hold['hold_challenge_sha256'],
        'evidence_gaps_acknowledged':True}


def _inspect_reviews(manifest: dict,gov: dict,gov_sha: str,
                     hold: dict,hold_sha: str) -> tuple[int,int,list[str],list[str]]:
    refs=manifest['attestations']
    need(type(refs) is list and len(refs)<=len(gov['reviewers']),
         'REVIEW_SET_EXCEEDS_ROSTER','invalid_input')
    supporters=0;objectors=0;ids=set();paths=[];pins=[]
    by_id={x['signer_id']:x for x in gov['reviewers']}
    for ref in refs:
        need(type(ref) is dict and set(ref)==REVIEW_REF_FIELDS and
             ceremony._sha(ref.get('sha256')),
             'WHOLE_SIGNED_REVIEW_FILE_SHA_REQUIRED','invalid_input')
        paths.append(ref['file']);pins.append(ref['sha256'])
        doc=_read(ref['file'],ref['sha256'],'REVIEW')
        claim=doc.get('claim') if type(doc) is dict else None
        rid=claim.get('reviewer_id') if type(claim) is dict else None
        need(type(rid) is str and rid in by_id and rid not in ids,
             'EXACT_ROSTER_REVIEWER_AND_SINGLE_VOTE_REQUIRED','invalid_input')
        ids.add(rid)
        actor=by_id[rid]
        expected=_review_claim(gov,gov_sha,hold_sha,hold,actor,
                 claim.get('decision'),claim.get('reviewer_reported_utc'))
        need(claim==expected,'REVIEW_CLAIM_NOT_EXACT','invalid_input')
        _verify_signed(doc,REVIEW_SCHEMA,DOMAIN_REVIEW,actor['public_hex'],
                       'INDEPENDENT_REVIEW')
        if claim['decision']=='support_hold':supporters+=1
        else:objectors+=1
    return supporters,objectors,paths,pins


def _review_manifest(path: str,sha: str,gov: dict,gov_sha: str):
    manifest=_read(path,sha,'REVIEW_MANIFEST')
    need(type(manifest) is dict and set(manifest)==REVIEW_MANIFEST_FIELDS and
         manifest.get('schema')==REVIEW_MANIFEST_SCHEMA and
         ceremony._sha(manifest.get('expected_hold_sha256')),
         'EXACT_PINNED_REVIEW_SET_REQUIRED','invalid_input')
    hold=_load_hold(manifest['hold_file'],manifest['expected_hold_sha256'],
                    gov,gov_sha)
    support,objections,paths,pins=_inspect_reviews(
         manifest,gov,gov_sha,hold,manifest['expected_hold_sha256'])
    rotation._paths(path,manifest['hold_file'],*paths)
    need(len(set([sha,manifest['expected_hold_sha256'],*pins]))==2+len(pins),
         'EACH_REVIEW_ORIGINAL_SHA_MUST_BE_DISTINCT','invalid_input')
    return manifest,hold,support,objections,paths,pins


def _approval_claim(gov: dict,gov_sha: str,review_sha: str,hold_sha: str,
                    hold: dict,support: int,approval_reported_utc: str) -> dict:
    need(ceremony._utc(approval_reported_utc) and
         old._time(hold['issued_utc'])<=old._time(approval_reported_utc)<
         old._time(hold['expires_utc']),
         'APPROVAL_REPORTED_UTC_MUST_BE_IN_HOLD_WINDOW','invalid_input')
    need(support>=gov['required_support_quorum'],
         'THRESHOLD_SUPPORT_REQUIRED_BEFORE_APPROVAL','permission_denied')
    a=gov['external_approver']
    return {'schema':APPROVAL_CLAIM_SCHEMA,'case_id':gov['case_id'],
        'governance_roster_original_raw_sha256':gov_sha,
        'hold_original_raw_sha256':hold_sha,
        'review_manifest_original_raw_sha256':review_sha,
        'supporting_distinct_reviewer_count':support,
        'required_support_quorum':gov['required_support_quorum'],
        'approver_id':a['signer_id'],'approver_public_hex':a['public_hex'],
        'approver_organization_id':a['organization_id'],
        'hold_challenge_sha256':hold['hold_challenge_sha256'],
        'approval_reported_utc':approval_reported_utc,
        'decision':'approve_offline_conflict_hold_review_only',
        'remote_cas_freeze_not_performed':True,
        'no_fork_winner_selected':True}


def _late(paths: list[str],pins: list[str]) -> None:
    for path,sha in zip(paths,pins,strict=True):
        need(_same(_sha(path),sha),
             'PINNED_ORIGINAL_MUTATED_DURING_CONFLICT_HOLD_REVIEW')


def _candidate(command: str, kind: str, sha: str) -> dict:
    return {'schema':RESULT_SCHEMA,'command':command,
            'status':'owner_private_candidate_untrusted','exit_code':2,
            kind:sha,'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}


def issue_hold(*,out: str,private_key_file: str,
               governance_roster_file: str,expected_governance_roster_sha256: str,
               hold_challenge_sha256: str,issued_utc: str,expires_utc: str,
               **lineage_args) -> dict:
    need(set(lineage_args)==set(LINEAGE_KEYS),
         'EXACT_LINEAGE_TRUST_ARGUMENTS_REQUIRED','invalid_input')
    rotation._paths(out,private_key_file,governance_roster_file,
                    lineage_args['manifest_file'])
    gov=_governance(governance_roster_file,expected_governance_roster_sha256)
    _trusted_case(gov,lineage_args)
    claim=_hold_claim(gov,expected_governance_roster_sha256,
                      hold_challenge_sha256,issued_utc,expires_utc)
    key,pub=rotation._private_key_public(private_key_file)
    need(_same(pub,gov['initiator']['public_hex']),
         'INITIATOR_PRIVATE_KEY_ROLE_REQUIRED')
    doc={'schema':HOLD_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(DOMAIN_HOLD+reg.canonical(claim)).hex()}
    paths=[governance_roster_file,lineage_args['manifest_file']]
    pins=[expected_governance_roster_sha256,lineage_args['expected_manifest_sha256']]
    sha=old._write_and_check(out,doc,[private_key_file,*paths],
                             late_recheck=lambda:_late(paths,pins))
    return _candidate('issue-hold','candidate_hold_original_raw_sha256',sha)


def sign_review(*,out: str,private_key_file: str,
                governance_roster_file: str,expected_governance_roster_sha256: str,
                hold_file: str,expected_hold_sha256: str,
                decision: str,reviewer_reported_utc: str) -> dict:
    rotation._paths(out,private_key_file,governance_roster_file,hold_file)
    gov=_governance(governance_roster_file,expected_governance_roster_sha256)
    hold=_load_hold(hold_file,expected_hold_sha256,gov,
                    expected_governance_roster_sha256)
    key,pub=rotation._private_key_public(private_key_file)
    actors=[x for x in gov['reviewers'] if _same(pub,x['public_hex'])]
    need(len(actors)==1,'ONE_REGISTERED_INDEPENDENT_REVIEW_KEY_REQUIRED')
    claim=_review_claim(gov,expected_governance_roster_sha256,
                        expected_hold_sha256,hold,actors[0],decision,
                        reviewer_reported_utc)
    doc={'schema':REVIEW_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(DOMAIN_REVIEW+reg.canonical(claim)).hex()}
    paths=[governance_roster_file,hold_file]
    pins=[expected_governance_roster_sha256,expected_hold_sha256]
    sha=old._write_and_check(out,doc,[private_key_file,*paths],
                             late_recheck=lambda:_late(paths,pins))
    return _candidate('sign-review','candidate_review_original_raw_sha256',sha)


def assemble_review(*,out: str,governance_roster_file: str,
                    expected_governance_roster_sha256: str,
                    hold_file: str,expected_hold_sha256: str,
                    attestation_files: list[str],attestation_shas: list[str]) -> dict:
    need(type(attestation_files) is list and type(attestation_shas) is list and
         len(attestation_files)==len(attestation_shas) and
         len(attestation_files)<=MAX_REVIEWERS,
         'MATCHED_BOUNDED_ATTESTATION_REFS_REQUIRED','invalid_input')
    rotation._paths(out,governance_roster_file,hold_file,*attestation_files)
    gov=_governance(governance_roster_file,expected_governance_roster_sha256)
    hold=_load_hold(hold_file,expected_hold_sha256,gov,
                    expected_governance_roster_sha256)
    manifest={'schema':REVIEW_MANIFEST_SCHEMA,'hold_file':hold_file,
        'expected_hold_sha256':expected_hold_sha256,
        'attestations':[{'file':f,'sha256':s} for f,s in
                        zip(attestation_files,attestation_shas,strict=True)]}
    _,_,paths,pins=_inspect_reviews(manifest,gov,
               expected_governance_roster_sha256,hold,expected_hold_sha256)
    need(len(set([expected_hold_sha256,*pins]))==1+len(pins),
         'REVIEW_ORIGINAL_SHA_MUST_BE_DISTINCT','invalid_input')
    sources=[governance_roster_file,hold_file,*paths]
    hashes=[expected_governance_roster_sha256,expected_hold_sha256,*pins]
    sha=old._write_and_check(out,manifest,sources,
                            late_recheck=lambda:_late(sources,hashes))
    return _candidate('assemble-review','candidate_review_manifest_original_raw_sha256',sha)


def issue_approval(*,out: str,private_key_file: str,
                   governance_roster_file: str,expected_governance_roster_sha256: str,
                   review_manifest_file: str,expected_review_manifest_sha256: str,
                   approval_reported_utc: str) -> dict:
    rotation._paths(out,private_key_file,governance_roster_file,
                    review_manifest_file)
    gov=_governance(governance_roster_file,expected_governance_roster_sha256)
    review,hold,support,_,paths,pins=_review_manifest(
         review_manifest_file,expected_review_manifest_sha256,gov,
         expected_governance_roster_sha256)
    for ref in review['attestations']:
        vote=_read(ref['file'],ref['sha256'],'PRE_APPROVAL_REVIEW_TIME')
        need(old._time(vote['claim']['reviewer_reported_utc'])<=
             old._time(approval_reported_utc),
             'APPROVAL_CANNOT_PRECEDE_REVIEWER_REPORTED_TIME','invalid_input')
    claim=_approval_claim(gov,expected_governance_roster_sha256,
         expected_review_manifest_sha256,review['expected_hold_sha256'],
         hold,support,approval_reported_utc)
    key,pub=rotation._private_key_public(private_key_file)
    need(_same(pub,gov['external_approver']['public_hex']),
         'ONLY_NAMED_SEPARATE_EXTERNAL_APPROVER_KEY_REQUIRED')
    doc={'schema':APPROVAL_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(DOMAIN_APPROVAL+reg.canonical(claim)).hex()}
    sources=[governance_roster_file,review_manifest_file,review['hold_file'],*paths]
    hashes=[expected_governance_roster_sha256,expected_review_manifest_sha256,
            review['expected_hold_sha256'],*pins]
    rotation._paths(out,private_key_file,*sources)
    sha=old._write_and_check(out,doc,[private_key_file,*sources],
                             late_recheck=lambda:_late(sources,hashes))
    return _candidate('issue-approval','candidate_approval_original_raw_sha256',sha)


def verify_hold(*,manifest_file: str,expected_manifest_sha256: str,
                expected_current_root_sha256: str,expected_current_root_epoch: int,
                minimum_acceptable_epoch: int,current_root_evaluation_utc: str,
                governance_roster_file: str,expected_governance_roster_sha256: str,
                review_manifest_file: str,expected_review_manifest_sha256: str,
                hold_evaluation_utc: str,
                approval_file: str|None=None,
                expected_approval_sha256: str|None=None) -> dict:
    """Only validate independently pinned originals; never install a hold."""
    need((approval_file is None)==(expected_approval_sha256 is None) and
         ceremony._utc(hold_evaluation_utc),
         'APPROVAL_PAIR_AND_EXTERNAL_EVALUATION_UTC_REQUIRED','invalid_input')
    rotation._paths(manifest_file,governance_roster_file,
                    review_manifest_file,*([approval_file] if approval_file else []))
    gov=_governance(governance_roster_file,expected_governance_roster_sha256)
    trust={'manifest_file':manifest_file,
           'expected_manifest_sha256':expected_manifest_sha256,
           'expected_current_root_sha256':expected_current_root_sha256,
           'expected_current_root_epoch':expected_current_root_epoch,
           'minimum_acceptable_epoch':minimum_acceptable_epoch,
           'current_root_evaluation_utc':current_root_evaluation_utc}
    _,manifest=_trusted_case(gov,trust)
    review,hold,support,objections,paths,pins=_review_manifest(
         review_manifest_file,expected_review_manifest_sha256,gov,
         expected_governance_roster_sha256)
    rotation._paths(manifest_file,governance_roster_file,review_manifest_file,
                    review['hold_file'],*paths,
                    *([approval_file] if approval_file else []))
    need(old._time(hold['issued_utc'])<=old._time(hold_evaluation_utc)<
         old._time(hold['expires_utc']),
         'EXTERNALLY_CLAIMED_EVALUATION_OUTSIDE_HOLD_WINDOW')
    for ref in review['attestations']:
        vote=_read(ref['file'],ref['sha256'],'EVALUATION_REVIEW_TIME')
        need(old._time(vote['claim']['reviewer_reported_utc'])<=
             old._time(hold_evaluation_utc),
             'CANNOT_COUNT_REVIEW_CLAIMED_AFTER_EVALUATION','invalid_input')
    approved=False
    if approval_file is not None:
        approval=_read(approval_file,expected_approval_sha256,'EXTERNAL_APPROVAL')
        need(type(approval) is dict and type(approval.get('claim')) is dict,
             'SIGNED_APPROVAL_CLAIM_REQUIRED','invalid_input')
        c=approval['claim']
        need(ceremony._utc(c.get('approval_reported_utc')),
             'APPROVAL_SIGNED_TIME_REQUIRED','invalid_input')
        expected=_approval_claim(gov,expected_governance_roster_sha256,
                  expected_review_manifest_sha256,review['expected_hold_sha256'],
                  hold,support,c['approval_reported_utc'])
        need(c==expected,'APPROVAL_MUST_BIND_EXACT_QUORUM_AND_REVIEW_SHA',
             'invalid_input')
        need(old._time(c['approval_reported_utc'])<=
             old._time(hold_evaluation_utc) and
             all(old._time(_read(ref['file'],ref['sha256'],
                 'APPROVAL_REVIEW_CHRONOLOGY')['claim']['reviewer_reported_utc'])<=
                 old._time(c['approval_reported_utc'])
                 for ref in review['attestations']),
             'APPROVAL_OR_REVIEW_CLAIMED_IN_FUTURE_OF_RECEIVER_EVALUATION',
             'invalid_input')
        _verify_signed(approval,APPROVAL_SCHEMA,DOMAIN_APPROVAL,
                      gov['external_approver']['public_hex'],'EXTERNAL_APPROVER')
        approved=True
    sources=[manifest_file,governance_roster_file,review_manifest_file,
             review['hold_file'],*paths]
    hashes=[expected_manifest_sha256,expected_governance_roster_sha256,
            expected_review_manifest_sha256,review['expected_hold_sha256'],*pins]
    if approval_file is not None:
        sources.append(approval_file);hashes.append(expected_approval_sha256)
    # EC341 also replays and re-reads all older EC340->EC337 originals.
    _late(sources,hashes)
    need(len(set(hashes))==len(hashes),
         'DIFFERENT_EVIDENCE_ROLES_MUST_HAVE_DISTINCT_ORIGINAL_SHA',
         'invalid_input')
    status=('quorum_insufficient' if support<gov['required_support_quorum'] else
            'hold_verified_unresolved' if approved else
            'external_approval_missing')
    return {'schema':RESULT_SCHEMA,'command':'verify-hold',
        'status':status,'exit_code':2,
        'lineage_manifest_original_raw_sha256':expected_manifest_sha256,
        'governance_roster_original_raw_sha256':expected_governance_roster_sha256,
        'review_manifest_original_raw_sha256':expected_review_manifest_sha256,
        'hold_original_raw_sha256':review['expected_hold_sha256'],
        'external_approval_original_raw_sha256':expected_approval_sha256,
        'current_root_original_raw_sha256':expected_current_root_sha256,
        'current_root_epoch':expected_current_root_epoch,
        'minimum_acceptable_epoch':minimum_acceptable_epoch,
        'hold_evaluation_utc':hold_evaluation_utc,
        'case_id':gov['case_id'],'parent_epoch':gov['parent_epoch'],
        'parent_root_original_raw_sha256':gov['parent_root_original_raw_sha256'],
        'selected_successor_original_raw_sha256':
             gov['selected_successor_original_raw_sha256'],
        'alternative_successor_original_raw_sha256':
             gov['alternative_successor_original_raw_sha256'],
        'required_support_quorum':gov['required_support_quorum'],
        'supporting_distinct_reviewer_count':support,
        'objecting_distinct_reviewer_count':objections,
        'total_signed_reviewer_count':support+objections,
        'initiator_signature_verified':True,
        'reviewer_signatures_verified':True,
        'separate_approver_signature_verified':approved,
        'signed_sibling_fork_and_historical_full_replay_verified':True,
        'only_supplied_visible_sibling_conflict_examined':True,
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES}}
