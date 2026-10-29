#!/usr/bin/env python3
"""EC341: bounded epoch 1..8 roots, real multi-hop signatures and observable forks.

Historical epoch 1->2 evidence is checked by the *unchanged* EC340 verifier.
Epoch >=3 has fresh EC341 signatures/claims, never aliases old grant authority.
Unsigned plan documents are only useful if their WHOLE SHA is entrusted from
outside this software. No external latest, legal issuer or credible clock is proven.
"""
from __future__ import annotations

from datetime import timedelta
import hmac
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from finding_query_host import protocol as io
from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from independent_custody import ceremony
from offline_authority import authority as old
from issuer_root_rotation import rotation as one
from issuer_root_rotation import operator as one_op

MAX_EPOCH = 8
MAX_FORKS = 8
MAX_MANIFEST_BYTES = 128_000
ROOT_SCHEMA = 'ces.ec341.chain_issuer_epoch_roster.v1'
EDGE_CLAIM_SCHEMA = 'ces.ec341.chain_role_scoped_root_edge_claim.v1'
EDGE_SCHEMA = 'ces.ec341.ed25519_chain_root_edge_signature.v1'
OBSERVER_CLAIM_SCHEMA = 'ces.ec341.challenged_chain_root_observation_claim.v1'
OBSERVER_SCHEMA = 'ces.ec341.ed25519_chain_root_observation.v1'
MANIFEST_SCHEMA = 'ces.ec341.externally_pinned_lineage_and_fork_manifest.v1'
RESULT_SCHEMA = 'ces.ec341.bounded_issuer_lineage_audit_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec341.bounded_issuer_lineage_denial.v1'
HOP_FIELDS = frozenset({'epoch','successor_roster_file',
    'expected_successor_roster_sha256','observer_roster_file',
    'expected_observer_roster_sha256','root_observation_file',
    'expected_root_observation_sha256','edge_signatures',
    'evaluation_utc','verifier_challenge_sha256'})
EDGE_REF_FIELDS = frozenset({'side','role','file','sha256'})
FORK_FIELDS = frozenset({'parent_epoch','hop'})
CONTEXT_FIELDS = frozenset(one_op.CONTEXT_KEYS)
HISTORY_FIELDS = frozenset(x for x in one_op.BASE_KEYS if x not in
                            (*one_op.CONTEXT_KEYS, 'verifier_challenge_sha256'))
MANIFEST_FIELDS = frozenset({'schema','context','history','hops','forks'})
NEGATIVES = (
    'lineage_manifest_sha_proves_institutional_or_global_trust',
    'reported_forks_are_a_complete_global_fork_discovery',
    'verified_signatures_confer_current_new_epoch_grants',
    'signature_claimed_observation_utc_is_trusted_wall_clock',
    'observer_signatures_prove_actual_revocation_registry_completeness',
    'current_sha_and_epoch_or_minimum_floor_prove_global_latest',
    'actual_independent_people_organizations_or_key_custody_proven',
    'deep_ec317_ec318_old_mock_fixtures_are_real_production_evidence',
    'remote_cas_worm_nonexecution_winner_or_provider_persist_verified',
    'any_business_or_remote_persist_write_performed',
)


def need(valid: Any, code: str, status: str='permission_denied') -> None:
    if valid is not True:
        raise anchor.AnchorError('EC341_' + code, status)


def _same(a: Any, b: Any) -> bool:
    return type(a) is str and type(b) is str and hmac.compare_digest(a,b)


def _read(path: str, sha: str, label: str, limit: int=one.MAX_JSON) -> dict:
    doc,_=old._read_json(path,sha,limit,'EC341_'+label)
    return doc


def _context(policy_file: str, expected_policy_sha256: str) -> dict:
    policy=_read(policy_file,expected_policy_sha256,'POLICY')
    need(type(policy.get('original_roots')) is dict,
         'LEGACY_POLICY_ROOTS_REQUIRED','invalid_input')
    ceremony._policy_validate(policy,policy['original_roots'])
    return policy


def _predecessor(path: str, sha: str, policy: dict,
                 policy_sha: str) -> dict:
    doc=_read(path,sha,'PREDECESSOR')
    need(type(doc) is dict and set(doc)==one.ROOT_FIELDS and
         doc.get('schema') in (one.ROOT_SCHEMA,ROOT_SCHEMA) and
         type(doc.get('epoch')) is int and 2<=doc['epoch']<MAX_EPOCH and
         (doc['epoch']==2)==(doc['schema']==one.ROOT_SCHEMA) and
         doc.get('transfer_id')==policy['transfer_id'] and
         doc.get('policy_original_raw_sha256')==policy_sha and
         ceremony._sha(doc.get('predecessor_roster_original_raw_sha256')) and
         ceremony._id(doc.get('rotation_id')) and
         ceremony._sha(doc.get('rotation_nonce_sha256')) and
         ceremony._utc(doc.get('effective_utc')) and
         doc.get('old_root_retired_from_effective_utc') is True and
         doc.get('external_successor_root_trust_required') is True,
         'MUST_USE_A_PREVIOUS_EPOCH_ROOT_NOT_ARBITRARY_OLD_ROSTER',
         'invalid_input')
    _issuer_set(doc,policy)
    return doc


def _issuer_set(root: dict, policy: dict) -> None:
    issuers=root.get('issuers')
    need(type(issuers) is list and len(issuers)==4,
         'EXACT_FOUR_ISSUERS','invalid_input')
    for i,x in enumerate(issuers):
        need(type(x) is dict and set(x)==old.ISSUER_FIELDS and
             x.get('role')==one.ROLES[i] and
             ceremony._id(x.get('issuer_id')) and
             anchor.valid_pub(x.get('issuer_public_hex')) and
             x.get('subject_organization_id')==policy['actors'][i]['organization_id'],
             'ROLE_PUBLIC_ID_OR_ORGANIZATION_MISMATCH','invalid_input')
    need(len({x['issuer_id'] for x in issuers})==4 and
         len({x['issuer_public_hex'] for x in issuers})==4 and
         not ({x['issuer_public_hex'] for x in issuers} &
              {x['public_hex'] for x in policy['actors']}),
         'DUPLICATE_ISSUER_OR_ACTOR_KEY','invalid_input')


def _validate_successor(doc: dict, prev: dict, prev_sha: str,
                        policy: dict, policy_sha: str) -> None:
    need(type(doc) is dict and set(doc)==one.ROOT_FIELDS and
         doc.get('schema')==ROOT_SCHEMA and
         doc.get('transfer_id')==policy['transfer_id'] and
         doc.get('policy_original_raw_sha256')==policy_sha and
         doc.get('predecessor_roster_original_raw_sha256')==prev_sha and
         type(doc.get('epoch')) is int and doc['epoch']==prev['epoch']+1 and
         3<=doc['epoch']<=MAX_EPOCH and
         ceremony._id(doc.get('rotation_id')) and
         ceremony._sha(doc.get('rotation_nonce_sha256')) and
         ceremony._utc(doc.get('effective_utc')) and
         doc.get('old_root_retired_from_effective_utc') is True and
         doc.get('external_successor_root_trust_required') is True and
         old._time(doc['effective_utc'])>old._time(prev['effective_utc']),
         'ADJACENT_ROOT_SHA_EPOCH_AND_STRICTLY_INCREASING_EFFECTIVE_UTC_REQUIRED',
         'invalid_input')
    _issuer_set(doc,policy)
    need(not ({x['issuer_id'] for x in doc['issuers']} &
              {x['issuer_id'] for x in prev['issuers']}) and
         not ({x['issuer_public_hex'] for x in doc['issuers']} &
              {x['issuer_public_hex'] for x in prev['issuers']}),
         'ADJACENT_EPOCH_KEY_AND_ID_REUSE_REFUSED','invalid_input')


def _load_successor(path: str, sha: str, prev: dict, prev_sha: str,
                    policy: dict, policy_sha: str) -> dict:
    doc=_read(path,sha,'SUCCESSOR')
    _validate_successor(doc,prev,prev_sha,policy,policy_sha)
    return doc


def _edge_claim(side: str, role: str, child: dict, parent: dict,
                parent_sha: str, child_sha: str) -> dict:
    need(side in one.SIDES and role in one.ROLES,
         'ROOT_EDGE_ROLE_AND_SIDE_REQUIRED','invalid_input')
    entry=(parent if side=='old' else child)['issuers'][one.ROLES.index(role)]
    return {'schema':EDGE_CLAIM_SCHEMA,
        'successor_roster_original_raw_sha256':child_sha,
        'predecessor_roster_original_raw_sha256':parent_sha,
        'role':role,'side':side,'issuer_id':entry['issuer_id'],
        'issuer_public_hex':entry['issuer_public_hex'],
        'rotation_id':child['rotation_id'],
        'rotation_nonce_sha256':child['rotation_nonce_sha256'],
        'epoch':child['epoch'],'effective_utc':child['effective_utc']}


def _domain(side: str, role: str) -> bytes:
    need(side in one.SIDES and role in one.ROLES,
         'ONLY_EIGHT_ED25519_DOMAINS','invalid_input')
    return ('CES/EC341/IssuerRootHandoff/'+side+'/'+role+'/v1\0').encode('ascii')


def _verify_edges(edge_files: dict, edge_shas: dict, child: dict,
                  parent: dict, parent_sha: str, child_sha: str) -> None:
    one._edge_inputs(edge_files,edge_shas)
    for side,role in one.EDGE_KEYS:
        doc=_read(edge_files[(side,role)],edge_shas[(side,role)],
                  'EDGE_'+side+'_'+role)
        claim=_edge_claim(side,role,child,parent,parent_sha,child_sha)
        need(type(doc) is dict and set(doc)==old.SIGNED_FIELDS and
             doc.get('schema')==EDGE_SCHEMA and doc.get('claim')==claim and
             type(doc.get('signature_ed25519')) is str and
             anchor.SIG.fullmatch(doc['signature_ed25519']) is not None,
             'SIGNED_EDGE_CLAIM_AND_SIGNATURE_REQUIRED','invalid_input')
        try:
            io.pub_from_hex(claim['issuer_public_hex']).verify(
                bytes.fromhex(doc['signature_ed25519']),
                _domain(side,role)+reg.canonical(claim))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise anchor.AnchorError('EC341_ED25519_CHAIN_EDGE_SIGNATURE_INVALID',
                                     'permission_denied') from exc


def _observation_claim(*, parent_sha: str, child_sha: str,
                       witness_sha: str, edge_shas: dict, child: dict,
                       challenge_sha: str, observed_utc: str,
                       expires_utc: str) -> dict:
    need(ceremony._sha(challenge_sha),
         'INDEPENDENT_ROOT_OBSERVER_CHALLENGE_SHA_REQUIRED','invalid_input')
    old._interval(observed_utc,expires_utc,timedelta(hours=24),
                  'ROOT_OBSERVATION_WINDOW_MUST_BE_MAX_24H')
    need(old._time(child['effective_utc'])<=old._time(observed_utc),
         'CANNOT_OBSERVE_RETIREMENT_BEFORE_EFFECTIVE_TIME','invalid_input')
    return {'schema':OBSERVER_CLAIM_SCHEMA,
        'predecessor_roster_original_raw_sha256':parent_sha,
        'successor_roster_original_raw_sha256':child_sha,
        'observer_trust_original_raw_sha256':witness_sha,
        'edge_signature_original_raw_sha256s':one._edge_vector(edge_shas),
        'rotation_id':child['rotation_id'],
        'rotation_nonce_sha256':child['rotation_nonce_sha256'],
        'epoch':child['epoch'],'verifier_challenge_sha256':challenge_sha,
        'observed_utc':observed_utc,'expires_utc':expires_utc,
        'predecessor_root_state':'retired','successor_root_state':'active'}


def _verify_observation(path: str, sha: str, observer: dict,
                        expected: dict, evaluation_utc: str) -> None:
    doc=_read(path,sha,'OBSERVATION')
    need(type(doc) is dict and set(doc)==old.SIGNED_FIELDS and
         doc.get('schema')==OBSERVER_SCHEMA and doc.get('claim')==expected and
         type(doc.get('signature_ed25519')) is str and
         anchor.SIG.fullmatch(doc['signature_ed25519']) is not None,
         'EXACT_OBSERVER_STATUS_CLAIM_AND_SIGNATURE_REQUIRED','invalid_input')
    need(old._time(expected['observed_utc'])<=old._time(evaluation_utc)
         <old._time(expected['expires_utc']),
         'OBSERVATION_MUST_COVER_EXTERNAL_OPERATOR_EVALUATION',
         'permission_denied')
    try:
        io.pub_from_hex(observer['observer_public_hex']).verify(
            bytes.fromhex(doc['signature_ed25519']),
            b'CES/EC341/IndependentRootLineageObservation/v1\0'+
            reg.canonical(expected))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise anchor.AnchorError('EC341_ROOT_OBSERVER_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _hop_refs(hop: dict) -> tuple[dict,dict,list[str],list[str]]:
    need(type(hop) is dict and set(hop)==HOP_FIELDS and
         type(hop.get('epoch')) is int and 2<=hop['epoch']<=MAX_EPOCH and
         ceremony._utc(hop.get('evaluation_utc')) and
         ceremony._sha(hop.get('verifier_challenge_sha256')),
         'EXACT_HOP_FIELDS_EPOCH_AND_EXTERNAL_TIME_REQUIRED','invalid_input')
    refs=hop.get('edge_signatures')
    need(type(refs) is list and len(refs)==8,
         'EXACT_EIGHT_ROLE_SCOPED_EDGE_REFS_REQUIRED','invalid_input')
    files={};shas={}
    for i,ref in enumerate(refs):
        need(type(ref) is dict and set(ref)==EDGE_REF_FIELDS and
             (ref.get('side'),ref.get('role'))==one.EDGE_KEYS[i] and
             ceremony._sha(ref.get('sha256')),
             'EXACT_ORDERED_OLD_NEW_ROLE_AND_PIN_REQUIRED','invalid_input')
        files[one.EDGE_KEYS[i]]=ref['file']
        shas[one.EDGE_KEYS[i]]=ref['sha256']
    need(all(ceremony._sha(hop.get(k)) for k in (
             'expected_successor_roster_sha256',
             'expected_observer_roster_sha256',
             'expected_root_observation_sha256')) and
         len(set([*shas.values(),hop['expected_successor_roster_sha256'],
                  hop['expected_observer_roster_sha256'],
                  hop['expected_root_observation_sha256']]))==11,
         'ELEVEN_DISTINCT_ORIGINAL_SHA_PINS_PER_HOP_REQUIRED','invalid_input')
    paths=[hop['successor_roster_file'],hop['observer_roster_file'],
           hop['root_observation_file'],*files.values()]
    pins=[hop['expected_successor_roster_sha256'],
          hop['expected_observer_roster_sha256'],
          hop['expected_root_observation_sha256'],*shas.values()]
    return files,shas,paths,pins


def _check_manifest(doc: dict) -> tuple[list[str],list[str]]:
    need(type(doc) is dict and set(doc)==MANIFEST_FIELDS and
         doc.get('schema')==MANIFEST_SCHEMA and
         type(doc.get('context')) is dict and
         set(doc['context'])==CONTEXT_FIELDS and
         type(doc.get('history')) is dict and
         set(doc['history'])==HISTORY_FIELDS and
         type(doc.get('hops')) is list and
         1<=len(doc['hops'])<=MAX_EPOCH-1 and
         type(doc.get('forks')) is list and
         len(doc['forks'])<=MAX_FORKS,
         'STRICT_EXTERNALLY_PINNED_LINEAGE_MANIFEST_REQUIRED','invalid_input')
    context,history=doc['context'],doc['history']
    need(all(ceremony._sha(context[k]) for k in CONTEXT_FIELDS if k.endswith('sha256')) and
         all(ceremony._sha(history[k]) for k in HISTORY_FIELDS if k.endswith('sha256')) and
         ceremony._utc(history['evaluation_utc']),
         'HISTORICAL_INDIVIDUAL_WHOLE_SHA_AND_UTC_REQUIRED','invalid_input')
    # Only actual external files belong to the final byte-for-byte recheck.
    # EC337 nested plan/manifest SHA values have no separate local file here;
    # they are verified inside EC340->EC337's original ZIP replay.
    paths=[context['policy_file'],context['authority_roster_file']]
    pins=[context['expected_policy_sha256'],
          context['expected_authority_roster_sha256']]
    for k in sorted(x for x in HISTORY_FIELDS if x.endswith('_file')):
        expected='expected_'+k[:-5]+'_sha256'
        paths.append(history[k]);pins.append(history[expected])
    for i,hop in enumerate(doc['hops']):
        need(type(hop) is dict and hop.get('epoch')==i+2,
             'NO_SKIP_REORDER_OR_DUPLICATE_EPOCH','invalid_input')
        _,_,p,s=_hop_refs(hop);paths+=p;pins+=s
    for item in doc['forks']:
        need(type(item) is dict and set(item)==FORK_FIELDS and
             type(item.get('parent_epoch')) is int and
             1<=item['parent_epoch']<=len(doc['hops']) and
             type(item.get('hop')) is dict and
             item['hop'].get('epoch')==item['parent_epoch']+1,
             'FORK_MUST_ATTACH_TO_EXPLICIT_OBSERVED_PARENT','invalid_input')
        _,_,p,s=_hop_refs(item['hop']);paths+=p;pins+=s
    need(len(set(pins))==len(pins),
         'ALL_ORIGINAL_PINS_DISTINCT_NO_SELF_REFERENCE','invalid_input')
    one._paths(*paths)
    return paths,pins


def _check_witness(path: str, sha: str, policy: dict, policy_sha: str,
                   parent: dict, child: dict, identities: dict) -> dict:
    observer=one._load_observer_root(path,sha,policy,policy_sha,parent,child)
    need(observer['observer_public_hex'] not in identities['issuer_pubs'] and
         observer['observer_public_hex'] not in identities['observer_pubs'] and
         observer['observer_id'] not in identities['issuer_ids'] and
         observer['observer_id'] not in identities['observer_ids'] and
         observer['observer_organization_id'] not in identities['observer_orgs'],
         'OBSERVER_MUST_NOT_REUSE_PRIOR_LINEAGE_KEYS_IDS_OR_ORGANIZATION',
         'invalid_input')
    return observer


def _verify_hop(hop: dict, parent: dict, parent_sha: str, policy: dict,
                policy_sha: str, identities: dict, *, is_first: bool=False,
                previous_effective_utc: str|None=None) -> tuple[dict,dict]:
    edge_files,edge_shas,_,_=_hop_refs(hop)
    child_sha=hop['expected_successor_roster_sha256']
    if is_first:
        child=one._load_successor(hop['successor_roster_file'],child_sha,
                                  parent,parent_sha,policy,policy_sha)
    else:
        child=_load_successor(hop['successor_roster_file'],child_sha,
                              parent,parent_sha,policy,policy_sha)
    need(old._time(hop['evaluation_utc'])>=old._time(child['effective_utc']),
         'ROTATION_EVALUATION_MUST_FOLLOW_EFFECTIVE','invalid_input')
    if previous_effective_utc is not None:
        need(old._time(child['effective_utc'])>old._time(previous_effective_utc),
             'SIBLING_EPOCH_TIME_ROLLBACK','invalid_input')
    # Detect ABA in non-adjacent epochs BEFORE verifying the signature. All
    # ancestor keys/IDs and witness keys are prohibited for any new issuer.
    issuers=child['issuers']
    need(not ({x['issuer_public_hex'] for x in issuers} &
              (identities['issuer_pubs']|identities['observer_pubs'])) and
         not ({x['issuer_id'] for x in issuers} &
              (identities['issuer_ids']|identities['observer_ids'])),
         'ABA_OR_NONADJACENT_ISSUER_KEY_ID_REUSE','invalid_input')
    observer=_check_witness(hop['observer_roster_file'],
        hop['expected_observer_roster_sha256'],policy,policy_sha,parent,child,
        identities)
    need(observer['observer_public_hex'] not in
         {x['issuer_public_hex'] for x in issuers} and
         observer['observer_id'] not in {x['issuer_id'] for x in issuers},
         'WITNESS_AND_NEW_ISSUER_MUST_BE_DISTINCT','invalid_input')
    if is_first:
        one._verify_edges(edge_files,edge_shas,child,parent,parent_sha,child_sha)
    else:
        _verify_edges(edge_files,edge_shas,child,parent,parent_sha,child_sha)
    observed=_read(hop['root_observation_file'],
                   hop['expected_root_observation_sha256'],'HOP_OBSERVATION')
    need(type(observed) is dict and type(observed.get('claim')) is dict and
         set(observed['claim'])==one.OBSERVATION_FIELDS and
         ceremony._utc(observed['claim'].get('observed_utc')) and
         ceremony._utc(observed['claim'].get('expires_utc')),
         'EXACT_SIGNED_OBSERVATION_UTC_FIELDS_REQUIRED','invalid_input')
    claim=observed['claim']
    if is_first:
        expected=one._observe_claim(predecessor_sha=parent_sha,
            successor_sha=child_sha,
            witness_sha=hop['expected_observer_roster_sha256'],edge_shas=edge_shas,
            new_doc=child,verifier_challenge_sha256=hop['verifier_challenge_sha256'],
            observed_utc=claim['observed_utc'],expires_utc=claim['expires_utc'])
        one._verify_observation(hop['root_observation_file'],
            hop['expected_root_observation_sha256'],observer,expected,
            hop['evaluation_utc'])
    else:
        expected=_observation_claim(parent_sha=parent_sha,child_sha=child_sha,
            witness_sha=hop['expected_observer_roster_sha256'],edge_shas=edge_shas,
            child=child,challenge_sha=hop['verifier_challenge_sha256'],
            observed_utc=claim['observed_utc'],expires_utc=claim['expires_utc'])
        _verify_observation(hop['root_observation_file'],
            hop['expected_root_observation_sha256'],observer,expected,
            hop['evaluation_utc'])
    return child,observer


def _identities(legacy: dict,policy: dict) -> dict:
    return {'issuer_ids':{x['issuer_id'] for x in legacy['issuers']},
            'issuer_pubs':{x['issuer_public_hex'] for x in legacy['issuers']},
            'observer_ids':set(), 'observer_pubs':set(),
            'observer_orgs':set(),
            'rotation_ids':set(), 'rotation_nonces':set()}


def _extend(identities: dict,child: dict,witness: dict) -> None:
    need(child['rotation_id'] not in identities['rotation_ids'] and
         child['rotation_nonce_sha256'] not in identities['rotation_nonces'],
         'REUSED_ROTATION_ID_OR_NONCE_ACROSS_NONADJACENT_EPOCHS','invalid_input')
    identities['rotation_ids'].add(child['rotation_id'])
    identities['rotation_nonces'].add(child['rotation_nonce_sha256'])
    identities['issuer_ids'].update(x['issuer_id'] for x in child['issuers'])
    identities['issuer_pubs'].update(x['issuer_public_hex'] for x in child['issuers'])
    identities['observer_ids'].add(witness['observer_id'])
    identities['observer_pubs'].add(witness['observer_public_hex'])
    identities['observer_orgs'].add(witness['observer_organization_id'])


def _late(paths: list[str],shas: list[str],*,bundle_file: str|None=None) -> None:
    for p,sha in zip(paths,shas,strict=True):
        # File extensions are untrusted. ZIPs are hashed as whole byte streams
        # under *the explicit bundle role*, not by a guessed filename suffix.
        expected=(ceremony.transport._sha_path(p) if p==bundle_file else
                  case.sha(reg._private_read(p,MAX_MANIFEST_BYTES,'EC341_LATE_PIN')))
        need(_same(expected,sha),'ORIGINAL_FILE_CHANGED_DURING_LINEAGE_REPLAY')


def _candidate(command: str, field: str, sha: str) -> dict:
    return {'schema':RESULT_SCHEMA,'command':command,'exit_code':2,
        'status':'owner_private_local_candidate_untrusted',field:sha,
        'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def create_roster(*,out: str,policy_file: str,expected_policy_sha256: str,
                  predecessor_roster_file: str,
                  expected_predecessor_roster_sha256: str,
                  issuer_config_file: str,expected_issuer_config_sha256: str,
                  rotation_id: str,rotation_nonce_sha256: str,
                  effective_utc: str) -> dict:
    one._paths(out,policy_file,predecessor_roster_file,issuer_config_file)
    policy=_context(policy_file,expected_policy_sha256)
    parent=_predecessor(predecessor_roster_file,
                        expected_predecessor_roster_sha256,policy,
                        expected_policy_sha256)
    config=_read(issuer_config_file,expected_issuer_config_sha256,
                 'ISSUER_CONFIG')
    need(type(config) is dict and set(config)=={'issuers'},
         'ONLY_FOUR_ISSUER_CONFIG','invalid_input')
    child={'schema':ROOT_SCHEMA,'transfer_id':policy['transfer_id'],
           'policy_original_raw_sha256':expected_policy_sha256,
           'predecessor_roster_original_raw_sha256':
               expected_predecessor_roster_sha256,
           'epoch':parent['epoch']+1,'rotation_id':rotation_id,
           'rotation_nonce_sha256':rotation_nonce_sha256,
           'effective_utc':effective_utc,'issuers':config['issuers'],
           'old_root_retired_from_effective_utc':True,
           'external_successor_root_trust_required':True}
    _validate_successor(child,parent,expected_predecessor_roster_sha256,
                        policy,expected_policy_sha256)
    paths=[policy_file,predecessor_roster_file,issuer_config_file]
    shas=[expected_policy_sha256,expected_predecessor_roster_sha256,
          expected_issuer_config_sha256]
    sha=old._write_and_check(out,child,paths,
                              late_recheck=lambda:_late(paths,shas))
    return _candidate('create-roster','candidate_root_original_raw_sha256',sha)


def _load_pair(*,policy_file: str,expected_policy_sha256: str,
               predecessor_roster_file: str,
               expected_predecessor_roster_sha256: str,
               successor_roster_file: str,
               expected_successor_roster_sha256: str) -> tuple[dict,dict,dict]:
    policy=_context(policy_file,expected_policy_sha256)
    parent=_predecessor(predecessor_roster_file,
                        expected_predecessor_roster_sha256,policy,
                        expected_policy_sha256)
    child=_load_successor(successor_roster_file,expected_successor_roster_sha256,
                           parent,expected_predecessor_roster_sha256,
                           policy,expected_policy_sha256)
    return policy,parent,child


def sign_edge(*,out: str,private_key_file: str,side: str,role: str,
              policy_file: str,expected_policy_sha256: str,
              predecessor_roster_file: str,
              expected_predecessor_roster_sha256: str,
              successor_roster_file: str,
              expected_successor_roster_sha256: str) -> dict:
    allpaths=[out,private_key_file,policy_file,predecessor_roster_file,
              successor_roster_file]
    one._paths(*allpaths)
    policy,parent,child=_load_pair(policy_file=policy_file,
        expected_policy_sha256=expected_policy_sha256,
        predecessor_roster_file=predecessor_roster_file,
        expected_predecessor_roster_sha256=expected_predecessor_roster_sha256,
        successor_roster_file=successor_roster_file,
        expected_successor_roster_sha256=expected_successor_roster_sha256)
    claim=_edge_claim(side,role,child,parent,
                      expected_predecessor_roster_sha256,
                      expected_successor_roster_sha256)
    key,pub=one._private_key_public(private_key_file)
    need(_same(pub,claim['issuer_public_hex']),
         'ONE_PRIVATE_KEY_MUST_MATCH_ROLE_SIDE','permission_denied')
    signed={'schema':EDGE_SCHEMA,'claim':claim,
            'signature_ed25519':key.sign(
                _domain(side,role)+reg.canonical(claim)).hex()}
    source=[policy_file,predecessor_roster_file,successor_roster_file]
    pins=[expected_policy_sha256,expected_predecessor_roster_sha256,
          expected_successor_roster_sha256]
    sha=old._write_and_check(out,signed,allpaths[1:],
             late_recheck=lambda:_late(source,pins))
    return _candidate('sign-edge','candidate_edge_original_raw_sha256',sha)


def issue_observation(*,out: str,private_key_file: str,
                      policy_file: str,expected_policy_sha256: str,
                      predecessor_roster_file: str,
                      expected_predecessor_roster_sha256: str,
                      successor_roster_file: str,
                      expected_successor_roster_sha256: str,
                      observer_roster_file: str,
                      expected_observer_roster_sha256: str,
                      edge_files: dict,edge_shas: dict,
                      verifier_challenge_sha256: str,
                      observed_utc: str,expires_utc: str) -> dict:
    edges,shas=one._edge_inputs(edge_files,edge_shas)
    allpaths=[out,private_key_file,policy_file,predecessor_roster_file,
              successor_roster_file,observer_roster_file,*edges]
    one._paths(*allpaths)
    policy,parent,child=_load_pair(policy_file=policy_file,
        expected_policy_sha256=expected_policy_sha256,
        predecessor_roster_file=predecessor_roster_file,
        expected_predecessor_roster_sha256=expected_predecessor_roster_sha256,
        successor_roster_file=successor_roster_file,
        expected_successor_roster_sha256=expected_successor_roster_sha256)
    observer=one._load_observer_root(observer_roster_file,
        expected_observer_roster_sha256,policy,expected_policy_sha256,parent,child)
    _verify_edges(edge_files,edge_shas,child,parent,
                  expected_predecessor_roster_sha256,
                  expected_successor_roster_sha256)
    claim=_observation_claim(parent_sha=expected_predecessor_roster_sha256,
        child_sha=expected_successor_roster_sha256,
        witness_sha=expected_observer_roster_sha256,
        edge_shas=edge_shas,child=child,
        challenge_sha=verifier_challenge_sha256,
        observed_utc=observed_utc,expires_utc=expires_utc)
    key,pub=one._private_key_public(private_key_file)
    need(_same(pub,observer['observer_public_hex']),
         'OBSERVER_PRIVATE_KEY_MUST_MATCH_PINNED_WITNESS')
    signed={'schema':OBSERVER_SCHEMA,'claim':claim,
            'signature_ed25519':key.sign(
                b'CES/EC341/IndependentRootLineageObservation/v1\0'+
                reg.canonical(claim)).hex()}
    sources=allpaths[2:]
    pins=[expected_policy_sha256,expected_predecessor_roster_sha256,
          expected_successor_roster_sha256,expected_observer_roster_sha256,*shas]
    sha=old._write_and_check(out,signed,allpaths[1:],
                             late_recheck=lambda:_late(sources,pins))
    return _candidate('issue-observation','candidate_observation_original_raw_sha256',sha)


def verify_lineage(*,manifest_file: str,expected_manifest_sha256: str,
                   expected_current_root_sha256: str,
                   expected_current_root_epoch: int,
                   minimum_acceptable_epoch: int,
                   current_root_evaluation_utc: str) -> dict:
    """Read only: one independently pinned manifest, explicit current root and floor.

    The manifest carries all individual original-file pins, which must have
    been independently entrusted and sealed BEFORE signing/verification. The
    verifier intentionally cannot establish where that SHA was sourced.
    """
    need(ceremony._sha(expected_manifest_sha256) and
         ceremony._sha(expected_current_root_sha256) and
         type(expected_current_root_epoch) is int and
         type(minimum_acceptable_epoch) is int and
         2<=minimum_acceptable_epoch<=expected_current_root_epoch<=MAX_EPOCH and
         ceremony._utc(current_root_evaluation_utc),
         'EXTERNAL_MANIFEST_ROOT_EPOCH_FLOOR_AND_TIME_REQUIRED','invalid_input')
    manifest=_read(manifest_file,expected_manifest_sha256,
                   'LINEAGE_MANIFEST',MAX_MANIFEST_BYTES)
    paths,pins=_check_manifest(manifest)
    one._paths(manifest_file,*paths)
    hops=manifest['hops']
    last=hops[-1]
    need(expected_current_root_epoch==len(hops)+1 and
         _same(expected_current_root_sha256,
               last['expected_successor_roster_sha256']) and
         _same(current_root_evaluation_utc,last['evaluation_utc']),
         'EXTERNALLY_PINNED_CURRENT_ROOT_OR_EPOCH_ROLLBACK_REJECTED',
         'permission_denied')
    context,history=manifest['context'],manifest['history']
    # History challenge is intentionally separate from the nested manifest
    # shape: EC339 status records must be independently checked using hop 2.
    policy,legacy=one._load_context(**context)
    historical_eval=old._time(history['evaluation_utc'])
    need(historical_eval < old._time(current_root_evaluation_utc),
         'HISTORICAL_EVALUATION_MUST_PRECEDE_CURRENT','invalid_input')
    roots=[legacy]; root_shas=[context['expected_authority_roster_sha256']]
    ids=_identities(legacy,policy)
    verified=[]
    previous_evaluation=historical_eval
    for index,hop in enumerate(hops):
        need(old._time(hop['evaluation_utc'])>=previous_evaluation,
             'EVALUATION_TIME_MUST_NOT_RUN_BACKWARDS','invalid_input')
        parent=roots[-1];parent_sha=root_shas[-1]
        child,witness=_verify_hop(hop,parent,parent_sha,policy,
            context['expected_policy_sha256'],ids,
            is_first=index==0)
        need(historical_eval < old._time(child['effective_utc']),
             'OLD_EC339_HISTORY_AFTER_ROOT_RETIREMENT','permission_denied')
        if index and old._time(hops[index-1]['evaluation_utc'])>=old._time(child['effective_utc']):
            need(False,'INTERMEDIATE_ROOT_EVALUATED_AFTER_NEXT_RETIREMENT',
                 'permission_denied')
        need(root_shas[-1]!=hop['expected_successor_roster_sha256'] and
             hop['expected_successor_roster_sha256'] not in root_shas,
             'LINEAGE_ROOT_SHA_ROLLBACK_OR_CYCLE','invalid_input')
        _extend(ids,child,witness)
        roots.append(child);root_shas.append(hop['expected_successor_roster_sha256'])
        previous_evaluation=old._time(hop['evaluation_utc'])
        verified.append({'epoch':child['epoch'],
          'predecessor_roster_original_raw_sha256':parent_sha,
          'successor_roster_original_raw_sha256':root_shas[-1],
          'effective_utc':child['effective_utc'],
          'eight_signed_edges_verified':True,
          'independent_signed_observation_verified':True})
    # A real lower-chain replay is mandatory. EC340 executes EC339->338->337,
    # complete original/nested ZIP SHA and all original signature checks.
    first=hops[0];first_edges,first_pins,_,_=_hop_refs(first)
    inherited=one.verify_rotation(
        **context,
        successor_roster_file=first['successor_roster_file'],
        expected_successor_roster_sha256=first['expected_successor_roster_sha256'],
        expected_current_root_sha256=first['expected_successor_roster_sha256'],
        expected_current_root_epoch=2,
        observer_roster_file=first['observer_roster_file'],
        expected_observer_roster_sha256=first['expected_observer_roster_sha256'],
        root_observation_file=first['root_observation_file'],
        expected_root_observation_sha256=first['expected_root_observation_sha256'],
        edge_files=first_edges,edge_shas=first_pins,
        root_evaluation_utc=first['evaluation_utc'],
        verifier_challenge_sha256=first['verifier_challenge_sha256'],
        **history)
    need(inherited.get('exit_code')==2 and
         inherited.get('historical_ec339_to_ec337_original_full_replay_verified') is True and
         inherited.get('historical_ec339_not_accepted_as_new_epoch_authorization') is True and
         inherited.get('eight_separate_old_new_ed25519_signatures_verified') is True,
         'UNCHANGED_EC340_TO_EC337_HISTORICAL_REPLAY_REQUIRED')
    # Verify every *presented* sibling with eight real side/role signatures
    # and an independent witness before it is called a conflict. Never choose
    # a winner. This is NOT global fork discovery.
    conflicts=[]
    fork_ids={k:set(v) for k,v in ids.items()}
    observed_alternative_shas=set()
    for item in manifest['forks']:
        parent_index=item['parent_epoch']-1
        parent=roots[parent_index];parent_sha=root_shas[parent_index]
        alt=item['hop']; selected=hops[parent_index]
        need(alt['expected_successor_roster_sha256']!=
             selected['expected_successor_roster_sha256'] and
             alt['expected_successor_roster_sha256'] not in root_shas,
             'FORK_MUST_BE_A_DISTINCT_SUCCESSOR_OF_SAME_PARENT',
             'invalid_input')
        # Isolated fork identities contain all earlier chain identities, but
        # never allow reuse of a new key already selected on the main chain.
        need(alt['expected_successor_roster_sha256'] not in observed_alternative_shas,
             'DUPLICATE_ALTERNATIVE_ROOT_REPORTED_TWICE','invalid_input')
        alt_child,alt_witness=_verify_hop(alt,parent,parent_sha,policy,
              context['expected_policy_sha256'],fork_ids,
              is_first=item['parent_epoch']==1)
        _extend(fork_ids,alt_child,alt_witness)
        observed_alternative_shas.add(alt['expected_successor_roster_sha256'])
        need(old._time(alt['evaluation_utc'])>=old._time(alt_child['effective_utc']),
             'SIGNED_ALTERNATIVE_NOT_YET_EFFECTIVE','permission_denied')
        if item['parent_epoch']==1:
            need(historical_eval<old._time(alt_child['effective_utc']),
                 'ALTERNATIVE_CANNOT_REAUTHORIZE_HISTORICAL_OLD_GRANTS',
                 'permission_denied')
            for role in one.ROLES:
                receipt=_read(history[role+'_receipt_file'],
                              history['expected_'+role+'_receipt_sha256'],
                              'ALTERNATIVE_OLD_RECEIPT')
                need(old._time(receipt['claim']['signer_reported_utc'])<
                     old._time(alt_child['effective_utc']),
                     'ALTERNATIVE_OLD_RECEIPT_AFTER_RETIREMENT')
        else:
            need(old._time(alt_child['effective_utc'])>
                 old._time(hops[parent_index-1]['evaluation_utc']),
                 'FORK_EFFECTIVE_BEFORE_PREVIOUS_EVALUATION',
                 'permission_denied')
        conflicts.append({'parent_epoch':item['parent_epoch'],
             'parent_roster_original_raw_sha256':parent_sha,
             'selected_successor_original_raw_sha256':
                 selected['expected_successor_roster_sha256'],
             'alternative_successor_original_raw_sha256':
                 alt['expected_successor_roster_sha256']})
    # Re-read every original file and independently entrusted manifest at end.
    _late([manifest_file,*paths],[expected_manifest_sha256,*pins],
          bundle_file=history['bundle_file'])
    need(_same(ceremony.transport._sha_path(history['bundle_file']),
               history['expected_bundle_sha256']),
         'EC337_ZIP_WHOLE_ORIGINAL_CHANGED_DURING_LINEAGE')
    return {'schema':RESULT_SCHEMA,'command':'verify-lineage',
        'status':'conflict_unresolved' if conflicts else
                 'lineage_locally_verified_unresolved',
        'exit_code':2,
        'manifest_original_raw_sha256':expected_manifest_sha256,
        'policy_original_raw_sha256':context['expected_policy_sha256'],
        'historical_authority_root_original_raw_sha256':root_shas[0],
        'externally_pinned_current_root_original_raw_sha256':
            expected_current_root_sha256,
        'externally_pinned_current_root_epoch':expected_current_root_epoch,
        'independent_minimum_acceptable_epoch':minimum_acceptable_epoch,
        'operator_current_root_evaluation_utc':current_root_evaluation_utc,
        'verified_lineage':verified,'fork_conflicts':conflicts,
        'real_role_signature_count':8*(len(hops)+len(conflicts)),
        'real_observer_signature_count':len(hops)+len(conflicts),
        'historical_ec340_to_ec337_real_original_replay_verified':True,
        'old_grants_not_new_epoch_authorizations':True,
        'only_supplied_externally_pinned_forks_examined':True,
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES}}
