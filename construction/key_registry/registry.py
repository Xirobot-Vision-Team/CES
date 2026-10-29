#!/usr/bin/env python3
"""EC352: genuinely verify bounded *submitted* signer-registry key histories.

This module does not trust a purported institution because its Ed25519 root
self-signs a registry.  Source facts are inherited ONLY by re-executing the
EC351 -> EC337 actual source verifier, not by ingesting a report. Every file,
including each operational signer public key and its signed predecessor,
requires an independently specified exact-byte SHA-256 pin. Zero IO beyond
explicitly named input files; no networking, key generation, signers or writers.
"""
from __future__ import annotations

from collections import Counter
from datetime import timedelta
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as reg
from tsa_timestamp import timestamp as old350
from tsa_provenance import provenance as old351

RESULT_SCHEMA='ces.ec352.offline_dual_attester_key_registry_history_unresolved.v1'
DENIAL_SCHEMA='ces.ec352.offline_dual_attester_key_registry_history_denial.v1'
HANDOFF_SCHEMA='ces.ec352.unsigned_dual_key_registry_handoff.v1'
ROOT_SCHEMA='ces.ec352.self_signed_institutional_registry_reference.v1'
EVENT_SCHEMA='ces.ec352.root_authorized_key_registry_event.v1'
ROOT_DOMAIN=b'CES/EC352/RegistryRootReference/v1\x00'
EVENT_DOMAIN=b'CES/EC352/RootAuthorizedEvent/v1\x00'
OPERATOR_DOMAIN=b'CES/EC352/OperationalSignerEvent/v1\x00'
PRIOR_DOMAIN=b'CES/EC352/PriorSignerRotation/v1\x00'
GENESIS='GENESIS'
NONE='NONE'
MAX_ROOT_BYTES=12_000
MAX_EVENT_BYTES=24_000
MAX_EVENTS=8
MAX_PER_REGISTRY=6
MAX_SEQUENCE=4
MAX_SIGNER_KEY_BYTES=32
MAX_WINDOW=timedelta(days=7)
MAX_ROOT_WINDOW=timedelta(days=366)

OUTCOMES=(
    'ec351_parent_signed_origin_or_revocation_unresolved',
    'ec352_two_separately_pinned_registry_roots_not_furnished',
    'ec352_signed_registry_history_missing_or_incomplete',
    'ec352_signed_registry_fork_or_contradiction_unresolved',
    'ec352_key_revoked_or_retroactive_authorization_unresolved',
    'ec352_registry_stale_or_attester_coverage_incomplete',
    'ec352_matching_signed_registry_claims_real_official_issuer_unproven',
)
NEGATIVES=(
    'caller_selected_registry_root_key_proves_official_institution_identity',
    'self_signed_root_reference_proves_independent_official_provenance',
    'two_registry_files_or_names_prove_two_external_institutions',
    'registry_signature_proves_legal_tsa_or_policy_qualification',
    'historical_registry_claims_prove_globally_complete_rotation_or_revocations',
    'unobserved_forks_or_unsupplied_registry_epochs_are_ruled_out',
    'later_registry_authorization_repairs_earlier_ec351_parent_defects',
    'registry_issued_utc_is_an_independently_calibrated_clock',
    'reader_fetches_registry_uris_or_uses_os_trust_anchors',
    'audit_generates_keys_signs_or_writes_provider_cas_worm',
    'ec317_ec318_production_custody_and_final_acceptance_proven',
)
SHA_RE=re.compile(r'[0-9a-f]{64}\Z')
HEX_SIGNATURE=re.compile(r'[0-9a-f]{128}\Z')
IDENTIFIER_RE=re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,99}\Z')
POLICY_RE=re.compile(r'[0-2](?:\.\d+)+\Z')
HTTPS_RE=re.compile(r'https://[A-Za-z0-9][A-Za-z0-9._~:/?#@!$&()*+,;=%-]{4,999}\Z')


def require(test:Any,code:str,status:str='invalid_input')->None:
    if test is not True:
        raise errors.AnchorError('EC352_'+code,status)


def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    d={}
    for k,v in pairs:
        if k in d:raise ValueError('duplicate JSON key')
        d[k]=v
    return d


def _strict_json(raw:bytes,kind:str)->dict:
    import json
    try:
        doc=json.loads(raw.decode('utf8'),object_pairs_hook=_pairs,
                       parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (ValueError,UnicodeError,TypeError) as exc:
        raise errors.AnchorError('EC352_'+kind+'_JSON_MALFORMED','invalid_input') from exc
    require(type(doc) is dict and reg.canonical(doc)==raw,
            kind+'_CANONICAL_JSON_REQUIRED')
    return doc


def _str_fields(doc:dict,fields:set[str],kind:str)->None:
    require(set(doc)==fields,kind+'_FIELDS_MUST_BE_EXACT')
    require(all(type(doc[k]) is str for k in fields),kind+'_STRING_FIELDS_REQUIRED')


def _is_sha(s):
    return type(s) is str and SHA_RE.fullmatch(s) is not None and s!='0'*64


def _sig(key:bytes,signature:str,domain:bytes,body:dict,reason:str)->None:
    require(type(signature) is str and HEX_SIGNATURE.fullmatch(signature) is not None,
            reason+'_SIGNATURE_FORMAT_INVALID')
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(signature),domain+reg.canonical(body))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise errors.AnchorError('EC352_'+reason+'_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _parse_root(raw:bytes,public_key:bytes,key_sha:str,evaluation,claimed_id:str)->dict:
    doc=_strict_json(raw,'ROOT_REFERENCE')
    fields={'schema','registry_channel_id','root_public_key_original_sha256',
            'claimed_issuer_organization','claimed_issuer_document_uri',
            'valid_from_utc','valid_until_utc','self_signature_ed25519_hex'}
    _str_fields(doc,fields,'ROOT_REFERENCE')
    require(doc['schema']==ROOT_SCHEMA and doc['registry_channel_id']==claimed_id
            and doc['root_public_key_original_sha256']==key_sha,
            'ROOT_REFERENCE_SCHEMA_ID_OR_KEY_SHA_MISMATCH','permission_denied')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 .,_()&/-]{2,119}',
                         doc['claimed_issuer_organization']) is not None and
            HTTPS_RE.fullmatch(doc['claimed_issuer_document_uri']) is not None,
            'ROOT_ISSUER_CLAIMS_FORMAT_INVALID')
    frm=old350._utc(doc['valid_from_utc']);to=old350._utc(doc['valid_until_utc'])
    require(frm<=evaluation<=to and to>frm and to-frm<=MAX_ROOT_WINDOW,
            'ROOT_REFERENCE_EVALUATION_WINDOW_INVALID','permission_denied')
    require(len(public_key)==32,'ROOT_PUBLIC_KEY_NOT_32_BYTES')
    _sig(public_key,doc['self_signature_ed25519_hex'],ROOT_DOMAIN,
         {k:v for k,v in doc.items() if k!='self_signature_ed25519_hex'},
         'ROOT_SELF')
    return doc


ENTRY_KEYS={'tsa_channel_id','source_attestation_original_sha256',
            'attester_public_key_original_sha256','source_document_original_sha256',
            'tsa_root_original_sha256','tsa_root_der_sha256','tsa_policy_oid',
            'authorization','not_before_utc','not_after_utc'}
EVENT_KEYS={'schema','registry_channel_id','sequence','previous_event_sha256',
            'event_kind','root_reference_original_sha256',
            'root_public_key_original_sha256',
            'signer_public_key_original_sha256','issued_utc','valid_until_utc',
            'entries','root_signature_ed25519_hex',
            'previous_signer_signature_ed25519_hex',
            'current_signer_signature_ed25519_hex'}


def _parse_event(raw:bytes,root_key:bytes,root_sha:str,root_ref_sha:str,
                 actual_signer_key:bytes,signer_sha:str,registry_id:str,
                 allowed_channels:set[str],evaluation)->dict:
    doc=_strict_json(raw,'REGISTRY_EVENT')
    require(set(doc)==EVENT_KEYS,'REGISTRY_EVENT_FIELDS_MUST_BE_EXACT')
    require(type(doc['sequence']) is int and 1<=doc['sequence']<=MAX_SEQUENCE,
            'EVENT_SEQUENCE_INVALID')
    require(all(type(doc[k]) is str for k in EVENT_KEYS-{'sequence','entries'}),
            'EVENT_STRING_FIELDS_REQUIRED')
    require(doc['schema']==EVENT_SCHEMA and doc['registry_channel_id']==registry_id
            and doc['root_reference_original_sha256']==root_ref_sha and
            doc['root_public_key_original_sha256']==root_sha and
            doc['signer_public_key_original_sha256']==signer_sha,
            'REGISTRY_EVENT_ROOT_OR_SIGNER_BINDING_INVALID','permission_denied')
    require(doc['event_kind'] in ('activate','renew','rotate','revoke'),
            'EVENT_KIND_UNSUPPORTED')
    require(doc['previous_event_sha256']==GENESIS or
            _is_sha(doc['previous_event_sha256']),
            'EVENT_PREDECESSOR_SHA_INVALID')
    issued=old350._utc(doc['issued_utc']);to=old350._utc(doc['valid_until_utc'])
    require(issued<=evaluation and issued<to and to-issued<=MAX_WINDOW,
            'REGISTRY_EVENT_ISSUANCE_OR_7_DAY_WINDOW_INVALID','permission_denied')
    require(type(doc['entries']) is list and len(doc['entries'])<=2,
            'REGISTRY_EVENT_ENTRIES_NOT_BOUNDED')
    seen=[]
    for ent in doc['entries']:
        require(type(ent) is dict and set(ent)==ENTRY_KEYS and
                all(type(v) is str for v in ent.values()),
                'REGISTRY_ENTRY_FIELDS_INVALID')
        ch=ent['tsa_channel_id'];seen.append(ch)
        require(ch in allowed_channels,'REGISTRY_ENTRY_UNPRESENTED_TSA_CHANNEL',
                'permission_denied')
        require(all(_is_sha(ent[k]) for k in ENTRY_KEYS if k.endswith('sha256')) and
                POLICY_RE.fullmatch(ent['tsa_policy_oid']) is not None and
                ent['authorization'] in ('authorized','revoked'),
                'REGISTRY_ENTRY_HASH_POLICY_OR_AUTHORIZATION_INVALID')
        begin=old350._utc(ent['not_before_utc']);end=old350._utc(ent['not_after_utc'])
        require(begin<end and end-begin<=MAX_ROOT_WINDOW and
                begin<=to and end>=issued,
                'REGISTRY_ENTRY_AUTHORIZATION_WINDOW_INVALID')
    require(seen==sorted(set(seen)),'REGISTRY_ENTRIES_UNIQUE_ASCENDING_REQUIRED')
    require(doc['event_kind']!='revoke' or not doc['entries'],
            'TERMINAL_ROOT_REVOKE_CANNOT_AUTHORIZE_NEW_ENTRIES')
    require(len(actual_signer_key)==32 and signer_sha!=root_sha,
            'REGISTRY_OPERATOR_AND_ROOT_MUST_BE_DISTINCT')
    body={k:v for k,v in doc.items() if k not in (
        'root_signature_ed25519_hex','previous_signer_signature_ed25519_hex',
        'current_signer_signature_ed25519_hex')}
    _sig(root_key,doc['root_signature_ed25519_hex'],EVENT_DOMAIN,body,'EVENT_ROOT')
    # Every non-terminal snapshot must additionally prove possession of the
    # operational public key (not just name one); rotate checks predecessor below.
    if doc['event_kind']=='revoke':
        require(doc['current_signer_signature_ed25519_hex']==NONE,
                'REVOKE_FORBIDS_CURRENT_SIGNER_SIGNATURE')
    else:
        _sig(actual_signer_key,doc['current_signer_signature_ed25519_hex'],
             OPERATOR_DOMAIN,body,'EVENT_OPERATOR')
    return {'document':doc,'body':body,'issued':issued,'expiry':to,
            'signer_raw':actual_signer_key,'sha256':sha(raw),
            'signed_root_authorization_verified':True}


def _validate_chain(events:list[dict])->dict:
    by_sha={e['sha256']:e for e in events}
    require(len(by_sha)==len(events),'DUPLICATE_SIGNED_EVENT_ORIGINAL')
    seq_counts=Counter(e['document']['sequence'] for e in events)
    require(all(v<=4 for v in seq_counts.values()),'TOO_MANY_SAME_SEQUENCE_EVENTS')
    refs=Counter(e['document']['previous_event_sha256'] for e in events)
    require(all(n<=2 for v,n in refs.items() if v!=GENESIS),
            'MORE_THAN_TWO_SIBLING_EVENTS_PER_PREDECESSOR')
    for e in sorted(events,key=lambda x:x['document']['sequence']):
        doc=e['document'];version=doc['sequence'];prev_sha=doc['previous_event_sha256']
        kind=doc['event_kind']
        if version==1:
            require(prev_sha==GENESIS and kind=='activate',
                    'FIRST_EVENT_MUST_ACTIVATE_AT_GENESIS','permission_denied')
            require(doc['previous_signer_signature_ed25519_hex']==NONE,
                    'ACTIVATION_FORBIDS_PREVIOUS_SIGNER')
            e['history']=[e]
            e['revoked_keys']=set()
        else:
            require(kind!='activate',
                    'ACTIVATION_MAY_ONLY_OCCUR_AT_GENESIS','permission_denied')
            require(prev_sha in by_sha,'SIGNED_REGISTRY_PREDECESSOR_NOT_PRESENTED',
                    'permission_denied')
            prev=by_sha[prev_sha];parent=prev['document']
            require(parent['sequence']==version-1 and
                    parent['event_kind']!='revoke' and
                    prev['issued']<=e['issued'],
                    'REGISTRY_SEQUENCE_CAUSALITY_OR_REVOKED_SIGNER_INVALID',
                    'permission_denied')
            oldkey=prev['signer_raw'];oldsha=parent['signer_public_key_original_sha256']
            newsha=doc['signer_public_key_original_sha256']
            if kind=='rotate':
                require(newsha!=oldsha,
                        'ROTATION_REQUIRES_DISTINCT_NEW_OPERATIONAL_KEY')
                _sig(oldkey,doc['previous_signer_signature_ed25519_hex'],
                     PRIOR_DOMAIN,e['body'],'ROTATION_PREVIOUS_SIGNER')
            else:
                require(newsha==oldsha and
                        doc['previous_signer_signature_ed25519_hex']==NONE,
                        'NONROTATION_MUST_KEEP_SIGNER_KEY_AND_NO_PREVIOUS_SIGNATURE',
                        'permission_denied')
            e['history']=[*prev['history'],e]
            e['revoked_keys']=set(prev['revoked_keys'])
        # An enrolled key's authorization cannot be silently re-granted after
        # a *signed* revocation in this same history branch.
        for ent in doc['entries']:
            key=ent['attester_public_key_original_sha256']
            if ent['authorization']=='revoked':e['revoked_keys'].add(key)
            else:
                require(key not in e['revoked_keys'],
                        'REVOKED_ATTESTER_REAUTHORIZATION_FORBIDDEN',
                        'permission_denied')
    heads=sorted((e for e in events if e['sha256'] not in refs),
                 key=lambda e:e['sha256'])
    return {'heads':heads,'forked':len(heads)>1,
            'events_count':len(events),
            'all_signatures_and_predecessors_verified':True,
            'all_furnished_heads':[e['sha256'] for e in heads],
            'unseen_head_or_fork_completeness_proven':False}


def _observe_registry(channel:str,entry_expected:dict,stmt_issued,
                      registry:dict,evaluation)->dict:
    base={'registry_channel_id':registry['id'],
          'self_signed_root_reference_sha256':registry['root_ref_sha'],
          'root_key_original_sha256':registry['root_key_sha'],
          'complete_external_registry_census_proven':False,
          'signed_history_present':registry['events_count']>0,
          'all_supplied_event_signatures_verified':True,
          'furnished_terminal_event_original_shas':registry['heads'],
          'active_signer_key_sha256':None,
          'latest_event_kind':None,'claimed_latest_snapshot_fresh':False,
          'key_binding_status':'not_furnished',
          'registration_claim_predates_ec351_statement':False,
          'event_history_original_shas':[],
          'historical_other_attester_key_sha_claims':[],
          'registry_authorization_officially_independent':False}
    if not registry['events_count']:return base
    if registry['forked']:
        base['key_binding_status']='fork_no_winner'
        return base
    event=registry['head_objects'][0]
    d=event['document'];base['latest_event_kind']=d['event_kind']
    base['active_signer_key_sha256']=d['signer_public_key_original_sha256']
    base['event_history_original_shas']=[v['sha256'] for v in event['history']]
    base['claimed_latest_snapshot_fresh']=event['issued']<=evaluation<=event['expiry']
    if d['event_kind']=='revoke':
        base['key_binding_status']='registry_signer_revoked'
        return base
    # Look at *every* supplied ancestor of the claimed latest, never a single
    # unconnected JSON assertion. Signed gaps, revocations and missing latest
    # records prevent an authorization claim from being treated as continuous.
    history=event['history']
    signed_history_gap=any(new['issued']>old['expiry']
                           for old,new in zip(history,history[1:]))
    seen=False;revoked=False;historical_activation=False;last_record=None
    latest_record=False;other_attester_states={}
    for v in event['history']:
        for ent in v['document']['entries']:
            if ent['tsa_channel_id']!=channel:continue
            old_attester_sha=ent['attester_public_key_original_sha256']
            if old_attester_sha!=entry_expected['attester_public_key_original_sha256']:
                # Only a *historical*, separately named former source key may
                # differ. The latest snapshot must cover the actual EC351 key.
                if v is event:
                    base['key_binding_status']='contradictory_signed_binding'
                    return base
                other_attester_states[old_attester_sha]=ent['authorization']
                continue
            matches=all(ent[k]==expected for k,expected in entry_expected.items())
            if not matches:
                base['key_binding_status']='contradictory_signed_binding'
                return base
            seen=True;last_record=ent
            if v is event:latest_record=True
            if ent['authorization']=='revoked':revoked=True
            if ent['authorization']=='authorized' and v['issued']<=stmt_issued:
                historical_activation=True
    base['historical_other_attester_key_sha_claims']=sorted(other_attester_states)
    if revoked:
        base['key_binding_status']='attester_key_revoked_in_signed_history'
    elif any(status=='authorized' for status in other_attester_states.values()):
        base['key_binding_status']='former_attester_key_not_signed_revoked'
    elif not seen or not latest_record:
        base['key_binding_status']='missing_attester_record'
    elif last_record['authorization']!='authorized':
        base['key_binding_status']='attester_last_claim_not_authorized'
    elif not historical_activation:
        base['key_binding_status']='retroactive_registry_claim_only'
    elif signed_history_gap:
        base['key_binding_status']='signed_registry_history_freshness_gap'
    elif (not base['claimed_latest_snapshot_fresh'] or
          not old350._utc(last_record['not_before_utc'])<=evaluation<=
              old350._utc(last_record['not_after_utc'])):
        base['key_binding_status']='stale_signed_record_or_registry'
    else:
        base['key_binding_status']='authorized_claim_exact_binding'
    base['registration_claim_predates_ec351_statement']=historical_activation
    return base


def _all_parent_files(inputs:dict)->set[str]:
    files=set()
    for k,v in inputs.items():
        if k.endswith('_file') and type(v) is str:files.add(v)
        elif k.endswith('_files') and type(v) is list:files.update(v)
    return files


def _read_new_file(path:str,pin:str,cap:int,role:str,pins:dict)->bytes:
    # Renewals legitimately repeat an unchanged operational public-key file.
    # The *same* pinned original may only reappear under the same key role.
    if path in pins:
        oldsha,oldcap,oldrole= pins[path]
        require(oldsha==pin and oldcap==cap and oldrole==role,
                'ORIGINAL_REUSED_WITH_DIFFERENT_KEY_ROLE_OR_SHA','permission_denied')
        return old350._read_pinned(path,pin,cap,role,{})
    data=old350._read_pinned(path,pin,cap,role,{})
    pins[path]=(pin,cap,role)
    return data


def _late_verify(pins:dict)->None:
    old350._check_late({p:(h,cap) for p,(h,cap,role) in pins.items()})


def audit(*,registry_evaluation_utc:str,
          registry_channel_ids:list[str],
          registry_root_reference_files:list[str],
          registry_root_reference_shas:list[str],
          registry_root_key_files:list[str],registry_root_key_shas:list[str],
          registry_event_channel_ids:list[str],registry_event_files:list[str],
          registry_event_shas:list[str],registry_signer_key_files:list[str],
          registry_signer_key_shas:list[str],**ec351_inputs)->dict:
    evaluation=old350._utc(registry_evaluation_utc)
    require(evaluation>=old350._utc(ec351_inputs.get('provenance_evaluation_utc')),
            'REGISTRY_EVALUATION_PRECEDES_EC351','permission_denied')
    roots=(registry_channel_ids,registry_root_reference_files,
           registry_root_reference_shas,registry_root_key_files,registry_root_key_shas)
    events=(registry_event_channel_ids,registry_event_files,
            registry_event_shas,registry_signer_key_files,registry_signer_key_shas)
    require(all(type(a) is list for a in (*roots,*events)) and
            len({len(a) for a in roots})==1 and len(roots[0])<=2 and
            len({len(a) for a in events})==1 and len(events[0])<=MAX_EVENTS,
            'REGISTRY_ROOT_OR_EVENT_ARRAYS_NOT_ALIGNED_OR_OVER_LIMIT')
    require(registry_channel_ids==sorted(set(registry_channel_ids)) and
            all(type(i) is str and IDENTIFIER_RE.fullmatch(i) is not None
                for i in registry_channel_ids) and
            all(type(i) is str and i in registry_channel_ids
                for i in registry_event_channel_ids),
            'REGISTRY_CHANNEL_IDS_INVALID')
    require(all(registry_event_channel_ids.count(i)<=MAX_PER_REGISTRY
                for i in registry_channel_ids),
            'REGISTRY_PER_CHANNEL_EVENT_LIMIT_EXCEEDED')
    parent_paths=_all_parent_files(ec351_inputs)
    fresh=[*registry_root_reference_files,*registry_root_key_files,
           *registry_event_files,*registry_signer_key_files]
    # Repeated operational signer *paths* are permitted only within a single
    # registry; all other new originals must have independent names.
    unique_only=[*registry_root_reference_files,*registry_root_key_files,
                 *registry_event_files]
    require(len(set(unique_only))==len(unique_only) and
            not set(fresh).intersection(parent_paths) and
            not set(unique_only).intersection(registry_signer_key_files),
            'REGISTRY_ORIGINALS_ALIAS_PARENT_OR_EACH_OTHER','permission_denied')
    signer_path_owners={}
    for channel,p in zip(registry_event_channel_ids,registry_signer_key_files,strict=True):
        if p in signer_path_owners:
            require(signer_path_owners[p]==channel,
                    'REGISTRY_SIGNER_PATH_SHARED_BETWEEN_CHANNELS',
                    'permission_denied')
        signer_path_owners[p]=channel
    # Only EC351's real execution establishes source/OCSP conditions. A
    # caller-supplied previous "PASS" document is never an input to the API.
    parent=old351.audit(**ec351_inputs)
    require(parent.get('exit_code')==2 and
            parent.get('ec350_to_ec337_actual_originals_replayed') is True,
            'EC351_TO_EC337_ACTUAL_REPLAY_REQUIRED','permission_denied')
    pins={};roots_loaded={}
    for id,ref,refsha,pub,pubsha in zip(*roots,strict=True):
        key=_read_new_file(pub,pubsha,MAX_SIGNER_KEY_BYTES,'REGISTRY_ROOT_KEY',pins)
        doc=_parse_root(_read_new_file(ref,refsha,MAX_ROOT_BYTES,
                      'REGISTRY_ROOT_REFERENCE',pins),key,pubsha,evaluation,id)
        roots_loaded[id]={'id':id,'root':doc,'root_key':key,
                          'root_key_sha':pubsha,'root_ref_sha':refsha,
                          'events':[],'events_count':0}
    require(len({r['root_key_sha'] for r in roots_loaded.values()})==len(roots_loaded),
            'TWO_REGISTRIES_REUSE_ONE_ROOT_KEY','permission_denied')
    allowed={r['channel_id'] for r in parent['channel_evidence']}
    all_keyroles={r['root_key_sha'] for r in roots_loaded.values()}
    parentsigner=set(ec351_inputs['authority_key_shas'])
    require(not all_keyroles.intersection(parentsigner),
            'REGISTRY_ROOT_REUSES_EC351_ATTESTER_KEY','permission_denied')
    for channel,eventfile,eventsha,signerfile,signersha in zip(*events,strict=True):
        r=roots_loaded[channel]
        signer=_read_new_file(signerfile,signersha,MAX_SIGNER_KEY_BYTES,
                              'REGISTRY_SIGNER_KEY',pins)
        raw=_read_new_file(eventfile,eventsha,MAX_EVENT_BYTES,
                           'REGISTRY_SIGNED_EVENT',pins)
        parsed=_parse_event(raw,r['root_key'],r['root_key_sha'],r['root_ref_sha'],
                            signer,signersha,channel,allowed,evaluation)
        rootfrom=old350._utc(r['root']['valid_from_utc'])
        rootuntil=old350._utc(r['root']['valid_until_utc'])
        require(rootfrom<=parsed['issued'] and parsed['expiry']<=rootuntil,
                'EVENT_OUTSIDE_OWN_SIGNED_ROOT_REFERENCE_VALIDITY',
                'permission_denied')
        r['events'].append(parsed)
        require(signersha not in all_keyroles and signersha not in parentsigner,
                'REGISTRY_OPERATOR_REUSES_ROOT_OR_EC351_ATTESTER_KEY',
                'permission_denied')
    # Forbid a single operational public key posing as independent channels,
    # but allow repeated use of that key in renewals within one channel.
    signer_owners={}
    for id,r in roots_loaded.items():
        for e in r['events']:
            key=e['document']['signer_public_key_original_sha256']
            require(key not in signer_owners or signer_owners[key]==id,
                    'REGISTRY_OPERATIONAL_KEY_SHARED_ACROSS_CHANNELS',
                    'permission_denied')
            signer_owners[key]=id
        if r['events']:
            hist=_validate_chain(r['events'])
            r['heads']=[e['sha256'] for e in hist['heads']]
            r['head_objects']=hist['heads'];r['forked']=hist['forked']
        else:
            r['heads']=[];r['head_objects']=[];r['forked']=False
        r['events_count']=len(r['events'])
    # Read *supplied and parent-verified* EC351 signed statements again to
    # compare registry claims to the actual prior signer/source/root/policy.
    authority={id:(f,h) for id,f,h in zip(
        ec351_inputs['authority_channel_ids'],
        ec351_inputs['authority_statement_files'],
        ec351_inputs['authority_statement_shas'],strict=True)}
    parent_tsa={id:(root,policy) for id,root,policy in zip(
        ec351_inputs['tsa_channel_ids'],ec351_inputs['tsa_root_shas'],
        ec351_inputs['tsa_policy_oids'],strict=True)}
    rows=[]
    for row in parent['channel_evidence']:
        ch=row['channel_id'];src=row['source_attestation'];binding=None;issued=None
        if src is not None:
            orig,expected=authority[ch]
            source_doc=old351._read_statement(old350._read_pinned(
                orig,expected,old351.MAX_ATTESTATION,'EC352_RECHECK_SOURCE',{}))
            issued=old350._utc(source_doc['issued_utc'])
            tsa_root,policy=parent_tsa[ch]
            binding={'source_attestation_original_sha256':
                        src['signed_source_statement_original_sha256'],
                     'attester_public_key_original_sha256':
                        src['attester_public_key_original_sha256'],
                     'source_document_original_sha256':
                        src['source_document_original_sha256'],
                     'tsa_root_original_sha256':tsa_root,
                     'tsa_root_der_sha256':src['root_cert_der_sha256_bound_by_signature'],
                     'tsa_policy_oid':policy}
        obs=[]
        if binding is not None:
            obs=[_observe_registry(ch,binding,issued,r,evaluation)
                 for r in roots_loaded.values()]
        states=[o['key_binding_status'] for o in obs]
        if row['outcome']!=old351.OUTCOMES[6]:outcome=OUTCOMES[0]
        elif len(roots_loaded)!=2:outcome=OUTCOMES[1]
        elif any(not o['signed_history_present'] for o in obs):outcome=OUTCOMES[2]
        elif any(s in ('fork_no_winner','contradictory_signed_binding') for s in states):
            outcome=OUTCOMES[3]
        elif any(s in ('registry_signer_revoked','attester_key_revoked_in_signed_history',
                        'attester_last_claim_not_authorized','retroactive_registry_claim_only')
                 for s in states):outcome=OUTCOMES[4]
        elif any(s!='authorized_claim_exact_binding' for s in states):
            outcome=OUTCOMES[5]
        else:outcome=OUTCOMES[6]
        rows.append({'tsa_channel_id':ch,'parent_ec351_outcome':row['outcome'],
                     'ec351_signed_source_original_sha256':
                        binding['source_attestation_original_sha256'] if binding else None,
                     'ec351_attester_public_key_original_sha256':
                        binding['attester_public_key_original_sha256'] if binding else None,
                     'registries':obs,'outcome':outcome})
    _late_verify(pins)
    counts={k:sum(r['outcome']==k for r in rows) for k in OUTCOMES}
    status=next(k for k in OUTCOMES if counts[k])+'_unresolved'
    return {'schema':RESULT_SCHEMA,'command':'audit-registry-history',
            'status':status,'exit_code':2,'case_id':parent['case_id'],
            'ec351_to_ec337_actual_signed_originals_replayed':True,
            'ec351_verified_result_canonical_sha256':sha(reg.canonical(parent)),
            'registry_evaluation_utc_as_caller_claim':registry_evaluation_utc,
            'registry_self_signed_root_count':len(roots_loaded),
            'registry_signed_event_original_count':len(registry_event_files),
            'registry_root_signing_key_shas':sorted(all_keyroles),
            'parent_signed_origin_and_crl_ocsp_facts_never_promoted':True,
            'external_institution_authorization_and_custody_unproven':True,
            'channel_evidence':rows,'outcome_counts':counts,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}


def checklist(**ec351_inputs)->dict:
    parent=old351.audit(**ec351_inputs)
    require(parent.get('exit_code')==2 and
            parent.get('ec350_to_ec337_actual_originals_replayed') is True,
            'EC351_TO_EC337_ACTUAL_REPLAY_REQUIRED','permission_denied')
    return {'schema':HANDOFF_SCHEMA,'command':'derive-registry-handoff',
            'status':'two_independent_registry_root_key_sources_and_signed_history_needed',
            'exit_code':2,'case_id':parent['case_id'],
            'ec351_verified_result_canonical_sha256':sha(reg.canonical(parent)),
            'source_statement_key_and_policy_bindings':[
                {'tsa_channel_id':r['channel_id'],
                 'ec351_outcome':r['outcome'],
                 'statement_sha256':(r['source_attestation'] or {}).get(
                    'signed_source_statement_original_sha256'),
                 'attester_key_sha256':(r['source_attestation'] or {}).get(
                    'attester_public_key_original_sha256'),
                 'policy_source_sha256':(r['source_attestation'] or {}).get(
                    'source_document_original_sha256'),
                 'tsa_root_der_sha256':(r['source_attestation'] or {}).get(
                    'root_cert_der_sha256_bound_by_signature')}
                for r in parent['channel_evidence']],
            'no_network_signing_or_authority_grant':True,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}
