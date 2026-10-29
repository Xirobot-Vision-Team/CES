#!/usr/bin/env python3
"""EC353: offline RFC6962 proofs for *furnished* EC352 root/event originals.

The complete EC352->EC337 evidence verifier runs for every audit. Log and
witness keys, signed checkpoints, consistency paths and inclusion paths must be
supplied as separately whole-SHA-pinned originals via a whole-SHA-pinned,
canonical manifest. No key is generated; no network, signer, log writer or
trust-store lookup exists here. Local cryptography cannot establish an actual
external publisher, independent witness, globally complete log or trusted UTC.
"""
from __future__ import annotations

from collections import Counter
from datetime import timedelta
import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from key_registry import registry as parent352

RESULT_SCHEMA='ces.ec353.offline_transparency_witnessed_inclusion_unresolved.v1'
DENIAL_SCHEMA='ces.ec353.offline_transparency_witnessed_inclusion_denial.v1'
HANDOFF_SCHEMA='ces.ec353.unsigned_published_registry_handoff.v1'
BUNDLE_SCHEMA='ces.ec353.pinned_publication_evidence_bundle.v1'
LOG_REF_SCHEMA='ces.ec353.self_signed_transparency_log_reference.v1'
WITNESS_REF_SCHEMA='ces.ec353.self_signed_checkpoint_witness_reference.v1'
CHECKPOINT_SCHEMA='ces.ec353.signed_merkle_checkpoint.v1'
WITNESS_SCHEMA='ces.ec353.signed_checkpoint_witness.v1'
CONSISTENCY_SCHEMA='ces.ec353.rfc6962_consistency_proof.v1'
INCLUSION_SCHEMA='ces.ec353.rfc6962_inclusion_proof.v1'
LOG_REF_DOMAIN=b'CES/EC353/LogReference/v1\x00'
WITNESS_REF_DOMAIN=b'CES/EC353/WitnessReference/v1\x00'
CHECKPOINT_DOMAIN=b'CES/EC353/LogCheckpoint/v1\x00'
WITNESS_DOMAIN=b'CES/EC353/CheckpointWitness/v1\x00'
GENESIS='GENESIS'
SHA_RE=re.compile(r'[0-9a-f]{64}\Z')
SIG_RE=re.compile(r'[0-9a-f]{128}\Z')
MAX_BUNDLE=128_000
MAX_REFERENCE=12_000
MAX_CHECKPOINT=12_000
MAX_WITNESS=12_000
MAX_PROOF=16_000
MAX_CHECKPOINTS_PER_LOG=4
MAX_INCLUSIONS_PER_LOG=12
MAX_LOG_LEAVES=64
MAX_REFERENCE_AGE=timedelta(days=366)
MAX_WITNESS_DELAY=timedelta(days=1)
MAX_WITNESS_FRESHNESS=timedelta(days=7)
MAX_CHECKPOINT_GAP=timedelta(days=7)

OUTCOMES=(
    'ec352_parent_registry_signature_or_authority_unresolved',
    'ec353_two_separate_transparency_logs_not_furnished',
    'ec353_checkpoint_or_distinct_witness_history_incomplete',
    'ec353_witnessed_split_view_or_append_only_consistency_unresolved',
    'ec353_signed_root_and_event_inclusion_coverage_incomplete',
    'ec353_publication_or_witness_clock_claims_stale_or_conflicting',
    'ec353_matching_signed_merkle_inclusion_external_publication_unproven',
)
NEGATIVES=(
    'self_signed_log_and_witness_keys_prove_real_external_publisher_identity',
    'different_key_bytes_prove_separate_legal_organizations_or_physical_sites',
    'valid_merkle_proof_proves_global_log_completeness_or_absence_of_hidden_forks',
    'witness_claimed_utc_is_independently_calibrated_time',
    'signed_log_checkpoints_prove_official_registry_authorization',
    'transparency_receipt_repairs_prior_ec352_or_ec351_invalid_evidence',
    'publication_proves_real_tsa_qualification_or_external_ocsp_crl',
    'audit_fetches_https_log_urls_or_uses_system_trust_store',
    'audit_creates_private_keys_signs_or_writes_remote_provider_cas_worm',
    'ec317_ec318_real_production_sources_and_final_acceptance_proven',
)


def require(ok:Any, reason:str, status:str='invalid_input')->None:
    if ok is not True:
        raise errors.AnchorError('EC353_'+reason,status)


def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()


def _sha(v):return type(v) is str and SHA_RE.fullmatch(v) is not None and v!='0'*64


def _object_pairs(pairs):
    d={}
    for k,v in pairs:
        if k in d:raise ValueError('duplicate key')
        d[k]=v
    return d


def strict_json(raw:bytes,role:str)->dict:
    try:
        doc=json.loads(raw.decode('utf-8'),object_pairs_hook=_object_pairs,
                       parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
    except (ValueError,UnicodeError,TypeError) as exc:
        raise errors.AnchorError('EC353_'+role+'_JSON_INVALID','invalid_input') from exc
    require(type(doc) is dict and canonical.canonical(doc)==raw,
            role+'_CANONICAL_JSON_REQUIRED')
    return doc


def _fields(d:dict,keys:set[str],role:str)->None:
    require(type(d) is dict and set(d)==keys,role+'_EXACT_FIELDS_REQUIRED')


def _sig(key:bytes,sig:str,domain:bytes,body:dict,role:str)->None:
    require(type(sig) is str and SIG_RE.fullmatch(sig) is not None,
            role+'_SIGNATURE_FORMAT_INVALID')
    require(len(key)==32,role+'_PUBLIC_KEY_NOT_32_BYTES')
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(sig),domain+canonical.canonical(body))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise errors.AnchorError('EC353_'+role+'_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _split_signature(doc:dict,sig_field:str)->dict:
    return {k:v for k,v in doc.items() if k!=sig_field}


def _load(pin:dict,role:str,cap:int,pins:dict)->bytes:
    _fields(pin,{'path','sha256'},role+'_PIN')
    require(type(pin['path']) is str and _sha(pin['sha256']),
            role+'_SHA_PIN_INVALID')
    path=pin['path'];expected=pin['sha256']
    require(path not in pins,'ORIGINAL_PATH_REUSED_ACROSS_ROLES','permission_denied')
    data=tsa._read_pinned(path,expected,cap,role,{})
    pins[path]=(expected,cap)
    return data


def _ident(v):return type(v) is str and parent352.IDENTIFIER_RE.fullmatch(v) is not None


def _utc(v):
    require(type(v) is str,'UTC_TYPE_INVALID')
    return tsa._utc(v)


def _ref(raw:bytes,public:bytes,key_sha:str,log_id:str,evaluation,*,is_witness:bool)->dict:
    kind='WITNESS_REFERENCE' if is_witness else 'LOG_REFERENCE'
    doc=strict_json(raw,kind)
    if is_witness:
        keys={'schema','log_id','witness_public_key_original_sha256',
              'claimed_witness_organization','claimed_witness_document_uri',
              'valid_from_utc','valid_until_utc','signature_ed25519_hex'}
        key_field='witness_public_key_original_sha256'
        org='claimed_witness_organization';url='claimed_witness_document_uri'
        schema=WITNESS_REF_SCHEMA;domain=WITNESS_REF_DOMAIN
    else:
        keys={'schema','log_id','log_public_key_original_sha256',
              'claimed_log_organization','claimed_log_publication_uri',
              'valid_from_utc','valid_until_utc','signature_ed25519_hex'}
        key_field='log_public_key_original_sha256'
        org='claimed_log_organization';url='claimed_log_publication_uri'
        schema=LOG_REF_SCHEMA;domain=LOG_REF_DOMAIN
    _fields(doc,keys,kind)
    require(all(type(v) is str for v in doc.values()),kind+'_STRINGS_REQUIRED')
    require(doc['schema']==schema and doc['log_id']==log_id and
            doc[key_field]==key_sha and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 .,_()&/-]{2,119}',doc[org]) is not None and
            parent352.HTTPS_RE.fullmatch(doc[url]) is not None,
            kind+'_SCHEMA_ID_SHA_OR_CLAIM_FORMAT_INVALID','permission_denied')
    frm=_utc(doc['valid_from_utc']);to=_utc(doc['valid_until_utc'])
    require(frm<=evaluation<=to and to>frm and to-frm<=MAX_REFERENCE_AGE,
            kind+'_VALIDITY_WINDOW_INVALID','permission_denied')
    _sig(public,doc['signature_ed25519_hex'],domain,
         _split_signature(doc,'signature_ed25519_hex'),kind)
    return doc


def leaf_hash(raw:bytes)->bytes:
    """RFC6962 v1 SHA-256 0x00-prefixed exact original bytes."""
    return hashlib.sha256(b'\x00'+raw).digest()


def node_hash(left:bytes,right:bytes)->bytes:
    return hashlib.sha256(b'\x01'+left+right).digest()


def _hashes(doc:dict,field:str,role:str)->list[bytes]:
    items=doc[field]
    require(type(items) is list and len(items)<=64 and all(_sha(v) for v in items),
            role+'_PATH_HASHES_INVALID')
    return [bytes.fromhex(v) for v in items]


def verify_inclusion(leaf:bytes,index:int,size:int,root:bytes,proof:list[bytes])->bool:
    """RFC6962 v1 inclusion; reject redundant as well as truncated paths."""
    if (type(index) is not int or type(size) is not int or
        not 0<=index<size<=MAX_LOG_LEAVES or len(leaf)!=32 or len(root)!=32):
        return False
    fn=index;sn=size-1;running=leaf
    for p in proof:
        if len(p)!=32 or sn==0:return False
        if fn&1 or fn==sn:
            running=node_hash(p,running)
            while fn!=0 and (fn&1)==0:
                fn>>=1;sn>>=1
        else:
            running=node_hash(running,p)
        fn>>=1;sn>>=1
    return sn==0 and running==root


def verify_consistency(old_size:int,new_size:int,old_root:bytes,
                       new_root:bytes,proof:list[bytes])->bool:
    """RFC6962 v1 consistency of the first old_size leaves of new_size."""
    if (type(old_size) is not int or type(new_size) is not int or
        not 1<=old_size<=new_size<=MAX_LOG_LEAVES or
        len(old_root)!=32 or len(new_root)!=32 or
        any(len(x)!=32 for x in proof)):
        return False
    if old_size==new_size:return not proof and old_root==new_root
    fn=old_size-1;sn=new_size-1
    while fn&1:
        fn>>=1;sn>>=1
    if fn==0:
        fr=old_root;sr=old_root;idx=0
    else:
        if not proof:return False
        fr=proof[0];sr=proof[0];idx=1
    while idx<len(proof):
        p=proof[idx];idx+=1
        if sn==0:return False
        if fn&1 or fn==sn:
            fr=node_hash(p,fr);sr=node_hash(p,sr)
            while fn!=0 and (fn&1)==0:
                fn>>=1;sn>>=1
        else:
            sr=node_hash(sr,p)
        fn>>=1;sn>>=1
    return sn==0 and fr==old_root and sr==new_root


def _checkpoint(raw:bytes,log:dict,evaluation)->dict:
    d=strict_json(raw,'CHECKPOINT')
    keys={'schema','log_id','log_reference_original_sha256','previous_checkpoint_original_sha256',
          'tree_size','root_hash_sha256','issued_utc','log_signature_ed25519_hex'}
    _fields(d,keys,'CHECKPOINT')
    require(type(d['tree_size']) is int and 1<=d['tree_size']<=MAX_LOG_LEAVES and
            all(type(d[k]) is str for k in keys-{'tree_size'}),
            'CHECKPOINT_FIELD_TYPES_INVALID')
    require(d['schema']==CHECKPOINT_SCHEMA and d['log_id']==log['id'] and
            d['log_reference_original_sha256']==log['log_ref_sha'] and
            (d['previous_checkpoint_original_sha256']==GENESIS or
             _sha(d['previous_checkpoint_original_sha256'])) and
            _sha(d['root_hash_sha256']),
            'CHECKPOINT_SCHEMA_OR_PARENT_BINDING_INVALID','permission_denied')
    issued=_utc(d['issued_utc'])
    require(_utc(log['log_ref']['valid_from_utc'])<=issued<=
            _utc(log['log_ref']['valid_until_utc']) and issued<=evaluation,
            'CHECKPOINT_OUTSIDE_LOG_REFERENCE_OR_EVALUATION','permission_denied')
    _sig(log['log_key'],d['log_signature_ed25519_hex'],CHECKPOINT_DOMAIN,
         _split_signature(d,'log_signature_ed25519_hex'),'CHECKPOINT_LOG')
    return {'body':d,'sha256':sha(raw),'issued':issued,'size':d['tree_size'],
            'root':bytes.fromhex(d['root_hash_sha256'])}


def _witness(raw:bytes,cp:dict,log:dict,evaluation)->dict:
    d=strict_json(raw,'WITNESS')
    keys={'schema','log_id','checkpoint_original_sha256',
          'witness_reference_original_sha256','tree_size','root_hash_sha256',
          'witnessed_utc','witness_signature_ed25519_hex'}
    _fields(d,keys,'WITNESS')
    require(type(d['tree_size']) is int and
            all(type(d[k]) is str for k in keys-{'tree_size'}),
            'WITNESS_FIELD_TYPES_INVALID')
    require(d['schema']==WITNESS_SCHEMA and d['log_id']==log['id'] and
            d['checkpoint_original_sha256']==cp['sha256'] and
            d['witness_reference_original_sha256']==log['witness_ref_sha'] and
            d['tree_size']==cp['size'] and
            d['root_hash_sha256']==cp['body']['root_hash_sha256'],
            'WITNESS_CHECKPOINT_OR_KEY_BINDING_INVALID','permission_denied')
    when=_utc(d['witnessed_utc'])
    require(cp['issued']<=when<=cp['issued']+MAX_WITNESS_DELAY and
            when<=evaluation and
            _utc(log['witness_ref']['valid_from_utc'])<=when<=
            _utc(log['witness_ref']['valid_until_utc']),
            'WITNESS_CLAIMED_TIME_WINDOW_INVALID','permission_denied')
    _sig(log['witness_key'],d['witness_signature_ed25519_hex'],WITNESS_DOMAIN,
         _split_signature(d,'witness_signature_ed25519_hex'),'CHECKPOINT_WITNESS')
    return {'claimed_time':when,'sha256':sha(raw)}


def _parse_consistency(raw:bytes,log_id:str,prior:dict,cp:dict)->bool:
    d=strict_json(raw,'CONSISTENCY_PROOF')
    _fields(d,{'schema','log_id','previous_checkpoint_original_sha256',
               'next_checkpoint_original_sha256','previous_tree_size','next_tree_size',
               'audit_path_sha256_hex'},'CONSISTENCY_PROOF')
    require(d['schema']==CONSISTENCY_SCHEMA and d['log_id']==log_id and
            d['previous_checkpoint_original_sha256']==prior['sha256'] and
            d['next_checkpoint_original_sha256']==cp['sha256'] and
            type(d['previous_tree_size']) is int and d['previous_tree_size']==prior['size'] and
            type(d['next_tree_size']) is int and d['next_tree_size']==cp['size'],
            'CONSISTENCY_PARENT_AND_SIZE_BINDING_INVALID','permission_denied')
    proof=_hashes(d,'audit_path_sha256_hex','CONSISTENCY')
    return verify_consistency(prior['size'],cp['size'],prior['root'],cp['root'],proof)


def _parse_inclusion(raw:bytes,log_id:str,cp:dict,inventory:dict)->tuple[str,str,bool]:
    d=strict_json(raw,'INCLUSION_PROOF')
    _fields(d,{'schema','log_id','checkpoint_original_sha256','artifact_kind',
               'artifact_original_sha256','leaf_index','audit_path_sha256_hex'},
            'INCLUSION_PROOF')
    target=(d['artifact_kind'],d['artifact_original_sha256'])
    require(d['schema']==INCLUSION_SCHEMA and d['log_id']==log_id and
            d['checkpoint_original_sha256']==cp['sha256'] and
            target in inventory and type(d['leaf_index']) is int,
            'INCLUSION_CHECKPOINT_OR_PARENT_ORIGINAL_BINDING_INVALID',
            'permission_denied')
    proof=_hashes(d,'audit_path_sha256_hex','INCLUSION')
    # Inventory values are the actual re-opened and whole-SHA-revalidated raw
    # EC352 originals, never caller-only claimed leaf hashes.
    good=verify_inclusion(leaf_hash(inventory[target]),d['leaf_index'],
                          cp['size'],cp['root'],proof)
    return (*target,good)


def _bundle_evidence(raw:bytes,exclusions:set[str],parent:dict,
                     originals:dict,evaluation,pins:dict)->list[dict]:
    bundle=strict_json(raw,'PUBLICATION_BUNDLE')
    _fields(bundle,{'schema','logs'},'PUBLICATION_BUNDLE')
    require(bundle['schema']==BUNDLE_SCHEMA and type(bundle['logs']) is list and
            len(bundle['logs'])<=2,'PUBLICATION_BUNDLE_LOG_COUNT_OR_SCHEMA_INVALID')
    logs=[];key_shas=set()
    existing_roles=set(parent['registry_root_signing_key_shas'])
    # EC352's operational and EC351's source attester keys cannot be recycled
    # as log publishers or witnesses. Both lists are manifest-authoritative
    # inputs, cryptographically checked by the complete parent replay.
    for item in originals['registry_signer_key_shas']:
        existing_roles.add(item)
    existing_roles.update(originals['authority_key_shas'])
    for item in bundle['logs']:
        _fields(item,{'log_id','log_reference','log_public_key','witness_reference',
                      'witness_public_key','checkpoints','inclusions'},'LOG_ENTRY')
        ident=item['log_id']
        require(_ident(ident),'LOG_ID_INVALID')
        require(type(item['checkpoints']) is list and
                len(item['checkpoints'])<=MAX_CHECKPOINTS_PER_LOG and
                type(item['inclusions']) is list and
                len(item['inclusions'])<=MAX_INCLUSIONS_PER_LOG,
                'LOG_CHECKPOINT_OR_INCLUSION_COUNT_INVALID')
        log_raw_key=_load(item['log_public_key'],'LOG_KEY',32,pins)
        witness_raw_key=_load(item['witness_public_key'],'WITNESS_KEY',32,pins)
        log_key_sha=item['log_public_key']['sha256'];wit_key_sha=item['witness_public_key']['sha256']
        require(len(log_raw_key)==len(witness_raw_key)==32 and
                log_key_sha!=wit_key_sha and
                not {log_key_sha,wit_key_sha}.intersection(key_shas|existing_roles),
                'LOG_WITNESS_KEY_ROLE_REUSED','permission_denied')
        key_shas.update((log_key_sha,wit_key_sha))
        rawlog=_load(item['log_reference'],'LOG_REFERENCE',MAX_REFERENCE,pins)
        rawwit=_load(item['witness_reference'],'WITNESS_REFERENCE',MAX_REFERENCE,pins)
        logref=_ref(rawlog,log_raw_key,log_key_sha,ident,evaluation,is_witness=False)
        witref=_ref(rawwit,witness_raw_key,wit_key_sha,ident,evaluation,is_witness=True)
        log={'id':ident,'log_key':log_raw_key,'witness_key':witness_raw_key,
             'log_key_sha':log_key_sha,'witness_key_sha':wit_key_sha,
             'log_ref_sha':item['log_reference']['sha256'],
             'witness_ref_sha':item['witness_reference']['sha256'],
             'log_ref':logref,'witness_ref':witref,
             'claimed_organizations_distinct':logref['claimed_log_organization']!=
                                              witref['claimed_witness_organization']}
        checkpoints=[]
        for ck in item['checkpoints']:
            _fields(ck,{'checkpoint','witness_statement','consistency_proof'},
                    'CHECKPOINT_MANIFEST_ENTRY')
            require(ck['consistency_proof'] is None or type(ck['consistency_proof']) is dict,
                    'CONSISTENCY_PIN_OR_NULL_REQUIRED')
            cp=_checkpoint(_load(ck['checkpoint'],'CHECKPOINT',MAX_CHECKPOINT,pins),
                           log,evaluation)
            witness=_witness(_load(ck['witness_statement'],'WITNESS_STATEMENT',
                                   MAX_WITNESS,pins),cp,log,evaluation)
            cp['witness']=witness
            cp['consistency_pin']=ck['consistency_proof']
            checkpoints.append(cp)
        by_sha={c['sha256']:c for c in checkpoints}
        require(len(by_sha)==len(checkpoints),'DUPLICATE_CHECKPOINT_ORIGINAL')
        references=Counter(c['body']['previous_checkpoint_original_sha256'] for c in checkpoints)
        graph_issue=False;consistency_missing=False;split=False
        for cp in checkpoints:
            prevhash=cp['body']['previous_checkpoint_original_sha256']
            if prevhash==GENESIS:
                require(cp['consistency_pin'] is None,'GENESIS_MUST_NOT_HAVE_CONSISTENCY')
                cp['history']=[cp]
            else:
                require(prevhash in by_sha,'CHECKPOINT_PREDECESSOR_NOT_PRESENTED',
                        'permission_denied')
                prior=by_sha[prevhash]
                require(prior is not cp,'CHECKPOINT_SELF_PARENT_FORBIDDEN',
                        'permission_denied')
                # A signed contradictory rollback must be retained as a visible
                # dispute, not masked by an arbitrarily selected latest head.
                if prior['size']>cp['size'] or prior['issued']>cp['issued']:
                    graph_issue=True
                if prior['size']==cp['size'] and prior['root']!=cp['root']:
                    split=True
                if cp['consistency_pin'] is None:
                    if prior['size']!=cp['size'] or prior['root']!=cp['root']:
                        consistency_missing=True
                else:
                    proofraw=_load(cp['consistency_pin'],'CONSISTENCY_PROOF',
                                   MAX_PROOF,pins)
                    if not _parse_consistency(proofraw,ident,prior,cp):
                        # A false proof is not a valid append-only witness.
                        # A signed conflicting checkpoint stays visible.
                        graph_issue=True
            # Calculate ancestry only after complete structural validation.
        for cp in checkpoints:
            ancestors=[];seen=set();cur=cp
            while True:
                require(cur['sha256'] not in seen,'CHECKPOINT_CYCLE_DENIED',
                        'permission_denied')
                seen.add(cur['sha256']);ancestors.append(cur)
                prevhash=cur['body']['previous_checkpoint_original_sha256']
                if prevhash==GENESIS:break
                cur=by_sha[prevhash]
            cp['history']=list(reversed(ancestors))
            if any(b['issued']-a['issued']>MAX_CHECKPOINT_GAP for a,b in
                   zip(cp['history'],cp['history'][1:])):
                graph_issue=True
        heads=sorted((c for c in checkpoints if c['sha256'] not in references),
                     key=lambda c:c['sha256'])
        if len(heads)!=1 or references[GENESIS]>1 or any(
                count>1 for p,count in references.items() if p!=GENESIS):
            split=bool(checkpoints)
        if any(not (cp['witness']['claimed_time']<=evaluation<=
                    cp['witness']['claimed_time']+MAX_WITNESS_FRESHNESS)
               for cp in heads):
            stale=True
        else:stale=False
        inventory_proved=set();claimed_clock_conflict=False
        # All explicitly furnished proofs are validated, even if no unique
        # head exists. A legitimate sibling cannot excuse a forged proof.
        for pin in item['inclusions']:
            rawproof=_load(pin,'INCLUSION_PROOF',MAX_PROOF,pins)
            doc=strict_json(rawproof,'INCLUSION_PROOF')
            cp=by_sha.get(doc.get('checkpoint_original_sha256'))
            require(cp is not None,'INCLUSION_UNPRESENTED_CHECKPOINT',
                    'permission_denied')
            artifact_kind,artifact_sha,good=_parse_inclusion(
                rawproof,ident,cp,originals['artifacts'])
            require(good,'INCLUSION_MERKLE_PROOF_INVALID','permission_denied')
            identity=(artifact_kind,artifact_sha)
            require((cp['sha256'],identity) not in inventory_proved,
                    'DUPLICATE_CHECKPOINT_INCLUSION_PROOF')
            inventory_proved.add((cp['sha256'],identity))
            # A witness cannot be called a real clock; visible conflicting
            # signed *claims* remain unresolved instead of proof of freshness.
            issued=originals['artifact_issued_utc'].get(identity)
            if issued is not None and cp['issued']<issued:
                claimed_clock_conflict=True
        covered=set()
        if len(heads)==1 and not split and not graph_issue and not consistency_missing:
            anc={c['sha256'] for c in heads[0]['history']}
            covered={artifact for ck,artifact in inventory_proved if ck in anc}
        logs.append({'id':ident,'log_ref_sha':log['log_ref_sha'],
                     'witness_ref_sha':log['witness_ref_sha'],
                     'log_key_sha':log_key_sha,'witness_key_sha':wit_key_sha,
                     'claimed_organizations_distinct':log['claimed_organizations_distinct'],
                     '_organization_claims':(logref['claimed_log_organization'],
                                             witref['claimed_witness_organization']),
                     'checkpoint_count':len(checkpoints),
                     'heads':[c['sha256'] for c in heads],
                     'verified_signed_and_witnessed_checkpoint_original_shas':
                         sorted(by_sha),
                     'all_supplied_inclusion_proofs_verified':True,
                     'split_view':split,'append_only_unresolved':graph_issue or consistency_missing,
                     'claimed_checkpoint_stale':stale,
                     'claimed_publication_clock_conflict':claimed_clock_conflict,
                     'exact_originals_covered':covered,
                     'all_pinned_inclusion_proof_count':len(item['inclusions'])})
    require([l['id'] for l in logs]==sorted(set(l['id'] for l in logs)),
            'LOG_IDS_MUST_BE_UNIQUE_SORTED')
    # Equal claimed organization names across *any* publisher/witness roles
    # cannot be reported as four independent actors. Distinct names alone
    # remain entirely unverified assertions.
    claimed_counts=Counter(name for log in logs for name in log['_organization_claims'])
    parent_issuer_claims={strict_json(raw,'PARENT_REGISTRY_ROOT')['claimed_issuer_organization']
        for (kind,_),raw in originals['artifacts'].items()
        if kind=='registry_root_reference'}
    for log in logs:
        if (any(claimed_counts[name]>1 for name in log['_organization_claims']) or
            any(name in parent_issuer_claims for name in log['_organization_claims'])):
            log['claimed_organizations_distinct']=False
        del log['_organization_claims']
    require(not set(pins).intersection(exclusions),
            'PUBLICATION_FILE_PATH_ALIASES_PARENT_OR_BUNDLE','permission_denied')
    return logs


def _inventory(inputs:dict)->dict:
    artifacts={};issued={}
    for kind,paths,hashes,cap in (
        ('registry_root_reference',inputs['registry_root_reference_files'],
         inputs['registry_root_reference_shas'],parent352.MAX_ROOT_BYTES),
        ('registry_event',inputs['registry_event_files'],
         inputs['registry_event_shas'],parent352.MAX_EVENT_BYTES)):
        for p,h in zip(paths,hashes,strict=True):
            raw=tsa._read_pinned(p,h,cap,'EC353_PARENT_'+kind.upper(),{})
            require((kind,h) not in artifacts,'DUPLICATE_PARENT_ARTIFACT_SHA')
            artifacts[(kind,h)]=raw
            doc=strict_json(raw,'PARENT_'+kind.upper())
            stamp=doc.get('issued_utc') if kind=='registry_event' else doc.get('valid_from_utc')
            issued[(kind,h)]=_utc(stamp)
    return artifacts,issued


def _parents(**ec352_inputs)->dict:
    parent=parent352.audit(**ec352_inputs)
    require(parent.get('exit_code')==2 and
            parent.get('ec351_to_ec337_actual_signed_originals_replayed') is True,
            'REAL_EC352_THROUGH_EC337_REPLAY_REQUIRED','permission_denied')
    return parent


def checklist(**ec352_inputs)->dict:
    parent=_parents(**ec352_inputs)
    inv,_=_inventory(ec352_inputs)
    return {'schema':HANDOFF_SCHEMA,'command':'derive-publication-handoff',
            'status':'independent_pinned_transparency_log_checkpoints_witnesses_and_merkle_proofs_needed',
            'exit_code':2,'case_id':parent['case_id'],
            'parent_ec352_canonical_result_sha256':sha(canonical.canonical(parent)),
            'required_originals':[{'artifact_kind':k,'artifact_original_sha256':h}
                                  for k,h in sorted(inv)],
            'each_log_must_cover_every_presented_registry_root_and_event':True,
            'parent_actual_signed_originals_replayed':True,
            'no_external_authority_or_global_log_census_proven':True,
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,publication_evaluation_utc:str,publication_bundle_file:str,
          expected_publication_bundle_sha256:str,**ec352_inputs)->dict:
    evaluation=_utc(publication_evaluation_utc)
    require(evaluation>=_utc(ec352_inputs.get('registry_evaluation_utc')),
            'EVALUATION_PRECEDES_EC352','permission_denied')
    parent=_parents(**ec352_inputs)
    artifacts,issued=_inventory(ec352_inputs)
    pins={}
    bundle_pin={'path':publication_bundle_file,
                'sha256':expected_publication_bundle_sha256}
    bundle_raw=_load(bundle_pin,'BUNDLE',MAX_BUNDLE,pins)
    exclusions=parent352._all_parent_files(ec352_inputs)
    require(publication_bundle_file not in exclusions,
            'PUBLICATION_BUNDLE_ALIASES_PARENT','permission_denied')
    originals={'artifacts':artifacts,'artifact_issued_utc':issued,
               'registry_signer_key_shas':ec352_inputs['registry_signer_key_shas'],
               'authority_key_shas':ec352_inputs['authority_key_shas']}
    logs=_bundle_evidence(bundle_raw,exclusions,parent,originals,evaluation,pins)
    # Every new original is re-read after all cryptographic decisions. Parent
    # originals are independently late-verified by actual EC352 replay.
    tsa._check_late(pins)
    good_parent=parent352.OUTCOMES[-1]
    good_log=len(logs)==2
    for row in logs:
        row['missing_required_originals']=[
            {'artifact_kind':kind,'artifact_original_sha256':h}
            for kind,h in sorted(artifacts) if (kind,h) not in row['exact_originals_covered']]
        row['exact_originals_covered']=[
            {'artifact_kind':kind,'artifact_original_sha256':h}
            for kind,h in sorted(row['exact_originals_covered'])]
    result_rows=[]
    for row in parent['channel_evidence']:
        if row['outcome']!=good_parent:outcome=OUTCOMES[0]
        elif not good_log:outcome=OUTCOMES[1]
        elif any(l['checkpoint_count']==0 for l in logs):outcome=OUTCOMES[2]
        elif any(l['split_view'] or l['append_only_unresolved'] for l in logs):
            outcome=OUTCOMES[3]
        elif any(l['missing_required_originals'] for l in logs):outcome=OUTCOMES[4]
        elif any(l['claimed_checkpoint_stale'] or
                 l['claimed_publication_clock_conflict'] or
                 not l['claimed_organizations_distinct'] for l in logs):
            outcome=OUTCOMES[5]
        else:outcome=OUTCOMES[6]
        result_rows.append({'tsa_channel_id':row['tsa_channel_id'],
                            'parent_ec352_outcome':row['outcome'],
                            'outcome':outcome})
    counts={k:sum(r['outcome']==k for r in result_rows) for k in OUTCOMES}
    status=next(k for k in OUTCOMES if counts[k])+'_unresolved'
    return {'schema':RESULT_SCHEMA,'command':'audit-publication-witnesses',
            'status':status,'exit_code':2,'case_id':parent['case_id'],
            'parent_actual_signed_originals_replayed':True,
            'parent_ec352_canonical_result_sha256':sha(canonical.canonical(parent)),
            'publication_bundle_original_sha256':expected_publication_bundle_sha256,
            'publication_evaluation_utc_as_caller_claim':publication_evaluation_utc,
            'furnished_log_count':len(logs),'required_registry_original_count':len(artifacts),
            'log_evidence':logs,'channel_evidence':result_rows,'outcome_counts':counts,
            'external_publisher_witness_independence_and_time_unproven':True,
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}
