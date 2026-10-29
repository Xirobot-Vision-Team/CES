#!/usr/bin/env python3
"""EC356: read-only, two explicitly root-pinned offline channel original-byte custody.

The *caller*, not a network trust store, supplies two independently expected
institutional Ed25519 root public-key SHA pins. Each root signs a bounded
channel authorization and each channel signs exact EC355 request+receipt SHA,
checkpoint+witness bytes and nonce. The signer names, key diversity and locally
reopened files NEVER prove real external institutional identity, physical
separate custody, trusted time or global log completeness.

Never accepts a cached EC355 JSON in place of its SHA-pinned original inputs.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from gossip import gossip
from disclosure import disclosure as prior

RESULT_SCHEMA='ces.ec356.offline_two_channel_custody_unresolved.v1'
DENIAL_SCHEMA='ces.ec356.offline_two_channel_custody_denial.v1'
HANDOFF_SCHEMA='ces.ec356.unsigned_two_channel_custody_handoff.v1'
BUNDLE_SCHEMA='ces.ec356.pinned_two_channel_custody_bundle.v1'
ROOT_SCHEMA='ces.ec356.self_signed_institution_root_reference.v1'
AUTH_SCHEMA='ces.ec356.root_signed_channel_authorization.v1'
ACK_SCHEMA='ces.ec356.channel_signed_original_custody_acknowledgement.v1'
ROOT_DOMAIN=b'CES/EC356/InstitutionRootReference/v1\x00'
AUTH_DOMAIN=b'CES/EC356/RootChannelAuthorization/v1\x00'
ACK_DOMAIN=b'CES/EC356/CustodyOriginalAcknowledgement/v1\x00'
MAX_BUNDLE=110_000
MAX_RECORD=12_000
MAX_ACKS=48
MAX_PER_CHANNEL=24
MAX_PER_CLAIM_CHANNEL=2
MAX_FRESHNESS=timedelta(days=7)
GENESIS='GENESIS'
OUTCOMES=(
    'ec356_parent_signed_disclosures_or_transparency_unresolved',
    'ec356_no_verified_ec355_furnished_originals_to_custody',
    'ec356_both_separately_pinned_channel_roots_not_furnished',
    'ec356_missing_two_channel_genuine_original_acknowledgements',
    'ec356_signed_acknowledgement_forks_or_equivocation_visible',
    'ec356_institution_claim_collision_or_stale_signed_custody_visible',
    'ec356_no_matching_original_pair_across_distinct_channels_and_ec355_roles',
    'ec356_two_root_authorized_channels_signed_same_original_bytes_external_provenance_unproven',
)
NEGATIVES=(
    'caller_pinned_root_keys_prove_real_out_of_band_institution_authentication',
    'different_root_or_channel_signatures_prove_separate_legal_entities',
    'different_original_paths_prove_separate_physical_custody_sites',
    'signed_sha_only_or_unavailable_claim_proves_bytes_custodied',
    'self_declared_custody_time_proves_trusted_utc_or_tsa',
    'two_channel_quorum_proves_global_head_or_hidden_fork_absence',
    'channel_quorum_repairs_conflicting_ec355_or_ec354_ancestry',
    'two_channel_quorum_proves_official_external_accreditation',
    'audit_fetches_urls_or_uses_system_or_remote_trust_store',
    'audit_signs_creates_keys_or_writes_provider_cas_worm',
    'ec317_ec318_production_and_final_user_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC356_'+code,status)


def sha(data):return hashlib.sha256(data).hexdigest()


def _obj(raw,role):return tr.strict_json(raw,'EC356_'+role)


def _exact(doc,keys,role):need(type(doc) is dict and set(doc)==set(keys),role+'_EXACT_FIELDS_REQUIRED')


def _signed(raw,public,domain,field,role):
    doc=_obj(raw,role)
    signature=doc.get(field)
    need(type(public) is bytes and len(public)==32 and type(signature) is str and
         tr.SIG_RE.fullmatch(signature) is not None,
         role+'_SIGNATURE_OR_KEY_FORMAT_INVALID')
    body={k:v for k,v in doc.items() if k!=field}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(signature),domain+canonical.canonical(body))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise errors.AnchorError('EC356_'+role+'_REAL_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return doc


def _new(pin,role,cap,pins,oldpaths):
    _exact(pin,('path','sha256'),role+'_PIN')
    need(type(pin['path']) is str and tr._sha(pin['sha256']),
         role+'_PIN_INVALID')
    path=pin['path']
    need(path not in pins and path not in oldpaths,
         'NEW_ROLE_OR_PARENT_ORIGINAL_PATH_ALIAS','permission_denied')
    # EC350 protects the leaf and SHA. Do not allow a symlink *ancestor* to
    # silently redirect a nominally distinct institutional custody path.
    p=Path(path)
    need(not any(node.is_symlink() for node in (p,*p.parents)),
         'SYMLINKED_CUSTODY_PATH_ANCESTOR_DENIED','permission_denied')
    # Delegate bounded size, absolute canonical path, leaf type, and true SHA.
    raw=tsa._read_pinned(path,pin['sha256'],cap,'EC356_'+role,{})
    try:
        st=os.stat(path,follow_symlinks=False)
        identity=(st.st_dev,st.st_ino)
        for other in (*oldpaths,*pins):
            try:src=os.stat(other,follow_symlinks=False)
            except OSError:continue  # Parent audit handles its own required pins.
            need(identity!=(src.st_dev,src.st_ino),
                 'HARDLINK_ORIGINAL_INODE_ALIAS','permission_denied')
    except OSError as exc:
        raise errors.AnchorError('EC356_NEW_ORIGINAL_STAT_UNAVAILABLE',
                                 'unavailable') from exc
    pins[path]=(pin['sha256'],cap)
    return raw


def _inherited(pin,role,cap,pins):
    _exact(pin,('path','sha256'),role+'_PIN')
    path=pin['path']
    need(type(path) is str and tr._sha(pin['sha256']),
         role+'_PIN_INVALID')
    if path in pins:
        need(pins[path][0]==pin['sha256'],
             'PARENT_ORIGINAL_SHA_CONTRADICTION','permission_denied')
        pins[path]=(pin['sha256'],max(cap,pins[path][1]))
    else:pins[path]=(pin['sha256'],cap)
    return tsa._read_pinned(path,pin['sha256'],cap,'EC356_'+role,{})


def _parent_index(inputs,parent):
    """Reopen old disclosure pins, match each source to *replayed* EC355 rows.

    This supplements, rather than substitutes, the parent's own full EC337+
    signature validation and its late byte reread.
    """
    eligible={}
    for claim in parent['disclosure_claim_evidence']:
        for request in claim['disclosure_requests']:
            for receipt in request['signed_responses']:
                orig=receipt['verified_furnished_original']
                if orig is None:continue
                key=(claim['gossip_reply_original_sha256'],
                     request['request_original_sha256'],receipt['receipt_original_sha256'])
                need(key not in eligible,'PARENT_DUPLICATE_SIGNED_RECEIPT')
                eligible[key]={
                    'log_id':claim['log_id'],
                    'gossip_reply_sha256':key[0],
                    'request_sha256':key[1],
                    'receipt_sha256':key[2],
                    'requested_role':request['requested_role'],
                    'auditor_id':receipt['respondent_auditor_id'],
                    'checkpoint_sha256':orig['checkpoint_original_sha256'],
                    'checkpoint_length':orig['checkpoint_length'],
                    'witness_sha256':orig['witness_original_sha256'],
                    'witness_length':orig['witness_length'],
                    'relation':orig['relation_to_verified_ec353_challenge'],
                    'claimed_time_order_anomaly':orig['claimed_time_order_anomaly'],
                    'receipt_utc':receipt['responded_utc_as_claim'],
                }
    oldpins={}
    pub=_obj(_inherited({'path':inputs['publication_bundle_file'],
            'sha256':inputs['expected_publication_bundle_sha256']},
            'PARENT_PUBLICATION_BUNDLE',tr.MAX_BUNDLE,oldpins),'PARENT_PUBLICATION_BUNDLE')
    gp=_obj(_inherited({'path':inputs['gossip_bundle_file'],
            'sha256':inputs['expected_gossip_bundle_sha256']},
            'PARENT_GOSSIP_BUNDLE',gossip.MAX_BUNDLE,oldpins),'PARENT_GOSSIP_BUNDLE')
    db=_obj(_inherited({'path':inputs['checkpoint_disclosure_bundle_file'],
            'sha256':inputs['expected_checkpoint_disclosure_bundle_sha256']},
            'PARENT_DISCLOSURE_BUNDLE',prior.MAX_BUNDLE,oldpins),'PARENT_DISCLOSURE_BUNDLE')
    _exact(pub,('schema','logs'),'PARENT_PUBLICATION')
    _exact(gp,('schema','auditors','exchanges'),'PARENT_GOSSIP')
    _exact(db,('schema','requests'),'PARENT_DISCLOSURE')
    need(pub['schema']==tr.BUNDLE_SCHEMA and gp['schema']==gossip.BUNDLE_SCHEMA
         and db['schema']==prior.BUNDLE_SCHEMA,'PARENT_BUNDLE_SCHEMAS_INVALID')
    role_keys=set()
    for log in pub['logs']:
        for name in ('log_public_key','witness_public_key'):
            p=log[name];raw=_inherited(p,'PARENT_'+name.upper(),32,oldpins)
            role_keys.add(sha(raw))
    for auditor in gp['auditors']:
        raw=_inherited(auditor['auditor_public_key'],
                      'PARENT_AUDITOR_PUBLIC_KEY',32,oldpins)
        role_keys.add(sha(raw))
    indexed=set()
    for request in db['requests']:
        rp=request['request']
        request_doc=_obj(_inherited(rp,'PARENT_DISCLOSURE_REQUEST',MAX_RECORD,oldpins),
                         'PARENT_DISCLOSURE_REQUEST')
        for response in request['responses']:
            p=response['receipt']
            receipt_doc=_obj(_inherited(p,'PARENT_DISCLOSURE_RECEIPT',MAX_RECORD,oldpins),
                             'PARENT_DISCLOSURE_RECEIPT')
            if receipt_doc['response_kind']!='furnished_originals':continue
            key=(request_doc['gossip_reply_original_sha256'],rp['sha256'],p['sha256'])
            need(key in eligible and key not in indexed,
                 'PARENT_FURNISHED_ROW_NOT_REPLAYED','permission_denied')
            indexed.add(key)
            cp=_inherited(response['checkpoint'],'PARENT_DISCLOSURE_CHECKPOINT',
                          tr.MAX_CHECKPOINT,oldpins)
            witness=_inherited(response['witness_statement'],
                               'PARENT_DISCLOSURE_WITNESS',tr.MAX_WITNESS,oldpins)
            item=eligible[key]
            need(sha(cp)==item['checkpoint_sha256'] and len(cp)==item['checkpoint_length'] and
                 sha(witness)==item['witness_sha256'] and len(witness)==item['witness_length'],
                 'PARENT_REPLAYED_ORIGINAL_BYTES_MISMATCH','permission_denied')
            if response['consistency_proof'] is not None:
                _inherited(response['consistency_proof'],'PARENT_DISCLOSURE_CONSISTENCY',
                           tr.MAX_PROOF,oldpins)
    need(indexed==set(eligible),'PARENT_SIGNED_FURNISHED_INDEX_INCOMPLETE',
         'permission_denied')
    oldpaths=set(gossip.reg352._all_parent_files(inputs))|set(oldpins)
    return eligible,role_keys,oldpaths,oldpins


def _channel(entry,slot_pin,eval_at,oldrolekeys,pins,oldpaths):
    _exact(entry,('slot','institution_id','channel_id','claimed_organization',
                  'root_public_key','root_reference','channel_public_key',
                  'channel_authorization','acknowledgements'),'CHANNEL')
    slot=entry['slot'];inst=entry['institution_id'];cid=entry['channel_id']
    need(slot in ('a','b') and tr._ident(inst) and tr._ident(cid) and
         type(entry['claimed_organization']) is str and
         1<=len(entry['claimed_organization'])<=140 and
         entry['claimed_organization']==entry['claimed_organization'].strip() and
         type(entry['acknowledgements']) is list and
         len(entry['acknowledgements'])<=MAX_PER_CHANNEL,
         'CHANNEL_ID_OR_ATTESTATION_BOUNDS_INVALID')
    # These are *independent caller-provided SHA pins*, not server trust.
    need(entry['root_public_key']==slot_pin,'ROOT_KEY_MUST_MATCH_SEPARATE_CALLER_PIN',
         'permission_denied')
    root=_new(entry['root_public_key'],'ROOT_KEY_'+slot,32,pins,oldpaths)
    rootref_pin=entry['root_reference']
    rootref_raw=_new(rootref_pin,'ROOT_REF_'+slot,MAX_RECORD,pins,oldpaths)
    rootref=_signed(rootref_raw,root,ROOT_DOMAIN,'signature_ed25519_hex','ROOT_REF')
    _exact(rootref,('schema','institution_id','claimed_organization',
                    'root_public_key_original_sha256','valid_from_utc','valid_until_utc',
                    'signature_ed25519_hex'),
           'ROOT_REF')
    start=tr._utc(rootref['valid_from_utc']);end=tr._utc(rootref['valid_until_utc'])
    need(rootref['schema']==ROOT_SCHEMA and rootref['institution_id']==inst and
         rootref['claimed_organization']==entry['claimed_organization'] and
         rootref['root_public_key_original_sha256']==slot_pin['sha256'] and
         start<end and start<=eval_at<=end,
         'ROOT_REFERENCE_SCOPE_OR_VALIDITY_INVALID','permission_denied')
    chan_key=_new(entry['channel_public_key'],'CHANNEL_KEY_'+slot,32,pins,oldpaths)
    auth_pin=entry['channel_authorization']
    auth_raw=_new(auth_pin,'CHANNEL_AUTH_'+slot,MAX_RECORD,pins,oldpaths)
    auth=_signed(auth_raw,root,AUTH_DOMAIN,'signature_ed25519_hex','CHANNEL_AUTH')
    _exact(auth,('schema','institution_id','channel_id',
                 'root_reference_original_sha256','channel_public_key_original_sha256',
                 'claimed_physical_site_id','valid_from_utc','valid_until_utc',
                 'signature_ed25519_hex'),'CHANNEL_AUTH')
    astart=tr._utc(auth['valid_from_utc']);aend=tr._utc(auth['valid_until_utc'])
    need(auth['schema']==AUTH_SCHEMA and auth['institution_id']==inst and
         auth['channel_id']==cid and
         auth['root_reference_original_sha256']==rootref_pin['sha256'] and
         auth['channel_public_key_original_sha256']==entry['channel_public_key']['sha256'] and
         tr._ident(auth['claimed_physical_site_id']) and
         start<=astart<aend<=end and astart<=eval_at<=aend,
         'CHANNEL_AUTH_SCOPE_OR_VALIDITY_INVALID','permission_denied')
    rk=sha(root);ck=sha(chan_key)
    need(rk!=ck and rk not in oldrolekeys and ck not in oldrolekeys,
         'PARENT_SIGNATURE_ROLE_KEY_REUSED_AS_INSTITUTION_CUSTODIAN',
         'permission_denied')
    return {'slot':slot,'institution_id':inst,'channel_id':cid,
            'claimed_organization':entry['claimed_organization'],
            'claimed_physical_site_id':auth['claimed_physical_site_id'],
            'root_key_sha256':rk,'channel_key_sha256':ck,
            'root_reference_sha256':rootref_pin['sha256'],
            'channel_authorization_sha256':auth_pin['sha256'],
            'key':chan_key,'start':astart,'end':aend,
            'root_from':start,'root_until':end}


def _ack(raw,pin,entry,actor,eligible,inputs,eval_at,pins,oldpaths):
    doc=_signed(raw,actor['key'],ACK_DOMAIN,'signature_ed25519_hex','ACK')
    _exact(doc,('schema','acknowledgement_id','parent_disclosure_bundle_original_sha256',
                'gossip_reply_original_sha256','ec355_request_original_sha256',
                'ec355_receipt_original_sha256','ec355_requested_role','log_id',
                'checkpoint_original_sha256','witness_original_sha256',
                'checkpoint_length','witness_length','custody_status',
                'institution_id','channel_id','channel_authorization_original_sha256',
                'previous_ack_original_sha256','nonce_hex','acknowledged_utc',
                'signature_ed25519_hex'),'ACK')
    key=(doc['gossip_reply_original_sha256'],doc['ec355_request_original_sha256'],
         doc['ec355_receipt_original_sha256'])
    parent=eligible.get(key)
    need(doc['schema']==ACK_SCHEMA and tr._ident(doc['acknowledgement_id']) and
         parent is not None and
         doc['parent_disclosure_bundle_original_sha256']==inputs[
               'expected_checkpoint_disclosure_bundle_sha256'] and
         doc['log_id']==parent['log_id'] and
         doc['ec355_requested_role']==parent['requested_role'] and
         doc['checkpoint_original_sha256']==parent['checkpoint_sha256'] and
         doc['witness_original_sha256']==parent['witness_sha256'] and
         doc['institution_id']==actor['institution_id'] and
         doc['channel_id']==actor['channel_id'] and
         doc['channel_authorization_original_sha256']==actor[
             'channel_authorization_sha256'] and
         doc['custody_status'] in ('custodied_originals','sha_claim_only','unavailable_claim') and
         (doc['previous_ack_original_sha256']==GENESIS or
          tr._sha(doc['previous_ack_original_sha256'])) and
         type(doc['nonce_hex']) is str and gossip.NONCE_RE.fullmatch(
             doc['nonce_hex']) is not None,
         'ACK_SIGNED_PARENT_OR_CHANNEL_BINDING_INVALID','permission_denied')
    when=tr._utc(doc['acknowledged_utc'])
    need(tr._utc(parent['receipt_utc'])<=when<=eval_at and
         actor['start']<=when<=actor['end'] and
         actor['root_from']<=when<=actor['root_until'],
         'ACK_TIME_OUTSIDE_PARENT_OR_SIGNER_VALIDITY','permission_denied')
    originals=None
    if doc['custody_status']=='custodied_originals':
        need(type(doc['checkpoint_length']) is int and
             type(doc['witness_length']) is int and
             doc['checkpoint_length']==parent['checkpoint_length'] and
             doc['witness_length']==parent['witness_length'],
             'ACK_ORIGINAL_LENGTHS_NOT_EXACT_PARENT_BYTES','permission_denied')
        need(type(entry['checkpoint_original']) is dict and
             type(entry['witness_original']) is dict,
             'ACK_CUSTODY_REQUIRES_TWO_PRESENTED_FILES','permission_denied')
        cp=_new(entry['checkpoint_original'],'CHANNEL_CHECKPOINT',
                tr.MAX_CHECKPOINT,pins,oldpaths)
        wit=_new(entry['witness_original'],'CHANNEL_WITNESS',
                 tr.MAX_WITNESS,pins,oldpaths)
        need(sha(cp)==parent['checkpoint_sha256'] and
             sha(wit)==parent['witness_sha256'] and
             len(cp)==parent['checkpoint_length'] and len(wit)==parent['witness_length'],
             'ACK_TRUE_COPIES_DO_NOT_MATCH_EC355_VERIFIED_ORIGINAL_BYTES',
             'permission_denied')
        originals={'checkpoint_sha256':sha(cp),'witness_sha256':sha(wit),
                   'checkpoint_length':len(cp),'witness_length':len(wit),
                   'ec355_requested_role':parent['requested_role'],
                   'ec355_request_original_sha256':key[1],
                   'ec355_receipt_original_sha256':key[2],
                   'relation_to_challenged_parent':parent['relation']}
    else:
        need(doc['checkpoint_length'] is None and doc['witness_length'] is None and
             entry['checkpoint_original'] is None and entry['witness_original'] is None,
             'SIGNED_CLAIM_MUST_NOT_SMUGGLE_MEASURED_ORIGINALS','permission_denied')
    return {'ack_original_sha256':pin['sha256'],
            'acknowledgement_id':doc['acknowledgement_id'],
            'previous_ack_original_sha256':doc['previous_ack_original_sha256'],
            'nonce_hex':doc['nonce_hex'],
            'channel_slot':actor['slot'],'channel_id':actor['channel_id'],
            'institution_id':actor['institution_id'],
            'gossip_reply_original_sha256':key[0],
            'requested_role':parent['requested_role'],
            'custody_status':doc['custody_status'],
            'acknowledged_utc_as_self_claim':doc['acknowledged_utc'],
            'ec355_request_original_sha256':key[1],
            'ec355_receipt_original_sha256':key[2],
            'verified_originals':originals}


def _parent(inputs):
    result=prior.audit(**inputs)  # Real EC355->EC354->EC337 replay; never cached.
    need(result.get('schema')==prior.RESULT_SCHEMA and
         result.get('actual_ec354_through_ec337_original_signatures_replayed') is True and
         result.get('exit_code')==2,
         'PARENT_EC355_SIGNATURE_AND_ORIGINAL_REPLAY_REQUIRED','permission_denied')
    return result


def checklist(**disclosure_inputs):
    parent=_parent(disclosure_inputs)
    eligible,_,_,inherited=_parent_index(disclosure_inputs,parent)
    tsa._check_late(inherited)
    result=[]
    for key,item in sorted(eligible.items()):
        result.append({'gossip_reply_original_sha256':key[0],
                       'ec355_request_original_sha256':key[1],
                       'ec355_receipt_original_sha256':key[2],
                       'ec355_requested_role':item['requested_role'],
                       'log_id':item['log_id'],
                       'checkpoint_original_sha256':item['checkpoint_sha256'],
                       'witness_original_sha256':item['witness_sha256'],
                       'checkpoint_length':item['checkpoint_length'],
                       'witness_length':item['witness_length']})
    return {'schema':HANDOFF_SCHEMA,'command':'derive-custody-handoff',
            'status':'external_two_independently_pinned_root_channels_required_unresolved',
            'exit_code':2,'case_id':parent['case_id'],
            'actual_ec355_through_ec337_signed_originals_replayed':True,
            'parent_ec355_canonical_result_sha256':sha(canonical.canonical(parent)),
            'parent_disclosure_bundle_original_sha256':disclosure_inputs[
                'expected_checkpoint_disclosure_bundle_sha256'],
            'eligible_signed_furnished_receipts':result,
            'caller_must_independently_sha_pin_both_institution_root_public_keys':True,
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,two_channel_custody_evaluation_utc,custody_bundle_file,
          expected_custody_bundle_sha256,root_a_public_key_file,
          expected_root_a_public_key_sha256,root_b_public_key_file,
          expected_root_b_public_key_sha256,**disclosure_inputs):
    evaluation=tr._utc(two_channel_custody_evaluation_utc)
    need(evaluation>=tr._utc(disclosure_inputs['checkpoint_disclosure_evaluation_utc']),
         'CUSTODY_EVALUATION_BEFORE_EC355','permission_denied')
    parent=_parent(disclosure_inputs)
    eligible,oldrolekeys,oldpaths,oldpins=_parent_index(disclosure_inputs,parent)
    slots={
        'a':{'path':root_a_public_key_file,'sha256':expected_root_a_public_key_sha256},
        'b':{'path':root_b_public_key_file,'sha256':expected_root_b_public_key_sha256}}
    need(all(type(v['path']) is str and tr._sha(v['sha256']) for v in slots.values())
         and slots['a']!=slots['b'] and slots['a']['sha256']!=slots['b']['sha256'],
         'SEPARATE_ROOT_SHA_PINS_REQUIRED','permission_denied')
    pins={}
    doc=_obj(_new({'path':custody_bundle_file,'sha256':expected_custody_bundle_sha256},
                  'BUNDLE',MAX_BUNDLE,pins,oldpaths),'BUNDLE')
    _exact(doc,('schema','channels'),'BUNDLE')
    need(doc['schema']==BUNDLE_SCHEMA and type(doc['channels']) is list and
         len(doc['channels'])<=2,'BUNDLE_SCHEMA_OR_CHANNEL_BOUNDS_INVALID')
    seen_slots=set();seen_ids=set();seen_institution_ids=set()
    used_keys=set();actors={};all_ack=[];ids=set();nonces=set()
    chain_rows={};branch_count=Counter();by_claim=defaultdict(list)
    for entry in doc['channels']:
        slot=entry.get('slot') if type(entry) is dict else None
        need(slot in slots and slot not in seen_slots,'CHANNEL_SLOT_DUPLICATE_OR_UNKNOWN')
        actor=_channel(entry,slots[slot],evaluation,oldrolekeys,pins,oldpaths)
        seen_slots.add(slot)
        need(actor['channel_id'] not in seen_ids and
             actor['institution_id'] not in seen_institution_ids,
             'CHANNEL_OR_INSTITUTION_ID_REUSE','permission_denied')
        seen_ids.add(actor['channel_id']);seen_institution_ids.add(actor['institution_id'])
        for keysha in (actor['root_key_sha256'],actor['channel_key_sha256']):
            need(keysha not in used_keys,'INDEPENDENT_CHANNEL_KEY_REUSE',
                 'permission_denied')
            used_keys.add(keysha)
        actors[slot]=actor
        per_claim=Counter()
        for item in entry['acknowledgements']:
            _exact(item,('acknowledgement','checkpoint_original','witness_original'),
                   'ACK_MANIFEST')
            ap=item['acknowledgement'];raw=_new(ap,'ACK',MAX_RECORD,pins,oldpaths)
            signed=_ack(raw,ap,item,actor,eligible,disclosure_inputs,
                        evaluation,pins,oldpaths)
            need(signed['acknowledgement_id'] not in ids and
                 signed['nonce_hex'] not in nonces,
                 'GLOBAL_ACK_ID_OR_NONCE_REPLAY','permission_denied')
            ids.add(signed['acknowledgement_id']);nonces.add(signed['nonce_hex'])
            chainkey=(slot,signed['gossip_reply_original_sha256'])
            per_claim[chainkey]+=1
            need(per_claim[chainkey]<=MAX_PER_CLAIM_CHANNEL,
                 'TOO_MANY_PER_CLAIM_ACKNOWLEDGEMENTS')
            chain_rows[ap['sha256']]=(chainkey,signed)
            branch_count[(chainkey,signed['previous_ack_original_sha256'])]+=1
            by_claim[signed['gossip_reply_original_sha256']].append(signed)
            all_ack.append(signed)
    need(len(all_ack)<=MAX_ACKS,'TOO_MANY_ACKNOWLEDGEMENTS')
    for sig,(chainkey,row) in chain_rows.items():
        seen=set();cur=sig
        while cur!=GENESIS:
            need(cur in chain_rows and cur not in seen and
                 chain_rows[cur][0]==chainkey,
                 'ACK_SHA_PREDECESSOR_CYCLE_OR_CROSS_CHANNEL_LINK',
                 'permission_denied')
            seen.add(cur)
            need(len(seen)<=MAX_PER_CLAIM_CHANNEL,'ACK_CHAIN_TOO_DEEP')
            prior_sha=chain_rows[cur][1]['previous_ack_original_sha256']
            if prior_sha!=GENESIS:
                need(prior_sha in chain_rows,
                     'ACK_SHA_PREDECESSOR_CYCLE_OR_CROSS_CHANNEL_LINK',
                     'permission_denied')
                need(tr._utc(chain_rows[prior_sha][1][
                         'acknowledged_utc_as_self_claim'])<=tr._utc(chain_rows[cur][1][
                         'acknowledged_utc_as_self_claim']),
                     'ACK_SHA_PREDECESSOR_TIME_ORDER_INVALID','permission_denied')
            cur=prior_sha
    forks=any(n>1 for n in branch_count.values())
    collision=(len(actors)==2 and (len({a['claimed_organization'].casefold()
                             for a in actors.values()})<2 or
               len({a['claimed_physical_site_id'].casefold()
                             for a in actors.values()})<2))
    stale=any(evaluation-tr._utc(r['acknowledged_utc_as_self_claim'])>MAX_FRESHNESS
              for r in all_ack)
    equivocation=False;different_pairs=False;quorum=True
    claim_detail=[]
    for claim in sorted(parent['disclosure_claim_evidence'],key=lambda d:d[
                'gossip_reply_original_sha256']):
        claimsha=claim['gossip_reply_original_sha256'];rows=by_claim[claimsha]
        per_slot={slot:[r for r in rows if r['channel_slot']==slot] for slot in ('a','b')}
        confirmed={slot:[r for r in vals if r['verified_originals'] is not None]
                   for slot,vals in per_slot.items()}
        both_roles=False;matched_pair=None
        for a in confirmed['a']:
            for b in confirmed['b']:
                x=a['verified_originals'];y=b['verified_originals']
                if ((x['checkpoint_sha256'],x['witness_sha256'])==(
                     y['checkpoint_sha256'],y['witness_sha256']) and
                     x['ec355_requested_role']!=y['ec355_requested_role'] and
                     x['ec355_receipt_original_sha256']!=y['ec355_receipt_original_sha256']):
                    both_roles=True
                    matched_pair={'checkpoint_original_sha256':x['checkpoint_sha256'],
                                  'witness_original_sha256':x['witness_sha256'],
                                  'first_role_receipt_original_sha256':x[
                                     'ec355_receipt_original_sha256'],
                                  'second_role_receipt_original_sha256':y[
                                     'ec355_receipt_original_sha256']}
        pairset={(r['verified_originals']['checkpoint_sha256'],
                  r['verified_originals']['witness_sha256'])
                 for r in rows if r['verified_originals'] is not None}
        if len(pairset)>1:different_pairs=True
        for slot in ('a','b'):
            here=per_slot[slot]
            if len(here)==2 and (here[0]['custody_status'],here[0]['verified_originals'])!=(
                      here[1]['custody_status'],here[1]['verified_originals']):
                equivocation=True
        quorum &= both_roles
        claim_detail.append({
            'gossip_reply_original_sha256':claimsha,'log_id':claim['log_id'],
            'parent_same_original_observed_by_both_signed_roles':claim[
                 'same_original_observed_by_both_signed_roles'],
            'channel_a_acknowledgements':per_slot['a'],
            'channel_b_acknowledgements':per_slot['b'],
            'two_root_authorized_channels_same_original_different_ec355_roles':both_roles,
            'matching_original_pair':matched_pair,
            'incompatible_signed_original_pairs_present':len(pairset)>1,
        })
    # Re-read every old EC355 furnished original and every new channel signature
    # and original after making the quorum/ancestry decisions (no cache/report).
    need(not set(pins).intersection(oldpaths),'NEW_PARENT_PATH_ALIAS',
         'permission_denied')
    tsa._check_late(pins);tsa._check_late(oldpins)
    parent_good=(all(r['outcome']==prior.OUTCOMES[-1]
                     for r in parent['channel_evidence']) and
                 parent['both_roles_furnished_same_original_for_all_claims'] and
                 not parent['request_sha_predecessor_forks_visible'] and
                 not parent['signed_receipt_equivocation_visible'] and
                 not parent['verified_same_log_conflict_or_unproved_ancestry_visible'] and
                 not parent['stale_claimed_disclosure_time_visible'])
    if not eligible:outcome=OUTCOMES[1]
    elif not parent_good:outcome=OUTCOMES[0]
    elif len(actors)!=2:outcome=OUTCOMES[2]
    elif not all(confirmed for confirmed in (
              [r for r in all_ack if r['channel_slot']=='a' and r['verified_originals']],
              [r for r in all_ack if r['channel_slot']=='b' and r['verified_originals']])):
        outcome=OUTCOMES[3]
    elif forks or equivocation:outcome=OUTCOMES[4]
    elif collision or stale:outcome=OUTCOMES[5]
    elif not quorum or different_pairs:outcome=OUTCOMES[6]
    else:outcome=OUTCOMES[7]
    channels=[{'slot':x['slot'],'institution_id':x['institution_id'],
               'channel_id':x['channel_id'],
               'claimed_organization':x['claimed_organization'],
               'claimed_physical_site_id':x['claimed_physical_site_id'],
               'root_public_key_original_sha256':x['root_key_sha256'],
               'channel_public_key_original_sha256':x['channel_key_sha256'],
               'root_reference_original_sha256':x['root_reference_sha256'],
               'channel_authorization_original_sha256':x[
                   'channel_authorization_sha256']}
              for _,x in sorted(actors.items())]
    rows=[{'tsa_channel_id':r['tsa_channel_id'],
           'parent_ec355_outcome':r['outcome'],'outcome':outcome}
          for r in parent['channel_evidence']]
    counts={x:sum(row['outcome']==x for row in rows) for x in OUTCOMES}
    return {'schema':RESULT_SCHEMA,'command':'audit-two-channel-custody',
            'status':outcome+'_unresolved','exit_code':2,
            'case_id':parent['case_id'],'actual_ec355_through_ec337_signed_originals_replayed':True,
            'parent_ec355_canonical_result_sha256':sha(canonical.canonical(parent)),
            'parent_disclosure_bundle_original_sha256':disclosure_inputs[
                 'expected_checkpoint_disclosure_bundle_sha256'],
            'custody_bundle_original_sha256':expected_custody_bundle_sha256,
            'two_channel_custody_evaluation_utc_as_caller_claim':two_channel_custody_evaluation_utc,
            'externally_caller_pinned_root_key_sha256':{
                'a':slots['a']['sha256'],'b':slots['b']['sha256']},
            'channel_establishments':channels,
            'signed_acknowledgement_count':len(all_ack),
            'genuine_furnished_parent_receipt_count':len(eligible),
            'claim_custody_evidence':claim_detail,
            'signed_ack_sha_predecessor_forks_visible':forks,
            'signed_ack_equivocation_visible':equivocation,
            'incompatible_signed_original_sha_pairs_visible':different_pairs,
            'claimed_institution_or_site_identity_collision_visible':collision,
            'stale_custody_self_claimed_utc_visible':stale,
            'two_channel_cross_role_exact_original_quorum_for_all_claims':bool(
                claim_detail) and quorum and parent_good and len(actors)==2 and
                not (forks or equivocation or different_pairs or collision or stale),
            'out_of_band_root_custody_source_and_real_external_independence_unproven':True,
            'channel_evidence':rows,'outcome_counts':counts,
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}
