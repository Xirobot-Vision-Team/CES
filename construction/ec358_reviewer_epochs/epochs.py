#!/usr/bin/env python3
"""EC358: offline signed reviewer issue/rotate/revoke epoch ancestry over true EC357.

Cryptographic continuity is local to caller-SHA-pinned original public keys.
Neither these signatures nor local files authenticate any official institution,
independent legal authority, historical event time, physical custody or global
completeness. No signer, trust-store, network or remote writer is used here.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from pathlib import Path
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec357_provenance import provenance as parent

RESULT_SCHEMA='ces.ec358.offline_reviewer_epoch_continuity_unresolved.v1'
DENIAL_SCHEMA='ces.ec358.offline_reviewer_epoch_continuity_denial.v1'
HANDOFF_SCHEMA='ces.ec358.unsigned_epoch_continuity_handoff.v1'
BUNDLE_SCHEMA='ces.ec358.pinned_reviewer_epoch_bundle.v1'
EVENT_SCHEMA='ces.ec358.signed_reviewer_epoch_event.v1'
DOMAINS={
    'owner':b'CES/EC358/ReviewerEpoch/Owner/v1\x00',
    'previous':b'CES/EC358/ReviewerEpoch/PreviousReviewer/v1\x00',
    'current':b'CES/EC358/ReviewerEpoch/CurrentReviewer/v1\x00',
}
MAX_BUNDLE=32_000
MAX_EVENT=8_000
MAX_EVENTS_PER_SOURCE=8
MAX_AGE=timedelta(days=30)
MAX_VALIDITY=timedelta(days=90)
OUTCOMES=(
    'ec358_parent_ec357_signed_custody_and_source_review_unresolved',
    'ec358_missing_two_caller_pinned_owner_and_reviewer_epoch_heads',
    'ec358_signed_reviewer_epoch_branch_fork_or_owner_collision_visible',
    'ec358_signed_reviewer_revocation_terminal_visible',
    'ec358_pinned_epoch_rollback_or_review_signer_mismatch_visible',
    'ec358_issued_expiry_or_historical_clock_claims_stale_or_conflicting',
    'ec358_two_real_signed_owner_reviewer_histories_official_identity_unproven',
)
NEGATIVES=(
    'caller_pinned_owner_sha_proves_official_owner_identity',
    'two_distinct_owner_signatures_prove_independent_legal_institutions',
    'source_review_epoch_chain_proves_true_historical_event_occurrence_time',
    'signed_minimum_epoch_proves_no_unseen_fork_or_later_epoch',
    'rotate_signature_overrides_any_signed_revoke_or_conflicting_branch',
    'revoked_reviewer_signer_is_authorized_to_sign_a_new_ec357_review',
    'epoch_signature_repairs_invalid_ec357_through_ec337_parent_evidence',
    'owner_identity_claim_proves_offsite_original_custody_or_trusted_utc',
    'audit_uses_network_system_trust_store_or_external_directory',
    'audit_creates_keys_signs_or_writes_provider_cas_worm',
    'native_powershell_ec317_318_final_acceptance_proven',
)
EVENT_FIELDS={
    'schema','slot','source_id','claimed_owner_id',
    'owner_public_key_original_sha256','parent_ec357_canonical_result_sha256',
    'parent_source_review_original_sha256','epoch','previous_event_original_sha256',
    'operation','previous_reviewer_public_key_original_sha256',
    'current_reviewer_public_key_original_sha256','issued_utc','expires_utc',
    'signature_owner_ed25519_hex','signature_previous_reviewer_ed25519_hex',
    'signature_current_reviewer_ed25519_hex',
}
SIGNATURE_FIELDS={
    'owner':'signature_owner_ed25519_hex',
    'previous':'signature_previous_reviewer_ed25519_hex',
    'current':'signature_current_reviewer_ed25519_hex',
}


def need(condition,reason,status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC358_'+reason,status)


def _exact(doc,keys,role):
    need(type(doc) is dict and set(doc)==set(keys),role+'_EXACT_FIELDS_REQUIRED')


def _sha(raw):return parent.sha(raw)


def _read_parent(provenance_inputs):
    result=parent.audit(**provenance_inputs)  # genuinely replays EC357 to EC337.
    need(result.get('schema')==parent.RESULT_SCHEMA and result.get('exit_code')==2
         and result.get('actual_ec356_through_ec337_originals_replayed') is True,
         'PARENT_EC357_REAL_REPLAY_REQUIRED','permission_denied')
    return result


def _old_boundary(provenance_inputs):
    """Recover original old manifest, nested parent file exclusions and source keys.

    Reopened complete originals stay bound by their whole-file SHA. The parent
    itself verifies older nested signed proofs; this layer forbids old key/file
    aliases masquerading as newly independent owner/event originals.
    """
    oldpins={}
    custody={'path':provenance_inputs['custody_bundle_file'],
             'sha256':provenance_inputs['expected_custody_bundle_sha256']}
    old_custody=parent.prior._inherited(custody,'EC358_PARENT_EC356_BUNDLE',
                                        parent.prior.MAX_BUNDLE,oldpins)
    custody_doc=parent._obj(old_custody,'EC358_PARENT_EC356_BUNDLE')
    oldpaths=parent._parent_files(provenance_inputs,custody_doc,oldpins)
    rolekeys=set()
    for channel in custody_doc['channels']:
        for role in ('root_public_key','channel_public_key'):
            raw=parent.prior._inherited(channel[role],
                 'EC358_PARENT_EC356_ROLE',32,oldpins)
            rolekeys.add(_sha(raw))
    for name,field,cap,entryfield,keyfields in (
        ('PUBLICATION','publication',tr.MAX_BUNDLE,'logs',('log_public_key','witness_public_key')),
        ('GOSSIP','gossip',parent.prior.gossip.MAX_BUNDLE,'auditors',('auditor_public_key',)),
    ):
        p={'path':provenance_inputs[field+'_bundle_file'],
           'sha256':provenance_inputs['expected_'+field+'_bundle_sha256']}
        doc=parent._obj(parent.prior._inherited(p,'EC358_PARENT_'+name,
                                cap,oldpins),'EC358_PARENT_'+name)
        for entry in doc[entryfield]:
            for fieldname in keyfields:
                raw=parent.prior._inherited(entry[fieldname],
                        'EC358_PARENT_ROLE_KEY',32,oldpins)
                rolekeys.add(_sha(raw))
    # Retain all caller-SHA-pinned EC351/EC352 Ed25519 signing roles. A new
    # epoch owner cannot be a renamed historic attester, registry root or
    # registry operator signing key, even if it was stored at a new path.
    for files_key,shas_key in (
        ('authority_key_files','authority_key_shas'),
        ('registry_root_key_files','registry_root_key_shas'),
        ('registry_signer_key_files','registry_signer_key_shas')):
        files=provenance_inputs.get(files_key,[])
        hashes=provenance_inputs.get(shas_key,[])
        need(type(files) is list and type(hashes) is list and
             len(files)==len(hashes),
             'INHERITED_ED25519_ROLE_KEY_PIN_LENGTH_MISMATCH',
             'permission_denied')
        for f,h in zip(files,hashes):
            raw=parent.prior._inherited({'path':f,'sha256':h},
                                        'EC358_LEGACY_ROLE_KEY',32,oldpins)
            rolekeys.add(_sha(raw))
            oldpaths.add(f)
    for slot in ('a','b'):
        path=provenance_inputs.get('source_'+slot+'_authority_public_key_file')
        digest=provenance_inputs.get('expected_source_'+slot+'_authority_public_key_sha256')
        if path is not None and digest is not None:
            pin={'path':path,'sha256':digest}
            parent.prior._inherited(pin,'EC358_EC357_SOURCE_KEY',32,oldpins)
            oldpaths.add(path)
    sfile=provenance_inputs.get('provenance_review_bundle_file')
    sdigest=provenance_inputs.get('expected_provenance_review_bundle_sha256')
    if sfile is not None and sdigest is not None:
        raw=parent.prior._inherited({'path':sfile,'sha256':sdigest},
                            'EC358_PARENT_EC357_SOURCE_BUNDLE',parent.MAX_BUNDLE,oldpins)
        oldpaths.add(sfile)
        doc=parent._obj(raw,'EC358_PARENT_EC357_SOURCE_BUNDLE')
        parent._all_pins(doc,oldpaths)
        for record in doc['sources']:
            for key in ('source_authority_public_key','signed_source_review'):
                cap=32 if key=='source_authority_public_key' else parent.MAX_SOURCE
                parent.prior._inherited(record[key],'EC358_PARENT_SOURCE_ORIGINAL',cap,oldpins)
                oldpaths.add(record[key]['path'])
            for inv in record['inventory_copies']:
                for key in ('checkpoint_original','witness_original'):
                    parent.prior._inherited(inv[key],'EC358_PARENT_COPY',
                                             tr.MAX_CHECKPOINT if key=='checkpoint_original'
                                             else tr.MAX_WITNESS,oldpins)
                    oldpaths.add(inv[key]['path'])
    return oldpins,oldpaths,rolekeys


def _key_pin(pair,role):
    _exact(pair,('path','sha256'),role+'_PIN')
    need(type(pair['path']) is str and tr._sha(pair['sha256']),role+'_PIN_INVALID')


def _read_new(pin,role,cap,pins,oldpaths,categories,category):
    _key_pin(pin,role)
    path=pin['path']
    if path in pins:
        need(pins[path][0]==pin['sha256'] and categories.get(path)==category,
             'INCONSISTENT_REUSED_OR_CROSS_ROLE_FILE','permission_denied')
        return parent.prior._inherited(pin,role,cap,pins)
    raw=parent.prior._new(pin,role,cap,pins,oldpaths)
    categories[path]=category
    return raw


def _sig(public,sign,domain,body,role):
    need(type(sign) is str and tr.SIG_RE.fullmatch(sign) is not None,
         role+'_SIGNATURE_FORMAT_INVALID')
    need(type(public) is bytes and len(public)==32,
         role+'_PUBLIC_KEY_NOT_32_BYTES')
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(sign),domain+canonical.canonical(body))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise errors.AnchorError('EC358_'+role+'_REAL_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _event(raw,source_slot,source,owner_key,owner_sha,parent_sha,
           parent_pins,rolekeys,owner_keys,pins,oldpaths,categories,key_ownership):
    doc=tr.strict_json(raw,'EC358_EPOCH_EVENT')
    _exact(doc,EVENT_FIELDS,'EPOCH_EVENT')
    need(doc['schema']==EVENT_SCHEMA and doc['slot']==source_slot and
         doc['source_id']==source['source_id_as_signed_claim'] and
         tr._ident(doc['claimed_owner_id']) and
         doc['owner_public_key_original_sha256']==owner_sha and
         doc['parent_ec357_canonical_result_sha256']==parent_sha and
         doc['parent_source_review_original_sha256']==source[
               'source_review_original_sha256'],
         'EVENT_MUST_BIND_ACTUAL_REPLAY_AND_SEPARATELY_PINNED_OWNER',
         'permission_denied')
    need(type(doc['epoch']) is int and 0<=doc['epoch']<MAX_EVENTS_PER_SOURCE and
         doc['operation'] in ('issue','rotate','revoke') and
         (doc['previous_event_original_sha256'] is None or
          tr._sha(doc['previous_event_original_sha256'])),
         'EVENT_EPOCH_LINK_OR_OPERATION_INVALID')
    issued=tr._utc(doc['issued_utc']);expires=tr._utc(doc['expires_utc'])
    need(issued<expires and expires-issued<=MAX_VALIDITY,
         'EVENT_SIGNED_TIME_INTERVAL_INVALID','permission_denied')
    old_hash=doc['previous_reviewer_public_key_original_sha256']
    next_hash=doc['current_reviewer_public_key_original_sha256']
    if doc['operation']=='issue':
        need(doc['epoch']==0 and doc['previous_event_original_sha256'] is None and
             old_hash is None and tr._sha(next_hash),
             'ISSUE_GENESIS_SHAPE_INVALID','permission_denied')
    elif doc['operation']=='rotate':
        need(doc['epoch']>0 and tr._sha(doc['previous_event_original_sha256']) and
             tr._sha(old_hash) and tr._sha(next_hash) and old_hash!=next_hash,
             'ROTATION_REQUIRES_DISTINCT_PREVIOUS_AND_CURRENT_KEYS',
             'permission_denied')
    else:
        need(doc['epoch']>0 and tr._sha(doc['previous_event_original_sha256']) and
             tr._sha(old_hash) and next_hash is None,
             'REVOCATION_MUST_BE_TERMINAL','permission_denied')
    payload={k:v for k,v in doc.items() if k not in SIGNATURE_FIELDS.values()}
    _sig(owner_key,doc[SIGNATURE_FIELDS['owner']],DOMAINS['owner'],payload,'OWNER')
    for side,hsh,required in (
        ('previous',old_hash,doc['operation'] in ('rotate','revoke')),
        ('current',next_hash,doc['operation'] in ('issue','rotate')),
    ):
        sig=doc[SIGNATURE_FIELDS[side]]
        if not required:
            need(sig is None and parent_pins[side] is None,
                 'UNEXPECTED_REVIEWER_SIGNATURE_OR_PUBLIC_KEY','permission_denied')
            continue
        keypin=parent_pins[side]
        _key_pin(keypin,'EVENT_'+side.upper()+'_REVIEWER')
        need(keypin['sha256']==hsh,'SIGNED_EVENT_KEY_MUST_EQUAL_PINNED_KEY',
             'permission_denied')
        # Reuse the actual EC357 reviewer key *in its established role*. New
        # reviewer keys require fresh originals, not copies of older roles.
        actual_source_path=source['__reviewer_key_path']
        actual_source_sha=source['authority_public_key_original_sha256']
        if hsh==actual_source_sha:
            need(keypin=={'path':actual_source_path,'sha256':actual_source_sha},
                 'PARENT_REVIEWER_KEY_MUST_USE_EXACT_ORIGINAL_PIN',
                 'permission_denied')
            public=parent.prior._inherited(keypin,'EC358_REUSED_EC357_REVIEWER',
                                          32,source['__parent_key_pins'])
        else:
            need(hsh not in rolekeys and hsh not in owner_keys and
                 hsh not in source['__other_source_keys'],
                 'REVIEWER_KEY_REUSES_OLD_OR_OWNER_ROLE','permission_denied')
            public=_read_new(keypin,'REVIEWER_KEY',32,pins,oldpaths,
                             categories,'reviewer')
        need(len(public)==32 and _sha(public)==hsh,
             'REVIEWER_PUBLIC_KEY_BYTES_INVALID','permission_denied')
        other=key_ownership.setdefault(hsh,source_slot)
        need(other==source_slot,'REVIEWER_SIGNER_CROSSES_SOURCE_SLOTS',
             'permission_denied')
        _sig(public,sig,DOMAINS[side],payload,side.upper()+'_REVIEWER')
    return doc,issued,expires


def checklist(**provenance_inputs):
    p=_read_parent(provenance_inputs)
    return {'schema':HANDOFF_SCHEMA,'command':'derive-reviewer-epoch-handoff',
            'status':'caller_must_furnish_two_independently_sha_pinned_signed_owner_epoch_histories_unresolved',
            'exit_code':2,'case_id':p['case_id'],
            'actual_ec357_through_ec337_originals_replayed':True,
            'parent_ec357_canonical_result_sha256':_sha(canonical.canonical(p)),
            'required_source_reviews':[{'slot':r['slot'],
                'source_id':r['source_id_as_signed_claim'],
                'source_review_original_sha256':r['source_review_original_sha256'],
                'reviewer_key_original_sha256':r['authority_public_key_original_sha256']}
                for r in p['source_establishments']],
            'caller_must_supply_persisted_minimum_epochs_and_expected_head_sha':True,
            'actual_official_owner_authentication_and_global_fork_completeness_unproven':True,
            'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,reviewer_epoch_evaluation_utc,reviewer_epoch_bundle_file=None,
          expected_reviewer_epoch_bundle_sha256=None,
          owner_a_public_key_file=None,expected_owner_a_public_key_sha256=None,
          owner_b_public_key_file=None,expected_owner_b_public_key_sha256=None,
          minimum_a_epoch=None,minimum_b_epoch=None,
          expected_a_head_event_sha256=None,expected_b_head_event_sha256=None,
          **provenance_inputs):
    evaluated=tr._utc(reviewer_epoch_evaluation_utc)
    need(evaluated>=tr._utc(provenance_inputs['provenance_review_evaluation_utc']),
         'EPOCH_EVALUATION_BEFORE_EC357','permission_denied')
    p=_read_parent(provenance_inputs)
    parent_sha=_sha(canonical.canonical(p))
    sources={r['slot']:r for r in p['source_establishments']}
    oldpins,oldpaths,rolekeys=_old_boundary(provenance_inputs)
    inputowners={
        'a':(owner_a_public_key_file,expected_owner_a_public_key_sha256),
        'b':(owner_b_public_key_file,expected_owner_b_public_key_sha256),
    }
    heads={'a':expected_a_head_event_sha256,'b':expected_b_head_event_sha256}
    floors={'a':minimum_a_epoch,'b':minimum_b_epoch}
    for slot in ('a','b'):
        pair=inputowners[slot]
        need(pair==(None,None) or (type(pair[0]) is str and tr._sha(pair[1])),
             'OWNER_'+slot.upper()+'_FILE_AND_SHA_MUST_BE_PAIRED')
        need(heads[slot] is None or tr._sha(heads[slot]),
             'EXPECTED_HEAD_'+slot.upper()+'_SHA_INVALID')
        need(floors[slot] is None or (type(floors[slot]) is int and
                0<=floors[slot]<MAX_EVENTS_PER_SOURCE),
             'MINIMUM_'+slot.upper()+'_EPOCH_INVALID')
    if all(inputowners[k]!=(None,None) for k in ('a','b')):
        need(inputowners['a'][0]!=inputowners['b'][0] and
             inputowners['a'][1]!=inputowners['b'][1],
             'TWO_INDEPENDENT_CALLER_OWNER_SHA_PINS_REQUIRED',
             'permission_denied')
    bundle_pair=(reviewer_epoch_bundle_file,expected_reviewer_epoch_bundle_sha256)
    need(bundle_pair==(None,None) or (type(bundle_pair[0]) is str and
         tr._sha(bundle_pair[1])),'EPOCH_BUNDLE_AND_SHA_MUST_BE_PAIRED')
    newpins={};categories={};owner_rows=[];owner_keys=set();
    reviewer_key_ownership={};fork=False;rollback=False;revoked=False
    missing=False;stale=False;collisions=False
    entries=[]
    if bundle_pair!=(None,None):
        bundleraw=_read_new({'path':bundle_pair[0],'sha256':bundle_pair[1]},
                            'EPOCH_BUNDLE',MAX_BUNDLE,newpins,oldpaths,
                            categories,'manifest')
        doc=tr.strict_json(bundleraw,'EC358_BUNDLE')
        _exact(doc,('schema','sources'),'EPOCH_BUNDLE')
        need(doc['schema']==BUNDLE_SCHEMA and type(doc['sources']) is list and
             len(doc['sources'])<=2,'EPOCH_BUNDLE_FORMAT_OR_BOUNDS')
        entries=doc['sources']
    usedslots=set();owner_ids=set()
    all_source_sha={r['authority_public_key_original_sha256'] for r in sources.values()}
    for entry in entries:
        _exact(entry,('slot','owner_public_key','events'),'SOURCE_EPOCH_ENTRY')
        slot=entry['slot']
        need(slot in ('a','b') and slot not in usedslots,
             'DUPLICATE_OR_INVALID_SOURCE_SLOT','permission_denied')
        usedslots.add(slot)
        need(slot in sources,'EPOCH_SOURCE_MISSING_GENUINE_EC357_REVIEW',
             'permission_denied')
        pair=inputowners[slot]
        need(pair!=(None,None),'OWNER_MUST_BE_SEPARATELY_CALLER_PINNED',
             'permission_denied')
        ownerpin={'path':pair[0],'sha256':pair[1]}
        need(entry['owner_public_key']==ownerpin,
             'OWNER_KEY_MUST_EQUAL_SEPARATE_CALLER_SHA_PIN','permission_denied')
        owner_key=_read_new(ownerpin,'OWNER_KEY',32,newpins,oldpaths,
                            categories,'owner')
        owner_sha=_sha(owner_key)
        need(owner_sha not in owner_keys and owner_sha not in rolekeys and
             owner_sha not in all_source_sha and
             owner_sha not in reviewer_key_ownership,
             'OWNER_KEY_REUSES_PARENT_OR_OTHER_OWNER_ROLE',
             'permission_denied')
        owner_keys.add(owner_sha)
        source=dict(sources[slot]);source['__reviewer_key_path']=provenance_inputs[
            'source_'+slot+'_authority_public_key_file']
        source['__parent_key_pins']=oldpins
        source['__other_source_keys']=all_source_sha-{source['authority_public_key_original_sha256']}
        event_pins=entry['events']
        need(type(event_pins) is list and len(event_pins)<=MAX_EVENTS_PER_SOURCE,
             'SOURCE_EVENT_COUNT_BOUNDS_INVALID')
        records={};owners=set();genesis=[];children=defaultdict(list)
        for part in event_pins:
            _exact(part,('event_original','previous_reviewer_public_key',
                         'current_reviewer_public_key'),'PINNED_EPOCH_EVENT')
            eventpin=part['event_original']
            raw=_read_new(eventpin,'SIGNED_EPOCH_EVENT',MAX_EVENT,newpins,
                          oldpaths,categories,'event')
            digest=_sha(raw)
            need(digest not in records,'DUPLICATE_EPOCH_EVENT_ORIGINAL',
                 'permission_denied')
            d,issued,expires=_event(raw,slot,source,owner_key,owner_sha,
                parent_sha,{'previous':part['previous_reviewer_public_key'],
                            'current':part['current_reviewer_public_key']},
                rolekeys,owner_keys,newpins,oldpaths,categories,reviewer_key_ownership)
            records[digest]=(d,issued,expires)
            if issued>evaluated:stale=True
            owners.add(d['claimed_owner_id'])
            if d['operation']=='issue':genesis.append(digest)
            else:children[d['previous_event_original_sha256']].append(digest)
        # No missing ancestry may be used to authorize a rotate or revoke.
        for digest,(d,issued,expires) in records.items():
            if d['operation']=='issue':continue
            prior=records.get(d['previous_event_original_sha256'])
            need(prior is not None,'MISSING_SIGNED_PREDECESSOR_ORIGINAL',
                 'permission_denied')
            prev,prev_issued,_=prior
            need(prev['operation']!='revoke' and prev['epoch']+1==d['epoch'] and
                 d['previous_reviewer_public_key_original_sha256']==
                      prev['current_reviewer_public_key_original_sha256'],
                 'EPOCH_LINK_OR_REVOKED_PREDECESSOR_INVALID',
                 'permission_denied')
            if issued<prev_issued:stale=True
        if len(genesis)>1 or any(len(v)>1 for v in children.values()):fork=True
        if len(owners)>1:collisions=True
        if any(x in owner_ids for x in owners):collisions=True
        owner_ids.update(owners)
        headsha=heads[slot]
        selected=records.get(headsha)
        if headsha is not None:
            need(selected is not None,'CALLER_PINNED_HEAD_NOT_IN_SIGNED_HISTORY',
                 'permission_denied')
        if not records or headsha is None or floors[slot] is None:missing=True
        if not genesis and records:
            need(False,'SIGNATURE_HISTORY_WITHOUT_ISSUE_GENESIS',
                 'permission_denied')
        for digest,(_,_,_) in records.items():
            # Every event must trace to a signed genesis (max 8 depth).
            trace=set();cursor=digest
            while cursor is not None:
                need(cursor not in trace,'CYCLIC_EPOCH_ANCESTRY',
                     'permission_denied')
                trace.add(cursor)
                cursor=records[cursor][0]['previous_event_original_sha256']
        head_epoch=None;head_state=None;head_key=None;matches_review=False
        if selected is not None:
            d,issued,expires=selected
            head_epoch=d['epoch'];head_state=d['operation'];
            head_key=d['current_reviewer_public_key_original_sha256']
            if d['operation']=='revoke':revoked=True
            if children.get(headsha):rollback=True
            if floors[slot] is not None and head_epoch<floors[slot]:rollback=True
            matches_review=(head_key==source['authority_public_key_original_sha256'])
            if not matches_review:rollback=True
            if issued>evaluated or expires<evaluated or evaluated-issued>MAX_AGE:
                stale=True
        # Valid signed branches may end at distinct heads. A caller-pinned head
        # is never allowed to erase visibility of other signed branches.
        endpoints=[d for d in records if not children.get(d)]
        if len(endpoints)>1:fork=True
        if any(records[x][0]['operation']=='revoke' for x in endpoints):revoked=True
        owner_rows.append({
            'slot':slot,'owner_id_as_signed_claim':next(iter(owners)) if len(owners)==1 else None,
            'owner_public_key_original_sha256':owner_sha,
            'parent_source_review_original_sha256':source['source_review_original_sha256'],
            'parent_reviewer_public_key_original_sha256':source['authority_public_key_original_sha256'],
            'expected_head_sha256_as_caller_pin':headsha,
            'minimum_epoch_as_caller_claim':floors[slot],
            'observed_signed_event_count':len(records),
            'observed_signed_endpoint_count':len(endpoints),
            'selected_head_epoch':head_epoch,'selected_head_operation':head_state,
            'selected_head_reviewer_public_key_sha256':head_key,
            'head_matches_ec357_reviewer_signer':matches_review,
            'signed_events':[{'event_original_sha256':digest,'epoch':d['epoch'],
                'operation':d['operation'],
                'previous_event_original_sha256':d['previous_event_original_sha256'],
                'reviewer_key_after_sha256':d['current_reviewer_public_key_original_sha256'],
                'issued_utc_as_signed_claim':d['issued_utc'],
                'expires_utc_as_signed_claim':d['expires_utc']}
                for digest,(d,_,_) in sorted(records.items(),key=lambda x:
                    (x[1][0]['epoch'],x[0]))],
        })
    if len(usedslots)!=2:missing=True
    # Late re-read every new owner/key/event/bundle original, then all tracked
    # parent source/publication/custody pins; inode/path alias recheck last.
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    parent._late_identity_check(newpins,oldpaths)
    parent_good=(p['source_review_count']==2 and
                 p['both_source_copies_match_ec356_parent_for_all_signed_eligible_receipts']
                 and all(r['outcome']==parent.OUTCOMES[-1] for r in p['channel_evidence']))
    if not parent_good:outcome=OUTCOMES[0]
    elif missing:outcome=OUTCOMES[1]
    elif fork or collisions:outcome=OUTCOMES[2]
    elif revoked:outcome=OUTCOMES[3]
    elif rollback:outcome=OUTCOMES[4]
    elif stale:outcome=OUTCOMES[5]
    else:outcome=OUTCOMES[6]
    evidence=[{'tsa_channel_id':r['tsa_channel_id'],
               'parent_ec357_outcome':r['outcome'],'outcome':outcome}
              for r in p['channel_evidence']]
    return {'schema':RESULT_SCHEMA,'command':'audit-reviewer-epochs',
            'status':outcome+'_unresolved','exit_code':2,'case_id':p['case_id'],
            'actual_ec357_through_ec337_signed_originals_replayed':True,
            'parent_ec357_canonical_result_sha256':parent_sha,
            'parent_source_review_bundle_original_sha256':p['source_review_bundle_original_sha256'],
            'reviewer_epoch_bundle_original_sha256':bundle_pair[1],
            'epoch_evaluation_utc_as_caller_claim':reviewer_epoch_evaluation_utc,
            'owner_establishments':owner_rows,'owner_review_count':len(owner_rows),
            'signed_branch_or_owner_identity_collision_visible':bool(fork or collisions),
            'signed_reviewer_revocation_visible':revoked,
            'pinned_rollback_or_review_signer_mismatch_visible':rollback,
            'missing_epoch_chain_owner_or_caller_pin_visible':missing,
            'stale_future_or_reordered_self_claimed_epoch_time_visible':stale,
            'two_signed_owner_histories_locally_continuous_and_match_ec357_review':bool(
                parent_good and len(owner_rows)==2 and
                not (fork or collisions or revoked or rollback or missing or stale)),
            'independent_official_owner_identity_physical_custody_trusted_utc_and_global_head_unproven':True,
            'channel_evidence':evidence,
            'outcome_counts':{x:sum(row['outcome']==x for row in evidence) for x in OUTCOMES},
            'offline_unresolved_exit_code':2,
            **{x:False for x in NEGATIVES}}
