#!/usr/bin/env python3
"""EC368 offline, receiver-retained, *byte-complete* witness-status handoffs.

The only authority for EC367 observations is a fresh EC367 -> EC366 -> EC337
signed-original audit. Receiver copies are checked byte-for-byte against every
referenced EC366 institution-status/provenance and EC367 witness original.
Independently pinned Ed25519 dispatch and receipt originals commit to the exact
portable inventory, authenticated predecessor handoffs and BOTH witness heads.
This module neither signs, downloads, writes custody material nor promotes a
claimed sender/receiver to an official/legal custody provider.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec360_authority_directory import authority
from ec364_cross_epoch import continuity as historic
from ec367_witness_distribution import distribution as parent

RESULT_SCHEMA='ces.ec368.offline_portable_receiver_custody_unresolved.v1'
DENIAL_SCHEMA='ces.ec368.offline_portable_receiver_custody_denial.v1'
HANDOFF_SCHEMA='ces.ec368.unsigned_portable_receiver_handoff.v1'
BUNDLE_SCHEMA='ces.ec368.receiver_portable_copies_and_dual_signed_handoffs.v1'
INVENTORY_SCHEMA='ces.ec368.portable_original_byte_inventory.v1'
DISPATCH_SCHEMA='ces.ec368.sender_signed_witness_status_dispatch.v1'
ACK_SCHEMA='ces.ec368.receiver_signed_witness_status_acknowledgment.v1'
DISPATCH_DOMAIN=b'CES/EC368/PortableWitnessStatusDispatch/v1\x00'
ACK_DOMAIN=b'CES/EC368/PortableWitnessStatusReceiverAck/v1\x00'
MAX_BUNDLE=30000
MAX_HANDOFFS=4
MAX_SIGNED=6000
MAX_COPIES=52
MAX_COPIED_ORIGINAL=32000
MAX_WINDOW=timedelta(days=7)
BUNDLE_FIELDS={'schema','parent_ec367_canonical_result_sha256','portable_inventory','handoffs'}
COPY_FIELDS={'kind','source_original_sha256','byte_length','receiver_copy'}
HANDOFF_FIELDS={'sender_dispatch_original','receiver_ack_original'}
COMMON_FIELDS={'schema','claimed_sender_id','sender_public_key_original_sha256',
               'claimed_receiver_id','receiver_public_key_original_sha256',
               'parent_ec367_canonical_result_sha256','portable_inventory_canonical_sha256',
               'sequence','previous_sender_dispatch_original_sha256',
               'previous_receiver_ack_original_sha256','witness_head_original_shas',
               'issued_utc','expires_utc'}
DISPATCH_FIELDS=COMMON_FIELDS|{'signature_sender_ed25519_hex'}
ACK_FIELDS=(COMMON_FIELDS-{'issued_utc'})|{
    'sender_dispatch_original_sha256','receipt_state','received_utc',
    'signature_receiver_ed25519_hex'}
NEW_REQUIRED=('portable_receiver_evaluation_utc',)
NEW_OPTIONAL=('portable_receiver_bundle_file','expected_portable_receiver_bundle_sha256',
 'expected_portable_inventory_sha256','sender_public_key_file',
 'expected_sender_public_key_sha256','claimed_sender_id',
 'receiver_public_key_file','expected_receiver_public_key_sha256',
 'claimed_receiver_id','expected_retained_sender_dispatch_head_sha256',
 'expected_retained_receiver_ack_head_sha256',
 'minimum_retained_sender_dispatch_sequence',
 'minimum_retained_receiver_ack_sequence')
NEW_REPEATS=(('signed_sender_dispatch_shas','--signed-sender-dispatch-sha256'),
             ('signed_receiver_ack_shas','--signed-receiver-ack-sha256'))
NEW_REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
FLAGS=(
 'inherited_ec367_distribution_or_source_status_unresolved',
 'sender_or_receiver_signer_reuses_witness_source_or_historical_role',
 'independently_retained_portable_inventory_or_handoff_sha_stream_mismatch',
 'receiver_copy_inventory_does_not_cover_exact_ec367_originals',
 'authentic_sender_or_receiver_handoff_fork_gap_or_cross_link_visible',
 'sender_receiver_signed_parent_inventory_or_witness_head_disagreement',
 'retained_sender_or_receiver_head_or_sequence_rollback_visible',
 'authentic_receiver_ack_withheld_or_disputed_visible',
 'source_signed_revocation_or_rotation_survives_portable_ack',
 'self_reported_dispatch_or_receipt_clock_untrusted_or_out_of_order',
 'complete_current_independent_receiver_ack_not_demonstrated',
)
OUTCOMES=(
 'ec368_inherited_ec367_witness_or_source_status_not_locally_current',
 'ec368_sender_or_receiver_signer_alias_to_prior_source_role',
 'ec368_externally_retained_inventory_or_signed_stream_mismatch',
 'ec368_receiver_original_byte_inventory_incomplete_or_inconsistent',
 'ec368_authentic_sender_receiver_chain_gap_fork_or_cross_link',
 'ec368_signed_sender_receiver_inventory_parent_or_witness_heads_disagree',
 'ec368_retained_sender_receiver_handoff_rollback',
 'ec368_genuinely_signed_receiver_withholding_or_dispute',
 'ec368_verified_source_signed_terminal_status_not_overridden_by_custody',
 'ec368_claimed_sender_or_receiver_time_not_independently_trusted',
 'ec368_current_complete_received_handoff_not_demonstrated',
 'ec368_locally_complete_dual_signed_portable_copy_only_official_custody_unproven',
)
NEGATIVES=(
 'receiver_signature_proves_actual_physical_possession_outside_audited_files',
 'sender_or_receiver_key_proves_independent_legal_official_identity',
 'receiver_ack_establishes_global_latest_unseen_forks_or_no_hidden_withholding',
 'receiver_accepted_claim_clears_true_signed_source_revocation',
 'locally_held_copy_replaces_bad_parent_cryptographic_verification',
 'self_claimed_send_receive_time_is_trusted_utc',
 'verifier_generates_sender_or_receiver_private_signatures',
 'network_provider_os_trust_or_remote_cas_worm_accessed_or_modified',
 'native_powershell_legacy_mocks_or_user_final_acceptance_proven',
)


def need(condition,code,status='invalid_input'):
    if condition is not True:raise errors.AnchorError('EC368_'+code,status)


def exact(value,fields,role):
    need(type(value) is dict and set(value)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _parent_inputs(inputs):
    return {k:v for k,v in inputs.items() if
            k not in NEW_REQUIRED and k not in NEW_OPTIONAL and
            k not in NEW_REPEAT_NAMES}


def _pin(ref,role):
    historic.ref_check(ref,'EC368_'+role)


def _new_inputs(inputs):
    for stem in ('portable_receiver_bundle','sender_public_key','receiver_public_key'):
        if stem=='portable_receiver_bundle':
            a,b='portable_receiver_bundle_file','expected_portable_receiver_bundle_sha256'
        else:
            a,b=stem+'_file','expected_'+stem+'_sha256'
        authority.outer_pin(inputs.get(a),inputs.get(b),'EC368_'+stem.upper())
        need(inputs.get(a) is not None and inputs.get(b) is not None,
             stem.upper()+'_EXTERNAL_FILE_AND_SHA_REQUIRED')
    for k in ('expected_portable_inventory_sha256',
              'expected_retained_sender_dispatch_head_sha256',
              'expected_retained_receiver_ack_head_sha256'):
        need(tr._sha(inputs.get(k)),k.upper()+'_EXTERNAL_SHA_REQUIRED')
    for k in ('claimed_sender_id','claimed_receiver_id'):
        need(tr._ident(inputs.get(k)),k.upper()+'_STRICT_ID_REQUIRED')
    need(inputs['claimed_sender_id']!=inputs['claimed_receiver_id'] and
         inputs['expected_sender_public_key_sha256']!=
               inputs['expected_receiver_public_key_sha256'],
         'INDEPENDENT_SENDER_RECEIVER_PUBLIC_KEYS_AND_IDENTITIES_REQUIRED',
         'permission_denied')
    for k in ('minimum_retained_sender_dispatch_sequence',
              'minimum_retained_receiver_ack_sequence'):
        v=inputs.get(k)
        need(type(v) is int and 0<=v<MAX_HANDOFFS,
             k.upper()+'_EXTERNAL_FLOOR_REQUIRED')
    for k in NEW_REPEAT_NAMES:
        vals=inputs.get(k,[])
        need(type(vals) is list and 1<=len(vals)<=MAX_HANDOFFS and
             all(tr._sha(v) for v in vals) and len(set(vals))==len(vals),
             k.upper()+'_EXACT_BOUNDED_PIN_STREAM_REQUIRED')


def _origins(inputs):
    """Enumerate true source originals in fixed order, not caller copy choices.

    EC367 has authenticated these originals, their roles and signatures. We
    independently reopen the exact original bytes instead of trusting an EC367
    JSON result or a self-declared inventory list from the receiver bundle.
    """
    originals=[];known=set()
    oldpins={}

    def add(kind,ref,limit):
        _pin(ref,kind)
        need(kind not in {x['kind'] for x in originals},
             'DUPLICATED_SOURCE_ORIGINAL_ROLE','permission_denied')
        need(ref['sha256'] not in known,'SOURCE_ORIGINAL_SHA_REUSED_ACROSS_ROLES',
             'permission_denied')
        raw=parent._old(ref,'EC368_SOURCE_'+kind,limit,oldpins)
        need(len(raw)<=MAX_COPIED_ORIGINAL,'SOURCE_ORIGINAL_TOO_LARGE')
        known.add(ref['sha256'])
        originals.append({'kind':kind,'sha256':ref['sha256'],
                          'length':len(raw),'raw':raw,'path':ref['path']})
        return raw

    root_ref={'path':inputs['root_provenance_bundle_file'],
              'sha256':inputs['expected_root_provenance_bundle_sha256']}
    root=tr.strict_json(add('ec366_root_bundle',root_ref,parent.parent.MAX_BUNDLE),
                        'EC368_REOPEN_EC366_ROOT')
    exact(root,parent.parent.BUNDLE_FIELDS,'EC366_ROOT')
    need(root['schema']==parent.parent.BUNDLE_SCHEMA and
         type(root['institutions']) is list and len(root['institutions'])==2,
         'INHERITED_EC366_STATUS_ROOT_NOT_PRESENT','permission_denied')
    for i,role in enumerate(parent.SOURCES):
        inst=root['institutions'][i]
        exact(inst,parent.parent.INSTITUTION_FIELDS,'INHERITED_INSTITUTION')
        need(inst['claimed_institution_role']==role,
             'INHERITED_INSTITUTION_ORDER_INVALID','permission_denied')
        add('institution_key_'+role,
            {'path':inputs['institution_root_public_key_files'][i],
             'sha256':inputs['institution_root_public_key_shas'][i]},32)
        for j,ref in enumerate(inst['signed_status_events']):
            add('institution_status_'+role+'_'+str(j),ref,parent.parent.MAX_STATUS)
        for j,ref in enumerate(inst['signed_provenance_attestations']):
            add('institution_provenance_'+role+'_'+str(j),ref,
                parent.parent.MAX_ATTEST)
    # EC366 can add independently signed directory checkpoints beyond the
    # two institution histories. They too must survive portable transfer.
    for j,item in enumerate(root['additional_signed_checkpoints']):
        exact(item,parent.parent.EXTRA_CP_FIELDS,'INHERITED_EC366_EXTRA_CHECKPOINT')
        add('ec366_additional_checkpoint_'+str(j),item['original'],
            parent.parent.MAX_ORIGINAL_CP)
    wref={'path':inputs['witness_distribution_bundle_file'],
          'sha256':inputs['expected_witness_distribution_bundle_sha256']}
    witness=tr.strict_json(add('ec367_witness_bundle',wref,parent.MAX_BUNDLE),
                           'EC368_REOPEN_WITNESS_BUNDLE')
    exact(witness,parent.BUNDLE_FIELDS,'INHERITED_WITNESS_BUNDLE')
    need(witness['schema']==parent.BUNDLE_SCHEMA and
         type(witness['distribution_paths']) is list and
         len(witness['distribution_paths'])==2 and
         type(witness['additional_source_status_originals']) is list,
         'INHERITED_DUAL_WITNESS_STRUCTURE_INVALID','permission_denied')
    for i,path in enumerate(parent.PATHS):
        entry=witness['distribution_paths'][i]
        exact(entry,parent.PATH_FIELDS,'INHERITED_WITNESS_PATH')
        need(entry['distribution_path']==path,'INHERITED_WITNESS_PATH_ORDER',
             'permission_denied')
        add('witness_key_'+path,
            {'path':inputs['witness_public_key_files'][i],
             'sha256':inputs['witness_public_key_shas'][i]},32)
        for j,ref in enumerate(entry['signed_witness_observations']):
            add('witness_status_'+path+'_'+str(j),ref,parent.MAX_RECORD)
    for j,item in enumerate(witness['additional_source_status_originals']):
        exact(item,parent.EXTRA_FIELDS,'ADDITIONAL_SOURCE_STATUS_REF')
        add('extra_institution_status_'+item['source_role']+'_'+str(j),
            item['original'],parent.MAX_EXTRA_STATUS)
    need(8<=len(originals)<=MAX_COPIES,'PORTABLE_INVENTORY_BOUNDS')
    return originals,oldpins


def _inventory(originals,parent_sha):
    return {'schema':INVENTORY_SCHEMA,
       'parent_ec367_canonical_result_sha256':parent_sha,
       'items':[{'kind':x['kind'],'source_original_sha256':x['sha256'],
                 'byte_length':x['length']} for x in originals]}


def _review_copies(provided,originals,newpins,oldpaths,categories):
    need(type(provided) is list and len(provided)==len(originals),
         'PORTABLE_COPIES_MUST_COVER_EVERY_SOURCE_ORIGINAL')
    for i,(item,old) in enumerate(zip(provided,originals)):
        exact(item,COPY_FIELDS,'PORTABLE_RECEIVER_COPY')
        need(item['kind']==old['kind'] and
             item['source_original_sha256']==old['sha256'] and
             type(item['byte_length']) is int and
             item['byte_length']==old['length'],
             'PORTABLE_COPY_INVENTORY_ORDER_OR_ORIGINAL_MISMATCH',
             'permission_denied')
        _pin(item['receiver_copy'],'RECEIVER_COPY_REF')
        need(item['receiver_copy']['sha256']==old['sha256'],
             'RECEIVER_COPY_SHA_MUST_EQUAL_ORIGINAL_SHA',
             'permission_denied')
        raw=parent._new(item['receiver_copy'],'EC368_RECEIVER_COPY_'+str(i),
                max(old['length'],1),newpins,oldpaths,categories,
                'ec368_receiver_copy_'+str(i))
        need(raw==old['raw'],
             'RECEIVER_COPY_BYTES_DIFFER_FROM_AUTHENTIC_ORIGINAL',
             'permission_denied')


def _signed(doc,*,sender,receiver,parent_sha,inv_sha,heads,kind,now):
    signature='signature_sender_ed25519_hex' if kind=='sender' else 'signature_receiver_ed25519_hex'
    fields=DISPATCH_FIELDS if kind=='sender' else ACK_FIELDS
    exact(doc,fields,'SIGNED_'+kind.upper())
    need(doc['schema']==(DISPATCH_SCHEMA if kind=='sender' else ACK_SCHEMA) and
         doc['claimed_sender_id']==sender['id'] and
         doc['sender_public_key_original_sha256']==sender['sha'] and
         doc['claimed_receiver_id']==receiver['id'] and
         doc['receiver_public_key_original_sha256']==receiver['sha'],
         'SIGNED_HANDOFF_IDENTITY_MUST_MATCH_INDEPENDENT_PINS',
         'permission_denied')
    n=doc['sequence']
    need(type(n) is int and 0<=n<MAX_HANDOFFS and
         all(x is None or tr._sha(x) for x in (
             doc['previous_sender_dispatch_original_sha256'],
             doc['previous_receiver_ack_original_sha256'])) and
         type(doc['witness_head_original_shas']) is list and
         len(doc['witness_head_original_shas'])==2 and
         all(x is None or tr._sha(x) for x in doc['witness_head_original_shas']),
         'SIGNED_HANDOFF_SEQUENCE_LINK_OR_WITNESS_HEAD_FORMAT_INVALID')
    if kind=='receiver':
        need(tr._sha(doc['sender_dispatch_original_sha256']) and
             doc['receipt_state'] in ('accepted','withheld','disputed'),
             'SIGNED_RECEIPT_STATE_OR_DISPATCH_SHA_INVALID')
    public=sender['public'] if kind=='sender' else receiver['public']
    authority.sig(doc,signature,public,
        DISPATCH_DOMAIN if kind=='sender' else ACK_DOMAIN,
        'EC368_TRUE_'+kind.upper()+'_SIGNATURE')
    issued=doc['issued_utc'] if kind=='sender' else doc['received_utc']
    first,last=authority.window(issued,doc['expires_utc'],MAX_WINDOW,
                                'EC368_'+kind.upper()+'_CLAIMED_WINDOW')
    return {'claim_time':first,
            'time_anomaly':authority.utc_untrusted(now,first,last,MAX_WINDOW),
            'bound':doc['parent_ec367_canonical_result_sha256']==parent_sha and
               doc['portable_inventory_canonical_sha256']==inv_sha and
               doc['witness_head_original_shas']==heads}


def _lineage(pairs,sender_shas,receiver_shas,flags):
    """Keep all genuine signed forks; no convenient branch selection."""
    ss=defaultdict(set);aa=defaultdict(set)
    sd={p['dispatch_sha']:p for p in pairs}
    ar={p['ack_sha']:p for p in pairs}
    sequence={}
    for index,p in enumerate(pairs):
        d,a=p['dispatch'],p['ack'];n=d['sequence'];m=a['sequence']
        # The bundle and the caller-retained original SHA streams are
        # canonical chronological lists; reordering authentic entries must
        # not redefine which epoch appears to be latest.
        if n!=index or m!=index:flags[FLAGS[4]]=True
        ss[n].add(p['dispatch_sha']);aa[m].add(p['ack_sha'])
        if n!=m or n in sequence:
            flags[FLAGS[4]]=True
        else:sequence[n]=p
        if (a['sender_dispatch_original_sha256']!=p['dispatch_sha'] or
            a['previous_sender_dispatch_original_sha256']!=
                 d['previous_sender_dispatch_original_sha256'] or
            a['previous_receiver_ack_original_sha256']!=
                 d['previous_receiver_ack_original_sha256']):
            flags[FLAGS[4]]=True
        if n==0:
            if (d['previous_sender_dispatch_original_sha256'] is not None or
                d['previous_receiver_ack_original_sha256'] is not None):
                flags[FLAGS[4]]=True
        else:
            prev_s=d['previous_sender_dispatch_original_sha256']
            prev_a=d['previous_receiver_ack_original_sha256']
            if (prev_s not in sd or prev_a not in ar or
                sd[prev_s]['dispatch']['sequence']!=n-1 or
                ar[prev_a]['ack']['sequence']!=n-1 or
                sd[prev_s]['ack_sha']!=prev_a):
                flags[FLAGS[4]]=True
        if a['receipt_state']!='accepted':flags[FLAGS[7]]=True
    if (any(len(v)>1 for v in ss.values()) or
        any(len(v)>1 for v in aa.values()) or
        set(sequence)!=set(range(max(sequence,default=-1)+1)) or
        len(sequence)!=len(pairs)):
        flags[FLAGS[4]]=True
    # A genuine signed sequence-0 fork or incomplete link must not be
    # presented as the selected newest head, even if the caller pins one.
    if flags[FLAGS[4]] or not sequence:return None
    return sequence[max(sequence)]


def checklist(**inputs):
    parent_result=parent.audit(**inputs)
    need(parent_result['schema']==parent.RESULT_SCHEMA and
         parent_result['exit_code']==2 and
         parent_result['actual_ec366_through_ec337_signed_originals_replayed'] is True,
         'GENUINE_EC367_THROUGH_EC337_PARENT_REPLAY_REQUIRED',
         'permission_denied')
    psha=sha(canonical.canonical(parent_result))
    originals,oldpins=_origins(inputs)
    tsa._check_late(oldpins)
    return {'schema':HANDOFF_SCHEMA,'command':'derive-portable-receiver-handoff',
      'status':'receiver_retained_copies_and_independent_dual_signatures_required_unresolved',
      'exit_code':2,'case_id':parent_result['case_id'],
      'actual_ec367_through_ec337_signed_originals_replayed':True,
      'parent_ec367_canonical_result_sha256':psha,
      'expected_portable_inventory_sha256':sha(canonical.canonical(_inventory(originals,psha))),
      'required_exact_original_inventory':_inventory(originals,psha)['items'],
      'read_only_original_file_refs_for_copying':[
          {'kind':x['kind'],'path':x['path'],'sha256':x['sha256']}
          for x in originals],
      'expected_witness_head_original_shas':[x['actual_witness_head_sha256'] for x in
                                  parent_result['two_witness_distribution_reviews']],
      'receiver_signed_and_physical_custody_not_proven':True,
      'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,portable_receiver_evaluation_utc,**inputs):
    now=tr._utc(portable_receiver_evaluation_utc)
    _new_inputs(inputs)
    old=_parent_inputs(inputs)
    need(now>=tr._utc(old['witness_distribution_evaluation_utc']),
         'RECEIVER_EVALUATION_PRECEDES_EC367_PUBLISHER_EVALUATION',
         'permission_denied')
    # Crucially, no supplied EC367 report can skip this live parent replay.
    prior=parent.audit(**old)
    need(prior['schema']==parent.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec366_through_ec337_signed_originals_replayed'] is True,
         'REAL_EC367_THROUGH_EC337_PARENT_REPLAY_REQUIRED',
         'permission_denied')
    psha=sha(canonical.canonical(prior))
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not prior['locally_two_independently_retained_paths_correlate_on_verified_source_heads']
    flags[FLAGS[8]]=any(x['terminal_original_shas'] for x in
                       prior['true_source_signed_terminal_status_original_shas'])
    originals,oldpins=_origins(old)
    inv=_inventory(originals,psha)
    inv_sha=sha(canonical.canonical(inv))
    if inv_sha!=inputs['expected_portable_inventory_sha256']:
        flags[FLAGS[2]]=True
    heads=[r['actual_witness_head_sha256'] for r in prior['two_witness_distribution_reviews']]
    need(all(v is None or tr._sha(v) for v in heads),
         'EC367_WITNESS_HEAD_RETURN_FORMAT_INVALID',
         'permission_denied')
    oldpaths={v for x in originals for v in [x['path']]}
    for k,v in old.items():
        if k.endswith('_file') and type(v) is str:oldpaths.add(v)
        if k.endswith('_files') and type(v) is list:
            oldpaths.update(x for x in v if type(x) is str)
    newpins={};categories={}
    bundle_ref={'path':inputs['portable_receiver_bundle_file'],
          'sha256':inputs['expected_portable_receiver_bundle_sha256']}
    bundle_raw=parent._new(bundle_ref,'EC368_RECEIVER_BUNDLE',MAX_BUNDLE,
             newpins,oldpaths,categories,'ec368_receiver_bundle')
    b=tr.strict_json(bundle_raw,'EC368_PORTABLE_RECEIVER_BUNDLE')
    exact(b,BUNDLE_FIELDS,'PORTABLE_RECEIVER_BUNDLE')
    need(b['schema']==BUNDLE_SCHEMA,'PORTABLE_RECEIVER_BUNDLE_SCHEMA')
    if b['parent_ec367_canonical_result_sha256']!=psha:
        flags[FLAGS[5]]=True
    _review_copies(b['portable_inventory'],originals,newpins,oldpaths,categories)
    keyrefs=(('sender',inputs['sender_public_key_file'],
                inputs['expected_sender_public_key_sha256'],inputs['claimed_sender_id']),
             ('receiver',inputs['receiver_public_key_file'],
                inputs['expected_receiver_public_key_sha256'],inputs['claimed_receiver_id']))
    keys=[]
    for role,path,digest,claimed in keyrefs:
        raw=parent._new({'path':path,'sha256':digest},'EC368_'+role.upper()+'_KEY',32,
                        newpins,oldpaths,categories,'ec368_'+role+'_key')
        need(len(raw)==32,'SIGNING_PUBLIC_KEY_MUST_BE_RAW_32_BYTES',
             'permission_denied')
        keys.append({'id':claimed,'sha':digest,'public':raw})
    sender,receiver=keys
    forbidden={v for x in originals for v in [x['sha256']]}
    for k,v in old.items():
        if 'public_key' in k or 'signer_key' in k or 'root_key' in k:
            if tr._sha(v):forbidden.add(v)
            if type(v) is list:forbidden.update(x for x in v if tr._sha(x))
    if (sender['sha'] in forbidden or receiver['sha'] in forbidden or
        sender['id'] in old['institution_claimed_ids']+old['witness_claimed_ids'] or
        receiver['id'] in old['institution_claimed_ids']+old['witness_claimed_ids']):
        flags[FLAGS[1]]=True
    handoffs=b['handoffs']
    need(type(handoffs) is list and 1<=len(handoffs)<=MAX_HANDOFFS,
         'RECEIVER_HANDOFFS_BOUNDED_NONEMPTY_REQUIRED')
    rows=[]
    for i,item in enumerate(handoffs):
        exact(item,HANDOFF_FIELDS,'DUAL_SIGNED_HANDOFF_PAIR')
        pair={}
        for kind,field in (('sender','sender_dispatch_original'),
                           ('receiver','receiver_ack_original')):
            ref=item[field]
            _pin(ref,field)
            raw=parent._new(ref,'EC368_'+kind.upper()+'_SIGNED_HANDOFF_'+str(i),
                  MAX_SIGNED,newpins,oldpaths,categories,
                  'ec368_'+kind+'_signed_original_'+str(i))
            doc=tr.strict_json(raw,'EC368_'+kind.upper()+'_SIGNED_HANDOFF')
            reviewed=_signed(doc,sender=sender,receiver=receiver,parent_sha=psha,
                            inv_sha=inv_sha,heads=heads,kind=kind,now=now)
            pair['dispatch' if kind=='sender' else 'ack']=doc
            pair['dispatch_sha' if kind=='sender' else 'ack_sha']=ref['sha256']
            pair[kind+'_review']=reviewed
            if not reviewed['bound']:flags[FLAGS[5]]=True
            if reviewed['time_anomaly']:flags[FLAGS[9]]=True
        if pair['sender_review']['claim_time']>pair['receiver_review']['claim_time']:
            flags[FLAGS[9]]=True
        rows.append(pair)
    actual_sender=[p['dispatch_sha'] for p in rows]
    actual_receiver=[p['ack_sha'] for p in rows]
    if (actual_sender!=inputs['signed_sender_dispatch_shas'] or
        actual_receiver!=inputs['signed_receiver_ack_shas']):
        flags[FLAGS[2]]=True
    head=_lineage(rows,actual_sender,actual_receiver,flags)
    if (head is None or
        head['dispatch_sha']!=inputs['expected_retained_sender_dispatch_head_sha256'] or
        head['ack_sha']!=inputs['expected_retained_receiver_ack_head_sha256'] or
        head['dispatch']['sequence']<inputs['minimum_retained_sender_dispatch_sequence'] or
        head['ack']['sequence']<inputs['minimum_retained_receiver_ack_sequence']):
        flags[FLAGS[6]]=True
    if head is None or head['ack']['receipt_state']!='accepted':
        flags[FLAGS[10]]=True
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    parent.parent.parent.parent.history.parent.previous.parent.parent._late_identity_check(
       newpins,oldpaths)
    locally=head is not None and not any(flags.values())
    winner=next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])
    return {'schema':RESULT_SCHEMA,'command':'audit-portable-receiver',
       'status':winner+'_unresolved','exit_code':2,
       'case_id':prior['case_id'],
       'actual_ec367_through_ec337_signed_originals_replayed':True,
       'parent_ec367_canonical_result_sha256':psha,
       'parent_ec367_locally_two_witness_paths_current':prior[
         'locally_two_independently_retained_paths_correlate_on_verified_source_heads'],
       'portable_receiver_evaluation_utc_as_caller_claim':portable_receiver_evaluation_utc,
       'portable_receiver_bundle_original_sha256':bundle_ref['sha256'],
       'actual_portable_inventory_sha256':inv_sha,
       'expected_portable_inventory_sha256_as_caller_pin':inputs['expected_portable_inventory_sha256'],
       'byte_identical_original_copy_count':len(originals),
       'actual_sender_ed25519_dispatch_signature_count':len(rows),
       'actual_receiver_ed25519_ack_signature_count':len(rows),
       'actual_sender_dispatch_sha_stream':actual_sender,
       'actual_receiver_ack_sha_stream':actual_receiver,
       'actual_sender_dispatch_head_sha256':head['dispatch_sha'] if head else None,
       'actual_receiver_ack_head_sha256':head['ack_sha'] if head else None,
       'actual_latest_handoff_sequence':head['dispatch']['sequence'] if head else None,
       'latest_receiver_receipt_state':head['ack']['receipt_state'] if head else None,
       'two_witness_head_original_shas_from_replayed_ec367':heads,
       'verified_source_terminal_original_shas_preserved':[
         x['terminal_original_shas'] for x in prior['true_source_signed_terminal_status_original_shas']],
       **flags,
       'locally_receiver_held_complete_portable_inventory_acknowledged':bool(locally),
       'official_receiver_identity_actual_physical_custody_trusted_utc_global_completeness_unproven':True,
       'offline_unresolved_exit_code':2,
       **{k:False for k in NEGATIVES}}
