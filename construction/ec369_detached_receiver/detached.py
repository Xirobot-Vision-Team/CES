#!/usr/bin/env python3
"""EC369: receive-side verification when ALL original sender paths are gone.

Only EC366/EC367 source-status, attestation and witness original signatures,
EC368 dual handoffs, and newly signed map/disclosure challenges can be checked
from the received copies. EC365..EC337, directory signed checkpoints, official
identities, custody, complete global histories and trusted time CANNOT be
reconstructed from this bounded inventory. Those are never reported as proven.
No private signing, source-path reads, network or writes.
"""
from __future__ import annotations

import os
from collections import defaultdict
from datetime import timedelta

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec360_authority_directory import authority
from ec364_cross_epoch import continuity as historic
from ec366_root_provenance import provenance as source
from ec367_witness_distribution import distribution as witness
from ec368_portable_receiver import portable as previous

RESULT_SCHEMA='ces.ec369.detached_receiver_signed_original_replay_unresolved.v1'
DENIAL_SCHEMA='ces.ec369.detached_receiver_signed_original_replay_denial.v1'
BUNDLE_SCHEMA='ces.ec369.detached_receiver_bundle.v1'
MAP_SCHEMA='ces.ec369.sender_signed_source_to_receiver_copy_map.v1'
CHALLENGE_SCHEMA='ces.ec369.receiver_signed_detached_disclosure_challenge.v1'
ANSWER_SCHEMA='ces.ec369.sender_signed_detached_disclosure_answer.v1'
MAP_DOMAIN=b'CES/EC369/DetachedSourceCopyMap/v1\x00'
CHALLENGE_DOMAIN=b'CES/EC369/DetachedReceiverChallenge/v1\x00'
ANSWER_DOMAIN=b'CES/EC369/DetachedSenderAnswer/v1\x00'
MAX_BUNDLE=16000
MAX_MAP=26000
MAX_SIGNED=7000
MAX_COPIES=previous.MAX_COPIES
MAX_HANDOFFS=previous.MAX_HANDOFFS
MAX_WINDOW=timedelta(days=7)
BUNDLE_FIELDS={'schema','signed_copy_map_original','handoffs','disclosure_challenges'}
MAP_FIELDS={'schema','claimed_sender_id','sender_public_key_original_sha256',
 'claimed_receiver_id','receiver_public_key_original_sha256',
 'parent_ec367_canonical_result_sha256','parent_ec366_canonical_result_sha256',
 'parent_ec365_canonical_result_sha256','portable_inventory_canonical_sha256',
 'witness_head_original_shas','institution_root_public_key_original_shas',
 'witness_public_key_original_shas','institution_claimed_ids','witness_claimed_ids',
 'originals','issued_utc','expires_utc','signature_sender_ed25519_hex'}
MAP_ROW_FIELDS={'kind','source_original','byte_length','receiver_copy'}
CHALLENGE_FIELDS={'schema','claimed_sender_id','sender_public_key_original_sha256',
 'claimed_receiver_id','receiver_public_key_original_sha256','sequence',
 'previous_challenge_original_sha256','previous_answer_original_sha256',
 'signed_copy_map_original_sha256','portable_inventory_canonical_sha256',
 'parent_ec367_canonical_result_sha256','receiver_nonce_sha256',
 'challenged_source_original_shas','issued_utc','expires_utc',
 'signature_receiver_ed25519_hex'}
ANSWER_FIELDS={'schema','claimed_sender_id','sender_public_key_original_sha256',
 'claimed_receiver_id','receiver_public_key_original_sha256','sequence',
 'previous_challenge_original_sha256','previous_answer_original_sha256',
 'signed_copy_map_original_sha256','portable_inventory_canonical_sha256',
 'parent_ec367_canonical_result_sha256','receiver_nonce_sha256',
 'receiver_challenge_original_sha256','disclosure_state',
 'disclosed_source_original_shas','answered_utc','expires_utc',
 'signature_sender_ed25519_hex'}
FLAGS=(
 'independently_retained_parent_inventory_or_witness_head_mismatch',
 'detached_source_signed_status_chain_fork_or_gap_visible',
 'detached_true_source_signed_terminal_or_provenance_dispute_visible',
 'detached_witness_signed_chain_fork_withholding_or_gap_visible',
 'detached_witness_claim_mismatches_copied_source_signed_status_or_attestation',
 'independently_retained_source_or_witness_head_rollback_visible',
 'signed_map_signer_source_witness_role_collision_visible',
 'sender_receiver_signed_handoff_conflict_or_withholding_visible',
 'independently_retained_handoff_sha_stream_head_or_floor_mismatch',
 'receiver_challenge_sender_disclosure_fork_gap_or_withholding_visible',
 'independently_retained_challenge_answer_stream_head_nonce_or_floor_mismatch',
 'untrusted_or_out_of_order_claimed_utc_visible',
 'fully_bound_accepted_and_disclosed_local_detached_chain_not_demonstrated',
)
OUTCOMES=(
 'ec369_external_parent_inventory_or_witness_head_conflict',
 'ec369_authentic_source_status_history_fork_or_gap',
 'ec369_authentic_source_terminal_or_provenance_dispute',
 'ec369_authentic_witness_history_or_withholding',
 'ec369_witness_source_signed_observation_mismatch',
 'ec369_external_source_or_witness_head_rollback',
 'ec369_sender_receiver_reused_source_or_witness_key',
 'ec369_authentic_sender_receiver_handoff_conflict',
 'ec369_external_sender_receiver_stream_or_head_rollback',
 'ec369_authentic_disclosure_challenge_gap_fork_or_withholding',
 'ec369_external_disclosure_nonce_or_head_rollback',
 'ec369_self_claimed_time_not_trusted',
 'ec369_complete_local_detached_disclosure_not_established',
 'ec369_local_detached_copied_crypto_consistent_but_historical_parent_unreplayable',
)
NEGATIVES=(
 'ec365_through_ec337_full_historical_signed_parent_replayed',
 'detached_copy_map_authenticates_official_legal_institution_or_sender_identity',
 'detached_signed_challenge_establishes_real_world_freshness_or_physical_custody',
 'presented_signed_status_or_witness_heads_exclude_hidden_forks',
 'detached_receipt_repairs_known_root_revocation_or_fork',
 'copied_directory_checkpoint_original_without_directory_key_verifies_signature',
 'claimed_utc_establishes_trusted_time_or_globally_latest_status',
 'auditor_accesses_missing_original_source_paths_or_remote_provider_cas_worm',
 'private_signer_network_or_native_powershell_modified',
 'ec317_ec318_mock_replacement_or_final_user_acceptance_proven',
)
SCALARS=('detached_evaluation_utc','detached_bundle_file',
 'expected_detached_bundle_sha256','expected_signed_copy_map_sha256',
 'expected_portable_inventory_sha256','expected_parent_ec367_canonical_result_sha256',
 'expected_parent_ec366_canonical_result_sha256',
 'expected_parent_ec365_canonical_result_sha256',
 'sender_public_key_file','expected_sender_public_key_sha256','claimed_sender_id',
 'receiver_public_key_file','expected_receiver_public_key_sha256','claimed_receiver_id',
 'expected_retained_sender_dispatch_head_sha256',
 'expected_retained_receiver_ack_head_sha256',
 'minimum_retained_sender_dispatch_sequence',
 'minimum_retained_receiver_ack_sequence',
 'expected_retained_challenge_head_sha256',
 'expected_retained_answer_head_sha256',
 'expected_retained_challenge_nonce_sha256',
 'minimum_retained_challenge_sequence')
REPEATS=(('institution_root_public_key_shas','--institution-root-public-key-sha256'),
 ('witness_public_key_shas','--witness-public-key-sha256'),
 ('institution_claimed_ids','--institution-claimed-id'),
 ('witness_claimed_ids','--witness-claimed-id'),
 ('expected_source_status_head_shas','--expected-source-status-head-sha256'),
 ('expected_source_attestation_head_shas','--expected-source-attestation-head-sha256'),
 ('expected_witness_head_shas','--expected-witness-head-sha256'),
 ('signed_sender_dispatch_shas','--signed-sender-dispatch-sha256'),
 ('signed_receiver_ack_shas','--signed-receiver-ack-sha256'),
 ('signed_challenge_shas','--signed-challenge-sha256'),
 ('signed_answer_shas','--signed-answer-sha256'))
REPEAT_NAMES=tuple(k for k,_ in REPEATS)


def need(ok,code,status='invalid_input'):
    if ok is not True:raise errors.AnchorError('EC369_'+code,status)


def exact(doc,fields,role):
    need(type(doc) is dict and set(doc)==set(fields),role+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return witness.sha(raw)


def _refs(*refs):
    for ref in refs:historic.ref_check(ref,'EC369_PINNED_FILE_REFERENCE')


def _inputs(opts):
    need(set(opts)==set(SCALARS)|set(REPEAT_NAMES),'COMPLETE_EXACT_INPUTS_REQUIRED')
    tr._utc(opts['detached_evaluation_utc'])
    for stem in ('detached_bundle','sender_public_key','receiver_public_key'):
        authority.outer_pin(opts[stem+'_file'],opts['expected_'+stem+'_sha256'],
                            'EC369_'+stem.upper())
        need(opts[stem+'_file'] is not None and
             opts['expected_'+stem+'_sha256'] is not None,
             'ABSOLUTE_EXTERNAL_FILE_SHA_PIN_REQUIRED')
    for key in SCALARS:
        if key.endswith('_sha256'):
            need(tr._sha(opts[key]),key.upper()+'_REQUIRED')
        if key.startswith('minimum_'):
            need(type(opts[key]) is int and 0<=opts[key]<MAX_HANDOFFS,
                 key.upper()+'_BOUNDED_FLOOR_REQUIRED')
    for key in ('claimed_sender_id','claimed_receiver_id'):
        need(tr._ident(opts[key]),'STRICT_'+key.upper()+'_REQUIRED')
    for key in ('institution_root_public_key_shas','witness_public_key_shas',
                'expected_source_status_head_shas','expected_source_attestation_head_shas',
                'expected_witness_head_shas'):
        arr=opts[key]
        allow_none=key=='expected_source_attestation_head_shas'
        need(type(arr) is list and len(arr)==2 and all(
            (x is None and allow_none) or tr._sha(x) for x in arr),
            key.upper()+'_EXACT_TWO_EXTERNAL_PINS_REQUIRED')
        if 'public_key' in key:need(len(set(arr))==2,'TWO_DISTINCT_ROLE_ROOTS_REQUIRED')
    for key in ('institution_claimed_ids','witness_claimed_ids'):
        arr=opts[key]
        need(type(arr) is list and len(arr)==2 and
             all(tr._ident(x) for x in arr) and len(set(arr))==2,
             key.upper()+'_TWO_STRICT_IDENTITIES_REQUIRED')
    for key in ('signed_sender_dispatch_shas','signed_receiver_ack_shas',
                'signed_challenge_shas','signed_answer_shas'):
        arr=opts[key]
        need(type(arr) is list and 1<=len(arr)<=MAX_HANDOFFS and
             all(tr._sha(x) for x in arr) and len(set(arr))==len(arr),
             key.upper()+'_BOUNDED_ORIGINAL_SHA_STREAM_REQUIRED')
    need(len(opts['signed_sender_dispatch_shas'])==len(opts['signed_receiver_ack_shas'])
         and len(opts['signed_challenge_shas'])==len(opts['signed_answer_shas']),
         'MATCHED_HANDOFF_AND_DISCLOSURE_STREAM_COUNTS_REQUIRED')
    need(opts['claimed_sender_id']!=opts['claimed_receiver_id'] and
         opts['expected_sender_public_key_sha256']!=opts['expected_receiver_public_key_sha256'] and
         set(opts['institution_claimed_ids']).isdisjoint(opts['witness_claimed_ids']),
         'ROLE_INDEPENDENCE_REQUIRED','permission_denied')


def _metadata_ref(ref):
    _refs(ref)
    path=ref['path']
    # This path is *data only*. It must be a well-formed absolute provenance
    # label, and it is NEVER handed to a filesystem reader or stat syscall.
    need(type(path) is str and len(path)<=4000 and os.path.isabs(path) and
         os.path.normpath(path)==path and not path.startswith('//') and
         '\\' not in path and '\x00' not in path,
         'SIGNED_MAP_SOURCE_LABEL_MUST_BE_NORMALIZED_ABSOLUTE')


def _expected_items(root,wit,mapdoc):
    """Derive every EC368 role from copied nested manifests, not map selection.

    Source reference paths inside nested EC366/EC367 JSON are ONLY compared
    as string labels. No source-origin file is ever opened here.
    """
    need(root['schema']==source.BUNDLE_SCHEMA and wit['schema']==witness.BUNDLE_SCHEMA,
         'COPIED_EC366_EC367_SCHEMA_INVALID')
    exact(root,source.BUNDLE_FIELDS,'COPIED_EC366_ROOT')
    exact(wit,witness.BUNDLE_FIELDS,'COPIED_EC367_WITNESS')
    need(type(root['institutions']) is list and len(root['institutions'])==2 and
         type(root['additional_signed_checkpoints']) is list and
         len(root['additional_signed_checkpoints'])<=source.MAX_EXTRA_CP and
         type(wit['distribution_paths']) is list and len(wit['distribution_paths'])==2 and
         type(wit['additional_source_status_originals']) is list and
         len(wit['additional_source_status_originals'])<=4,
         'BOUNDED_TWO_SOURCE_TWO_WITNESS_MANIFESTS_REQUIRED')
    expected=[]
    def add(kind,ref=None,key_sha=None):
        if key_sha is None:_metadata_ref(ref)
        digest=key_sha if key_sha is not None else ref['sha256']
        need(tr._sha(digest) and digest not in {x['sha'] for x in expected},
             'DUPLICATE_OR_INVALID_SOURCE_ORIGINAL_SHA','permission_denied')
        expected.append({'kind':kind,'sha':digest,'source_ref':ref})
    add('ec366_root_bundle',key_sha=mapdoc['originals'][0]['source_original']['sha256'])
    for i,role in enumerate(source.ROLES):
        item=root['institutions'][i]
        exact(item,source.INSTITUTION_FIELDS,'COPIED_EC366_INSTITUTION')
        need(item['claimed_institution_role']==role and
             item['claimed_institution_id']==mapdoc['institution_claimed_ids'][i] and
             item['institution_public_key_original_sha256']==
                   mapdoc['institution_root_public_key_original_shas'][i],
             'COPIED_SOURCE_ROLE_KEY_OR_ID_MISMATCH','permission_denied')
        add('institution_key_'+role,key_sha=item['institution_public_key_original_sha256'])
        for field,label,cap in (('signed_status_events','institution_status_',source.MAX_EVENTS_PER_ROLE),
                                ('signed_provenance_attestations','institution_provenance_',source.MAX_EVENTS_PER_ROLE)):
            need(type(item[field]) is list and len(item[field])<=cap,
                 'COPIED_INSTITUTION_ORIGINAL_COUNT_OUT_OF_BOUNDS')
            for j,ref in enumerate(item[field]):add(label+role+'_'+str(j),ref)
    for j,row in enumerate(root['additional_signed_checkpoints']):
        exact(row,source.EXTRA_CP_FIELDS,'COPIED_EC366_EXTRA_CHECKPOINT')
        need(type(row['signer_epoch_index']) is int and 0<=row['signer_epoch_index']<=3,
             'COPIED_CHECKPOINT_EPOCH_INDEX_INVALID')
        add('ec366_additional_checkpoint_'+str(j),row['original'])
    add('ec367_witness_bundle',key_sha=mapdoc['originals'][len(expected)]['source_original']['sha256'])
    for i,path in enumerate(witness.PATHS):
        row=wit['distribution_paths'][i]
        exact(row,witness.PATH_FIELDS,'COPIED_EC367_WITNESS_PATH')
        need(row['distribution_path']==path and
             row['claimed_witness_id']==mapdoc['witness_claimed_ids'][i] and
             row['witness_public_key_original_sha256']==
                   mapdoc['witness_public_key_original_shas'][i],
             'COPIED_WITNESS_ROLE_KEY_OR_ID_MISMATCH','permission_denied')
        add('witness_key_'+path,key_sha=row['witness_public_key_original_sha256'])
        need(type(row['signed_witness_observations']) is list and
             1<=len(row['signed_witness_observations'])<=witness.MAX_RECORDS_PER_PATH,
             'COPIED_WITNESS_SIGNED_EPOCHS_OUT_OF_BOUNDS')
        for j,ref in enumerate(row['signed_witness_observations']):
            add('witness_status_'+path+'_'+str(j),ref)
    source_extra_counts=defaultdict(int)
    for j,row in enumerate(wit['additional_source_status_originals']):
        exact(row,witness.EXTRA_FIELDS,'COPIED_EXTRA_SOURCE_STATUS')
        need(row['source_role'] in source.ROLES,
             'COPIED_EXTRA_STATUS_ROLE_UNKNOWN')
        source_extra_counts[row['source_role']]+=1
        need(source_extra_counts[row['source_role']]<=witness.MAX_ADDITIONAL_STATUS_PER_SOURCE,
             'COPIED_EXTRA_SOURCE_STATUS_PER_ROLE_BUDGET_EXCEEDED')
        add('extra_institution_status_'+row['source_role']+'_'+str(j),row['original'])
    need(8<=len(expected)<=MAX_COPIES,'COPIED_SOURCE_COUNT_OUT_OF_BOUNDS')
    return expected


def _replay_copied_source_and_witness(contents,mapdoc,opts,now,flags):
    """True Ed25519 replay of every included EC366/EC367 signed original.

    No claim about the EC365 directory originals or checkpoint signatures.
    """
    root=tr.strict_json(contents['ec366_root_bundle'],'EC369_COPIED_ROOT_BUNDLE')
    wit=tr.strict_json(contents['ec367_witness_bundle'],'EC369_COPIED_WITNESS_BUNDLE')
    status_count=attest_count=witness_count=0
    source_rows=[];terminal=[];actual_status_heads=[];actual_attest_heads=[]
    wflags={k:False for k in witness.FLAGS}
    for i,role in enumerate(source.ROLES):
        inst=root['institutions'][i];key=contents['institution_key_'+role]
        need(len(key)==32,'INSTITUTION_PUBLIC_KEY_MUST_BE_32_BYTES','permission_denied')
        documents={};base=[];att=[]
        for j,ref in enumerate(inst['signed_status_events']):
            h=ref['sha256'];doc=tr.strict_json(contents['institution_status_'+role+'_'+str(j)],
                                              'EC369_COPIED_SIGNED_SOURCE_STATUS')
            source._check_status_shape(doc)
            need(doc['claimed_institution_role']==role and
                 doc['claimed_institution_id']==inst['claimed_institution_id'] and
                 doc['institution_public_key_original_sha256']==sha(key),
                 'COPIED_SOURCE_STATUS_SIGNER_OR_ROLE_MISMATCH','permission_denied')
            authority.sig(doc,'signature_institution_ed25519_hex',key,source.STATUS_DOMAIN,
                          'EC369_COPIED_SOURCE_STATUS')
            status_count+=1
            if (doc['parent_ec365_canonical_result_sha256']!=
                    mapdoc['parent_ec365_canonical_result_sha256']):
                flags[FLAGS[0]]=True
            if authority.utc_untrusted(now,*authority.window(doc['issued_utc'],
                         doc['expires_utc'],source.MAX_SPAN,'EC369_STATUS_CLOCK'),source.MAX_SPAN):
                flags[FLAGS[11]]=True
            if doc['sequence']!=j:flags[FLAGS[1]]=True
            base.append((h,doc));documents[h]=doc
        if not base:flags[FLAGS[1]]=True
        for j,ref in enumerate(inst['signed_provenance_attestations']):
            h=ref['sha256'];doc=tr.strict_json(contents['institution_provenance_'+role+'_'+str(j)],
                                              'EC369_COPIED_SIGNED_ATTESTATION')
            source._check_attestation_shape(doc,3)
            need(doc['claimed_institution_id']==inst['claimed_institution_id'] and
                 doc['claimed_institution_role']==role and
                 doc['institution_public_key_original_sha256']==sha(key),
                 'COPIED_SOURCE_ATTESTATION_SIGNER_OR_ROLE_MISMATCH','permission_denied')
            authority.sig(doc,'signature_institution_ed25519_hex',key,source.ATTEST_DOMAIN,
                          'EC369_COPIED_SOURCE_ATTESTATION')
            attest_count+=1
            if (doc['parent_ec365_canonical_result_sha256']!=mapdoc[
                    'parent_ec365_canonical_result_sha256'] or
                doc['institution_status_original_sha256'] not in documents or
                doc['directory_lineage_id']!=root['claimed_directory_lineage_id']):
                flags[FLAGS[4]]=True
            if doc['attestation_kind'] in ('dispute','withdraw'):flags[FLAGS[2]]=True
            if authority.utc_untrusted(now,*authority.window(doc['issued_utc'],
                         doc['expires_utc'],source.MAX_SPAN,'EC369_ATTEST_CLOCK'),source.MAX_SPAN):
                flags[FLAGS[11]]=True
            if doc['sequence']!=j+1:flags[FLAGS[1]]=True
            att.append((h,doc))
        def chain(rows,prevfield,first_sequence,flag_index):
            graph={h:d for h,d in rows};byseq=defaultdict(set);links=defaultdict(set)
            for h,d in rows:
                n=d['sequence'];prev=d[prevfield]
                byseq[n].add(h);links[prev].add(h)
                if (n==first_sequence and prev is not None) or (n>first_sequence and
                      (prev not in graph or graph[prev]['sequence']!=n-1)):
                    flags[FLAGS[flag_index]]=True
            if any(len(v)>1 for v in byseq.values()) or any(len(v)>1 for v in links.values()):
                flags[FLAGS[flag_index]]=True
            if set(byseq)!=set(range(first_sequence,first_sequence+len(byseq))):
                flags[FLAGS[flag_index]]=True
            if not rows or flags[FLAGS[flag_index]]:return None
            return max(rows,key=lambda item:item[1]['sequence'])[0]
        h=chain(base,'previous_status_original_sha256',0,1)
        ah=chain(att,'previous_attestation_original_sha256',1,1) if att else None
        actual_status_heads.append(h);actual_attest_heads.append(ah)
        if ah is not None and (dict(att)[ah]['institution_status_original_sha256']!=h or
                               dict(att)[ah]['attestation_kind']!='corroborate'):
            flags[FLAGS[4]]=True
        # Do NOT compare the root-only status head against the external latest
        # head yet: EC367 may carry additional genuinely source-signed statuses.
        if ah!=opts['expected_source_attestation_head_shas'][i]:
            flags[FLAGS[5]]=True
        for hsh,doc in base:
            if doc['action'] in ('revoke','rotate'):
                flags[FLAGS[2]]=True;terminal.append(hsh)
            if doc['sequence']==0 and doc['action']!='activate':flags[FLAGS[1]]=True
            if doc['action']=='rotate' and doc['successor_public_key_original_sha256']==sha(key):
                flags[FLAGS[6]]=True
        src={'role':role,'id':inst['claimed_institution_id'],
             'root_sha':sha(key),'public':key,'statuses':documents,
             'attestations':{h:d for h,d in att},'head':h,'att_head':ah}
        source_rows.append(src)
    # Extra, genuine institution-signed status events are *never* dropped.
    for j,row in enumerate(wit['additional_source_status_originals']):
        role=row['source_role'];src=source_rows[source.ROLES.index(role)]
        digest=row['original']['sha256']
        doc=witness._status_document(contents['extra_institution_status_'+role+'_'+str(j)],
                 src['public'],role,'DETACHED_EXTRA',src['root_sha'],src['id'])
        need(digest not in src['statuses'],'DUPLICATE_EXTRA_STATUS_ACROSS_SOURCE',
             'permission_denied')
        src['statuses'][digest]=doc
        status_count+=1
        if doc['parent_ec365_canonical_result_sha256']!=mapdoc[
                'parent_ec365_canonical_result_sha256']:flags[FLAGS[0]]=True
        if doc['action'] in ('revoke','rotate'):
            flags[FLAGS[2]]=True;terminal.append(digest)
        if authority.utc_untrusted(now,*authority.window(doc['issued_utc'],
                     doc['expires_utc'],source.MAX_SPAN,'EC369_EXTRA_CLOCK'),source.MAX_SPAN):
            flags[FLAGS[11]]=True
    for i,src in enumerate(source_rows):
        # Rebuild the real latest source head from *all* copied original status
        # signatures, including EC367's extra source-signed terminal events.
        # A fork is never resolved by electing whichever item arrived last.
        h=chain(list(src['statuses'].items()),
                'previous_status_original_sha256',0,1)
        src['head']=h
        actual_status_heads[i]=h
        if h!=opts['expected_source_status_head_shas'][i]:
            flags[FLAGS[5]]=True
        ah=src['att_head']
        if ah is not None and h is not None and (
                src['attestations'][ah]['institution_status_original_sha256']!=h):
            flags[FLAGS[4]]=True
        witness._source_graph(src['statuses'],wflags)
    if wflags[witness.FLAGS[5]]:flags[FLAGS[2]]=True
    if wflags[witness.FLAGS[6]]:flags[FLAGS[1]]=True
    actual_witness_heads=[];latest_views=[]
    for i,path in enumerate(witness.PATHS):
        wrow=wit['distribution_paths'][i]
        pub=contents['witness_key_'+path]
        need(len(pub)==32,'WITNESS_PUBLIC_KEY_MUST_BE_32_BYTES','permission_denied')
        rows=[]
        for j,ref in enumerate(wrow['signed_witness_observations']):
            doc=tr.strict_json(contents['witness_status_'+path+'_'+str(j)],
                               'EC369_COPIED_SIGNED_WITNESS')
            witness.exact(doc,witness.RECORD_FIELDS,'EC369_COPIED_WITNESS_RECORD')
            need(doc['schema']==witness.RECORD_SCHEMA and
                 doc['distribution_path']==path and
                 doc['claimed_witness_id']==wrow['claimed_witness_id'] and
                 doc['witness_public_key_original_sha256']==sha(pub) and
                 type(doc['sequence']) is int and 0<=doc['sequence']<=8 and
                 (doc['previous_witness_original_sha256'] is None or
                  tr._sha(doc['previous_witness_original_sha256'])) and
                 doc['disclosure_state'] in ('published','withheld','disputed') and
                 type(doc['source_observations']) is list and
                 len(doc['source_observations'])==2,
                 'COPIED_WITNESS_RECORD_SHAPE_INVALID','permission_denied')
            authority.sig(doc,'signature_witness_ed25519_hex',pub,witness.RECORD_DOMAIN,
                          'EC369_COPIED_WITNESS_RECORD')
            witness_count+=1
            if doc['parent_ec366_canonical_result_sha256']!=mapdoc[
                      'parent_ec366_canonical_result_sha256']:
                flags[FLAGS[0]]=True
            if authority.utc_untrusted(now,*authority.window(doc['issued_utc'],
                         doc['expires_utc'],witness.MAX_WINDOW,'EC369_WITNESS_CLOCK'),
                     witness.MAX_WINDOW):flags[FLAGS[11]]=True
            for j,src in enumerate(source_rows):
                obs=doc['source_observations'][j]
                witness._check_observation(obs,src,wflags)
                if obs['source_attestation_head_original_sha256']!=src['att_head']:
                    flags[FLAGS[4]]=True
            rows.append({'sha':ref['sha256'],'document':doc})
        external={'expected_retained_'+path+'_witness_head_sha256':
                   opts['expected_witness_head_shas'][i],
                  'minimum_retained_'+path+'_sequence':0}
        head,_=witness._witness_history(rows,path,external,wflags)
        h=head['sha'] if head else None
        actual_witness_heads.append(h)
        latest=head['document']['source_observations'] if head else None
        latest_views.append(latest)
        if latest is None:
            flags[FLAGS[3]]=True
        else:
            for j,src in enumerate(source_rows):
                if (latest[j]['source_status_head_original_sha256']!=src['head'] or
                    latest[j]['source_attestation_head_original_sha256']!=src['att_head'] or
                    latest[j]['source_status_action'] not in ('activate','renew')):
                    flags[FLAGS[4]]=True
        if h!=opts['expected_witness_head_shas'][i]:flags[FLAGS[5]]=True
        for old,new in zip(rows,rows[1:]):
            for ix in range(2):
                x=old['document']['source_observations'][ix]
                y=new['document']['source_observations'][ix]
                if not witness._is_ancestor(x['source_status_head_original_sha256'],
                        y['source_status_head_original_sha256'],source_rows[ix]['statuses']):
                    flags[FLAGS[4]]=True
    if latest_views[0] is not None and latest_views[1] is not None:
        for j,src in enumerate(source_rows):
            left,right=latest_views[0][j],latest_views[1][j]
            a,b=left['source_status_head_original_sha256'],right['source_status_head_original_sha256']
            if a!=b:
                flags[FLAGS[4]]=True
                if not (witness._is_ancestor(a,b,src['statuses']) or
                        witness._is_ancestor(b,a,src['statuses'])):
                    flags[FLAGS[1]]=True
            if left['source_attestation_head_original_sha256']!=right['source_attestation_head_original_sha256']:
                flags[FLAGS[4]]=True
    left_att,right_att=(src['attestations'].get(src['att_head']) for src in source_rows)
    if left_att is not None and right_att is not None:
        for field in ('directory_lineage_id','directory_root_generation',
                      'observed_checkpoint_original_sha256','observed_tree_size',
                      'observed_merkle_root_sha256','epoch_signed_directory_observations',
                      'signed_directory_handoff_original_shas'):
            if left_att[field]!=right_att[field]:flags[FLAGS[4]]=True
    if wflags[witness.FLAGS[2]]:flags[FLAGS[5]]=True
    if wflags[witness.FLAGS[3]] or wflags[witness.FLAGS[4]]:flags[FLAGS[3]]=True
    if wflags[witness.FLAGS[8]] or wflags[witness.FLAGS[7]]:flags[FLAGS[4]]=True
    if wflags[witness.FLAGS[5]]:flags[FLAGS[2]]=True
    if root['parent_ec365_canonical_result_sha256']!=mapdoc[
            'parent_ec365_canonical_result_sha256'] or wit[
            'parent_ec366_canonical_result_sha256']!=mapdoc[
            'parent_ec366_canonical_result_sha256']:
        flags[FLAGS[0]]=True
    return {'source_signatures':status_count,'provenance_signatures':attest_count,
            'witness_signatures':witness_count,'source_terminal_shas':sorted(terminal),
            'source_heads':actual_status_heads,'attestation_heads':actual_attest_heads,
            'witness_heads':actual_witness_heads}


def _handshake(bundle,files,sender,receiver,mapdoc,mapref,opts,now,flags):
    rows=[];pflags={k:False for k in previous.FLAGS}
    need(type(bundle['handoffs']) is list and 1<=len(bundle['handoffs'])<=MAX_HANDOFFS,
         'DETACHED_HANDOFF_PAIRS_BOUNDED_REQUIRED')
    for i,row in enumerate(bundle['handoffs']):
        exact(row,previous.HANDOFF_FIELDS,'DETACHED_DUAL_HANDOFF')
        pair={}
        for kind,field in (('sender','sender_dispatch_original'),
                           ('receiver','receiver_ack_original')):
            ref=row[field];raw=files(ref,'handoff_'+kind+'_'+str(i),MAX_SIGNED)
            doc=tr.strict_json(raw,'EC369_COPIED_EC368_SIGNED_HANDOFF')
            review=previous._signed(doc,sender=sender,receiver=receiver,
               parent_sha=mapdoc['parent_ec367_canonical_result_sha256'],
               inv_sha=mapdoc['portable_inventory_canonical_sha256'],
               heads=mapdoc['witness_head_original_shas'],kind=kind,now=now)
            pair['dispatch' if kind=='sender' else 'ack']=doc
            pair['dispatch_sha' if kind=='sender' else 'ack_sha']=ref['sha256']
            if not review['bound']:flags[FLAGS[7]]=True
            if review['time_anomaly']:flags[FLAGS[11]]=True
        if tr._utc(pair['dispatch']['issued_utc'])>tr._utc(pair['ack']['received_utc']):
            flags[FLAGS[11]]=True
        rows.append(pair)
    ds=[r['dispatch_sha'] for r in rows];ack=[r['ack_sha'] for r in rows]
    if ds!=opts['signed_sender_dispatch_shas'] or ack!=opts['signed_receiver_ack_shas']:
        flags[FLAGS[8]]=True
    head=previous._lineage(rows,ds,ack,pflags)
    if pflags[previous.FLAGS[4]] or pflags[previous.FLAGS[7]]:
        flags[FLAGS[7]]=True
    if (head is None or
         head['dispatch_sha']!=opts['expected_retained_sender_dispatch_head_sha256'] or
         head['ack_sha']!=opts['expected_retained_receiver_ack_head_sha256'] or
         head['dispatch']['sequence']<opts['minimum_retained_sender_dispatch_sequence'] or
         head['ack']['sequence']<opts['minimum_retained_receiver_ack_sequence']):
        flags[FLAGS[8]]=True
    if head is None or head['ack']['receipt_state']!='accepted':flags[FLAGS[12]]=True
    return {'sender_shas':ds,'receiver_shas':ack,
            'sender_head':head['dispatch_sha'] if head else None,
            'receiver_head':head['ack_sha'] if head else None,
            'receipt_state':head['ack']['receipt_state'] if head else None}


def _disclosures(bundle,files,sender,receiver,mapdoc,mapref,opts,now,flags):
    need(type(bundle['disclosure_challenges']) is list and
         1<=len(bundle['disclosure_challenges'])<=MAX_HANDOFFS,
         'SIGNED_DISCs_BOUNDED_NONEMPTY_REQUIRED')
    required=[x['source_original']['sha256'] for x in mapdoc['originals']]
    requests=[];answers=[];previous_request=None;previous_answer=None
    seen_nonce=set()
    for i,row in enumerate(bundle['disclosure_challenges']):
        exact(row,('receiver_challenge_original','sender_disclosure_original'),
              'DUAL_SIGNED_DISCLOSURE_PAIR')
        rref=row['receiver_challenge_original'];aref=row['sender_disclosure_original']
        req=tr.strict_json(files(rref,'disclosure_challenge_'+str(i),MAX_SIGNED),
                           'SIGNED_RECEIVER_CHALLENGE')
        ans=tr.strict_json(files(aref,'disclosure_answer_'+str(i),MAX_SIGNED),
                           'SIGNED_SENDER_DISCLOSURE')
        exact(req,CHALLENGE_FIELDS,'SIGNED_RECEIVER_CHALLENGE')
        exact(ans,ANSWER_FIELDS,'SIGNED_SENDER_DISCLOSURE')
        need(req['schema']==CHALLENGE_SCHEMA and ans['schema']==ANSWER_SCHEMA,
             'SIGNED_DISCLOSURE_SCHEMAS_INVALID')
        for doc in (req,ans):
            need(doc['claimed_sender_id']==sender['id'] and
                 doc['sender_public_key_original_sha256']==sender['sha'] and
                 doc['claimed_receiver_id']==receiver['id'] and
                 doc['receiver_public_key_original_sha256']==receiver['sha'],
                 'SIGNED_DISCLOSURE_EXTERNAL_IDENTITIES_MUST_MATCH',
                 'permission_denied')
        authority.sig(req,'signature_receiver_ed25519_hex',receiver['public'],
                      CHALLENGE_DOMAIN,'EC369_TRUE_RECEIVER_CHALLENGE')
        authority.sig(ans,'signature_sender_ed25519_hex',sender['public'],
                      ANSWER_DOMAIN,'EC369_TRUE_SENDER_DISCLOSURE')
        rstart,rend=authority.window(req['issued_utc'],req['expires_utc'],
                              MAX_WINDOW,'EC369_RECEIVER_CHALLENGE_TIME')
        astart,aend=authority.window(ans['answered_utc'],ans['expires_utc'],
                              MAX_WINDOW,'EC369_SENDER_DISCLOSURE_TIME')
        if (authority.utc_untrusted(now,rstart,rend,MAX_WINDOW) or
            authority.utc_untrusted(now,astart,aend,MAX_WINDOW) or
            rstart>astart):flags[FLAGS[11]]=True
        if not tr._sha(req['receiver_nonce_sha256']) or not tr._sha(ans['receiver_nonce_sha256']):
            need(False,'SIGNED_RECEIVER_NONCE_SHA_FORMAT_INVALID')
        if req['receiver_nonce_sha256'] in seen_nonce:flags[FLAGS[9]]=True
        seen_nonce.add(req['receiver_nonce_sha256'])
        for doc in (req,ans):
            if (doc['signed_copy_map_original_sha256']!=mapref['sha256'] or
                doc['portable_inventory_canonical_sha256']!=mapdoc[
                    'portable_inventory_canonical_sha256'] or
                doc['parent_ec367_canonical_result_sha256']!=mapdoc[
                    'parent_ec367_canonical_result_sha256']):flags[FLAGS[9]]=True
        if (req['sequence']!=i or ans['sequence']!=i or
            req['previous_challenge_original_sha256']!=previous_request or
            req['previous_answer_original_sha256']!=previous_answer or
            ans['previous_challenge_original_sha256']!=previous_request or
            ans['previous_answer_original_sha256']!=previous_answer or
            ans['receiver_challenge_original_sha256']!=rref['sha256'] or
            ans['receiver_nonce_sha256']!=req['receiver_nonce_sha256'] or
            type(req['challenged_source_original_shas']) is not list or
            req['challenged_source_original_shas']!=required or
            type(ans['disclosed_source_original_shas']) is not list or
            ans['disclosed_source_original_shas']!=required or
            ans['disclosure_state']!='provided'):
            flags[FLAGS[9]]=True
        requests.append(rref['sha256']);answers.append(aref['sha256'])
        previous_request,previous_answer=rref['sha256'],aref['sha256']
    if (requests!=opts['signed_challenge_shas'] or
        answers!=opts['signed_answer_shas'] or
        requests[-1]!=opts['expected_retained_challenge_head_sha256'] or
        answers[-1]!=opts['expected_retained_answer_head_sha256'] or
        req['receiver_nonce_sha256']!=opts['expected_retained_challenge_nonce_sha256'] or
        len(requests)-1<opts['minimum_retained_challenge_sequence']):
        flags[FLAGS[10]]=True
    return {'challenge_shas':requests,'answer_shas':answers,
            'challenge_head':requests[-1],'answer_head':answers[-1],
            'latest_nonce_sha256':req['receiver_nonce_sha256']}


def audit(**opts):
    _inputs(opts)
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};source_paths=set()
    def read(ref,role,cap):
        _refs(ref)
        need(ref['path'] not in source_paths,
             'SENDER_SOURCE_PATH_CANNOT_BE_READ_AS_RECEIVER_COPY',
             'permission_denied')
        return previous.parent._new(ref,'EC369_'+role,cap,pins,set(),
                                    categories,'ec369_'+role)
    bref={'path':opts['detached_bundle_file'],
          'sha256':opts['expected_detached_bundle_sha256']}
    bundle=tr.strict_json(read(bref,'bundle',MAX_BUNDLE),'EC369_DETACHED_BUNDLE')
    exact(bundle,BUNDLE_FIELDS,'DETACHED_BUNDLE')
    need(bundle['schema']==BUNDLE_SCHEMA,'DETACHED_BUNDLE_SCHEMA_WRONG')
    keyrefs=(('sender',opts['sender_public_key_file'],
                    opts['expected_sender_public_key_sha256'],opts['claimed_sender_id']),
             ('receiver',opts['receiver_public_key_file'],
                    opts['expected_receiver_public_key_sha256'],opts['claimed_receiver_id']))
    keys=[]
    for role,path,digest,claimed in keyrefs:
        pub=read({'path':path,'sha256':digest},role+'_key',32)
        need(len(pub)==32,'RAW_ED25519_PUBLIC_KEY_MUST_BE_32_BYTES',
             'permission_denied')
        keys.append({'id':claimed,'sha':digest,'public':pub})
    sender,receiver=keys
    mapref=bundle['signed_copy_map_original']
    need(mapref['sha256']==opts['expected_signed_copy_map_sha256'],
         'INDEPENDENT_SIGNED_COPY_MAP_SHA_MUST_MATCH','permission_denied')
    mapdoc=tr.strict_json(read(mapref,'signed_map',MAX_MAP),'EC369_SIGNED_COPY_MAP')
    exact(mapdoc,MAP_FIELDS,'DETACHED_SIGNED_COPY_MAP')
    need(mapdoc['schema']==MAP_SCHEMA and
         mapdoc['claimed_sender_id']==sender['id'] and
         mapdoc['claimed_receiver_id']==receiver['id'] and
         mapdoc['sender_public_key_original_sha256']==sender['sha'] and
         mapdoc['receiver_public_key_original_sha256']==receiver['sha'],
         'SIGNED_MAP_IDENTITY_AND_EXTERNAL_KEY_PINS_MUST_MATCH',
         'permission_denied')
    authority.sig(mapdoc,'signature_sender_ed25519_hex',sender['public'],
                  MAP_DOMAIN,'EC369_TRUE_SENDER_SIGNED_MAP')
    flags={k:False for k in FLAGS}
    for k,external in (
        ('parent_ec367_canonical_result_sha256','expected_parent_ec367_canonical_result_sha256'),
        ('parent_ec366_canonical_result_sha256','expected_parent_ec366_canonical_result_sha256'),
        ('parent_ec365_canonical_result_sha256','expected_parent_ec365_canonical_result_sha256'),
        ('portable_inventory_canonical_sha256','expected_portable_inventory_sha256'),
        ('institution_root_public_key_original_shas','institution_root_public_key_shas'),
        ('witness_public_key_original_shas','witness_public_key_shas'),
        ('institution_claimed_ids','institution_claimed_ids'),
        ('witness_claimed_ids','witness_claimed_ids'),
        ('witness_head_original_shas','expected_witness_head_shas')):
        if mapdoc[k]!=opts[external]:flags[FLAGS[0]]=True
    start,end=authority.window(mapdoc['issued_utc'],mapdoc['expires_utc'],
                                MAX_WINDOW,'EC369_SIGNED_COPY_MAP_TIME')
    if authority.utc_untrusted(now,start,end,MAX_WINDOW):flags[FLAGS[11]]=True
    originals=mapdoc['originals']
    need(type(originals) is list and 8<=len(originals)<=MAX_COPIES,
         'SIGNED_MAP_BOUNDED_EXACT_ORIGINALS_REQUIRED')
    seen=set();contents={}
    for i,row in enumerate(originals):
        exact(row,MAP_ROW_FIELDS,'SIGNED_SOURCE_ORIGINAL_TO_COPY_ROW')
        ref=row['source_original'];_metadata_ref(ref)
        copy=row['receiver_copy'];_refs(copy)
        need(copy['sha256']==ref['sha256'] and
             ref['sha256'] not in seen and
             type(row['kind']) is str and len(row['kind'])<=120 and
             type(row['byte_length']) is int and 1<=row['byte_length']<=previous.MAX_COPIED_ORIGINAL,
             'SIGNED_MAP_SHA_SIZE_OR_ROLE_DUPLICATION','permission_denied')
        seen.add(ref['sha256']);source_paths.add(ref['path'])
        need(copy['path']!=ref['path'],'ORIGINAL_PATH_CANNOT_BE_RECEIVER_COPY',
             'permission_denied')
    need(len(source_paths)==len(originals),
         'SOURCE_PATH_REUSED_FOR_DIFFERENT_ORIGINAL','permission_denied')
    # The source paths are now an alias *exclusion set*, never a read target.
    need(not source_paths.intersection(pins),
         'SOURCE_REFERENCE_ALIASES_DETACHED_BUNDLE_OR_KEYS','permission_denied')
    for i,row in enumerate(originals):
        raw=read(row['receiver_copy'],'original_copy_'+str(i),
                 previous.MAX_COPIED_ORIGINAL)
        need(len(raw)==row['byte_length'],
             'SIGNED_MAP_BYTE_LENGTH_MUST_MATCH_ACTUAL_COPY','permission_denied')
        contents[row['kind']]=raw
    need(len(contents)==len(originals),'UNIQUE_ROLE_NAMES_REQUIRED','permission_denied')
    root=tr.strict_json(contents.get('ec366_root_bundle',b''),'EC369_ROOT_COPY')
    wit=tr.strict_json(contents.get('ec367_witness_bundle',b''),'EC369_WITNESS_COPY')
    expected=_expected_items(root,wit,mapdoc)
    for row,e in zip(originals,expected):
        need(row['kind']==e['kind'] and row['source_original']['sha256']==e['sha'],
             'INDEPENDENTLY_DERIVED_EC368_ORIGINAL_ROLE_OR_SHA_MISMATCH',
             'permission_denied')
        if e['source_ref'] is not None:
            need(row['source_original']==e['source_ref'],
                 'SOURCE_ORIGINAL_REFERENCE_LABEL_MISMATCH','permission_denied')
    need(len(originals)==len(expected),'SIGNED_MAP_MISSING_OR_EXTRA_ORIGINALS',
         'permission_denied')
    inventory={'schema':previous.INVENTORY_SCHEMA,
        'parent_ec367_canonical_result_sha256':mapdoc['parent_ec367_canonical_result_sha256'],
        'items':[{'kind':x['kind'],'source_original_sha256':x['source_original']['sha256'],
                  'byte_length':x['byte_length']} for x in originals]}
    digest=sha(canonical.canonical(inventory))
    if digest!=mapdoc['portable_inventory_canonical_sha256'] or digest!=opts[
            'expected_portable_inventory_sha256']:
        flags[FLAGS[0]]=True
    forbidden=set(mapdoc['institution_root_public_key_original_shas']+
                  mapdoc['witness_public_key_original_shas'])
    ids=mapdoc['institution_claimed_ids']+mapdoc['witness_claimed_ids']
    if (sender['sha'] in forbidden or receiver['sha'] in forbidden or
        sender['id'] in ids or receiver['id'] in ids or len(set(ids))!=len(ids)):
        flags[FLAGS[6]]=True
    sigs=_replay_copied_source_and_witness(contents,mapdoc,opts,now,flags)
    if sigs['witness_heads']!=mapdoc['witness_head_original_shas']:
        flags[FLAGS[0]]=True
    handshake=_handshake(bundle,read,sender,receiver,mapdoc,mapref,opts,now,flags)
    disclosures=_disclosures(bundle,read,sender,receiver,mapdoc,mapref,opts,now,flags)
    tsa._check_late(pins)
    previous.parent.parent.parent.parent.history.parent.previous.parent.parent._late_identity_check(
         pins,set())
    local=not any(flags.values())
    if not local:flags[FLAGS[12]]=True
    winner=next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])
    return {'schema':RESULT_SCHEMA,'command':'audit-detached-receiver',
      'status':winner+'_unresolved','exit_code':2,
      'detached_evaluation_utc_as_caller_claim':opts['detached_evaluation_utc'],
      'signed_copy_map_original_sha256':mapref['sha256'],
      'detached_bundle_original_sha256':bref['sha256'],
      'parent_ec367_canonical_result_sha256_as_external_pin':opts[
                   'expected_parent_ec367_canonical_result_sha256'],
      'actual_portable_inventory_canonical_sha256':digest,
      'actual_copied_source_original_count':len(originals),
      'true_copied_institution_status_ed25519_signature_count':sigs['source_signatures'],
      'true_copied_institution_provenance_ed25519_signature_count':sigs['provenance_signatures'],
      'true_copied_witness_ed25519_signature_count':sigs['witness_signatures'],
      'true_copied_sender_dispatch_ed25519_signature_count':len(handshake['sender_shas']),
      'true_copied_receiver_ack_ed25519_signature_count':len(handshake['receiver_shas']),
      'true_disclosure_challenge_ed25519_signature_count':len(disclosures['challenge_shas']),
      'true_disclosure_answer_ed25519_signature_count':len(disclosures['answer_shas']),
      'verified_copy_source_terminal_status_original_shas':sigs['source_terminal_shas'],
      'actual_source_status_head_shas':sigs['source_heads'],
      'actual_source_attestation_head_shas':sigs['attestation_heads'],
      'actual_witness_head_shas':sigs['witness_heads'],
      'actual_sender_dispatch_head_sha256':handshake['sender_head'],
      'actual_receiver_ack_head_sha256':handshake['receiver_head'],
      'latest_receiver_signed_receipt_state':handshake['receipt_state'],
      'actual_disclosure_challenge_head_sha256':disclosures['challenge_head'],
      'actual_disclosure_answer_head_sha256':disclosures['answer_head'],
      'locally_detached_signed_copy_inventory_and_dual_receipt_consistent':bool(local),
      'original_sender_source_paths_required_or_read':False,
      'ec365_through_ec337_historical_parent_or_directory_checkpoint_replay_performed':False,
      'offline_unresolved_exit_code':2,**flags,
      **{k:False for k in NEGATIVES}}
