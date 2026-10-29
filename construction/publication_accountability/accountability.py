#!/usr/bin/env python3
"""EC370: offline, two-key signed publication accountability for EC369.

Replays the REAL EC369 receiver-only audit each invocation, then reopens
SHA-pinned signed publisher and separately signed observer publication epochs.
The signed history is finite/caller-anchored: local completeness DOES NOT prove
independent legal parties, a public log, global freshness or hidden-fork absence.
No signer, network, writes, sender-origin file access or PowerShell changes.
"""
from __future__ import annotations

from datetime import timedelta

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from authority_directory import authority
from cross_epoch import continuity as historic
from witness_distribution import distribution as witness
from detached_receiver import detached as prior

RESULT_SCHEMA='ces.ec370.detached_publication_accountability_unresolved.v1'
DENIAL_SCHEMA='ces.ec370.detached_publication_accountability_denial.v1'
BUNDLE_SCHEMA='ces.ec370.publication_accountability_bundle.v1'
NOTICE_SCHEMA='ces.ec370.publisher_signed_disclosure_history.v1'
OBSERVATION_SCHEMA='ces.ec370.observer_signed_publication_inclusion.v1'
INVENTORY_SCHEMA='ces.ec370.cumulative_published_detached_original_sha_inventory.v1'
DERIVE_SCHEMA='ces.ec370.unsigned_publication_inventory_for_external_signers_unresolved.v1'
NOTICE_DOMAIN=b'CES/EC370/PublisherHistory/v1\x00'
OBSERVATION_DOMAIN=b'CES/EC370/ObserverInclusion/v1\x00'
MAX_EPOCHS=4
MAX_EVIDENCE=4
MAX_BUNDLE=9000
MAX_SIGNED=7500
MAX_WINDOW=timedelta(days=7)

# These values are caller supplied OUTSIDE the signed publication bundle.
NEW_SCALARS=(
 'publication_bundle_file','expected_publication_bundle_sha256',
 'publisher_public_key_file','expected_publisher_public_key_sha256',
 'claimed_publisher_id',
 'publication_observer_public_key_file','expected_publication_observer_public_key_sha256',
 'claimed_publication_observer_id',
 'expected_retained_publisher_notice_head_sha256',
 'expected_retained_publication_observer_head_sha256',
 'expected_latest_publication_inventory_sha256',
 'minimum_retained_publication_sequence',
 'minimum_retained_published_challenge_count',
)
NEW_REPEATS=(
 ('signed_publisher_notice_shas','--signed-publisher-notice-sha256'),
 ('signed_publication_observer_shas','--signed-publication-observer-sha256'),
)
NEW_REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
BUNDLE_FIELDS={'schema','publication_epochs',
               'competing_publisher_notice_originals',
               'competing_publication_observation_originals'}
EPOCH_FIELDS={'publisher_notice_original','publication_observation_original'}
PAIR_HANDOFF_FIELDS={'sender_dispatch_original_sha256','receiver_ack_original_sha256'}
PAIR_DISCLOSURE_FIELDS={'receiver_challenge_original_sha256','sender_disclosure_original_sha256'}
COMMON_FIELDS={
 'claimed_publisher_id','publisher_public_key_original_sha256',
 'claimed_publication_observer_id','publication_observer_public_key_original_sha256',
 'claimed_sender_id','claimed_receiver_id','sequence',
 'previous_publisher_notice_original_sha256',
 'previous_publication_observation_original_sha256',
 'detached_bundle_original_sha256','signed_copy_map_original_sha256',
 'parent_ec367_canonical_result_sha256','portable_inventory_canonical_sha256',
 'publication_inventory_canonical_sha256',
 'published_handoff_sha_pairs','published_disclosure_sha_pairs',
 'issued_utc','expires_utc',
}
NOTICE_FIELDS=COMMON_FIELDS|{'schema','publication_state','signature_publisher_ed25519_hex'}
OBSERVATION_FIELDS=COMMON_FIELDS|{'schema','publisher_notice_original_sha256',
                                  'observation_state','signature_observer_ed25519_hex'}
# Publisher and observer bind identical evidence, but sign at their own times.
BINDING_FIELDS=COMMON_FIELDS-{'issued_utc','expires_utc'}

FLAGS=(
 'inherited_true_ec369_detached_source_or_receipt_defect_visible',
 'authentic_publisher_or_observer_signed_withholding_or_dispute_visible',
 'signed_publication_manifest_omits_reorders_or_contradicts_detached_originals',
 'signed_publication_predecessor_gap_fork_or_nonmonotonic_history_visible',
 'signed_publisher_and_observer_inclusion_statements_disagree',
 'externally_retained_publisher_observer_stream_head_floor_or_inventory_mismatch',
 'genuinely_signed_competing_publication_or_observation_fork_visible',
 'self_claimed_publication_or_observation_utc_untrusted',
 'fully_bound_current_two_party_publication_inclusion_not_demonstrated',
)
OUTCOMES=(
 'ec370_inherited_detached_signed_original_problem',
 'ec370_genuine_publisher_or_observer_withholding',
 'ec370_signed_publication_missing_or_divergent_sha_inventory',
 'ec370_genuine_signed_publication_sequence_or_prefix_conflict',
 'ec370_publisher_observer_signed_inclusion_disagreement',
 'ec370_externally_anchored_publication_history_rollback_or_divergence',
 'ec370_real_publication_signer_equivocation',
 'ec370_signed_self_claimed_clock_untrusted',
 'ec370_complete_local_publication_inclusion_not_established',
 'ec370_two_party_local_sha_publication_consistent_but_global_log_unproven',
)
NEGATIVES=(
 'full_ec365_through_ec337_original_directory_signatures_replayed',
 'publisher_and_observer_signatures_prove_independent_official_legal_entities',
 'receipt_signatures_establish_actual_physical_custody_or_public_network_delivery',
 'finite_signed_publication_views_prove_globally_complete_append_only_log',
 'retained_heads_establish_absence_of_hidden_signed_forks',
 'claimed_publication_utc_is_trusted_time_or_actual_challenge_freshness',
 'new_publication_evidence_repairs_ec369_signed_revoke_dispute_or_bad_copies',
 'sender_original_source_paths_reopened_or_restored',
 'private_keys_network_provider_cas_worm_or_native_powershell_used',
 'old_ec317_ec318_mock_or_final_user_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:raise errors.AnchorError('EC370_'+code,status)


def exact(obj,keys,role):
    need(type(obj) is dict and set(obj)==set(keys),role+'_EXACT_FIELDS_REQUIRED')


def digest(raw):return witness.sha(raw)


def _ref(ref):historic.ref_check(ref,'EC370_SIGNED_ORIGINAL_REF')


def _inputs(opts):
    need(set(opts)==set(prior.SCALARS)|set(prior.REPEAT_NAMES)|
         set(NEW_SCALARS)|set(NEW_REPEAT_NAMES),
         'EXACT_PARENT_AND_NEW_EXTERNAL_INPUTS_REQUIRED')
    inherited={k:opts[k] for k in (*prior.SCALARS,*prior.REPEAT_NAMES)}
    prior._inputs(inherited)
    for file,sha in (("publication_bundle_file","expected_publication_bundle_sha256"),
                     ("publisher_public_key_file","expected_publisher_public_key_sha256"),
                     ("publication_observer_public_key_file","expected_publication_observer_public_key_sha256")):
        authority.outer_pin(opts[file],opts[sha],'EC370_EXTERNAL_'+file.upper())
        need(opts[file] is not None and opts[sha] is not None,
             'THREE_INDEPENDENT_NEW_FILE_SHA_PAIRS_REQUIRED')
    for key in ('expected_retained_publisher_notice_head_sha256',
                'expected_retained_publication_observer_head_sha256',
                'expected_latest_publication_inventory_sha256'):
        need(tr._sha(opts[key]),'EXTERNAL_'+key.upper()+'_REQUIRED')
    for key in ('claimed_publisher_id','claimed_publication_observer_id'):
        need(tr._ident(opts[key]),'STRICT_'+key.upper()+'_REQUIRED')
    roles=(opts['claimed_publisher_id'],opts['claimed_publication_observer_id'],
           opts['claimed_sender_id'],opts['claimed_receiver_id'],
           *opts['institution_claimed_ids'],*opts['witness_claimed_ids'])
    keys=(opts['expected_publisher_public_key_sha256'],
          opts['expected_publication_observer_public_key_sha256'],
          opts['expected_sender_public_key_sha256'],
          opts['expected_receiver_public_key_sha256'],
          *opts['institution_root_public_key_shas'],*opts['witness_public_key_shas'])
    need(len(set(roles))==len(roles) and len(set(keys))==len(keys),
         'EIGHT_SIGNER_ROLES_MUST_HAVE_DISTINCT_KEYS_AND_IDS','permission_denied')
    for key in ('minimum_retained_publication_sequence',
                'minimum_retained_published_challenge_count'):
        need(type(opts[key]) is int and 0<=opts[key]<MAX_EPOCHS+int('count' in key),
             'PUBLICATION_SEQUENCE_OR_DISCLOSURE_FLOOR_OUT_OF_RANGE')
    for key in NEW_REPEAT_NAMES:
        arr=opts[key]
        need(type(arr) is list and 1<=len(arr)<=MAX_EPOCHS and
             all(tr._sha(x) for x in arr) and len(set(arr))==len(arr),
             key.upper()+'_BOUNDED_DISTINCT_OUTSIDE_SHA_STREAM_REQUIRED')
    need(len(opts['signed_publisher_notice_shas'])==len(
         opts['signed_publication_observer_shas']),
         'INDEPENDENTLY_RETAINED_DUAL_STREAM_LENGTHS_DISAGREE')
    return inherited


def _read(ref,kind,limit,pins,categories,forbidden):
    _ref(ref)
    need(ref['path'] not in forbidden,'READ_PATH_ALIASES_HISTORICAL_SOURCE_LABEL',
         'permission_denied')
    # Same inherited read-only no-symlink, path/inode and full SHA reader as EC369.
    return prior.previous.parent._new(ref,'EC370_'+kind,limit,pins,set(),
                                      categories,'ec370_'+kind)


def _pairs(value,fields,role):
    need(type(value) is list and 1<=len(value)<=MAX_EPOCHS,
         role+'_BOUNDED_NONEMPTY_PAIR_INVENTORY_REQUIRED')
    result=[]
    for item in value:
        exact(item,fields,role+'_PAIR')
        need(all(tr._sha(x) for x in item.values()),
             role+'_ORIGINAL_SHA_INVALID')
        result.append(item)
    need(len({tuple(x[k] for k in sorted(fields)) for x in result})==len(result),
         role+'_DUPLICATE_SHA_PAIR_DENIED')
    return result


def inventory_document(opts,parent,hand,pairs):
    # An *actual* replayed EC369 result is bound, including all adverse flags.
    # Only publisher/observer listing lengths vary across historical snapshots.
    doc={'schema':INVENTORY_SCHEMA,
         'detached_bundle_original_sha256':opts['expected_detached_bundle_sha256'],
         'signed_copy_map_original_sha256':opts['expected_signed_copy_map_sha256'],
         'parent_ec367_canonical_result_sha256':opts[
              'expected_parent_ec367_canonical_result_sha256'],
         'portable_inventory_canonical_sha256':parent[
              'actual_portable_inventory_canonical_sha256'],
         'verified_detached_audit_result_canonical_sha256':digest(
              canonical.canonical(parent)),
         'actual_source_status_head_shas':parent['actual_source_status_head_shas'],
         'actual_source_attestation_head_shas':parent[
              'actual_source_attestation_head_shas'],
         'actual_witness_head_shas':parent['actual_witness_head_shas'],
         'verified_source_terminal_status_original_shas':parent[
              'verified_copy_source_terminal_status_original_shas'],
         'published_handoff_sha_pairs':hand,
         'published_disclosure_sha_pairs':pairs}
    return doc


def _inventory_hash(opts,parent,hand,pairs):
    return digest(canonical.canonical(inventory_document(opts,parent,hand,pairs)))


def _signed(doc,kind,pub,opts,now):
    notice=kind=='publisher'
    exact(doc,NOTICE_FIELDS if notice else OBSERVATION_FIELDS,
          'SIGNED_'+kind.upper())
    need(doc['schema']==(NOTICE_SCHEMA if notice else OBSERVATION_SCHEMA),
         'SIGNED_PUBLICATION_SCHEMA_WRONG')
    for k,v in (
      ('claimed_publisher_id',opts['claimed_publisher_id']),
      ('publisher_public_key_original_sha256',opts['expected_publisher_public_key_sha256']),
      ('claimed_publication_observer_id',opts['claimed_publication_observer_id']),
      ('publication_observer_public_key_original_sha256',opts[
          'expected_publication_observer_public_key_sha256']),
      ('claimed_sender_id',opts['claimed_sender_id']),
      ('claimed_receiver_id',opts['claimed_receiver_id'])):
        need(doc[k]==v,'SIGNED_'+kind.upper()+'_EXTERNAL_ROLE_BINDING_WRONG',
             'permission_denied')
    need(type(doc['sequence']) is int and 0<=doc['sequence']<MAX_EPOCHS,
         'SIGNED_SEQUENCE_OUT_OF_RANGE')
    for k in ('previous_publisher_notice_original_sha256',
              'previous_publication_observation_original_sha256'):
        need(doc[k] is None or tr._sha(doc[k]),
             'SIGNED_PREDECESSOR_SHA_REQUIRED')
    if not notice:
        need(tr._sha(doc['publisher_notice_original_sha256']),
             'SIGNED_OBSERVER_SOURCE_SHA_REQUIRED')
    state=doc['publication_state'] if notice else doc['observation_state']
    need(state in (('published','withheld','disputed') if notice else
                   ('confirmed','withheld','disputed')),
         'SIGNED_PUBLICATION_OR_OBSERVATION_STATE_UNKNOWN')
    need(all(tr._sha(doc[k]) for k in (
        'detached_bundle_original_sha256','signed_copy_map_original_sha256',
        'parent_ec367_canonical_result_sha256','portable_inventory_canonical_sha256',
        'publication_inventory_canonical_sha256')),
        'SIGNED_PUBLICATION_CROSS_SHA_INVALID')
    _pairs(doc['published_handoff_sha_pairs'],PAIR_HANDOFF_FIELDS,'SIGNED_HANDOFFS')
    _pairs(doc['published_disclosure_sha_pairs'],PAIR_DISCLOSURE_FIELDS,
           'SIGNED_DISCLOSURES')
    start,end=authority.window(doc['issued_utc'],doc['expires_utc'],MAX_WINDOW,
                               'EC370_SIGNED_'+kind.upper()+'_TIME')
    authority.sig(doc,'signature_publisher_ed25519_hex' if notice else
                  'signature_observer_ed25519_hex',pub,
                  NOTICE_DOMAIN if notice else OBSERVATION_DOMAIN,
                  'EC370_TRUE_'+kind.upper()+'_ED25519')
    return authority.utc_untrusted(now,start,end,MAX_WINDOW)


def _bounds(doc,opts,parent,hand,pairs):
    return (doc['detached_bundle_original_sha256']==opts[
                'expected_detached_bundle_sha256'] and
            doc['signed_copy_map_original_sha256']==opts[
                'expected_signed_copy_map_sha256'] and
            doc['parent_ec367_canonical_result_sha256']==opts[
                'expected_parent_ec367_canonical_result_sha256'] and
            doc['portable_inventory_canonical_sha256']==parent[
                'actual_portable_inventory_canonical_sha256'] and
            doc['publication_inventory_canonical_sha256']==_inventory_hash(
                opts,parent,hand,pairs))


def _prefix(values,actual):
    return len(values)<=len(actual) and values==actual[:len(values)]


def derive_inventory(*,published_handoff_prefix_count=None,
                     published_disclosure_prefix_count=None,**opts):
    """Read-only export of the exact *unsigned* content to sign externally.

    A real EC369 replay is mandatory even here. This is NOT itself a
    publication signature or an independently authenticated external pin.
    No new publisher/observer key, bundle or external signer's secret is needed.
    """
    prior._inputs(opts)
    parent=prior.audit(**opts)
    need(parent['exit_code']==2 and parent['schema']==prior.RESULT_SCHEMA,
         'REAL_EC369_PARENT_UNEXPECTED_RESULT','unavailable')
    pins={};categories={}
    dref={'path':opts['detached_bundle_file'],
          'sha256':opts['expected_detached_bundle_sha256']}
    bundle=tr.strict_json(_read(dref,'derive_ec369_bundle',prior.MAX_BUNDLE,
                                pins,categories,set()),
                          'EC370_DERIVE_REOPEN_PINNED_EC369_BUNDLE')
    prior.exact(bundle,prior.BUNDLE_FIELDS,'EC370_DERIVE_PINNED_EC369_BUNDLE')
    hand=[{'sender_dispatch_original_sha256':x['sender_dispatch_original']['sha256'],
           'receiver_ack_original_sha256':x['receiver_ack_original']['sha256']}
          for x in bundle['handoffs']]
    pairs=[{'receiver_challenge_original_sha256':x['receiver_challenge_original']['sha256'],
            'sender_disclosure_original_sha256':x['sender_disclosure_original']['sha256']}
           for x in bundle['disclosure_challenges']]
    for key,num,total in (
        ('PUBLISHED_HANDOFF_PREFIX_COUNT',published_handoff_prefix_count,len(hand)),
        ('PUBLISHED_DISCLOSURE_PREFIX_COUNT',published_disclosure_prefix_count,len(pairs))):
        need(num is None or (type(num) is int and 1<=num<=total),
             key+'_WITHIN_ACTUAL_SIGNED_STREAM_REQUIRED')
    take_hand=len(hand) if published_handoff_prefix_count is None else published_handoff_prefix_count
    take_pairs=len(pairs) if published_disclosure_prefix_count is None else published_disclosure_prefix_count
    tsa._check_late(pins)
    material=inventory_document(opts,parent,hand[:take_hand],pairs[:take_pairs])
    return {'schema':DERIVE_SCHEMA,'command':'derive-publication-inventory',
        'status':'ec370_unsigned_publication_inventory_for_external_signers_unresolved',
        'exit_code':2,'offline_unresolved_exit_code':2,
        'current_unsigned_canonical_inventory':material,
        'current_unsigned_canonical_inventory_sha256':digest(canonical.canonical(material)),
        'actual_full_handoff_pair_count':len(hand),
        'actual_full_disclosure_pair_count':len(pairs),
        'selected_handoff_pair_count':take_hand,
        'selected_disclosure_pair_count':take_pairs,
        'inherited_ec369_detached_locally_consistent':parent[
            'locally_detached_signed_copy_inventory_and_dual_receipt_consistent'],
        'original_sender_source_paths_required_or_read':False,
        'ec365_through_ec337_historical_parent_replay_performed':False,
        'new_private_signing_or_publication_record_generated':False,
        **{k:False for k in NEGATIVES}}


def audit(**opts):
    inherited=_inputs(opts)
    # No cached parent result accepted. If any received original is bad,
    # the exact EC369 signature/byte denial propagates to the caller.
    parent=prior.audit(**inherited)
    need(parent['exit_code']==2 and parent['schema']==prior.RESULT_SCHEMA,
         'REAL_EC369_PARENT_UNEXPECTED_RESULT','unavailable')
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};source_labels=set()
    def read(ref,role,cap):return _read(ref,role,cap,pins,categories,source_labels)
    # Collect the full actual EC369 source-label set; NEVER open or stat these
    # historical paths. Prevent any new EC370 input from being one of them.
    dref={'path':opts['detached_bundle_file'],
          'sha256':opts['expected_detached_bundle_sha256']}
    detached_doc=tr.strict_json(read(dref,'ec369_bundle',prior.MAX_BUNDLE),
                                'EC370_REOPEN_PINNED_EC369_BUNDLE')
    prior.exact(detached_doc,prior.BUNDLE_FIELDS,'EC370_PINNED_EC369_BUNDLE')
    mapdoc=tr.strict_json(read(detached_doc['signed_copy_map_original'],
                               'ec369_signed_map',prior.MAX_MAP),
                          'EC370_REOPEN_PINNED_EC369_MAP')
    prior.exact(mapdoc,prior.MAP_FIELDS,'EC370_PINNED_EC369_MAP')
    source_labels.update(x['source_original']['path'] for x in mapdoc['originals'])
    need(not source_labels.intersection(pins),
         'PUBLICATION_INPUT_ALIASES_REMOVED_SENDER_SOURCE_PATH',
         'permission_denied')

    pref={'path':opts['publication_bundle_file'],
          'sha256':opts['expected_publication_bundle_sha256']}
    bundle=tr.strict_json(read(pref,'publication_bundle',MAX_BUNDLE),
                          'EC370_PUBLICATION_BUNDLE')
    exact(bundle,BUNDLE_FIELDS,'PUBLICATION_BUNDLE')
    need(bundle['schema']==BUNDLE_SCHEMA,'PUBLICATION_BUNDLE_SCHEMA_WRONG')
    pubs=[]
    for role,path,sha in (
        ('publisher',opts['publisher_public_key_file'],
                     opts['expected_publisher_public_key_sha256']),
        ('observer',opts['publication_observer_public_key_file'],
                    opts['expected_publication_observer_public_key_sha256'])):
        raw=read({'path':path,'sha256':sha},'root_'+role,32)
        need(len(raw)==32,'ED25519_PUBLIC_KEYS_ARE_EXACTLY_32_BYTES',
             'permission_denied')
        pubs.append(raw)
    pubkey,observerkey=pubs
    epochs=bundle['publication_epochs']
    need(type(epochs) is list and 1<=len(epochs)<=MAX_EPOCHS,
         'BOUNDED_NONEMPTY_PUBLICATION_EPOCHS_REQUIRED')
    for k in ('competing_publisher_notice_originals',
              'competing_publication_observation_originals'):
        need(type(bundle[k]) is list and len(bundle[k])<=MAX_EVIDENCE,
             k.upper()+'_BOUNDED_EVIDENCE_REQUIRED')

    full_hand=[{'sender_dispatch_original_sha256':x['sender_dispatch_original']['sha256'],
                'receiver_ack_original_sha256':x['receiver_ack_original']['sha256']}
               for x in detached_doc['handoffs']]
    full_disc=[{'receiver_challenge_original_sha256':x['receiver_challenge_original']['sha256'],
                'sender_disclosure_original_sha256':x['sender_disclosure_original']['sha256']}
               for x in detached_doc['disclosure_challenges']]
    need(1<=len(full_hand)<=MAX_EPOCHS and 1<=len(full_disc)<=MAX_EPOCHS,
         'UPSTREAM_SIGNED_ORIGINAL_HISTORY_BOUNDS_INVALID','unavailable')
    flags={x:False for x in FLAGS}
    flags[FLAGS[0]]=not parent['locally_detached_signed_copy_inventory_and_dual_receipt_consistent']
    records=[];previous_notice=None;previous_observation=None
    notice_shas=[];observation_shas=[]
    for i,refs in enumerate(epochs):
        exact(refs,EPOCH_FIELDS,'PUBLISHER_OBSERVER_EPOCH_REFS')
        nref,oref=refs['publisher_notice_original'],refs['publication_observation_original']
        ndoc=tr.strict_json(read(nref,'publisher_'+str(i),MAX_SIGNED),
                            'EC370_SIGNED_PUBLISHER_NOTICE')
        odoc=tr.strict_json(read(oref,'observer_'+str(i),MAX_SIGNED),
                            'EC370_SIGNED_PUBLICATION_OBSERVATION')
        if _signed(ndoc,'publisher',pubkey,opts,now):flags[FLAGS[7]]=True
        if _signed(odoc,'observer',observerkey,opts,now):flags[FLAGS[7]]=True
        notice_shas.append(nref['sha256']);observation_shas.append(oref['sha256'])
        for doc in (ndoc,odoc):
            if (doc['sequence']!=i or
                doc['previous_publisher_notice_original_sha256']!=previous_notice or
                doc['previous_publication_observation_original_sha256']!=previous_observation):
                flags[FLAGS[3]]=True
            if not _bounds(doc,opts,parent,doc['published_handoff_sha_pairs'],
                                          doc['published_disclosure_sha_pairs']):
                flags[FLAGS[2]]=True
            if not (_prefix(doc['published_handoff_sha_pairs'],full_hand) and
                    _prefix(doc['published_disclosure_sha_pairs'],full_disc)):
                flags[FLAGS[2]]=True
        if odoc['publisher_notice_original_sha256']!=nref['sha256']:
            flags[FLAGS[4]]=True
        if (any(ndoc[k]!=odoc[k] for k in BINDING_FIELDS) or
            ndoc['published_handoff_sha_pairs']!=odoc['published_handoff_sha_pairs'] or
            ndoc['published_disclosure_sha_pairs']!=odoc['published_disclosure_sha_pairs']):
            flags[FLAGS[4]]=True
        if ndoc['publication_state']!='published' or odoc['observation_state']!='confirmed':
            flags[FLAGS[1]]=True
        # Signed time claims are not trusted timestamps, but contradictions in
        # the parties' own purported order must remain visible.
        if tr._utc(odoc['issued_utc'])<tr._utc(ndoc['issued_utc']):
            flags[FLAGS[7]]=True
        if records:
            pprev,oprev=records[-1]
            for old,new in ((pprev,ndoc),(oprev,odoc)):
                for key in ('published_handoff_sha_pairs','published_disclosure_sha_pairs'):
                    if not _prefix(old[key],new[key]):flags[FLAGS[3]]=True
                if tr._utc(new['issued_utc'])<tr._utc(old['issued_utc']):
                    flags[FLAGS[7]]=True
        records.append((ndoc,odoc))
        previous_notice=nref['sha256'];previous_observation=oref['sha256']
    latest_pub,latest_observer=records[-1]
    if (latest_pub['published_handoff_sha_pairs']!=full_hand or
        latest_pub['published_disclosure_sha_pairs']!=full_disc or
        latest_observer['published_handoff_sha_pairs']!=full_hand or
        latest_observer['published_disclosure_sha_pairs']!=full_disc):
        flags[FLAGS[2]]=True
    complete_inventory=_inventory_hash(opts,parent,full_hand,full_disc)
    if (notice_shas!=opts['signed_publisher_notice_shas'] or
        observation_shas!=opts['signed_publication_observer_shas'] or
        notice_shas[-1]!=opts['expected_retained_publisher_notice_head_sha256'] or
        observation_shas[-1]!=opts['expected_retained_publication_observer_head_sha256'] or
        complete_inventory!=opts['expected_latest_publication_inventory_sha256'] or
        latest_pub['sequence']<opts['minimum_retained_publication_sequence'] or
        len(latest_pub['published_disclosure_sha_pairs'])<opts[
                        'minimum_retained_published_challenge_count']):
        flags[FLAGS[5]]=True
    # Explicit competing originals are verified with the same genuine signer
    # before being treated as evidence. Their presence is not silently pruned;
    # a same-sequence divergent signed original proves a *visible* fork.
    fork_counts=[]
    for key,kind,pubkey,relevant in (
        ('competing_publisher_notice_originals','publisher',pubkey,0),
        ('competing_publication_observation_originals','observer',observerkey,1)):
        seen=set();observed=0
        for i,ref in enumerate(bundle[key]):
            _ref(ref)
            need(ref['sha256'] not in seen and ref['sha256'] not in (
                    notice_shas if relevant==0 else observation_shas),
                 'COMPETING_EVIDENCE_REPEATS_SELECTED_OR_DUPLICATE_SHA')
            seen.add(ref['sha256'])
            doc=tr.strict_json(read(ref,kind+'_competing_'+str(i),MAX_SIGNED),
                               'EC370_COMPETING_SIGNED_PUBLICATION_RECORD')
            if _signed(doc,kind,pubkey,opts,now):flags[FLAGS[7]]=True
            if doc['publication_state' if relevant==0 else 'observation_state'] not in (
                    'published' if relevant==0 else 'confirmed',):
                flags[FLAGS[1]]=True
            observed+=1
            # All genuine extra statements are conflicts until their place
            # in an independently pinned, complete stream has been resolved.
            # Same-sequence/parent divergent original is specifically a fork.
            if any(doc['sequence']==selected['sequence'] and
                   doc['previous_publisher_notice_original_sha256']==selected[
                       'previous_publisher_notice_original_sha256'] and
                   doc['previous_publication_observation_original_sha256']==selected[
                       'previous_publication_observation_original_sha256']
                   for p,o in records for selected in ((p,) if relevant==0 else (o,))):
                flags[FLAGS[6]]=True
            else:
                flags[FLAGS[3]]=True
            if not _bounds(doc,opts,parent,doc['published_handoff_sha_pairs'],
                                          doc['published_disclosure_sha_pairs']):
                flags[FLAGS[2]]=True
        fork_counts.append(observed)
    tsa._check_late(pins)
    prior.previous.parent.parent.parent.parent.history.parent.previous.parent.parent._late_identity_check(
        pins,set())
    local=not any(flags.values())
    if not local:flags[FLAGS[8]]=True
    status=next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                OUTCOMES[-1])+'_unresolved'
    return {
        'schema':RESULT_SCHEMA,'command':'audit-publication-accountability',
        'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
        'publication_bundle_original_sha256':pref['sha256'],
        'detached_bundle_original_sha256':opts['expected_detached_bundle_sha256'],
        'signed_copy_map_original_sha256':opts['expected_signed_copy_map_sha256'],
        'verified_detached_audit_result_canonical_sha256':digest(
             canonical.canonical(parent)),
        'current_full_publication_inventory_canonical_sha256':complete_inventory,
        'actual_publisher_notice_shas':notice_shas,
        'actual_publication_observer_shas':observation_shas,
        'actual_publisher_notice_head_sha256':notice_shas[-1],
        'actual_publication_observer_head_sha256':observation_shas[-1],
        'true_verified_publisher_notice_ed25519_count':len(notice_shas),
        'true_verified_publication_observer_ed25519_count':len(observation_shas),
        'true_verified_competing_publisher_ed25519_count':fork_counts[0],
        'true_verified_competing_observer_ed25519_count':fork_counts[1],
        'latest_publisher_signed_state':latest_pub['publication_state'],
        'latest_publication_observer_signed_state':latest_observer['observation_state'],
        'latest_publisher_signed_handoff_count':len(latest_pub['published_handoff_sha_pairs']),
        'latest_publisher_signed_disclosure_count':len(latest_pub['published_disclosure_sha_pairs']),
        'inherited_ec369_detached_locally_consistent':bool(parent[
            'locally_detached_signed_copy_inventory_and_dual_receipt_consistent']),
        'inherited_ec369_unresolved_status':parent['status'],
        'locally_two_party_publication_and_full_inventory_consistent':bool(local),
        'original_sender_source_paths_required_or_read':False,
        'ec365_through_ec337_historical_parent_replay_performed':False,
        **flags,**{k:False for k in NEGATIVES},
    }
