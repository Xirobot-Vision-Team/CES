#!/usr/bin/env python3
"""EC361: read-only signed directory evolution and bounded independent observer gossip.

Everything here is an offline statement about caller-pinned public keys and bytes.
No official trust anchor, historical time, global latest head, remote log or
independent real-world custody is inferred from locally coherent signatures.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from authority_directory import authority as parent

RESULT_SCHEMA = 'ces.ec361.offline_directory_consistency_gossip_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec361.offline_directory_consistency_gossip_denial.v1'
HANDOFF_SCHEMA = 'ces.ec361.unsigned_directory_consistency_handoff.v1'
BUNDLE_SCHEMA = 'ces.ec361.directory_consistency_observer_bundle.v1'
OBSERVER_SCHEMA = 'ces.ec361.signed_directory_observer_receipt.v1'
OBSERVER_DOMAIN = b'CES/EC361/DirectoryObserverGossip/v1\x00'
MAX_BUNDLE = 36_000
MAX_CHECKPOINTS = 3
MAX_OBSERVERS = 2
MAX_INCLUSIONS = 4
MAX_PATH_NODES = 7
MAX_LAG = timedelta(days=7)
MAX_OBSERVER_SPAN = timedelta(days=7)
BUNDLE_FIELDS = {'schema','checkpoint_originals','consistency_proofs',
                 'observer_receipt_originals','head_inclusions'}
CONSISTENCY_FIELDS = {'older_checkpoint_sha256','newer_checkpoint_sha256',
                      'audit_path_sha256'}
INCLUSION_FIELDS = {'original_sha256','leaf_index','audit_path_sha256'}
OBSERVER_FIELDS = {'schema','slot','claimed_observer_id',
                   'observer_public_key_original_sha256',
                   'directory_public_key_original_sha256',
                   'directory_id','parent_ec360_canonical_result_sha256',
                   'parent_directory_checkpoint_original_sha256',
                   'observed_checkpoint_original_sha256',
                   'observed_tree_size','observed_root_sha256',
                   'observed_utc','expires_utc',
                   'signature_observer_ed25519_hex'}

OUTCOMES = (
    'ec361_ec360_parent_not_locally_verified',
    'ec361_parent_anchor_or_caller_pins_or_originals_missing',
    'ec361_visible_signed_directory_same_size_split_view',
    'ec361_rfc6962_consistency_missing_or_invalid',
    'ec361_caller_retained_head_or_minimum_tree_size_rollback',
    'ec361_observer_receipts_missing_divergent_or_identity_collision',
    'ec361_current_signed_directory_head_inclusion_missing_or_invalid',
    'ec361_self_reported_signed_time_outside_window',
    'ec361_locally_consistent_signed_checkpoints_and_gossip_official_provenance_unproven',
)
NEGATIVES = (
    'locally_signed_directory_proves_official_public_log_identity',
    'observer_key_diversity_proves_two_real_independent_organizations',
    'observer_receipts_prove_globally_latest_directory_checkpoint',
    'signed_directory_times_are_trusted_historical_utc',
    'rfc6962_local_consistency_proves_undisclosed_forks_absent',
    'local_consistency_repairs_parent_ec360_or_earlier_evidence',
    'offline_auditor_fetches_network_or_os_trust_roots',
    'offline_auditor_creates_private_signatures_or_remote_cas_worm_writes',
    'native_powershell_deep_mock_or_final_acceptance_proven',
)


def need(ok, code, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC361_' + code, status)


def exact(obj, fields, role):
    need(type(obj) is dict and set(obj) == set(fields),
         role + '_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return parent.sha(raw)


def pin_pair(path, digest, role):
    parent.outer_pin(path, digest, role)


def hashes(value, role):
    need(type(value) is list and len(value) <= MAX_PATH_NODES and
         all(tr._sha(x) for x in value), role + '_BOUNDED_RFC6962_PATH_REQUIRED')
    return [bytes.fromhex(x) for x in value]


def check_old_parent(authority_inputs, prior):
    """Reopen every furnished EC360 original and every earlier role/key.

    Prior audit has already done true EC359..337 replay; these second reads
    provide independent file-role, SHA and late TOCTOU boundaries for EC361.
    """
    oldpins, oldpaths, oldkeys = parent.parent_boundary(authority_inputs)
    inherited = parent.previous.parent.parent.prior._inherited
    parent_originals = {}
    directory_key = None
    parent_cp = None

    for role, kpath, ksha in (
        ('ROOT_A','authority_a_root_public_key_file','expected_authority_a_root_public_key_sha256'),
        ('ROOT_B','authority_b_root_public_key_file','expected_authority_b_root_public_key_sha256'),
        ('ORIGIN_A','origin_a_witness_public_key_file','expected_origin_a_witness_public_key_sha256'),
        ('ORIGIN_B','origin_b_witness_public_key_file','expected_origin_b_witness_public_key_sha256'),
        ('DIRECTORY','directory_public_key_file','expected_directory_public_key_sha256'),
    ):
        path, digest = authority_inputs.get(kpath), authority_inputs.get(ksha)
        if path is not None and digest is not None:
            raw = inherited({'path':path,'sha256':digest},
                            'EC361_OLD_' + role, 32, oldpins)
            need(len(raw)==32, 'PARENT_SIGNER_KEY_NOT_32_BYTES', 'permission_denied')
            oldpaths.add(path)
            oldkeys.add(sha(raw))
            if role=='DIRECTORY':
                directory_key=raw

    bundle_path=authority_inputs.get('authority_bundle_file')
    bundle_sha=authority_inputs.get('expected_authority_bundle_sha256')
    if bundle_path is not None and bundle_sha is not None:
        raw=inherited({'path':bundle_path,'sha256':bundle_sha},
                      'EC361_PARENT_AUTHORITY_BUNDLE',parent.MAX_BUNDLE,oldpins)
        oldpaths.add(bundle_path)
        doc=tr.strict_json(raw,'EC361_PARENT_AUTHORITY_BUNDLE')
        exact(doc,('schema','sources'),'PARENT_AUTHORITY_BUNDLE')
        need(doc['schema']==parent.BUNDLE_SCHEMA,
             'PARENT_AUTHORITY_BUNDLE_SCHEMA_INVALID','permission_denied')
        for entry in doc['sources']:
            # Read all shown branches, not only the selected revocation head.
            for fld,cap in (('authority_root_public_key',32),
                            ('origin_witness_public_key',32),
                            ('origin_original',parent.MAX_ORIGINAL),
                            ('delegation_original',parent.MAX_ORIGINAL)):
                ref=entry[fld]
                content=inherited(ref,'EC361_PARENT_'+fld.upper(),cap,oldpins)
                oldpaths.add(ref['path'])
                if fld.endswith('public_key'):oldkeys.add(sha(content))
                if fld=='delegation_original':parent_originals[sha(content)]=content
            for ref in entry['revocation_snapshot_originals']:
                content=inherited(ref,'EC361_PARENT_REVOCATION',
                                  parent.MAX_ORIGINAL,oldpins)
                oldpaths.add(ref['path'])
                if ref['sha256']==authority_inputs.get(
                        'expected_'+entry['slot']+'_revocation_head_sha256'):
                    parent_originals[sha(content)]=content

    cpfile=authority_inputs.get('directory_checkpoint_file')
    cpsha=authority_inputs.get('expected_directory_checkpoint_sha256')
    if cpfile is not None and cpsha is not None and directory_key is not None:
        cpraw=inherited({'path':cpfile,'sha256':cpsha},
                        'EC361_PARENT_SIGNED_CHECKPOINT',parent.MAX_ORIGINAL,oldpins)
        oldpaths.add(cpfile)
        parent_cp=parent.directory_checkpoint(
            cpraw,directory_key,
            authority_inputs['expected_directory_public_key_sha256'],
            tr._utc(authority_inputs['authority_evaluation_utc']))[0]
        need(sha(cpraw)==prior['directory_checkpoint_original_sha256'],
             'PARENT_CHECKPOINT_NOT_BOUND_TO_TRUE_EC360_RESULT',
             'permission_denied')

    # Only the exactly four originals selected by the *real* parent count.
    approved=set()
    for row in prior['authority_reviews']:
        approved.add(row['delegation_original_sha256'])
        if row['selected_revocation_head_sha256'] is not None:
            approved.add(row['selected_revocation_head_sha256'])
    originals={digest:parent_originals[digest] for digest in approved
               if digest in parent_originals}
    return oldpins,oldpaths,oldkeys,directory_key,parent_cp,originals


def signed_checkpoint(raw, key, key_sha, parent_id, evaluation):
    doc, stale = parent.directory_checkpoint(raw,key,key_sha,evaluation)
    need(doc['directory_id']==parent_id,
         'NEW_CHECKPOINT_DIRECTORY_ID_MUST_MATCH_PARENT','permission_denied')
    return doc, stale


def read_consistency(proofs, checkpoints):
    """Verify each adjacent distinct-size signed checkpoint, including parent.

    All provided signed same-size divergent roots are observed before choosing a
    head; proof selection cannot hide a split view. Nonadjacent/repeated edges
    are invalid input rather than silently ignored.
    """
    need(type(proofs) is list and len(proofs)<=MAX_CHECKPOINTS+1,
         'CONSISTENCY_PROOF_COUNT_OUT_OF_BOUNDS')
    by_size=defaultdict(list)
    for digest,doc in checkpoints.items():
        by_size[doc['tree_size']].append((digest,doc))
    split=any(len({doc['root_sha256'] for _,doc in nodes})>1
              for nodes in by_size.values())
    sizes=sorted(by_size)
    expected_pairs={(sizes[i],sizes[i+1]) for i in range(len(sizes)-1)}
    # Allow a proof to refer to *any* genuinely signed checkpoint at each
    # adjacent size. A contradictory same-size sibling is separately flagged
    # as split-view regardless of which sibling the proof tries to favor.
    if not expected_pairs:
        need(proofs==[], 'CONSISTENCY_PROOF_WITH_NO_SIZE_EVOLUTION')
        return split,False
    observed=set();invalid=False
    for proof in proofs:
        exact(proof,CONSISTENCY_FIELDS,'CONSISTENCY_PROOF')
        a,b=proof['older_checkpoint_sha256'],proof['newer_checkpoint_sha256']
        path=hashes(proof['audit_path_sha256'],'CONSISTENCY')
        need(tr._sha(a) and tr._sha(b) and a in checkpoints and b in checkpoints,
             'CONSISTENCY_CHECKPOINT_REFERENCE_NOT_FURNISHED')
        old,new=checkpoints[a],checkpoints[b]
        size_edge=(old['tree_size'],new['tree_size'])
        need(size_edge in expected_pairs and size_edge not in observed,
             'CONSISTENCY_EDGE_MUST_BE_ADJACENT_DISTINCT_AND_UNIQUE')
        observed.add(size_edge)
        invalid |= not tr.verify_consistency(
            old['tree_size'],new['tree_size'],
            bytes.fromhex(old['root_sha256']),
            bytes.fromhex(new['root_sha256']),path)
    return split, bool(observed==expected_pairs and not invalid and not split)



def verify_head_inclusions(proofs, originals, head):
    if head is None or len(originals)!=MAX_INCLUSIONS:
        need(type(proofs) is list and len(proofs)<=MAX_INCLUSIONS,
             'HEAD_INCLUSIONS_OUT_OF_BOUNDS')
        return False
    need(type(proofs) is list and len(proofs)<=MAX_INCLUSIONS,
         'HEAD_INCLUSIONS_OUT_OF_BOUNDS')
    used=set();all_valid=True
    for proof in proofs:
        exact(proof,INCLUSION_FIELDS,'HEAD_INCLUSION')
        digest=proof['original_sha256']
        index=proof['leaf_index']
        path=hashes(proof['audit_path_sha256'],'HEAD_INCLUSION')
        need(tr._sha(digest) and digest in originals and digest not in used and
             type(index) is int and 0<=index<head['tree_size'],
             'HEAD_INCLUSION_ORIGINAL_INDEX_OR_DUPLICATE_INVALID')
        used.add(digest)
        if not tr.verify_inclusion(tr.leaf_hash(originals[digest]),
               index,head['tree_size'],bytes.fromhex(head['root_sha256']),path):
            all_valid=False
    return bool(len(used)==len(originals) and all_valid)


def signed_observer(raw, public, expected_pub_sha, slot, parent_result_sha,
                    parent_head_sha, checkpoints, now):
    doc=tr.strict_json(raw,'EC361_OBSERVER_RECEIPT')
    exact(doc,OBSERVER_FIELDS,'OBSERVER_RECEIPT')
    need(doc['schema']==OBSERVER_SCHEMA and doc['slot']==slot and
         tr._ident(doc['claimed_observer_id']) and
         doc['observer_public_key_original_sha256']==expected_pub_sha and
         tr._sha(doc['observed_checkpoint_original_sha256']) and
         doc['parent_ec360_canonical_result_sha256']==parent_result_sha and
         doc['parent_directory_checkpoint_original_sha256']==parent_head_sha,
         'OBSERVER_GOSSIP_MUST_BIND_PARENT_AND_CALLER_PINNED_ROLE',
         'permission_denied')
    candidate=checkpoints.get(doc['observed_checkpoint_original_sha256'])
    need(candidate is not None,'OBSERVER_REFERENCED_SIGNED_HEAD_NOT_FURNISHED',
         'permission_denied')
    need(doc['directory_id']==candidate['directory_id'] and
         doc['observed_tree_size']==candidate['tree_size'] and
         doc['observed_root_sha256']==candidate['root_sha256'] and
         doc['directory_public_key_original_sha256']==
             candidate['directory_public_key_original_sha256'],
         'OBSERVER_TRUE_SIGNED_HEAD_FIELDS_MUST_MATCH','permission_denied')
    start,end=parent.window(doc['observed_utc'],doc['expires_utc'],
                            MAX_OBSERVER_SPAN,'EC361_OBSERVER')
    parent.sig(doc,'signature_observer_ed25519_hex',public,
               OBSERVER_DOMAIN,'EC361_OBSERVER')
    return doc,parent.utc_untrusted(now,start,end,MAX_LAG)


def checklist(**authority_inputs):
    # Derive still performs a genuine parent EC360->EC337 audit, not a cached
    # "passed" JSON. Missing parent evidence cannot become a verified handoff.
    prior=parent.audit(**authority_inputs)
    need(prior['schema']==parent.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec359_through_ec337_signed_originals_replayed'] is True,
         'REAL_EC360_PARENT_REPLAY_REQUIRED','permission_denied')
    return {
        'schema':HANDOFF_SCHEMA,
        'command':'derive-directory-consistency-handoff',
        'status':'caller_must_supply_chain_external_signed_checkpoints_and_observers_unresolved',
        'exit_code':2,'case_id':prior['case_id'],
        'actual_ec360_through_ec337_signed_originals_replayed':True,
        'parent_ec360_canonical_result_sha256':sha(canonical.canonical(prior)),
        'parent_directory_checkpoint_original_sha256':
            prior['directory_checkpoint_original_sha256'],
        'required_chain_external_inputs':[
            'signed directory checkpoint originals with caller SHA pins',
            'RFC6962 append-only consistency for every adjacent distinct tree size',
            'two separately caller SHA-pinned observer public keys and true signed head receipts',
            'caller-retained minimum tree size and exact newest head SHA',
            'four true EC360 delegation/revocation original inclusion proofs at chosen head'],
        'outside_official_origin_history_and_global_head_not_proven':True,
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES},
    }


def audit(*,consistency_evaluation_utc,
          consistency_bundle_file=None,expected_consistency_bundle_sha256=None,
          observer_a_public_key_file=None,expected_observer_a_public_key_sha256=None,
          observer_b_public_key_file=None,expected_observer_b_public_key_sha256=None,
          minimum_consistent_directory_tree_size=None,
          expected_latest_consistent_directory_checkpoint_sha256=None,
          expected_evolved_checkpoint_1_sha256=None,
          expected_evolved_checkpoint_2_sha256=None,
          expected_evolved_checkpoint_3_sha256=None,
          **authority_inputs):
    now=tr._utc(consistency_evaluation_utc)
    need(now>=tr._utc(authority_inputs['authority_evaluation_utc']),
         'EVALUATION_PRECEDES_TRUE_EC360_PARENT','permission_denied')
    # Genuine original signatures and Merkle evidence EC360 -> EC337, every call.
    prior=parent.audit(**authority_inputs)
    need(prior['schema']==parent.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec359_through_ec337_signed_originals_replayed'] is True,
         'REAL_EC360_THROUGH_EC337_REPLAY_REQUIRED','permission_denied')
    parent_result_sha=sha(canonical.canonical(prior))
    oldpins,oldpaths,oldkeys,directory_key,anchor,originals=check_old_parent(
        authority_inputs,prior)
    anchor_sha=prior['directory_checkpoint_original_sha256']
    parent_good=bool(prior['two_sources_directory_inclusion_locally_verified'] and
                     anchor_sha is not None and anchor is not None and
                     len(originals)==MAX_INCLUSIONS)
    pins={
        'a':(observer_a_public_key_file,expected_observer_a_public_key_sha256),
        'b':(observer_b_public_key_file,expected_observer_b_public_key_sha256)}
    for slot,pair in pins.items():pin_pair(*pair,'OBSERVER_'+slot.upper())
    pin_pair(consistency_bundle_file,expected_consistency_bundle_sha256,
             'CONSISTENCY_BUNDLE')
    need(minimum_consistent_directory_tree_size is None or
         (type(minimum_consistent_directory_tree_size) is int and
          1<=minimum_consistent_directory_tree_size<=parent.MAX_DIRECTORY_LEAVES),
         'CALLER_MINIMUM_SIZE_INVALID')
    head_sha=expected_latest_consistent_directory_checkpoint_sha256
    need(head_sha is None or tr._sha(head_sha),'CALLER_LATEST_HEAD_SHA_INVALID')
    caller_evolved=[v for v in (
        expected_evolved_checkpoint_1_sha256,
        expected_evolved_checkpoint_2_sha256,
        expected_evolved_checkpoint_3_sha256) if v is not None]
    need(all(tr._sha(v) for v in caller_evolved) and
         len(set(caller_evolved))==len(caller_evolved),
         'EACH_EVOLVED_CHECKPOINT_REQUIRES_DISTINCT_EXTERNAL_SHA')
    newpins={};categories={};seenkeys=set(oldkeys)
    checkpoints={anchor_sha:anchor} if anchor is not None else {}
    checkpoint_rows=[];receipts=[];proofs=[];inclusions=[]
    flags={'missing':False,'split':False,'consistency':False,'rollback':False,
           'gossip':False,'inclusion':False,'clock':False}
    if consistency_bundle_file is not None:
        raw=parent.load({'path':consistency_bundle_file,
                    'sha256':expected_consistency_bundle_sha256},
                    'CONSISTENCY_BUNDLE',MAX_BUNDLE,newpins,oldpaths,
                    categories,'manifest')
        doc=tr.strict_json(raw,'EC361_CONSISTENCY_BUNDLE')
        exact(doc,BUNDLE_FIELDS,'CONSISTENCY_BUNDLE')
        need(doc['schema']==BUNDLE_SCHEMA and
             type(doc['checkpoint_originals']) is list and
             len(doc['checkpoint_originals'])<=MAX_CHECKPOINTS and
             type(doc['observer_receipt_originals']) is list and
             len(doc['observer_receipt_originals'])<=MAX_OBSERVERS,
             'CONSISTENCY_BUNDLE_SCHEMA_OR_LIMIT_INVALID')
        proofs=doc['consistency_proofs']
        inclusions=doc['head_inclusions']
        for ref in doc['checkpoint_originals']:
            raw_cp=parent.load(ref,'EVOLVED_SIGNED_CHECKPOINT',parent.MAX_ORIGINAL,
                               newpins,oldpaths,categories,'checkpoint')
            digest=sha(raw_cp)
            need(digest not in checkpoints,'DUPLICATE_OR_REUSED_CHECKPOINT_ORIGINAL',
                 'permission_denied')
            need(anchor is not None and directory_key is not None,
                 'CANNOT_VERIFY_CHECKPOINT_WITHOUT_PARENT_SIGNER',
                 'permission_denied')
            cp,stale=signed_checkpoint(raw_cp,directory_key,
                   authority_inputs['expected_directory_public_key_sha256'],
                   anchor['directory_id'],now)
            checkpoints[digest]=cp
            checkpoint_rows.append({'checkpoint_original_sha256':digest,
                'tree_size_as_signed_claim':cp['tree_size'],
                'root_sha256_as_signed_claim':cp['root_sha256'],
                'signed_clock_anomaly':stale})
            flags['clock'] |= stale
        # SHA values in the bundle are NOT themselves a caller-held trust pin.
        # Reconcile the complete visible checkpoint set with separately supplied
        # values held outside this manifest; never accept an unpinned signed fork.
        visible_new_shas={ref['sha256'] for ref in doc['checkpoint_originals']}
        if not caller_evolved or visible_new_shas!=set(caller_evolved):
            flags['missing']=True
        seen_slots=set();seen_ids=set()
        for ref in doc['observer_receipt_originals']:
            raw_obs=parent.load(ref,'SIGNED_GOSSIP_RECEIPT',parent.MAX_ORIGINAL,
                      newpins,oldpaths,categories,'observer_receipt')
            receipt=tr.strict_json(raw_obs,'EC361_RECEIPT_SLOT_PEEK')
            need(type(receipt) is dict and receipt.get('slot') in ('a','b'),
                 'OBSERVER_SLOT_MISSING_OR_INVALID')
            slot=receipt['slot']
            need(slot not in seen_slots,'OBSERVER_SLOT_REUSED','permission_denied')
            seen_slots.add(slot)
            path,keysha=pins[slot]
            need(path is not None,'SIGNED_OBSERVER_MUST_HAVE_CHAIN_EXTERNAL_KEY_PIN',
                 'permission_denied')
            pub=parent.key_file(path,keysha,'OBSERVER_'+slot,
                                newpins,oldpaths,categories,seenkeys)
            r,stale=signed_observer(raw_obs,pub,keysha,slot,parent_result_sha,
                                   anchor_sha,checkpoints,now)
            if r['claimed_observer_id'] in seen_ids:flags['gossip']=True
            seen_ids.add(r['claimed_observer_id'])
            flags['clock']|=stale
            receipts.append({'slot':slot,
               'claimed_observer_id_unverified':r['claimed_observer_id'],
               'observer_public_key_sha256':keysha,
               'receipt_original_sha256':sha(raw_obs),
               'observed_checkpoint_original_sha256':
                   r['observed_checkpoint_original_sha256'],
               'signed_clock_anomaly':stale})
        if len(seen_slots)!=2:flags['gossip']=True
    else:
        flags['missing']=True
    if anchor is None or anchor_sha not in checkpoints:
        flags['missing']=True
    if len(checkpoints)<2:flags['missing']=True
    if anchor is not None and checkpoints:
        flags['split'],good_consistency=read_consistency(proofs,checkpoints)
        flags['consistency']=not good_consistency
    else:
        good_consistency=False
        flags['consistency']=True
    selected=checkpoints.get(head_sha)
    if head_sha is None or minimum_consistent_directory_tree_size is None:
        flags['missing']=True
    elif selected is None:
        flags['missing']=True
        # Unseen explicitly saved head must never silently fall back to another.
        flags['rollback']=True
    else:
        flags['rollback']|=(selected['tree_size']<
                            minimum_consistent_directory_tree_size)
        flags['rollback']|=any(cp['tree_size']>selected['tree_size']
                               for cp in checkpoints.values())
        if anchor is not None:
            flags['rollback']|=selected['tree_size']<anchor['tree_size']
    inclusion_good=verify_head_inclusions(inclusions,originals,selected)
    flags['inclusion']=not inclusion_good
    gossip_good=(len(receipts)==2 and
                 len({r['observer_public_key_sha256'] for r in receipts})==2 and
                 head_sha is not None and
                 all(r['observed_checkpoint_original_sha256']==head_sha
                     for r in receipts))
    flags['gossip']|=not gossip_good
    if selected is not None:
        start,end=parent.window(selected['issued_utc'],selected['expires_utc'],
                                parent.MAX_DIRECTORY_SPAN,'SELECTED_DIRECTORY')
        flags['clock']|=parent.utc_untrusted(now,start,end,MAX_LAG)
    if anchor is not None:
        start,end=parent.window(anchor['issued_utc'],anchor['expires_utc'],
                                parent.MAX_DIRECTORY_SPAN,'PARENT_DIRECTORY')
        flags['clock']|=parent.utc_untrusted(now,start,end,MAX_LAG)
    # Late re-read all child + parent pinned SHA/original bytes and inode/ancestors.
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    parent.previous.parent.parent._late_identity_check(newpins,oldpaths)
    local_consistent=bool(parent_good and len(checkpoints)>=2 and
        good_consistency and gossip_good and inclusion_good and
        not any(flags.values()))
    if not parent_good:outcome=OUTCOMES[0]
    elif flags['missing']:outcome=OUTCOMES[1]
    elif flags['split']:outcome=OUTCOMES[2]
    elif flags['consistency']:outcome=OUTCOMES[3]
    elif flags['rollback']:outcome=OUTCOMES[4]
    elif flags['gossip']:outcome=OUTCOMES[5]
    elif flags['inclusion']:outcome=OUTCOMES[6]
    elif flags['clock']:outcome=OUTCOMES[7]
    else:outcome=OUTCOMES[8]
    evidence=[{'tsa_channel_id':r['tsa_channel_id'],
         'parent_ec360_outcome':r['outcome'],'outcome':outcome}
         for r in prior['channel_evidence']]
    return {
        'schema':RESULT_SCHEMA,'command':'audit-directory-consistency',
        'status':outcome+'_unresolved','exit_code':2,'case_id':prior['case_id'],
        'actual_ec360_through_ec337_signed_originals_replayed':True,
        'parent_ec360_canonical_result_sha256':parent_result_sha,
        'parent_directory_checkpoint_original_sha256':anchor_sha,
        'consistency_bundle_original_sha256':expected_consistency_bundle_sha256,
        'consistency_evaluation_utc_as_caller_claim':consistency_evaluation_utc,
        'signed_checkpoint_reviews':checkpoint_rows,
        'signed_checkpoint_count_including_parent':len(checkpoints),
        'observer_reviews':receipts,'observer_review_count':len(receipts),
        'expected_latest_checkpoint_sha256_as_caller_pin':head_sha,
        'evolved_checkpoint_shas_as_separate_caller_pins':caller_evolved,
        'selected_head_tree_size_as_signed_claim':
            selected['tree_size'] if selected is not None else None,
        'minimum_tree_size_as_caller_pin':minimum_consistent_directory_tree_size,
        'ec360_parent_signed_directory_inclusion_verified':parent_good,
        'external_checkpoints_observers_or_saved_head_missing':flags['missing'],
        'visible_signed_same_size_checkpoint_split_view':flags['split'],
        'rfc6962_append_only_consistency_missing_or_invalid':flags['consistency'],
        'caller_saved_head_or_minimum_tree_size_rollback':flags['rollback'],
        'two_observer_signed_head_gossip_missing_or_divergent':flags['gossip'],
        'selected_signed_head_original_inclusions_missing_or_invalid':flags['inclusion'],
        'signed_utc_claims_stale_or_future':flags['clock'],
        'signed_directory_append_only_locally_verified':
            bool(good_consistency and not flags['split'] and len(checkpoints)>=2),
        'two_distinct_observer_keys_agree_on_head_locally':
            bool(gossip_good and not flags['gossip']),
        'four_parent_originals_in_selected_head_locally_verified':inclusion_good,
        'locally_coherent_signed_directory_evolution_and_gossip':local_consistent,
        'official_origin_legal_observer_independence_trusted_time_and_global_latest_unproven':True,
        'channel_evidence':evidence,
        'outcome_counts':{o:sum(r['outcome']==o for r in evidence) for o in OUTCOMES},
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES},
    }
