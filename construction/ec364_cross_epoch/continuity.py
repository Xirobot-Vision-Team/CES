#!/usr/bin/env python3
"""EC364: offline, true-crypto replay of separately retained EC361 publication windows.

A historic window is NOT a caller-provided 'passed' assertion: it must contain
all EC362 original-audit arguments and each audit replays EC361..EC337.
EC363 current-window challenge/disclosure is independently replayed as well.
A bridge is signed by BOTH actual endpoint custodians; verified directory
checkpoint append-only proofs and two observer claims are examined separately.
Neither a pinned key nor a signed claimed clock proves a public legal identity,
global history, real physical custody, or a trusted historical timestamp.
All lawful answers have exit code 2 / unresolved. This code is read-only.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
import re

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec360_authority_directory import authority as auth
from ec361_directory_consistency import consistency
from ec362_publication_custody import custody
from ec363_source_history import history

SLOTS = ('a', 'b')
RESULT_SCHEMA = 'ces.ec364.offline_cross_epoch_publisher_continuity_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec364.offline_cross_epoch_publisher_continuity_denial.v1'
HANDOFF_SCHEMA = 'ces.ec364.unsigned_cross_epoch_continuity_handoff.v1'
BUNDLE_SCHEMA = 'ces.ec364.pinned_cross_epoch_publication_windows.v1'
SNAPSHOT_SCHEMA = 'ces.ec364.historical_ec362_replay_inputs.v1'
TRANSITION_SCHEMA = 'ces.ec364.dual_custodian_cross_epoch_transition.v1'
TRANSITION_DOMAIN = b'CES/EC364/DualCustodianCrossEpochTransition/v1\x00'
MAX_BUNDLE = 24_000
MAX_SNAPSHOT = 80_000
MAX_TRANSITION = 8_000
MAX_EPOCHS = 2
MAX_TRANSITIONS = 8
MAX_EPOCH_INDEX = 2
MAX_PATH = 8
MAX_SPAN = timedelta(days=7)
BUNDLE_FIELDS = {'schema','current_ec363_canonical_result_sha256',
    'historical_parent_snapshots','signed_source_transitions',
    'directory_window_proofs'}
SNAPSHOT_FIELDS = {'schema','epoch_index','ec362_audit_inputs'}
TRANSITION_FIELDS = {'schema','source_slot','claimed_source_id',
    'from_epoch_index','to_epoch_index','event_kind',
    'from_parent_ec361_canonical_result_sha256',
    'to_parent_ec361_canonical_result_sha256',
    'from_manifest_original_sha256','to_manifest_original_sha256',
    'from_custodian_public_key_original_sha256',
    'to_custodian_public_key_original_sha256',
    'from_checkpoint_original_sha256','to_checkpoint_original_sha256',
    'issued_utc','expires_utc','signature_old_custodian_ed25519_hex',
    'signature_new_custodian_ed25519_hex'}
PROOF_FIELDS = {'from_epoch_index','to_epoch_index',
    'older_checkpoint_original_sha256','newer_checkpoint_original_sha256',
    'audit_path_sha256'}
NEW_OPTIONAL = (
    'cross_epoch_bundle_file','expected_cross_epoch_bundle_sha256',
    'minimum_retained_historical_epoch_count',
    'expected_retained_oldest_ec362_result_sha256',
    'expected_retained_current_ec362_result_sha256',
    'minimum_retained_directory_tree_size',
)
NEW_REPEATS = (
    ('historical_ec362_snapshot_shas','--historical-ec362-snapshot-sha256'),
    ('signed_source_epoch_transition_shas','--signed-source-epoch-transition-sha256'),
)
NEW_REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
OUTCOMES = (
    'ec364_parent_ec363_disclosures_not_locally_coherent',
    'ec364_historical_parent_windows_not_locally_coherent',
    'ec364_contradictory_dual_signed_transition_or_epoch_fork',
    'ec364_caller_retained_epochs_or_directory_head_regressed',
    'ec364_cross_epoch_source_or_signer_role_collision',
    'ec364_verified_directory_checkpoint_cross_window_conflict',
    'ec364_cross_window_rfc6962_consistency_missing_or_invalid',
    'ec364_signed_termination_blocks_later_publication',
    'ec364_signed_observer_or_publisher_timeline_contradiction',
    'ec364_historical_parent_snapshot_or_transition_missing',
    'ec364_cross_epoch_signed_continuity_locally_reconciled_external_trust_unproven',
)
NEGATIVES = (
    'cross_epoch_local_keys_prove_actual_public_publisher_identity',
    'historical_snapshot_claim_of_passing_substitutes_for_true_parent_crypto',
    'dual_signatures_establish_real_legal_or_physical_independence',
    'signed_transition_recovers_a_terminated_or_revoked_source',
    'one_valid_checkpoint_path_proves_global_untampered_history',
    'cross_window_observer_claims_are_trusted_historical_utc',
    'same_parent_ec363_history_is_silently_treated_as_cross_epoch_evidence',
    'unverified_directory_signer_rotation_is_authorized',
    'auditor_fetches_network_or_system_trust_store',
    'auditor_generates_private_keys_or_writes_remote_provider_cas_worm',
    'old_powershell_deep_mock_or_final_human_acceptance_proven',
)
FLAG_MAP = (
    ('historical_parent_windows_not_locally_coherent','old_parent'),
    ('dual_signed_transition_or_epoch_fork','equivocation'),
    ('caller_retained_epoch_or_tree_regression','rollback'),
    ('publisher_signer_role_collision','role'),
    ('directory_signed_cross_window_fork','fork'),
    ('cross_window_consistency_proof_missing_or_invalid','proof'),
    ('signed_terminal_source_event_visible','terminated'),
    ('signed_witness_or_publisher_timeline_anomaly','clock'),
    ('caller_pinned_epoch_or_transition_material_missing','missing'),
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC364_'+code,status)


def exact(value,fields,label):
    need(type(value) is dict and set(value)==set(fields),
         label+'_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return history.sha(raw)


def ref_check(ref,role):
    exact(ref,('path','sha256'),role)
    need(type(ref['path']) is str and tr._sha(ref['sha256']),
         role+'_PATH_AND_SHA_REQUIRED')


def _parent_inputs(inputs):
    return {k:v for k,v in inputs.items() if
            k not in NEW_OPTIONAL and k not in NEW_REPEAT_NAMES}


def _ec362_inputs(inputs):
    return {k:v for k,v in inputs.items() if
            k!='history_evaluation_utc' and k not in history.NEW_OPTIONAL and
            k not in history.NEW_REPEAT_NAMES}


def _raw_ref(ref,role,cap,pins):
    # This inherited loader enforces absolute path, no symlink ancestors,
    # regular file and exact SHA, without requiring old files to be distinct
    # across historical parent audits (read-only unchanged ancestors may recur).
    inherited=history.parent.previous.parent.parent.prior._inherited
    return inherited(ref,'EC364_'+role,cap,pins)


def _dual_signature(doc,old_pub,new_pub):
    keys=('signature_old_custodian_ed25519_hex',
          'signature_new_custodian_ed25519_hex')
    need(all(type(doc[k]) is str and tr.SIG_RE.fullmatch(doc[k])
             for k in keys),'SIGNED_TRANSITION_SIGNATURE_FORMAT_INVALID',
         'permission_denied')
    body=TRANSITION_DOMAIN+canonical.canonical({k:v for k,v in doc.items()
                                                if k not in keys})
    for role,pub,signature in (
            ('OLD',old_pub,doc[keys[0]]),('NEW',new_pub,doc[keys[1]])):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(
                bytes.fromhex(signature),body)
        except (InvalidSignature,TypeError,ValueError) as exc:
            raise errors.AnchorError('EC364_'+role+'_CUSTODIAN_TRUE_SIGNATURE_INVALID',
                                     'permission_denied') from exc


def _epoch(index,inputs,prior,now,pins):
    need(prior['schema']==custody.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec361_through_ec337_signed_originals_replayed'] is True,
         'HISTORICAL_EC362_PARENT_REAL_CRYPTO_REPLAY_REQUIRED','permission_denied')
    sources={};heads=set()
    for slot in SLOTS:
        manifest_ref={'path':inputs.get('source_'+slot+'_publication_manifest_file'),
            'sha256':inputs.get('expected_source_'+slot+'_publication_manifest_sha256')}
        raw=_raw_ref(manifest_ref,'WINDOW_'+str(index)+'_'+slot+'_MANIFEST',
                     custody.MAX_MANIFEST,pins)
        m=tr.strict_json(raw,'EC364_WINDOW_'+slot+'_MANIFEST')
        exact(m,custody.MANIFEST_FIELDS,'WINDOW_PUBLISHED_MANIFEST')
        need(m['schema']==custody.MANIFEST_SCHEMA and m['source_slot']==slot and
             sha(raw)==manifest_ref['sha256'] and
             m['parent_ec361_canonical_result_sha256']==
                prior['parent_ec361_canonical_result_sha256'] and
             m['custodian_public_key_original_sha256']==
                inputs['expected_source_'+slot+'_custody_public_key_sha256'],
             'WINDOW_PARENT_OR_SIGNED_CUSTODIAN_MISMATCH','permission_denied')
        exact(m['copies'],custody.COPY_ROLES,'WINDOW_SIGNED_COPY_ROLES')
        key_ref={'path':inputs['source_'+slot+'_custody_public_key_file'],
             'sha256':inputs['expected_source_'+slot+'_custody_public_key_sha256']}
        pub=_raw_ref(key_ref,'WINDOW_'+str(index)+'_'+slot+'_CUSTODIAN',32,pins)
        need(len(pub)==32,'WINDOW_CUSTODIAN_KEY_LENGTH_INVALID','permission_denied')
        auth.sig(m,'signature_custodian_ed25519_hex',pub,custody.DOMAIN,
                 'EC364_RECHECK_WINDOW_MANIFEST_'+slot)
        cp_ref=m['copies']['checkpoint']
        cp_raw=_raw_ref(cp_ref,'WINDOW_'+str(index)+'_'+slot+'_CHECKPOINT',
                        custody.COPY_CAPS['checkpoint'],pins)
        directory_key=_raw_ref({'path':inputs['directory_public_key_file'],
                'sha256':inputs['expected_directory_public_key_sha256']},
                'WINDOW_'+str(index)+'_DIRECTORY_KEY',32,pins)
        cp,stale=consistency.signed_checkpoint(cp_raw,directory_key,
              inputs['expected_directory_public_key_sha256'],m['directory_id'],now)
        need(m['advertised_checkpoint_original_sha256']==sha(cp_raw) and
             m['advertised_checkpoint_original_sha256']==cp_ref['sha256'] and
             m['advertised_tree_size']==cp['tree_size'] and
             m['advertised_root_sha256']==cp['root_sha256'],
             'RECHECK_SIGNED_DIRECTORY_OR_MANIFEST_HEAD_DIFFERS',
             'permission_denied')
        # Each EC362 replay already checks the four exact copied originals,
        # both observer signature keys, their claims and parent EC361 result.
        observer_claims={}
        for obs in SLOTS:
            obs_raw=_raw_ref(m['copies']['observer_'+obs+'_receipt'],
                'WINDOW_'+str(index)+'_OBSERVER_'+obs,
                custody.COPY_CAPS['observer_'+obs+'_receipt'],pins)
            ob=tr.strict_json(obs_raw,'EC364_WINDOW_OBSERVER_'+obs)
            exact(ob,consistency.OBSERVER_FIELDS,'WINDOW_OBSERVER')
            need(ob['slot']==obs and
                 ob['observed_checkpoint_original_sha256']==cp_ref['sha256'] and
                 ob['observed_tree_size']==cp['tree_size'] and
                 ob['observed_root_sha256']==cp['root_sha256'],
                 'WINDOW_OBSERVER_CLAIM_DOES_NOT_MATCH_SIGNED_HEAD',
                 'permission_denied')
            observer_claims[obs]=ob['observed_utc']
        sources[slot]={'manifest':m,'manifest_sha':manifest_ref['sha256'],
            'pub':pub,'key_sha':key_ref['sha256'],'cp':cp,
            'cp_sha':cp_ref['sha256'],'observer_clocks':observer_claims}
        heads.add((cp['tree_size'],cp['root_sha256'],cp_ref['sha256']))
    need(len(sources)==2,'TWO_HISTORICAL_SOURCE_SLOTS_REQUIRED','permission_denied')
    return {'epoch_index':index,'parent_ec362_result_sha256':
            sha(canonical.canonical(prior)),
        'parent_ec361_result_sha256':prior['parent_ec361_canonical_result_sha256'],
        'parent_locally_coherent':prior['two_offline_signed_publication_copies_locally_coherent'],
        'directory_key_sha256':inputs['expected_directory_public_key_sha256'],
        'sources':sources,'heads':heads}


def _transition(doc,edge,old,new,slot,now):
    exact(doc,TRANSITION_FIELDS,'DUAL_CUSTODIAN_TRANSITION')
    fm,tm=old['manifest'],new['manifest']
    need(doc['schema']==TRANSITION_SCHEMA and doc['source_slot']==slot and
         doc['claimed_source_id']==fm['claimed_source_id']==tm['claimed_source_id'] and
         type(doc['from_epoch_index']) is int and doc['from_epoch_index']==edge and
         type(doc['to_epoch_index']) is int and doc['to_epoch_index']==edge+1 and
         doc['from_parent_ec361_canonical_result_sha256']==
            fm['parent_ec361_canonical_result_sha256'] and
         doc['to_parent_ec361_canonical_result_sha256']==
            tm['parent_ec361_canonical_result_sha256'] and
         doc['from_manifest_original_sha256']==old['manifest_sha'] and
         doc['to_manifest_original_sha256']==new['manifest_sha'] and
         doc['from_custodian_public_key_original_sha256']==old['key_sha'] and
         doc['to_custodian_public_key_original_sha256']==new['key_sha'] and
         doc['from_checkpoint_original_sha256']==old['cp_sha'] and
         doc['to_checkpoint_original_sha256']==new['cp_sha'] and
         doc['event_kind'] in ('carry','rotate','terminate'),
         'CROSS_WINDOW_BRIDGE_NOT_BOUND_TO_ACTUAL_AUDITED_ENDPOINTS',
         'permission_denied')
    _dual_signature(doc,old['pub'],new['pub'])
    begin,end=auth.window(doc['issued_utc'],doc['expires_utc'],MAX_SPAN,
                          'EC364_DUAL_SIGNED_TRANSITION')
    clock=(auth.utc_untrusted(now,begin,end,MAX_SPAN) or
           begin<tr._utc(fm['issued_utc']) or
           begin>tr._utc(tm['issued_utc']))
    wrong_kind=(doc['event_kind']=='carry' and old['key_sha']!=new['key_sha']) or (
        doc['event_kind']=='rotate' and old['key_sha']==new['key_sha'])
    return clock,wrong_kind,(doc['event_kind']=='terminate')


def _review_manifest_sequences(inputs,old_epochs,current_epoch):
    """Only use authenticated same-parent EC363 manifests to bridge the
    publication sequence between the preceding EC362 parent and the current.
    A signed skip in the presented bounded interval remains a gap.
    """
    first=old_epochs[-1]['sources'] if old_epochs else None
    if first is None:return False
    for slot in SLOTS:
        source=first[slot]
        current=current_epoch['sources'][slot]
        bundle=_raw_ref({'path':inputs.get('source_'+slot+'_history_bundle_file'),
            'sha256':inputs.get('expected_source_'+slot+'_history_bundle_sha256')},
            'CURRENT_EC363_HISTORY_'+slot,history.MAX_BUNDLE,{})
        d=tr.strict_json(bundle,'EC364_EC363_HISTORY_'+slot)
        exact(d,history.BUNDLE_FIELDS,'CURRENT_HISTORY_BUNDLE')
        published=[source['manifest']['publication_sequence'],
                   current['manifest']['publication_sequence']]
        for ref in d['historical_manifest_originals']:
            raw=_raw_ref(ref,'CURRENT_EC363_MANIFEST_'+slot,
                        custody.MAX_MANIFEST,{})
            m=tr.strict_json(raw,'EC364_CURRENT_HISTORY_MANIFEST')
            exact(m,custody.MANIFEST_FIELDS,'CURRENT_HISTORY_MANIFEST')
            # Parent EC363 has already truly signature-validated these records.
            published.append(m['publication_sequence'])
        if len(set(published))!=len(published):return True
        seq=sorted(published)
        if any(b!=a+1 for a,b in zip(seq,seq[1:])):return True
    return False


def checklist(**history_inputs):
    prior=history.audit(**history_inputs)
    need(prior['schema']==history.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec362_through_ec337_signed_originals_replayed'] is True,
         'TRUE_EC363_SIGNED_CURRENT_WINDOW_REPLAY_REQUIRED','permission_denied')
    return {'schema':HANDOFF_SCHEMA,'command':'derive-cross-epoch-handoff',
        'status':'caller_retained_replayable_historical_windows_and_dual_signatures_required_unresolved',
        'exit_code':2,'case_id':prior['case_id'],
        'actual_ec363_through_ec337_signed_originals_replayed':True,
        'parent_ec363_canonical_result_sha256':sha(canonical.canonical(prior)),
        'required_external_material':[
            'one or two separately SHA-pinned full historical EC362 audit-input snapshots; each will truly re-run EC361 through EC337 originals',
            'per-source SHA-pinned two-custodian Ed25519 signed carry/rotate/terminate event for each adjacent distinct parent window',
            'real directory-signed checkpoints and caller-stored RFC6962 append-only proof for every adjacent distinct signed window',
            'caller retained minimum historical-epoch count, oldest/current true result hashes and directory tree-size floor'],
        'official_publishers_legal_identity_global_completeness_and_utc_unproven':True,
        'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,cross_epoch_evaluation_utc,**inputs):
    current_inputs=_parent_inputs(inputs)
    now=tr._utc(cross_epoch_evaluation_utc)
    need(now>=tr._utc(current_inputs['history_evaluation_utc']),
         'CROSS_EPOCH_EVALUATION_MUST_NOT_PRECEDE_EC363','permission_denied')
    auth.outer_pin(inputs.get('cross_epoch_bundle_file'),
                   inputs.get('expected_cross_epoch_bundle_sha256'),
                   'EC364_CROSS_EPOCH_BUNDLE')
    snapshot_shas=inputs.get('historical_ec362_snapshot_shas',[])
    transition_shas=inputs.get('signed_source_epoch_transition_shas',[])
    need(type(snapshot_shas) is list and len(snapshot_shas)<=MAX_EPOCHS and
         all(tr._sha(v) for v in snapshot_shas) and
         len(set(snapshot_shas))==len(snapshot_shas),
         'SNAPSHOT_EXTERNAL_SHA_PINS_INVALID')
    need(type(transition_shas) is list and len(transition_shas)<=MAX_TRANSITIONS and
         all(tr._sha(v) for v in transition_shas) and
         len(set(transition_shas))==len(transition_shas),
         'TRANSITION_EXTERNAL_SHA_PINS_INVALID')
    floor=inputs.get('minimum_retained_historical_epoch_count')
    size_floor=inputs.get('minimum_retained_directory_tree_size')
    need(floor is None or (type(floor) is int and 1<=floor<=MAX_EPOCHS),
         'HISTORICAL_EPOCH_COUNT_FLOOR_INVALID')
    need(size_floor is None or (type(size_floor) is int and 1<=size_floor<=64),
         'DIRECTORY_TREE_FLOOR_INVALID')
    for k in ('expected_retained_oldest_ec362_result_sha256',
              'expected_retained_current_ec362_result_sha256'):
        need(inputs.get(k) is None or tr._sha(inputs[k]),
             'EXTERNAL_RETAINED_EC362_RESULT_SHA_INVALID')

    # Both auditors independently perform true signature/proof/reopening work;
    # cached or supplied parent 'pass' JSON is never taken as evidence.
    prior=history.audit(**current_inputs)
    need(prior['schema']==history.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec362_through_ec337_signed_originals_replayed'] is True,
         'ACTUAL_EC363_CURRENT_HISTORY_PARENT_REQUIRED','permission_denied')
    parent_sha=sha(canonical.canonical(prior))
    ec362_inputs=_ec362_inputs(current_inputs)
    current_true=custody.audit(**ec362_inputs)
    need(current_true['schema']==custody.RESULT_SCHEMA and
         sha(canonical.canonical(current_true))==
             prior['parent_ec362_canonical_result_sha256'],
         'CURRENT_EC362_TRUE_PARENT_RESULT_SHA_MISMATCH','permission_denied')
    oldpins,oldpaths,oldkeys,_,_=history._parent_material(ec362_inputs,current_true)
    historical_input_docs=[]
    historical_parent_role_keys=set()
    for k,v in current_inputs.items():
        if k.endswith('_file') and type(v) is str:oldpaths.add(v)
    newpins={};historicalpins={};categories={}
    flags={k:False for _,k in FLAG_MAP}
    epochs=[];event_reviews=[];proof_validated=0
    bundle_file=inputs.get('cross_epoch_bundle_file')
    bundle_sha=inputs.get('expected_cross_epoch_bundle_sha256')
    if bundle_file is None:
        flags['missing']=True
        bundle=None
    else:
        raw=auth.load({'path':bundle_file,'sha256':bundle_sha},
            'EC364_CROSS_EPOCH_BUNDLE',MAX_BUNDLE,newpins,oldpaths,categories,
            'ec364_window_bundle')
        bundle=tr.strict_json(raw,'EC364_WINDOW_BUNDLE')
        exact(bundle,BUNDLE_FIELDS,'CROSS_EPOCH_BUNDLE')
        need(bundle['schema']==BUNDLE_SCHEMA and
             bundle['current_ec363_canonical_result_sha256']==parent_sha,
             'CROSS_EPOCH_BUNDLE_CURRENT_TRUE_PARENT_BINDING_MISMATCH',
             'permission_denied')
        refs=bundle['historical_parent_snapshots']
        events=bundle['signed_source_transitions']
        proofs=bundle['directory_window_proofs']
        need(type(refs) is list and len(refs)<=MAX_EPOCHS and
             type(events) is list and len(events)<=MAX_TRANSITIONS and
             type(proofs) is list and len(proofs)<=MAX_EPOCHS,
             'HISTORICAL_EPOCH_AND_TRANSITION_BOUNDS_INVALID')
        for ref in (*refs,*events):ref_check(ref,'BUNDLE_EXACT_ORIGINAL_REF')
        if (len(refs)!=len(snapshot_shas) or
            len(events)!=len(transition_shas)):
            flags['missing']=True
        for index,ref in enumerate(refs):
            if index>=len(snapshot_shas):flags['missing']=True
            elif ref['sha256']!=snapshot_shas[index]:flags['rollback']=True
        for index,ref in enumerate(events):
            if index>=len(transition_shas):flags['missing']=True
            elif ref['sha256']!=transition_shas[index]:flags['rollback']=True
        # A missing historical window is unresolved; never fabricate an empty
        # epoch, or reinterpret same-parent EC363 manifests as another window.
        for index,ref in enumerate(refs):
            snapshot_raw=auth.load(ref,'EC364_FULL_EC362_INPUT_SNAPSHOT_'+str(index),
                 MAX_SNAPSHOT,newpins,oldpaths,categories,
                 'ec364_snapshot_'+str(index))
            snap=tr.strict_json(snapshot_raw,'EC364_HISTORICAL_PARENT_INPUTS')
            exact(snap,SNAPSHOT_FIELDS,'HISTORICAL_PARENT_REPLAY_INPUTS')
            need(snap['schema']==SNAPSHOT_SCHEMA and
                 type(snap['epoch_index']) is int and snap['epoch_index']==index and
                 type(snap['ec362_audit_inputs']) is dict and
                 set(snap['ec362_audit_inputs'])==set(ec362_inputs),
                 'TRUE_HISTORICAL_AUDITOR_INPUTS_MUST_HAVE_EXACT_EC362_KEYS',
                 'permission_denied')
            historic_args=snap['ec362_audit_inputs']
            historical_input_docs.append(historic_args)
            need(tr._utc(historic_args['publication_copy_evaluation_utc'])<=now,
                 'HISTORICAL_WINDOW_EVALUATION_AFTER_EC364_EVALUATION',
                 'permission_denied')
            replay=custody.audit(**historic_args)
            epochs.append(_epoch(index,historic_args,replay,now,historicalpins))
            # Reopen independently verified nested historic authority bundles
            # and collect their verified signer roles as well: a new epoch's
            # custodian cannot quietly be a former root/observer/issuer.
            _,_,other_keys,_,_=history._parent_material(historic_args,replay)
            historic_source_keys={
                historic_args['expected_source_'+s+'_custody_public_key_sha256']
                for s in SLOTS}
            historical_parent_role_keys.update(other_keys-historic_source_keys)
            # This includes each direct old source and separately authenticated
            # nested old parent original; don't allow bridge/event to impersonate
            # an already displayed historical parent file or directory key.
            for k,v in historic_args.items():
                if k.endswith('_file') and type(v) is str:oldpaths.add(v)
            for slot in SLOTS:
                for role in ('checkpoint','consistency_bundle',
                             'observer_a_receipt','observer_b_receipt'):
                    oldpaths.add(epochs[-1]['sources'][slot]['manifest']['copies'][role]['path'])
        epochs.append(_epoch(len(refs),ec362_inputs,current_true,now,historicalpins))
        if (not refs or len(refs)>MAX_EPOCHS or floor is None or
            size_floor is None or
            inputs.get('expected_retained_oldest_ec362_result_sha256') is None or
            inputs.get('expected_retained_current_ec362_result_sha256') is None):
            flags['missing']=True
        if floor is not None and len(refs)<floor:flags['rollback']=True
        if refs and inputs.get('expected_retained_oldest_ec362_result_sha256') != \
                epochs[0]['parent_ec362_result_sha256']:
            flags['rollback']=True
        if inputs.get('expected_retained_current_ec362_result_sha256') != \
                epochs[-1]['parent_ec362_result_sha256']:
            flags['rollback']=True
        if size_floor is not None and (
            min(e['sources']['a']['cp']['tree_size'] for e in epochs[-1:])<size_floor):
            flags['rollback']=True
        if any(not e['parent_locally_coherent'] for e in epochs[:-1]):
            flags['old_parent']=True
        # A window must really have a new signed directory checkpoint and a
        # different true EC361 result; a mere changed evaluation time is NOT
        # an independently witnessed epoch.
        for prev,following in zip(epochs,epochs[1:]):
            if (prev['parent_ec361_result_sha256']==
                following['parent_ec361_result_sha256'] or
                prev['directory_key_sha256']!=following['directory_key_sha256']):
                flags['proof']=True
            for slot in SLOTS:
                left=prev['sources'][slot];right=following['sources'][slot]
                if left['cp']['tree_size']>=right['cp']['tree_size']:
                    flags['proof']=True
                if tr._utc(left['cp']['issued_utc'])>tr._utc(right['cp']['issued_utc']):
                    flags['clock']=True
                if (left['manifest']['publication_sequence']>=
                    right['manifest']['publication_sequence']):
                    flags['rollback']=True
                if (left['manifest']['claimed_source_id']!=
                    right['manifest']['claimed_source_id']):
                    flags['role']=True
                if tr._utc(left['manifest']['issued_utc'])>\
                   tr._utc(right['manifest']['issued_utc']):flags['clock']=True
                for ob in SLOTS:
                    if tr._utc(left['observer_clocks'][ob])>\
                       tr._utc(right['observer_clocks'][ob]):flags['clock']=True
        for epoch in epochs:
            for slot in SLOTS:
                item=epoch['sources'][slot]
                issue=tr._utc(item['manifest']['issued_utc'])
                if issue<tr._utc(item['cp']['issued_utc']) or any(
                    issue<tr._utc(stamp) for stamp in item['observer_clocks'].values()):
                    flags['clock']=True
        if len(epochs)>1 and _review_manifest_sequences(current_inputs,
                 epochs[:-1],epochs[-1]):flags['missing']=True
        # For earlier windows there is no same-parent EC363 disclosure chain;
        # the displayed EC362 signed source sequences must be adjacent.
        for earlier,later in zip(epochs[:-2],epochs[1:-1]):
            for slot in SLOTS:
                if later['sources'][slot]['manifest']['publication_sequence']!=\
                   earlier['sources'][slot]['manifest']['publication_sequence']+1:
                    flags['missing']=True
        # True directory signatures at *every* displayed endpoint precede all
        # root comparison logic. Never choose just one favorable fork.
        roots=defaultdict(set)
        for epoch in epochs:
            for slot in SLOTS:
                cp=epoch['sources'][slot]['cp']
                roots[cp['tree_size']].add(cp['root_sha256'])
        if any(len(v)>1 for v in roots.values()):flags['fork']=True
        if any(len(e['heads'])!=1 for e in epochs):flags['fork']=True
        # No cross-slot key reuse, including reuse of a historic custodian as
        # a current challenger / directory / observer / issuer actor.
        by_key=defaultdict(set)
        for epoch in epochs:
            for slot in SLOTS:
                by_key[epoch['sources'][slot]['key_sha']].add(slot)
        if any(len(slots)>1 for slots in by_key.values()):flags['role']=True
        reserved={v for args in [ec362_inputs,*historical_input_docs]
                    for k,v in args.items() if k.endswith('_public_key_sha256')
                    and 'custody_public_key' not in k and tr._sha(v)}
        # Each historical replay validated its own roles. Additional checks
        # guard custodian/challenger role reuse across *different* windows.
        reserved.update(v for k,v in current_inputs.items() if
                        k.endswith('challenger_public_key_sha256') and tr._sha(v))
        for historic in epochs:
            reserved.add(historic['directory_key_sha256'])
        reserved.update(historical_parent_role_keys)
        reserved.update(oldkeys-set(by_key))
        if any(k in reserved for k in by_key):flags['role']=True
        seen_edges=defaultdict(list)
        for index,ref in enumerate(events):
            raw=auth.load(ref,'EC364_DUAL_SOURCE_TRANSITION_'+str(index),
                 MAX_TRANSITION,newpins,oldpaths,categories,
                 'ec364_transition_'+str(index))
            d=tr.strict_json(raw,'EC364_DUAL_SOURCE_TRANSITION')
            exact(d,TRANSITION_FIELDS,'SIGNED_SOURCE_TRANSITION')
            edge=d['from_epoch_index'];slot=d['source_slot']
            need(type(edge) is int and 0<=edge<len(epochs)-1 and slot in SLOTS,
                 'SIGNED_SOURCE_EVENT_EDGE_OR_SLOT_INVALID','permission_denied')
            left=epochs[edge]['sources'][slot]
            right=epochs[edge+1]['sources'][slot]
            clock,wrong_kind,terminated=_transition(d,edge,left,right,slot,now)
            if wrong_kind:flags['role']=True
            if clock:flags['clock']=True
            if terminated:flags['terminated']=True
            seen_edges[(edge,slot)].append(ref['sha256'])
            event_reviews.append({'source_slot':slot,'from_epoch_index':edge,
               'to_epoch_index':edge+1,'transition_original_sha256':ref['sha256'],
               'event_kind':d['event_kind'],
               'true_both_custodian_signatures_verified':True,
               'signer_kind_matches_key_change':not wrong_kind,
               'signed_claimed_clock_anomaly':clock})
        expected_edges={(edge,slot) for edge in range(len(epochs)-1)
                        for slot in SLOTS}
        if any(len(seen_edges[e])!=1 for e in expected_edges):flags['missing']=True
        if any(len(v)>1 for v in seen_edges.values()):flags['equivocation']=True
        # Caller-pinned proof bundle is not signed by itself: the signed
        # checkpoint root+size on BOTH sides and true RFC6962 verification
        # are mandatory, with no implicit transitive skipped edge.
        proof_edges=set()
        for proof in proofs:
            exact(proof,PROOF_FIELDS,'CROSS_WINDOW_DIRECTORY_PROOF')
            i,j=proof['from_epoch_index'],proof['to_epoch_index']
            need(type(i) is int and type(j) is int and 0<=i<len(epochs)-1 and
                 j==i+1 and i not in proof_edges,
                 'CONSISTENCY_PROOF_ADJACENT_UNIQUE_EPOCH_EDGE_REQUIRED')
            path=proof['audit_path_sha256']
            need(type(path) is list and len(path)<=MAX_PATH and
                 all(tr._sha(v) for v in path),
                 'CONSISTENCY_PROOF_HASH_PATH_INVALID')
            proof_edges.add(i)
            a=epochs[i]['sources']['a'];b=epochs[j]['sources']['a']
            if (proof['older_checkpoint_original_sha256']!=a['cp_sha'] or
                proof['newer_checkpoint_original_sha256']!=b['cp_sha'] or
                epochs[i]['directory_key_sha256']!=epochs[j]['directory_key_sha256'] or
                a['cp']['tree_size']>=b['cp']['tree_size'] or
                not tr.verify_consistency(a['cp']['tree_size'],b['cp']['tree_size'],
                    bytes.fromhex(a['cp']['root_sha256']),
                    bytes.fromhex(b['cp']['root_sha256']),
                    [bytes.fromhex(x) for x in path])):
                flags['proof']=True
            else:proof_validated+=1
        if proof_edges!=set(range(len(epochs)-1)):flags['proof']=True
    # All individual current / historical SHA-pinned originals are rechecked
    # by their true auditors. New bundle / snapshot / transition originals are
    # also late rechecked here. Full filesystem atomicity is not claimed.
    tsa._check_late(historicalpins)
    tsa._check_late(newpins)
    if bundle is not None:
        history.parent.previous.parent.parent._late_identity_check(newpins,oldpaths)
    local=(prior['bounded_signed_history_and_disclosures_locally_coherent'] and
           len(epochs)>=2 and all(e['parent_locally_coherent'] for e in epochs) and
           proof_validated==len(epochs)-1 and
           len(event_reviews)==2*(len(epochs)-1) and
           not any(flags.values()))
    if not prior['bounded_signed_history_and_disclosures_locally_coherent']:
        outcome=OUTCOMES[0]
    else:
        rank=('old_parent','equivocation','rollback','role','fork','proof',
              'terminated','clock','missing')
        outcome=next((OUTCOMES[i+1] for i,k in enumerate(rank) if flags[k]),
                     OUTCOMES[-1])
    epoch_rows=[{'epoch_index':e['epoch_index'],
        'parent_ec362_result_sha256':e['parent_ec362_result_sha256'],
        'parent_ec361_result_sha256':e['parent_ec361_result_sha256'],
        'parent_locally_coherent':e['parent_locally_coherent'],
        'directory_signer_sha256':e['directory_key_sha256'],
        'signed_tree_size':e['sources']['a']['cp']['tree_size'],
        'signed_root_sha256':e['sources']['a']['cp']['root_sha256'],
        'source_a_manifest_sha256':e['sources']['a']['manifest_sha'],
        'source_b_manifest_sha256':e['sources']['b']['manifest_sha'],
        'source_a_custodian_key_sha256':e['sources']['a']['key_sha'],
        'source_b_custodian_key_sha256':e['sources']['b']['key_sha']}
        for e in epochs]
    evidence=[{'tsa_channel_id':row['tsa_channel_id'],
       'parent_ec363_outcome':row['outcome'],'outcome':outcome}
       for row in prior['channel_evidence']]
    return {'schema':RESULT_SCHEMA,'command':'audit-cross-epoch',
      'status':outcome+'_unresolved','exit_code':2,'case_id':prior['case_id'],
      'actual_ec363_through_ec337_signed_originals_replayed':True,
      'parent_ec363_canonical_result_sha256':parent_sha,
      'parent_ec362_canonical_result_sha256':
          prior['parent_ec362_canonical_result_sha256'],
      'cross_epoch_evaluation_utc_as_caller_claim':cross_epoch_evaluation_utc,
      'parent_ec363_locally_coherent':
          prior['bounded_signed_history_and_disclosures_locally_coherent'],
      'cross_epoch_bundle_original_sha256':bundle_sha,
      'caller_minimum_historical_epoch_count':floor,
      'caller_minimum_directory_tree_size':size_floor,
      'caller_retained_oldest_ec362_result_sha256':
          inputs.get('expected_retained_oldest_ec362_result_sha256'),
      'caller_retained_current_ec362_result_sha256':
          inputs.get('expected_retained_current_ec362_result_sha256'),
      'epoch_reviews':epoch_rows,'true_historical_parent_replays':max(0,len(epochs)-1),
      'signed_transition_reviews':event_reviews,
      'true_signed_transition_originals_verified':len(event_reviews),
      'adjacent_directory_consistency_proofs_verified':proof_validated,
      **{name:flags[key] for name,key in FLAG_MAP},
      'locally_coherent_cross_epoch_signed_publication':local,
      'official_publisher_origin_physical_custody_trusted_utc_global_forks_unproven':True,
      'channel_evidence':evidence,
      'outcome_counts':{o:sum(x['outcome']==o for x in evidence) for o in OUTCOMES},
      'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}
