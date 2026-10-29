#!/usr/bin/env python3
"""EC367: independently pinned, signed, two-path institution status distribution.

This *replays* EC366 (and its EC365..EC337 parents) on each audit, then
reopens original source signatures, authenticates additional source-side
terminal status proofs, and checks SHA-linked Ed25519-signed witness histories.
A witnessed copy is evidence of a claim, not a registry of official/trusted
witnesses, global completeness, an OS trust root, or trusted time.

Only read-only, offline verification. No signing private keys in production.
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
from ec366_root_provenance import provenance as parent

RESULT_SCHEMA = 'ces.ec367.offline_dual_witness_institution_status_distribution_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec367.offline_dual_witness_institution_status_distribution_denial.v1'
HANDOFF_SCHEMA = 'ces.ec367.unsigned_witness_distribution_handoff.v1'
BUNDLE_SCHEMA = 'ces.ec367.dual_witness_distribution_bundle.v1'
RECORD_SCHEMA = 'ces.ec367.witness_signed_source_status_observation.v1'
RECORD_DOMAIN = b'CES/EC367/InstitutionStatusWitnessDistribution/v1\x00'
PATHS = ('registry_distribution', 'archive_distribution')
SOURCES = parent.ROLES
MAX_BUNDLE = 16000
MAX_RECORD = 9000
MAX_EXTRA_STATUS = 5000
MAX_RECORDS_PER_PATH = 4
MAX_ADDITIONAL_STATUS_PER_SOURCE = 2
MAX_WINDOW = timedelta(days=7)
BUNDLE_FIELDS = {'schema','parent_ec366_canonical_result_sha256',
                 'distribution_paths','additional_source_status_originals'}
PATH_FIELDS = {'distribution_path','claimed_witness_id',
               'witness_public_key_original_sha256','signed_witness_observations'}
EXTRA_FIELDS = {'source_role','original'}
RECORD_FIELDS = {'schema','distribution_path','claimed_witness_id',
 'witness_public_key_original_sha256','parent_ec366_canonical_result_sha256',
 'sequence','previous_witness_original_sha256','disclosure_state',
 'source_observations','issued_utc','expires_utc','signature_witness_ed25519_hex'}
SOURCE_FIELDS = {'claimed_source_role','claimed_institution_id',
 'institution_public_key_original_sha256','source_status_head_original_sha256',
 'source_status_sequence','source_status_action',
 'previous_source_status_original_sha256','source_attestation_head_original_sha256',
 'source_revocation_proof_original_sha256'}
NEW_REQUIRED = ('witness_distribution_evaluation_utc',)
NEW_OPTIONAL = ('witness_distribution_bundle_file',
 'expected_witness_distribution_bundle_sha256',
 'minimum_retained_registry_distribution_sequence',
 'minimum_retained_archive_distribution_sequence',
 'expected_retained_registry_distribution_witness_head_sha256',
 'expected_retained_archive_distribution_witness_head_sha256')
NEW_REPEATS = (
 ('witness_public_key_files','--witness-public-key-file'),
 ('witness_public_key_shas','--witness-public-key-sha256'),
 ('witness_claimed_ids','--witness-claimed-id'),
 ('signed_witness_record_shas','--signed-witness-record-sha256'),
 ('additional_source_status_shas','--additional-source-status-sha256'),
)
NEW_REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
FLAGS = (
 'inherited_ec366_institution_provenance_unresolved',
 'witness_key_reuses_source_or_prior_signer_role_visible',
 'retained_witness_original_head_or_sequence_rollback_visible',
 'genuinely_signed_witness_chain_fork_gap_or_epoch_replay_visible',
 'signed_witness_withheld_or_disputed_distribution_visible',
 'genuinely_source_signed_revocation_or_rotation_proof_visible',
 'extra_source_signed_status_fork_or_parent_head_staleness_visible',
 'genuinely_signed_cross_path_source_view_conflict_or_lag_visible',
 'witness_signed_status_claim_mismatches_verified_source_original_visible',
 'two_complete_current_independent_distribution_paths_missing',
 'witness_self_claimed_time_untrusted_or_anomalous',
)
OUTCOMES = (
 'ec367_inherited_institution_root_provenance_unresolved',
 'ec367_witness_claimed_role_or_parent_signer_alias',
 'ec367_retained_witness_head_or_floor_rollback',
 'ec367_authentic_witness_history_fork_gap_or_epoch_replay',
 'ec367_genuinely_signed_withholding_or_dispute',
 'ec367_true_source_signed_revocation_or_rotation',
 'ec367_additional_source_status_fork_or_stale_ec366_parent',
 'ec367_authentic_cross_witness_status_head_disagreement_or_lag',
 'ec367_signed_witness_claim_inconsistent_with_reopened_source_original',
 'ec367_two_complete_current_distribution_paths_not_demonstrated',
 'ec367_self_reported_witness_clock_not_independently_trusted',
 'ec367_two_caller_pinned_witnesses_locally_agree_only_official_distribution_unproven',
)
NEGATIVES = (
 'two_witness_signers_prove_real_legal_third_party_independence',
 'witness_signatures_establish_legal_institutional_registration',
 'witness_claimed_utc_establishes_trusted_disclosure_or_revocation_time',
 'two_covered_paths_establish_global_latest_or_no_hidden_distribution',
 'source_terminal_status_silently_cleared_by_witness_active_claim',
 'unsigned_source_revocation_claim_accepted_as_authentic',
 'external_witness_receipts_repair_invalid_ec366_parent',
 'witness_publication_considered_official_trust_anchor',
 'unobserved_source_status_forks_proven_absent',
 'network_provider_os_trust_or_remote_cas_worm_queried_or_modified',
 'production_private_keys_used_to_create_source_or_witness_signatures',
 'native_powershell_or_old_mock_or_final_acceptance_proven',
)


def need(ok, code, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC367_'+code, status)


def exact(doc, fields, role):
    need(type(doc) is dict and set(doc)==set(fields), role+'_EXACT_FIELDS_REQUIRED')


def sha(data):
    return parent.sha(data)


def _parent_inputs(inputs):
    return {k:v for k,v in inputs.items() if k not in NEW_REQUIRED and
            k not in NEW_OPTIONAL and k not in NEW_REPEAT_NAMES}


def _validate_new(inputs):
    authority.outer_pin(inputs.get('witness_distribution_bundle_file'),
                        inputs.get('expected_witness_distribution_bundle_sha256'),
                        'EC367_WITNESS_BUNDLE')
    for path in PATHS:
        head=inputs.get('expected_retained_'+path+'_witness_head_sha256')
        floor=inputs.get('minimum_retained_'+path+'_sequence')
        need(head is None or tr._sha(head), 'RETAINED_WITNESS_HEAD_SHA_INVALID')
        need(floor is None or type(floor) is int and 0<=floor<=8,
             'RETAINED_WITNESS_SEQUENCE_FLOOR_INVALID')
    keys=inputs.get('witness_public_key_files',[])
    hashes=inputs.get('witness_public_key_shas',[])
    ids=inputs.get('witness_claimed_ids',[])
    need(type(keys) is list and len(keys)==2 and all(type(x) is str for x in keys)
         and type(hashes) is list and len(hashes)==2 and all(tr._sha(x) for x in hashes)
         and len(set(hashes))==2 and type(ids) is list and len(ids)==2 and
         all(tr._ident(x) for x in ids) and len(set(ids))==2,
         'TWO_INDEPENDENTLY_RETAINED_WITNESS_IDENTITIES_REQUIRED')
    for name,cap in (('signed_witness_record_shas',8),
                     ('additional_source_status_shas',4)):
        rows=inputs.get(name,[])
        need(type(rows) is list and len(rows)<=cap and
             all(tr._sha(x) for x in rows) and len(set(rows))==len(rows),
             'EXTERNALLY_RETAINED_'+name.upper()+'_INVALID')


def _old(ref, label, cap, oldpins):
    # This is the same secure, inherited original reader used by EC365;
    # it checks path/ancestor identity, regular files, SHA and late reopens.
    return parent.parent._read_original(ref,'EC367_'+label,cap,oldpins)


def _new(ref,label,cap,newpins,oldpaths,categories,category):
    return authority.load(ref,'EC367_'+label,cap,newpins,oldpaths,
                          categories,category)


def _status_document(raw, pub, source, role, key_sha, expected_id):
    doc=tr.strict_json(raw,'EC367_SOURCE_STATUS_'+role)
    parent._check_status_shape(doc)
    need(doc['claimed_institution_role']==source and
         doc['claimed_institution_id']==expected_id and
         doc['institution_public_key_original_sha256']==key_sha,
         'SOURCE_SIGNED_STATUS_WRONG_PINNED_IDENTITY','permission_denied')
    authority.sig(doc,'signature_institution_ed25519_hex',pub,
                  parent.STATUS_DOMAIN,'EC367_TRUE_SOURCE_STATUS_'+role)
    # Invalid signed successor semantics are visible, but never accepted as
    # an active status. No successor is promoted to a trusted institution key.
    return doc


def _source_graph(rows, flags):
    """Preserve all authentic source status branches; never choose a fork."""
    children=defaultdict(list)
    by_seq=defaultdict(set)
    for digest,doc in rows.items():
        n=doc['sequence'];prev=doc['previous_status_original_sha256']
        children[prev].append(digest)
        by_seq[n].add(digest)
        if n==0:
            if prev is not None or doc['action']!='activate':
                flags[FLAGS[6]]=True
        elif (prev not in rows or
              rows[prev]['sequence']!=n-1 or
              rows[prev]['action'] in ('revoke','rotate')):
            flags[FLAGS[6]]=True
        if (doc['action']=='rotate') != (
            doc['successor_public_key_original_sha256'] is not None):
            flags[FLAGS[6]]=True
        if doc['action'] in ('revoke','rotate'):
            flags[FLAGS[5]]=True
    if any(len(seq)>1 for seq in by_seq.values()) or any(
            len(group)>1 for group in children.values()):
        flags[FLAGS[6]]=True


def _is_ancestor(older,newer,rows):
    """True only for a continuously authenticated parent-SHA source chain."""
    if older==newer:return True
    seen=set();node=newer
    while node in rows and node not in seen:
        seen.add(node)
        node=rows[node]['previous_status_original_sha256']
        if node==older:return True
    return False


def _load_sources(inputs, prior, flags, oldpins, newpins, oldpaths, categories,
                  additional, external_additional_shas, now):
    ref={'path':inputs['root_provenance_bundle_file'],
         'sha256':inputs['expected_root_provenance_bundle_sha256']}
    raw=_old(ref,'INHERITED_EC366_BUNDLE',parent.MAX_BUNDLE,oldpins)
    b=tr.strict_json(raw,'EC367_REOPEN_EC366_BUNDLE')
    exact(b,parent.BUNDLE_FIELDS,'INHERITED_EC366_BUNDLE')
    need(b['schema']==parent.BUNDLE_SCHEMA and
         b['parent_ec365_canonical_result_sha256']==prior[
              'parent_ec365_canonical_result_sha256'] and
         type(b['institutions']) is list and len(b['institutions'])==2,
         'TRUE_EC366_SOURCE_BUNDLE_NOT_MATCHED','permission_denied')
    sources=[]
    for i,role in enumerate(SOURCES):
        inst=b['institutions'][i]
        exact(inst,parent.INSTITUTION_FIELDS,'EC366_INSTITUTION')
        expected_sha=inputs['institution_root_public_key_shas'][i]
        need(inst['claimed_institution_role']==role and
             inst['claimed_institution_id']==inputs['institution_claimed_ids'][i] and
             inst['institution_public_key_original_sha256']==expected_sha,
             'EC366_INHERITED_SOURCE_ID_NOT_EXTERNAL_PIN','permission_denied')
        pub=_old({'path':inputs['institution_root_public_key_files'][i],
                  'sha256':expected_sha},'EC366_INSTITUTION_KEY_'+role,32,oldpins)
        need(len(pub)==32,'EC366_SOURCE_PUBLIC_KEY_LENGTH_INVALID','permission_denied')
        status={}
        for j,sref in enumerate(inst['signed_status_events']):
            historic.ref_check(sref,'EC367_EC366_STATUS_REF')
            st=_old(sref,'INHERITED_STATUS_'+role+'_'+str(j),parent.MAX_STATUS,oldpins)
            d=_status_document(st,pub,role,'INHERITED',expected_sha,
                               inst['claimed_institution_id'])
            need(sref['sha256'] not in status,'REPEATED_SOURCE_STATUS_SHA',
                 'permission_denied')
            status[sref['sha256']]=d
            oldpaths.add(sref['path'])
        for ar in inst['signed_provenance_attestations']:
            historic.ref_check(ar,'EC367_EC366_ATTEST_REF')
            oldpaths.add(ar['path'])
        sources.append({'role':role,'id':inst['claimed_institution_id'],
           'root_sha':expected_sha,'public':pub,'statuses':status,
           'parent_status_head':prior['two_institution_original_reviews'][i][
                 'actual_status_head_sha256'],
           'parent_attestation_head':prior['two_institution_original_reviews'][i][
                 'actual_attestation_head_sha256'],
           'extra_shas':[]})
    # The caller separately retains the exact new original SHA stream; a
    # bundle-controlled path may not simply invent an unpinned revocation.
    need(type(additional) is list and len(additional)<=4,
         'ADDITIONAL_SOURCE_STATUS_REF_COUNT_INVALID')
    actual=[]
    for i,item in enumerate(additional):
        exact(item,EXTRA_FIELDS,'ADDITIONAL_SOURCE_STATUS')
        role=item['source_role']
        need(role in SOURCES,'ADDITIONAL_SOURCE_STATUS_ROLE_UNKNOWN')
        ref=item['original']
        historic.ref_check(ref,'ADDITIONAL_SOURCE_SIGNED_STATUS')
        actual.append(ref['sha256'])
        src=sources[SOURCES.index(role)]
        need(ref['sha256'] not in src['statuses'],
             'ADDITIONAL_STATUS_MUST_NOT_DUPLICATE_EC366_ORIGINAL')
        need(len(src['extra_shas'])<MAX_ADDITIONAL_STATUS_PER_SOURCE,
             'ADDITIONAL_SOURCE_STATUS_PER_ROLE_BUDGET_EXCEEDED')
        st=_new(ref,'ADDITIONAL_SOURCE_STATUS_'+str(i),MAX_EXTRA_STATUS,
                newpins,oldpaths,categories,'ec367_extra_source_status_'+str(i))
        d=_status_document(st,src['public'],role,'ADDITIONAL',src['root_sha'],src['id'])
        src['statuses'][ref['sha256']]=d
        src['extra_shas'].append(ref['sha256'])
    if actual!=external_additional_shas:
        flags[FLAGS[2]]=True
    for src in sources:
        _source_graph(src['statuses'],flags)
        for status in src['statuses'].values():
            if status['parent_ec365_canonical_result_sha256']!=prior[
                     'parent_ec365_canonical_result_sha256']:
                flags[FLAGS[8]]=True
            if parent._claimed_clock(status,now):
                flags[FLAGS[10]]=True
        if src['extra_shas']:
            flags[FLAGS[6]]=True  # EC366 parent did not verify those originals.
        if src['parent_status_head'] not in src['statuses']:
            flags[FLAGS[8]]=True
    return sources


def _check_observation(obs, src, flags):
    exact(obs,SOURCE_FIELDS,'SIGNED_WITNESS_SOURCE_OBSERVATION')
    need(obs['claimed_source_role']==src['role'] and
         obs['claimed_institution_id']==src['id'] and
         obs['institution_public_key_original_sha256']==src['root_sha'],
         'WITNESS_SOURCE_ROLE_OR_PINNED_IDENTITY_MISMATCH',
         'permission_denied')
    need(tr._sha(obs['source_status_head_original_sha256']) and
         type(obs['source_status_sequence']) is int and
         0<=obs['source_status_sequence']<=8 and
         obs['source_status_action'] in ('activate','renew','revoke','rotate') and
         (obs['previous_source_status_original_sha256'] is None or
          tr._sha(obs['previous_source_status_original_sha256'])) and
         (obs['source_attestation_head_original_sha256'] is None or
          tr._sha(obs['source_attestation_head_original_sha256'])) and
         (obs['source_revocation_proof_original_sha256'] is None or
          tr._sha(obs['source_revocation_proof_original_sha256'])),
         'SIGNED_OBSERVATION_SOURCE_FIELD_FORMAT_INVALID')
    digest=obs['source_status_head_original_sha256']
    signed=src['statuses'].get(digest)
    if signed is None:
        flags[FLAGS[8]]=True
    else:
        if (obs['source_status_sequence']!=signed['sequence'] or
            obs['source_status_action']!=signed['action'] or
            obs['previous_source_status_original_sha256']!=
               signed['previous_status_original_sha256'] or
            obs['source_revocation_proof_original_sha256']!=
               (digest if signed['action'] in ('revoke','rotate') else None)):
            flags[FLAGS[8]]=True
        # Even a witness claiming "active" cannot override an independently
        # verified source-side terminal revocation/rotation anywhere in view.
        if signed['action'] in ('revoke','rotate'):
            flags[FLAGS[5]]=True
    return signed


def _witness_history(rows, path, external, flags):
    """Verify every genuine branch before reporting. Never select a fork."""
    if not rows:
        flags[FLAGS[9]]=True
        return None,False
    by_sha={r['sha']:r for r in rows}
    by_seq=defaultdict(set);children=defaultdict(list)
    for row in rows:
        d=row['document'];n=d['sequence'];prev=d['previous_witness_original_sha256']
        by_seq[n].add(row['sha']);children[prev].append(row['sha'])
        if n==0:
            if prev is not None:flags[FLAGS[3]]=True
        elif prev not in by_sha or by_sha[prev]['document']['sequence']!=n-1:
            flags[FLAGS[3]]=True
        if prev in by_sha:
            previous=by_sha[prev]['document']
            for i in range(2):
                old=previous['source_observations'][i]
                new=d['source_observations'][i]
                if old['source_status_sequence']>new['source_status_sequence']:
                    flags[FLAGS[3]]=True
        if d['disclosure_state']!='published':flags[FLAGS[4]]=True
    if any(len(v)>1 for v in by_seq.values()) or any(
          len(v)>1 for v in children.values()):flags[FLAGS[3]]=True
    leaf=[r for r in rows if r['sha'] not in children]
    head=leaf[0] if len(leaf)==1 and leaf[0]['document']['sequence']==max(by_seq) else None
    if head is None:flags[FLAGS[3]]=True
    expected=external.get('expected_retained_'+path+'_witness_head_sha256')
    floor=external.get('minimum_retained_'+path+'_sequence')
    pinned=(head is not None and expected is not None and
            head['sha']==expected and floor is not None and
            head['document']['sequence']>=floor)
    if not pinned:flags[FLAGS[2]]=True
    return head,pinned


def _terminal_proofs(src):
    return sorted(digest for digest,doc in src['statuses'].items()
                  if doc['action'] in ('revoke','rotate'))


def checklist(**parent_inputs):
    prior=parent.audit(**parent_inputs)
    need(prior['schema']==parent.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec365_through_ec337_signed_originals_replayed'] is True,
         'TRUE_EC366_PARENT_CRYPTO_REPLAY_REQUIRED','permission_denied')
    return {'schema':HANDOFF_SCHEMA,'command':'derive-witness-distribution-handoff',
       'status':'independently_pinned_signed_dual_witness_distribution_required_unresolved',
       'exit_code':2,'case_id':prior['case_id'],
       'actual_ec366_through_ec337_signed_originals_replayed':True,
       'parent_ec366_canonical_result_sha256':sha(canonical.canonical(prior)),
       'required_external_material':[
          'two different caller-retained Ed25519 witness public-key originals with independent claimed identities',
          'two external distribution paths each containing signed SHA-linked witness epoch observations of BOTH source status and provenance heads',
          'independently retained actual original SHA stream, terminal witness head and minimum epoch floor for each path',
          'optional separately SHA-pinned original institution-signed extra status events including terminal revoke/rotate proofs'],
       'globally_complete_distribution_official_independence_trusted_utc_unproven':True,
       'offline_unresolved_exit_code':2,**{k:False for k in NEGATIVES}}


def audit(*,witness_distribution_evaluation_utc,**inputs):
    now=tr._utc(witness_distribution_evaluation_utc)
    _validate_new(inputs)
    earlier=_parent_inputs(inputs)
    need(now>=tr._utc(earlier['root_provenance_evaluation_utc']),
         'EVALUATION_PRECEDES_EC366_PARENT','permission_denied')
    # Real inherited cryptographic and signed-original execution, never
    # trusting user JSON or a success marker as the parent verdict.
    prior=parent.audit(**earlier)
    need(prior['schema']==parent.RESULT_SCHEMA and prior['exit_code']==2 and
         prior['actual_ec365_through_ec337_signed_originals_replayed'] is True,
         'EC366_THROUGH_EC337_TRUE_REPLAY_REQUIRED','permission_denied')
    prior_sha=sha(canonical.canonical(prior))
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not prior['locally_two_institutions_correlate_on_same_real_directory_lineage']
    oldpins={};newpins={};categories={}
    oldpaths={v for k,v in earlier.items() if k.endswith('_file') and
              type(v) is str}
    # Add original fixture and known referenced EC366 originals to the alias
    # exclusion set before reading any newly introduced witness file.
    bundle_ref={'path':inputs['witness_distribution_bundle_file'],
                'sha256':inputs['expected_witness_distribution_bundle_sha256']}
    need(bundle_ref['path'] is not None and bundle_ref['sha256'] is not None,
         'WITNESS_DISTRIBUTION_ORIGINAL_BUNDLE_REQUIRED')
    bundle_data=_new(bundle_ref,'WITNESS_BUNDLE',MAX_BUNDLE,newpins,oldpaths,
                     categories,'ec367_witness_bundle')
    bundle=tr.strict_json(bundle_data,'EC367_DUAL_WITNESS_BUNDLE')
    exact(bundle,BUNDLE_FIELDS,'WITNESS_DISTRIBUTION_BUNDLE')
    need(bundle['schema']==BUNDLE_SCHEMA,'WITNESS_DISTRIBUTION_BUNDLE_SCHEMA_INVALID')
    if bundle['parent_ec366_canonical_result_sha256']!=prior_sha:
        flags[FLAGS[8]]=True
    need(type(bundle['distribution_paths']) is list and
         len(bundle['distribution_paths'])==2,'EXACT_TWO_WITNESS_PATHS_REQUIRED')
    paths=bundle['distribution_paths']
    source_rows=_load_sources(earlier,prior,flags,oldpins,newpins,oldpaths,
                         categories,bundle['additional_source_status_originals'],
                         inputs['additional_source_status_shas'],now)
    # Root signer roles must not be recycled as alleged independent witness
    # signers. Reusing a former directory or source root is also visible.
    forbidden={r['root_sha'] for r in source_rows}
    forbidden.update(x['actual_directory_key_original_sha256'] for x in
                     prior['actual_epoch_directory_original_reviews'])
    for k,v in earlier.items():
        if 'public_key' in k or 'signer_key' in k or 'root_key' in k:
            if tr._sha(v):forbidden.add(v)
            elif type(v) is list:forbidden.update(x for x in v if tr._sha(x))
    witness_roots=[]
    for i,path in enumerate(PATHS):
        item=paths[i]
        exact(item,PATH_FIELDS,'WITNESS_DISTRIBUTION_PATH')
        need(item['distribution_path']==path and
             item['claimed_witness_id']==inputs['witness_claimed_ids'][i] and
             item['witness_public_key_original_sha256']==inputs[
                  'witness_public_key_shas'][i],
             'EXTERNAL_WITNESS_PATH_ID_OR_PUBLIC_KEY_SWAPPED',
             'permission_denied')
        ref={'path':inputs['witness_public_key_files'][i],
             'sha256':inputs['witness_public_key_shas'][i]}
        pub=_new(ref,'WITNESS_ROOT_'+path,32,newpins,oldpaths,categories,
                 'ec367_witness_public_key_'+path)
        need(len(pub)==32,'WITNESS_PUBLIC_KEY_MUST_BE_ED25519_BYTES',
             'permission_denied')
        witness_roots.append(pub)
        if (ref['sha256'] in forbidden or
            item['claimed_witness_id'] in {s['id'] for s in source_rows}):
            flags[FLAGS[1]]=True
    observations=[];verified=0;good_paths=0
    for i,path in enumerate(PATHS):
        item=paths[i];refs=item['signed_witness_observations']
        need(type(refs) is list and 1<=len(refs)<=MAX_RECORDS_PER_PATH,
             'WITNESS_PATH_NEEDS_BOUNDED_SIGNED_RECORDS')
        rows=[]
        for j,ref in enumerate(refs):
            historic.ref_check(ref,'EC367_WITNESS_RECORD_REF')
            data=_new(ref,'SIGNED_WITNESS_RECORD_'+path+'_'+str(j),
                      MAX_RECORD,newpins,oldpaths,categories,
                      'ec367_signed_witness_'+path+'_'+str(j))
            doc=tr.strict_json(data,'EC367_WITNESS_SIGNED_STATUS_RECORD')
            exact(doc,RECORD_FIELDS,'SIGNED_WITNESS_RECORD')
            need(doc['schema']==RECORD_SCHEMA and
                 doc['distribution_path']==path and
                 doc['claimed_witness_id']==item['claimed_witness_id'] and
                 doc['witness_public_key_original_sha256']==item[
                     'witness_public_key_original_sha256'],
                 'WITNESS_SIGNED_RECORD_IDENTITY_MISMATCH','permission_denied')
            need(type(doc['sequence']) is int and 0<=doc['sequence']<=8 and
                 (doc['previous_witness_original_sha256'] is None or
                  tr._sha(doc['previous_witness_original_sha256'])) and
                 doc['disclosure_state'] in ('published','withheld','disputed') and
                 type(doc['source_observations']) is list and
                 len(doc['source_observations'])==2,
                 'SIGNED_WITNESS_RECORD_FIELDS_INVALID')
            authority.sig(doc,'signature_witness_ed25519_hex',
                   witness_roots[i],RECORD_DOMAIN,'EC367_WITNESS_'+path)
            verified+=1
            if doc['parent_ec366_canonical_result_sha256']!=prior_sha:
                flags[FLAGS[8]]=True
            first,last=authority.window(doc['issued_utc'],doc['expires_utc'],
                                        MAX_WINDOW,'EC367_WITNESS_CLAIM')
            anomaly=authority.utc_untrusted(now,first,last,MAX_WINDOW)
            if anomaly:flags[FLAGS[10]]=True
            signed=[]
            for s,source in enumerate(source_rows):
                observed=doc['source_observations'][s]
                signed.append(_check_observation(observed,source,flags))
            rows.append({'sha':ref['sha256'],'document':doc,
                         'signed_source_status_documents':signed,
                         'clock':anomaly})
        head,retained=_witness_history(rows,path,inputs,flags)
        # Every earlier record must advance along real source-signed SHA
        # ancestry, not merely assert a larger integer or timestamp.
        for row in rows:
            previous=row['document']['previous_witness_original_sha256']
            ancestors={r['sha']:r for r in rows}
            if previous in ancestors:
                older=ancestors[previous]
                for s,source in enumerate(source_rows):
                    a=older['document']['source_observations'][s][
                        'source_status_head_original_sha256']
                    b=row['document']['source_observations'][s][
                        'source_status_head_original_sha256']
                    if not _is_ancestor(a,b,source['statuses']):
                        flags[FLAGS[3]]=True
        latest=head['document']['source_observations'] if head else None
        matched=(retained and head is not None and
                 head['document']['disclosure_state']=='published' and
                 not head['clock'] and
                 head['document']['parent_ec366_canonical_result_sha256']==prior_sha)
        if matched:
            for s,src in enumerate(source_rows):
                view=latest[s]
                matched=(matched and
                    view['source_status_head_original_sha256']==src['parent_status_head'] and
                    view['source_attestation_head_original_sha256']==src[
                         'parent_attestation_head'] and
                    view['source_status_action'] in ('activate','renew') and
                    view['source_status_head_original_sha256'] in src['statuses'])
        if matched:good_paths+=1
        else:flags[FLAGS[9]]=True
        observations.append({'distribution_path':path,
            'claimed_witness_id_as_caller_pin':item['claimed_witness_id'],
            'witness_public_key_original_sha256':item[
                    'witness_public_key_original_sha256'],
            'actual_signed_witness_original_count':len(rows),
            'expected_retained_witness_head_sha256':inputs.get(
                         'expected_retained_'+path+'_witness_head_sha256'),
            'actual_witness_head_sha256':head['sha'] if head else None,
            'actual_witness_head_sequence':head['document']['sequence'] if head else None,
            'source_status_head_original_shas':[x[
               'source_status_head_original_sha256'] for x in latest] if latest else [],
            'source_attestation_head_original_shas':[x[
               'source_attestation_head_original_sha256'] for x in latest] if latest else [],
            'source_disclosure_state':head['document']['disclosure_state'] if head else None,
            'locally_current_complete_signed_source_distribution':bool(matched)})
    actual_sha_stream=[r['sha256'] for p in paths for r in p['signed_witness_observations']]
    if actual_sha_stream!=inputs['signed_witness_record_shas']:
        flags[FLAGS[2]]=True
    # Cross-path comparison is only of each *externally retained* latest head,
    # not unrelated historical epochs. Different valid signed source status
    # heads at the same sequence expose a source fork; an ancestor gap shows
    # witnessed lag, not a fabricated malicious fork assertion.
    left,right=observations
    if (len(left['source_status_head_original_shas'])==2 and
        len(right['source_status_head_original_shas'])==2):
        for s,src in enumerate(source_rows):
            a,b=(x['source_status_head_original_shas'][s] for x in observations)
            if a!=b:
                flags[FLAGS[7]]=True
                if not (_is_ancestor(a,b,src['statuses']) or
                        _is_ancestor(b,a,src['statuses'])):
                    flags[FLAGS[6]]=True
            if (left['source_attestation_head_original_shas'][s]!=
                 right['source_attestation_head_original_shas'][s]):
                flags[FLAGS[7]]=True
    if good_paths!=2:flags[FLAGS[9]]=True
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    # Includes ancestor hardlink/identity checks for every newly introduced
    # original, while the inherited EC366 replay checks its own full boundary.
    parent.parent.parent.history.parent.previous.parent.parent._late_identity_check(
         newpins,oldpaths)
    locally=(good_paths==2 and verified>=2 and not any(flags.values()))
    winner=next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])
    return {'schema':RESULT_SCHEMA,'command':'audit-witness-distribution',
        'status':winner+'_unresolved','exit_code':2,'case_id':prior['case_id'],
        'actual_ec366_through_ec337_signed_originals_replayed':True,
        'parent_ec366_canonical_result_sha256':prior_sha,
        'parent_ec366_locally_two_institutions_correlated':prior[
            'locally_two_institutions_correlate_on_same_real_directory_lineage'],
        'witness_distribution_evaluation_utc_as_caller_claim':witness_distribution_evaluation_utc,
        'witness_distribution_bundle_original_sha256':bundle_ref['sha256'],
        'true_verified_witness_distribution_signatures':verified,
        'true_verified_additional_source_signed_status_originals':sum(
            len(s['extra_shas']) for s in source_rows),
        'true_source_signed_terminal_status_original_shas':[
            {'source_role':s['role'],'terminal_original_shas':_terminal_proofs(s)}
            for s in source_rows],
        'two_witness_distribution_reviews':observations,
        'number_of_current_two_source_witnessed_distribution_paths':good_paths,
        **flags,
        'locally_two_independently_retained_paths_correlate_on_verified_source_heads':locally,
        'official_witness_independence_physical_custody_trusted_utc_complete_global_distribution_and_hidden_forks_unproven':True,
        'channel_evidence':[{'tsa_channel_id':x['tsa_channel_id'],
           'parent_ec366_outcome':x['outcome'],'outcome':winner}
           for x in prior['channel_evidence']],
        'outcome_counts':{o:(len(prior['channel_evidence']) if o==winner else 0)
                           for o in OUTCOMES},
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES}}
