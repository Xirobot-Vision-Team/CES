#!/usr/bin/env python3
"""EC408 offline signed RFC6960 issuer/delegate OCSP evidence for EC407 custody.

Production always reruns the unchanged EC407 CMS/X509/CRL audit (and its real
EC406... ancestor chain). The new verifier accepts only independently SHA-pinned
original DER OCSP, and gives *local* signed-status/temporal consistency, never
independent issuer ownership, qualified time, public delivery or final PASS.
No network, private keys, signing, original writes, or mutable cache.
"""
from __future__ import annotations

import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from ec350_tsa_timestamp import timestamp as tsa
from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as readers
from ec401_ocsp_evidence import protocol as issuer_ocsp
from ec407_institutional_cms import protocol as parent

RESULT_SCHEMA = 'ces.ec408.institutional_dual_window_ocsp_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec408.unsigned_institutional_ocsp_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec408.institutional_dual_window_ocsp_denial.v1'
BUNDLE_SCHEMA = 'ces.ec408.original_institutional_dual_window_ocsp_bundle.v1'
INVENTORY_SCHEMA = 'ces.ec408.unsigned_institutional_ocsp_inventory.v1'
MAX_BUNDLE = 120_000
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_institutional_ocsp_bundle_file',
    'expected_historical_ec339_institutional_ocsp_bundle_sha256',
    'expected_outside_ec408_first_a_historical_ocsp_sha256',
    'expected_outside_ec408_first_b_historical_ocsp_sha256',
    'expected_outside_ec408_first_a_evaluation_ocsp_sha256',
    'expected_outside_ec408_first_b_evaluation_ocsp_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_institutional_ocsp_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_institutional_ocsp_epoch_inventory_shas',
     '--historical-ec339-institutional-ocsp-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_institutional_ocsp_publisher_counts',
     '--minimum-historical-ec339-joint-institutional-ocsp-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'unchanged_real_ec407_x509_cms_crl_or_earlier_parent_disputed',
    'outside_first_ocsp_epoch_inventory_or_whole_sha_and_floor_disagree',
    'one_or_more_later_historical_or_evaluation_ocsp_pairs_missing',
    'issuer_signed_ocsp_originals_lack_contemporaneous_dual_window_coverage',
    'actual_signed_ocsp_revoked_or_unknown_institutional_leaf',
    'two_role_real_ec407_and_ocsp_joint_coverage_incomplete',
    'official_issuer_identity_historical_external_authorization_unproven',
    'real_prior_public_availability_qualified_time_global_revocation_unproven',
    'full_unmocked_history_worm_native_powershell_and_final_acceptance_unproven',
)
OUTCOMES = (
    'ec408_inherited_ec407_and_ancestors_disputed',
    'ec408_outside_original_sha_or_epoch_joint_floor_disagrees',
    'ec408_later_original_historical_evaluation_ocsp_missing',
    'ec408_issuer_ocsp_dual_window_fresh_good_coverage_incomplete',
    'ec408_signed_ocsp_revoked_or_unknown_institutional_leaf',
    'ec408_two_role_ec407_and_original_ocsp_joint_coverage_incomplete',
    'ec408_official_independent_institutional_issuer_status_unproven',
    'ec408_real_public_time_and_exhaustive_revocation_unproven',
    'ec408_real_external_history_worm_native_acceptance_unproven',
)
NEGATIVES = (
    'issuer_or_delegated_ocsp_good_certifies_government_or_accredited_institution',
    'historical_signed_ocsp_proves_prior_independent_public_distribution',
    'ocsp_produced_at_is_a_calibrated_qualified_time_stamp',
    'signed_ocsp_supersedes_an_adverse_parent_signed_crl_or_cms',
    'ocsp_nocheck_proves_globally_unrevoked_responder_certificate',
    'two_locally_supplied_issuer_roots_establish_organization_independence',
    'pinned_source_hash_is_official_external_trust_list_attestation',
    'ocsp_good_proves_global_current_revocation_completeness',
    'receiver_signed_ocsp_or_generated_source_originals_or_credentials',
    'receiver_used_network_writable_cas_git_ci_provider_powershell_or_worm',
    'receiver_performed_fully_unmocked_real_public_history_or_final_acceptance',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec407_original_institutional_cms_bundle_original', 'epochs'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
ROLE_FIELDS = {'publisher_id', 'institutional_signer_id',
               'root_certificate_sha256', 'leaf_certificate_sha256',
               'original_historical_ocsp_response',
               'original_evaluation_ocsp_response',
               'historical_delegated_responder_certificate_original',
               'evaluation_delegated_responder_certificate_original'}


def need(ok, code, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC408_' + code, status)


def exact(value, fields, name):
    need(type(value) is dict and set(value) == fields,
         name + '_EXACT_FIELDS_REQUIRED', 'permission_denied')


def ref(value):
    return parent.ref(value)


def sha(raw):
    return parent.sha(raw)


def cdigest(obj):
    return parent.cdigest(obj)


def _sha_ok(value):
    return (type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
            and value!='0'*64)


def _inputs(opts, deriving):
    expected = set((*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        expected.update(AUDIT_ONLY)
    need(set(opts) == expected, 'COMPLETE_EC407_AND_EC408_ARGUMENTS_REQUIRED')
    inherited = {k:opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC408_ORIGINAL_INSTITUTIONAL_OCSP_BUNDLE')
    for k in (*NEW_SCALARS[2:], *(AUDIT_ONLY if not deriving else ())):
        need(_sha_ok(opts[k]), 'OUTSIDE_ORIGINAL_OCSP_SHA_INVALID')
    need(len({opts[k] for k in NEW_SCALARS[2:]}) == 4,
         'FOUR_INDEPENDENT_FIRST_HISTORICAL_AND_EVALUATION_OCSP_PINS_REQUIRED',
         'permission_denied')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3, 'ONE_TO_THREE_HISTORICAL_EPOCHS_REQUIRED')
    for k in REPEAT_NAMES:
        values=opts[k]
        need(type(values) is list and len(values)==n,
             'ONE_OUTSIDE_EPOCH_PIN_AND_MINIMUM_PER_EPOCH_REQUIRED')
        if k.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=2 for v in values),
                 'INVALID_TWO_ROLE_OCSP_JOINT_COUNT_FLOOR')
        else:
            need(all(_sha_ok(v) for v in values), 'INVALID_EPOCH_OCSP_SHA')
    return inherited


def _parent_report(report, opts):
    fields = {'schema','command','status','exit_code','offline_unresolved_exit_code',
              'verified_live_ec406_report_sha256', 'verified_live_ec406_inventory_sha256',
              'original_institutional_cms_bundle_sha256',
              'receiver_verified_institutional_cms_inventory_sha256',
              'verified_joint_institutional_cms_and_real_parent_publishers',
              'institutional_cms_epoch_reviews',
              'bounded_local_institutional_cms_and_real_ec406_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    n=len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report)==fields and
         report.get('schema')==parent.RESULT_SCHEMA and
         report.get('command')=='audit-historical-ec339-institutional-cms' and
         report.get('exit_code')==report.get('offline_unresolved_exit_code')==2 and
         report.get('original_institutional_cms_bundle_sha256')==opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_institutional_cms_inventory_sha256')==opts[parent.AUDIT_ONLY[0]] and
         all(_sha_ok(report.get(k)) for k in ('verified_live_ec406_report_sha256',
                  'verified_live_ec406_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('bounded_local_institutional_cms_and_real_ec406_parent_consistency') is
              (not any(report[k] for k in parent.FLAGS[:5])) and
         report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
                                     if report[k]),parent.OUTCOMES[-1])+'_unresolved',
         'UNCHANGED_REAL_EC407_PARENT_REPORT_NOT_AUTHENTIC', 'unavailable')
    fields = {'epoch_index','verified_original_cms_statement_count',
              'historical_crl_and_claimed_window_count',
              'joint_real_ec406_and_institutional_cms_count',
              'institutional_cms_epoch_inventory_sha256',
              'real_ec406_parent_joint_custody_witness_count'}
    rows=report.get('institutional_cms_epoch_reviews')
    need(type(rows) is list and len(rows)==n and all(
         type(row) is dict and set(row)==fields and
         type(row['epoch_index']) is int and row['epoch_index']==i and
         all(type(row[k]) is int and 0<=row[k]<=2 for k in (
           'verified_original_cms_statement_count','historical_crl_and_claimed_window_count',
           'joint_real_ec406_and_institutional_cms_count',
           'real_ec406_parent_joint_custody_witness_count')) and
         row['joint_real_ec406_and_institutional_cms_count']<=
             row['historical_crl_and_claimed_window_count']<=
             row['verified_original_cms_statement_count'] and
         row['joint_real_ec406_and_institutional_cms_count']<=
             row['real_ec406_parent_joint_custody_witness_count'] and
         _sha_ok(row['institutional_cms_epoch_inventory_sha256'])
         for i,row in enumerate(rows)) and
         type(report.get('verified_joint_institutional_cms_and_real_parent_publishers')) is int and
         report['verified_joint_institutional_cms_and_real_parent_publishers']==sum(
             row['joint_real_ec406_and_institutional_cms_count'] for row in rows),
         'REAL_EC407_ORIGINAL_CMS_PARENT_EPOCH_COUNTS_INVALID', 'unavailable')
    return cdigest(report)


def _roles(roster, opts, read, used):
    exact(roster,parent.ROSTER_FIELDS,'REOPENED_EC407_SIGNER_ROSTER')
    need(roster.get('schema')==parent.ROSTER_SCHEMA and
         roster.get('claimed_directory_lineage_id')==opts['claimed_historical_directory_lineage_id'] and
         type(roster.get('assignments')) is list and len(roster['assignments'])==2,
         'EC407_REAL_ROSTER_MUST_HAVE_TWO_INSTITUTIONS','permission_denied')
    pair={}; keys=set()
    for row in roster['assignments']:
        exact(row,parent.ASSIGNMENT_FIELDS,'REAL_EC407_ROSTER_ROLE')
        role=row['publisher_id']
        need(type(role) is str and role not in pair and
             type(row['institutional_signer_id']) is str and
             parent.IDENT.fullmatch(row['institutional_signer_id']) is not None,
             'REAL_EC407_ROSTER_DUPLICATE_ROLE_OR_ID','permission_denied')
        rr=ref(row['root_certificate_original']); lr=ref(row['leaf_certificate_original'])
        need(rr['path'] not in used and lr['path'] not in used and rr['path']!=lr['path'],
             'REOPENED_PARENT_ROOT_LEAF_PATH_ALIASED', 'permission_denied')
        # Independent outside pins were verified by the unchanged EC407 audit;
        # check again against sorted role order below, not roster presentation order.
        rawroot=read(rr,'ec408_reopen_actual_ec407_root',parent.MAX_CERT)
        rawleaf=read(lr,'ec408_reopen_actual_ec407_leaf',parent.MAX_CERT)
        root=parent._cert(rawroot,'ROOT');leaf=parent._cert(rawleaf,'LEAF')
        need(leaf.issuer==root.subject,
             'REOPENED_PARENT_LEAF_ROOT_ISSUER_MISMATCH', 'permission_denied')
        # Accept only the very same signature algorithms already authorized by
        # EC407's unchanged original certificate-chain verifier.
        tsa._cert_signed_by(leaf,root)
        keys.update((c.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo) for c in (root,leaf)))
        pair[role]={'id':row['institutional_signer_id'], 'root_ref':rr,
                    'leaf_ref':lr,'root':root,'leaf':leaf}
    need(len(keys)==4 and len(set(v['id'] for v in pair.values()))==2,
         'ORIGINAL_INSTITUTIONAL_CERT_PUBLIC_KEYS_REUSED','permission_denied')
    ordered=sorted(pair)
    for i,role in enumerate(ordered):
        need(pair[role]['root_ref']['sha256']==opts[parent.NEW_SCALARS[3+i]] and
             pair[role]['leaf_ref']['sha256']==opts[parent.NEW_SCALARS[5+i]],
             'REOPENED_INSTITUTIONAL_CERT_NOT_OUTSIDE_EC407_PIN',
             'permission_denied')
    return pair,keys


def _engine(deriving,**opts):
    inherited=_inputs(opts,deriving)
    live=parent.audit(**inherited)  # PRODUCTION: REAL UNMODIFIED EC407 -> EC406 -> all ancestors
    live_sha=_parent_report(live,opts)
    lineage=opts['claimed_historical_directory_lineage_id']
    n=len(opts['historical_directory_root_shas'])
    read,doc,late=readers._readers()
    b408={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    b407={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    bundle=doc(b408,'ec408_reopen_new_original_ocsp_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'ORIGINAL_OCSP_BUNDLE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec407_original_institutional_cms_bundle_original']==b407 and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'NEW_OCSP_BUNDLE_NOT_BOUND_TO_TRUE_EC407_OR_EPOCHS','permission_denied')
    prior=doc(b407,'ec408_reopen_real_ec407_cms_bundle',parent.MAX_BUNDLE)
    exact(prior,parent.BUNDLE_FIELDS,'REAL_EC407_CMS_BUNDLE')
    need(prior['schema']==parent.BUNDLE_SCHEMA and
         prior['claimed_directory_lineage_id']==lineage and
         type(prior['epochs']) is list and len(prior['epochs'])==n,
         'REAL_EC407_ORIGINAL_CMS_LINEAGE_WRONG','permission_denied')
    rosterref=ref(prior['outside_institutional_certificate_roster_original'])
    need(rosterref['sha256']==opts[parent.NEW_SCALARS[2]],
         'OUTSIDE_REAL_EC407_INSTITUTIONAL_ROSTER_PIN_MISMATCH','permission_denied')
    roster=doc(rosterref,'ec408_reopen_real_ec407_certificate_roster',parent.MAX_ROSTER)
    used={b408['path'],b407['path'],rosterref['path']}
    parent.parent.parent._find_ref_paths(prior,used)
    # Original source manifests belong to the real audited parent chain. Read
    # their SHA-pinned originals again to guard *nested* predecessor original
    # paths against new OCSP or responder-certificate path impersonation.
    b406={'path':opts[parent.parent.NEW_SCALARS[0]],
          'sha256':opts[parent.parent.NEW_SCALARS[1]]}
    b405={'path':opts[parent.parent.parent.NEW_SCALARS[0]],
          'sha256':opts[parent.parent.parent.NEW_SCALARS[1]]}
    earlier406=doc(b406,'ec408_reopen_real_ec406_custody_originals',
                   parent.parent.MAX_BUNDLE)
    earlier405=doc(b405,'ec408_reopen_real_ec405_warc_originals',
                   parent.parent.parent.MAX_BUNDLE)
    exact(earlier406,parent.parent.BUNDLE_FIELDS,'REAL_EC406_ORIGINAL')
    exact(earlier405,parent.parent.parent.BUNDLE_FIELDS,'REAL_EC405_ORIGINAL')
    need(earlier406['schema']==parent.parent.BUNDLE_SCHEMA and
         earlier405['schema']==parent.parent.parent.BUNDLE_SCHEMA and
         earlier406['claimed_directory_lineage_id']==lineage and
         earlier405['claimed_directory_lineage_id']==lineage and
         prior['parent_ec406_original_custody_witness_bundle_original']==b406 and
         earlier406['parent_ec405_original_warc_timestamp_bundle_original']==b405,
         'REAL_ORIGINAL_EC407_EC406_EC405_SOURCE_LINK_MISMATCH',
         'permission_denied')
    used.update((b406['path'],b405['path']))
    parent.parent.parent._find_ref_paths(earlier406,used)
    parent.parent.parent._find_ref_paths(earlier405,used)
    # All inherited manifest paths and known original certificate/CRL labels are
    # protected, even when a new OCSP source uses a different JSON reference.
    for k in PARENT_SCALARS:
        if k.endswith('_file') and type(opts.get(k)) is str:used.add(opts[k])
    parent.parent.parent._find_ref_paths(roster,used)
    pair,protected_keys=_roles(roster,opts,read,set())  # reopen true certs with original hash
    roles=sorted(pair)
    need(len(roles)==2,'REAL_EC407_EXACT_TWO_ROLES_REQUIRED','permission_denied')
    first={};missing=set();records=[];reviews=[];total=0
    ocsp_paths=set(); ocsp_shas=set(); delegate_paths={}; delegate_spkis={}
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=(not live['bounded_local_institutional_cms_and_real_ec406_parent_consistency'] or
                     any(r['joint_real_ec406_and_institutional_cms_count']!=2
                         for r in live['institutional_cms_epoch_reviews']))
    evaluated=parent.utc(opts['ec407_institutional_evaluation_utc'])
    for i,epoch in enumerate(bundle['epochs']):
        exact(epoch,EPOCH_FIELDS,'INSTITUTIONAL_OCSP_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             type(epoch['publishers']) is list and len(epoch['publishers'])==2,
             'NEW_EPOCH_MUST_HAVE_TWO_NAMED_ROLES','permission_denied')
        old=prior['epochs'][i]; exact(old,parent.EPOCH_FIELDS,'REAL_EC407_EPOCH')
        need(old['epoch_index']==i and type(old['publishers']) is list and
             len(old['publishers'])==2,'REAL_EC407_EPOCH_MISMATCH','permission_denied')
        old_roles={r['publisher_id']:r for r in old['publishers']}
        need(set(old_roles)==set(roles),'REAL_EC407_PARENT_ROLE_ID_MISMATCH',
             'permission_denied')
        new_roles={}
        for row in epoch['publishers']:
            exact(row,ROLE_FIELDS,'DUAL_WINDOW_OCSP_ROLE')
            role=row['publisher_id']
            need(type(role) is str and role in roles and role not in new_roles and
                 row['institutional_signer_id']==pair[role]['id'] and
                 row['root_certificate_sha256']==pair[role]['root_ref']['sha256'] and
                 row['leaf_certificate_sha256']==pair[role]['leaf_ref']['sha256'],
                 'NEW_OCSP_ROLE_CANNOT_SUBSTITUTE_EC407_ORIGINAL_CERTIFICATE',
                 'permission_denied')
            new_roles[role]=row
        need(set(new_roles)==set(roles),'OCSP_EPOCH_TWO_ROLES_REQUIRED','permission_denied')
        good_count=valid_count=0
        members=[]
        for role in roles:
            row=new_roles[role]
            oldrow=old_roles[role]
            exact(oldrow,parent.ROLE_FIELDS,'REAL_EC407_CMS_ROLE')
            need(oldrow['institutional_signer_id']==pair[role]['id'],
                 'REAL_EC407_CMS_SIGNER_MISMATCH','permission_denied')
            historical=row['original_historical_ocsp_response']
            current=row['original_evaluation_ocsp_response']
            historical_delegate=row['historical_delegated_responder_certificate_original']
            current_delegate=row['evaluation_delegated_responder_certificate_original']
            if historical is None or current is None:
                need(i>0 and historical is None and current is None and
                     historical_delegate is None and current_delegate is None,
                     'FIRST_BOTH_OCSP_ORIGINALS_REQUIRED_AND_NO_PARTIAL_WINDOWS',
                     'permission_denied')
                missing.add(role);flags[FLAGS[2]]=True
                members.append({'publisher_id':role,'institutional_signer_id':pair[role]['id'],
                                'original_historical_ocsp_sha256':None,
                                'original_evaluation_ocsp_sha256':None,
                                'historical_original':None,'evaluation_original':None,
                                'both_signed_good_contemporaneous_windows':None})
                continue
            need(role not in missing,'MISSING_HISTORICAL_ORIGINAL_CANNOT_RESUME',
                 'permission_denied')
            need(oldrow['original_custody_statement'] is not None and
                 oldrow['original_detached_cms'] is not None,
                 'SIGNED_OCSP_CANNOT_REPAIR_MISSING_PARENT_CMS','permission_denied')
            stmtref=ref(oldrow['original_custody_statement'])
            stmt=doc(stmtref,'ec408_reopen_real_signed_ec407_custody_statement',
                     parent.MAX_STATEMENT)
            exact(stmt,parent.STATEMENT_FIELDS,'REAL_EC407_SIGNED_STATEMENT')
            need(stmt['schema']==parent.STATEMENT_SCHEMA and
                 stmt['directory_lineage_id']==lineage and
                 stmt['publisher_id']==role and
                 stmt['institutional_signer_id']==pair[role]['id'] and
                 type(stmt['epoch_index']) is int and stmt['epoch_index']==i,
                 'REAL_PARENT_SIGNED_CUSTODY_STATEMENT_WRONG','permission_denied')
            at=parent.utc(stmt['claimed_custody_utc'])
            ocsprefs=[ref(historical),ref(current)]
            need(ocsprefs[0]['path'] != ocsprefs[1]['path'] and
                 ocsprefs[0]['sha256'] != ocsprefs[1]['sha256'],
                 'TWO_DISTINCT_REAL_OCSP_RESPONSES_FOR_TWO_WINDOWS_REQUIRED',
                 'permission_denied')
            for r in ocsprefs:
                need(r['path'] not in used and r['path'] not in ocsp_paths and
                     r['path'] not in delegate_paths and r['sha256'] not in ocsp_shas,
                     'NEW_OCSP_SOURCE_ALIASES_REAL_OR_PREVIOUS_ORIGINAL',
                     'permission_denied')
                ocsp_paths.add(r['path']);ocsp_shas.add(r['sha256'])
            delegaterefs=[]
            for original in (historical_delegate,current_delegate):
                if original is None:
                    delegaterefs.append(None);continue
                r=ref(original)
                need(r['path'] not in used and r['path'] not in ocsp_paths and
                     (r['path'] not in delegate_paths or delegate_paths[r['path']]==
                      (role,r['sha256'])),
                     'DELEGATED_CERTIFICATE_ORIGINAL_PATH_ALIASES_OTHER_ROLE_OR_PARENT',
                     'permission_denied')
                delegate_paths[r['path']]=(role,r['sha256'])
                raw=read(r,'ec408_real_delegated_cert_original',issuer_ocsp.MAX_RESPONDER_CERT)
                try:
                    cert=x509.load_der_x509_certificate(raw)
                    need(cert.public_bytes(serialization.Encoding.DER)==raw,
                         'DELEGATED_CERT_MUST_BE_EXACT_DER','permission_denied')
                except (ValueError,TypeError) as exc:
                    raise errors.AnchorError('EC408_INVALID_DELEGATE_CERT_DER',
                                             'permission_denied') from exc
                spki=cert.public_key().public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
                need(spki not in protected_keys,
                     'DELEGATED_RESPONDER_REUSES_EC407_ROOT_OR_CUSTODY_LEAF_KEY',
                     'permission_denied')
                need(spki not in delegate_spkis or delegate_spkis[spki]==role,
                     'INSTITUTIONS_MUST_NOT_SHARE_ONE_DELEGATED_RESPONDER_KEY',
                     'permission_denied')
                delegate_spkis[spki]=role
                delegaterefs.append(r)
            h=issuer_ocsp._verify_original(ocsprefs[0],delegaterefs[0],
                      pair[role]['leaf'],pair[role]['root'],at,evaluated,
                      read,historical=True)
            v=issuer_ocsp._verify_original(ocsprefs[1],delegaterefs[1],
                      pair[role]['leaf'],pair[role]['root'],evaluated,evaluated,
                      read,historical=False)
            need(h['signed_ocsp_valid'] is True and v['signed_ocsp_valid'] is True,
                 'DER_OCSP_MUST_HAVE_VALID_ISSUER_OR_DELEGATE_SIGNATURE',
                 'permission_denied')
            valid_count+=1
            if h['certificate_status']!='good' or v['certificate_status']!='good':
                flags[FLAGS[4]]=True
            good=h['local_good_coverage'] and v['local_good_coverage']
            if good:good_count+=1
            else:flags[FLAGS[3]]=True
            if i==0:
                first[role]=(ocsprefs[0]['sha256'],ocsprefs[1]['sha256'])
            members.append({'publisher_id':role,'institutional_signer_id':pair[role]['id'],
                            'original_historical_ocsp_sha256':ocsprefs[0]['sha256'],
                            'original_evaluation_ocsp_sha256':ocsprefs[1]['sha256'],
                            'historical_original':h,'evaluation_original':v,
                            'both_signed_good_contemporaneous_windows':bool(good)})
        parent_joint=live['institutional_cms_epoch_reviews'][i][
              'joint_real_ec406_and_institutional_cms_count']
        joint=good_count if (not flags[FLAGS[0]] and parent_joint==2) else 0
        if joint!=2:flags[FLAGS[5]]=True
        inv={'epoch_index':i,'publishers':members,
             'verified_signed_dual_ocsp_pair_count':valid_count,
             'signed_good_contemporaneous_dual_window_count':good_count,
             'joint_real_ec407_parent_and_ocsp_count':joint}
        digest=cdigest(inv)
        if digest!=opts[REPEAT_NAMES[0]][i] or joint<opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]]=True
        records.append(inv)
        reviews.append({'epoch_index':i,'verified_signed_dual_ocsp_pair_count':valid_count,
                        'signed_good_contemporaneous_dual_window_count':good_count,
                        'joint_real_ec407_parent_and_ocsp_count':joint,
                        'institutional_ocsp_epoch_inventory_sha256':digest,
                        'real_ec407_parent_joint_cms_count':parent_joint})
        total+=joint
    need(len(first)==2,'FIRST_HISTORICAL_AND_EVALUATION_OCSP_BOTH_ROLES_REQUIRED',
         'permission_denied')
    pinned=[first[roles[0]][0],first[roles[1]][0],
            first[roles[0]][1],first[roles[1]][1]]
    if pinned != [opts[k] for k in NEW_SCALARS[2:]]:flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
               'verified_real_ec407_report_sha256':live_sha,
               'verified_real_ec407_inventory_sha256':live[
                   'receiver_verified_institutional_cms_inventory_sha256'],
               'real_ec407_institutional_cms_bundle_sha256':b407['sha256'],
               'ec408_original_ocsp_bundle_sha256':b408['sha256'],
               'first_outside_historical_and_evaluation_original_shas':pinned,
               'ec407_institutional_evaluation_utc':opts['ec407_institutional_evaluation_utc'],
               'epochs':records}
    invsha=cdigest(inventory)
    if not deriving and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # Exactly the same late original readback guarantee as EC407, including
    # original OCSP and delegated certificate files, without writing evidence.
    for path,(digest,limit) in late.items():
        raw=io._read({'path':path,'sha256':digest},
                     'ec408_final_original_reopen',limit,{},{},set())
        need(sha(raw)==digest,'SOURCE_ORIGINAL_CHANGED_IN_READBACK',
             'permission_denied')
    for k in FLAGS[-3:]:flags[k]=True
    return {'schema':DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command':('derive-historical-ec339-institutional-ocsp-inventory' if deriving
                       else 'audit-historical-ec339-institutional-ocsp'),
            'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                          OUTCOMES[-1])+'_unresolved',
            'exit_code':2,'offline_unresolved_exit_code':2,
            'verified_live_ec407_report_sha256':live_sha,
            'verified_live_ec407_inventory_sha256':live[
                'receiver_verified_institutional_cms_inventory_sha256'],
            'original_institutional_ocsp_bundle_sha256':b408['sha256'],
            'receiver_verified_institutional_ocsp_inventory_sha256':invsha,
            'verified_joint_institutional_ocsp_and_real_parent_publishers':total,
            'institutional_ocsp_epoch_reviews':reviews,
            'bounded_local_signed_ocsp_and_real_ec407_parent_consistency':
                not any(flags[k] for k in FLAGS[:6]),
            'sender_origin_path_required_or_read':False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            **flags, **{k:False for k in NEGATIVES},
            **({'unsigned_institutional_ocsp_evidence_inventory':inventory} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True,**opts)


def audit(**opts):
    return _engine(False,**opts)
