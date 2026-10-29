#!/usr/bin/env python3
"""EC392 read-only, dual-offsite observer reconciliation with signed cross-view receipts.

Two *real* EC391 audits are invoked under the same immutable EC390 parent pins.
Both signed prior Heads are re-opened and their respective RFC3161 tokens, keeper
keys, CA paths and CRLs are checked again. Independent domain-separated Ed25519
cross-view receipts, separately timestamped as CMS, expose contradictions and
signed self-equivocation; they NEVER elect a fork winner or grant legal custody.
"""
from __future__ import annotations

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec372_historical_authority import authority_archive as io
from ec391_prior_time import prior_time as parent

RESULT_SCHEMA = 'ces.ec392.receiver_dual_offsite_crossview_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec392.unsigned_dual_offsite_crossview_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec392.receiver_dual_offsite_crossview_denial.v1'
BUNDLE_SCHEMA = 'ces.ec392.dual_offsite_crossview_checkpoint_bundle.v1'
CHECKPOINT_SCHEMA = 'ces.ec392.signed_crossview_observation_original.v1'
CLAIM_SCHEMA = 'ces.ec392.crossview_observation_claim.v1'
INVENTORY_SCHEMA = 'ces.ec392.receiver_unsigned_crossview_fork_inventory.v1'
DOMAIN = b'CES/EC392/DualOffsite/SignedCrossViewObservation/v1\0'
ZERO = '0'*64
MAX_BUNDLE = 100_000
MAX_CHECKPOINT = 14_000
MAX_EVIDENCE = 36  # 3 epochs x 2 channels x 2 observers x (signed + token + alternate).

PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_crossview_bundle_file',
    'expected_historical_ec339_crossview_bundle_sha256',
    'secondary_ec391_prior_offsite_time_bundle_file',
    'expected_secondary_ec391_prior_offsite_time_bundle_sha256',
    'expected_outside_retained_secondary_ec391_keeper_roster_sha256',
    'expected_outside_retained_secondary_ec391_tsa_registry_sha256',
    'expected_retained_secondary_ec391_prior_time_inventory_sha256',
    'expected_outside_retained_ec392_primary_observer_id',
    'expected_outside_retained_ec392_secondary_observer_id',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_crossview_inventory_sha256',)
NEW_REPEATS = (
    ('secondary_ec391_prior_signed_head_inventory_shas',
     '--secondary-ec391-prior-signed-head-inventory-sha256'),
    ('secondary_ec391_prior_rfc3161_token_inventory_shas',
     '--secondary-ec391-prior-rfc3161-token-inventory-sha256'),
    ('minimum_secondary_ec391_prior_timestamped_head_counts',
     '--minimum-secondary-ec391-prior-timestamped-head-count'),
    ('historical_ec339_crossview_signed_checkpoint_inventory_shas',
     '--historical-ec339-crossview-signed-checkpoint-inventory-sha256'),
    ('historical_ec339_crossview_rfc3161_token_inventory_shas',
     '--historical-ec339-crossview-rfc3161-token-inventory-sha256'),
    ('minimum_historical_ec339_crossview_timestamped_checkpoint_counts',
     '--minimum-historical-ec339-crossview-timestamped-checkpoint-count'),
)
REPEAT_NAMES = tuple(key for key,_ in NEW_REPEATS)
BUNDLE_FIELDS = {'schema','claimed_directory_lineage_id','primary_observer_id',
                 'secondary_observer_id','primary_ec391_offsite_bundle_original',
                 'secondary_ec391_offsite_bundle_original','epochs'}
EPOCH_FIELDS = {'epoch_index','channels'}
CHANNEL_FIELDS = {'tsa_channel_id','primary','secondary'}
OBSERVATION_FIELDS = {'signed_crossview_checkpoint_original',
  'rfc3161_crossview_checkpoint_token_original','tsa_authority_id',
  'alternate_signed_crossview_checkpoint_original'}
CLAIM_FIELDS = {'schema','directory_lineage_id','observer_id','peer_observer_id',
  'tsa_channel_id','epoch_index','checkpoint_sequence','offsite_keeper_id',
  'own_prior_signed_head_original_sha256','observed_peer_prior_signed_head_original_sha256',
  'own_signed_source_snapshot_sha256','previous_signed_crossview_checkpoint_original_sha256',
  'claimed_observed_utc'}
FLAGS = (
  'inherited_live_ec391_or_earlier_signed_historical_dispute',
  'outside_retained_two_observer_or_crossview_sha_floor_disagrees',
  'timestamped_observer_head_or_crossview_checkpoint_missing',
  'two_valid_signed_observer_source_snapshots_disagree',
  'two_valid_signed_observer_nonprefix_split_view',
  'valid_signed_crossview_claim_disagrees_with_reopened_peer_or_self_head',
  'same_keeper_same_epoch_has_two_distinct_valid_signed_crossview_claims',
  'cross_epoch_checkpoint_predecessor_prefix_or_seen_time_rollback',
  'crossview_rfc3161_gen_time_claim_order_or_bounded_crl_disagreement',
  'legal_observer_independence_prior_physical_custody_and_tsa_identity_not_proven',
  'unobserved_forks_full_revocation_census_and_trusted_utc_not_proven',
)
OUTCOMES = (
  'ec392_inherited_ec391_and_older_real_signed_receiver_dispute',
  'ec392_outside_retained_independent_crossview_inventory_or_floor_disagrees',
  'ec392_prior_timestamped_head_or_signed_crossview_checkpoint_missing',
  'ec392_two_authenticated_offsite_source_snapshots_disagree',
  'ec392_nonprefix_signed_observer_split_view',
  'ec392_signed_crossview_observation_contradicts_reopened_original_heads',
  'ec392_same_keeper_signed_two_incompatible_same_epoch_observations',
  'ec392_signed_crossview_epoch_chain_or_prefix_rollback',
  'ec392_crossview_signed_timestamp_or_offline_crl_disagrees',
  'ec392_real_external_legal_identity_and_prior_offsite_custody_not_proven',
  'ec392_hidden_forks_exhaustive_revocation_and_calibrated_utc_not_proven',
)
NEGATIVES = (
  'two_different_pinned_keeper_keys_prove_two_legally_independent_people_or_sites',
  'locally_supplied_roster_root_sha_or_unsigned_inventory_is_historically_independently_retained',
  'local_rfc3161_fixture_or_caller_pinned_root_proves_qualified_time_authority',
  'signed_claimed_observed_utc_proves_original_offsite_physical_possession',
  'cross_observer_gossip_proves_completeness_of_global_hidden_fork_census',
  'valid_conflicting_signed_views_select_an_authoritative_fork_winner',
  'secondary_ec391_parent_or_signed_source_is_allowed_to_be_caller_fabricated',
  'signed_crossview_observation_extends_historical_ec339_issuer_authority',
  'one_cms_token_proves_global_current_ocsp_or_exhaustive_revocation',
  'receiver_has_issued_timestamp_or_accessed_private_keys_or_external_network',
  'receiver_performed_native_powershell_git_ci_provider_or_cas_worm_write',
  'full_unmocked_ec317_ec318_and_final_independent_user_acceptance_proven',
)


def need(ok, code, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC392_'+code,status)


def exact(value, fields, label):
    need(type(value) is dict and set(value)==set(fields),label+'_EXACT_FIELDS_REQUIRED')


def sha(data):
    return parent.sha(data)


def _inputs(opts, derive):
    expected=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive: expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'EXACT_EC391_AND_DUAL_VIEW_INPUTS_REQUIRED')
    inherited={key:opts[key] for key in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC392_CROSSVIEW_BUNDLE')
    io.authority.outer_pin(opts[NEW_SCALARS[2]], opts[NEW_SCALARS[3]],
                           'EC392_SECOND_INDEPENDENT_EC391_BUNDLE')
    for key in NEW_SCALARS[4:7]:
        need(tr._sha(opts[key]),'OUTSIDE_RETAINED_'+key.upper()+'_REQUIRED')
    for key in NEW_SCALARS[7:]:
        need(type(opts[key]) is str and parent.prior.IDENT.fullmatch(opts[key]) is not None,
             'TWO_OUTSIDE_RETAINED_OBSERVER_IDS_REQUIRED')
    need(opts[NEW_SCALARS[7]]!=opts[NEW_SCALARS[8]],
         'TWO_DISTINCT_OBSERVER_IDENTITIES_REQUIRED','permission_denied')
    if not derive:
        need(tr._sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_RETAINED_CROSSVIEW_INVENTORY_REQUIRED')
    epochs=len(opts['historical_directory_root_shas'])
    need(1<=epochs<=3,'ONE_TO_THREE_EPOCHS_REQUIRED')
    for key in REPEAT_NAMES:
        seq=opts[key]
        need(type(seq) is list and len(seq)==epochs,'EXACT_PER_EPOCH_CROSSVIEW_PINS_REQUIRED')
        if key.startswith('minimum_'):
            bound=2 if key==NEW_REPEATS[2][0] else 4
            need(all(type(x) is int and 0<=x<=bound for x in seq),
                 'TIMESTAMPED_TWO_OBSERVER_MINIMUM_BOUND_REQUIRED')
        else:
            need(all(tr._sha(x) for x in seq),'OUTSIDE_PER_EPOCH_INVENTORY_SHA_INVALID')
    return inherited


def _parent_report(report, opts, bundle_sha):
    n=len(opts['historical_directory_root_shas'])
    scalar={
      'schema','command','status','exit_code','offline_unresolved_exit_code',
      'verified_live_parent_ec390_canonical_result_sha256',
      'historical_prior_offsite_time_original_sha256',
      'receiver_verified_prior_offsite_time_inventory_sha256',
      'cryptographically_verified_timestamped_prior_head_count',
      'historical_prior_offsite_time_epoch_reviews',
      'local_prior_offsite_signatures_timestamp_chain_consistent',
      'sender_origin_path_required_or_read',
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
      *parent.FLAGS,*parent.NEGATIVES}
    need(type(report) is dict and set(report)==scalar and
      report.get('schema')==parent.RESULT_SCHEMA and
      report.get('command')=='audit-historical-ec339-prior-offsite-time' and
      report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
      report.get('sender_origin_path_required_or_read') is False and
      report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
      report.get('historical_prior_offsite_time_original_sha256')==bundle_sha and
      all(type(report.get(k)) is bool for k in parent.FLAGS) and
      all(report[k] is True for k in parent.FLAGS[-2:]) and
      all(report.get(k) is False for k in parent.NEGATIVES) and
      type(report.get('local_prior_offsite_signatures_timestamp_chain_consistent')) is bool and
      report['local_prior_offsite_signatures_timestamp_chain_consistent']==(
        not any(report[k] for k in parent.FLAGS[:8])) and
      report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
         if report[k]),parent.OUTCOMES[-1])+'_unresolved' and
      type(report.get('cryptographically_verified_timestamped_prior_head_count')) is int and
      0<=report['cryptographically_verified_timestamped_prior_head_count']<=2*n and
      all(tr._sha(report.get(k)) for k in (
        'verified_live_parent_ec390_canonical_result_sha256',
        'receiver_verified_prior_offsite_time_inventory_sha256')),
      'REAL_EC391_AUDIT_REPORT_NOT_AUTHENTIC_UNRESOLVED','unavailable')
    rows=report['historical_prior_offsite_time_epoch_reviews']
    need(type(rows) is list and len(rows)==n and all(
      type(row) is dict and set(row)=={
        'epoch_index','prior_timestamped_signed_head_count',
        'prior_offsite_signed_head_inventory_sha256',
        'prior_rfc3161_token_inventory_sha256',
        'missing_prior_head_or_timestamp_channels'} and
      type(row['epoch_index']) is int and row['epoch_index']==i and
      type(row['prior_timestamped_signed_head_count']) is int and
      0<=row['prior_timestamped_signed_head_count']<=2 and
      type(row['missing_prior_head_or_timestamp_channels']) is int and
      0<=row['missing_prior_head_or_timestamp_channels']<=2 and
      tr._sha(row['prior_offsite_signed_head_inventory_sha256']) and
      tr._sha(row['prior_rfc3161_token_inventory_sha256'])
      for i,row in enumerate(rows)),
      'REAL_EC391_PARENT_EPOCH_REVIEWS_INVALID','unavailable')
    return sha(canonical.canonical(report))


def _secondary_opts(primary, opts):
    swapped=dict(primary)
    for oldkey,newkey in zip(parent.NEW_SCALARS[:4], NEW_SCALARS[2:6],strict=True):
        swapped[oldkey]=opts[newkey]
    swapped[parent.AUDIT_ONLY[0]]=opts[NEW_SCALARS[6]]
    for (oldkey,_),(newkey,_) in zip(parent.NEW_REPEATS,NEW_REPEATS[:3],strict=True):
        swapped[oldkey]=opts[newkey]
    return swapped


def _refs(view):
    """References are discovered only under fixed-schema already-audited EC391 bundles."""
    for row in view['roster']['log_keepers']:
        yield row['public_key_original']
    for authority in view['trust']['authorities']:
        yield authority['root_certificate_original']
        yield from authority['crl_originals']
    for epoch in view['bundle']['epochs']:
        for row in epoch['channels']:
            for key in ('signed_prior_offsite_head_original','rfc3161_timestamp_original'):
                if row[key] is not None: yield row[key]


def _reader():
    pins={};types={};late={};cache={}
    def read(ref,label,cap):
        parent.originals.prior.lineage.parent.ref_check(ref,'EC392_'+label)
        path=ref['path']
        if path in cache:
            previous,raw=cache[path]
            need(previous==ref['sha256'] and len(raw)<=cap,
                 'REUSED_ORIGINAL_PATH_MISMATCH','permission_denied')
            return raw
        raw=io._read(ref,'ec392_'+label,cap,pins,types,set())
        cache[path]=(ref['sha256'],raw)
        late[path]=(ref['sha256'],cap)
        return raw
    def doc(ref,label,cap):
        return tr.strict_json(read(ref,label,cap),'EC392_'+label)
    return read,doc,late


def _view(obs_id, ref, expected_roster_sha, expected_trust_sha,
          read, doc, lineage):
    bundle=doc(ref,'ec391_authenticated_observer_bundle',parent.MAX_BUNDLE)
    exact(bundle,parent.BUNDLE_FIELDS,'AUDITED_EC391_OFFSITE_BUNDLE')
    need(bundle['schema']==parent.BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage,
         'EC391_OBSERVER_BUNDLE_LINEAGE_INVALID','permission_denied')
    roster=doc(bundle['offsite_log_keeper_roster_original'],
               'reopened_ec391_keeper_roster',parent.MAX_ROSTER)
    trust=doc(bundle['tsa_trust_registry_original'],
              'reopened_ec391_tsa_registry',parent.MAX_TRUST)
    keys=parent._keeper_roster(roster,bundle['offsite_log_keeper_roster_original'],
                                 expected_roster_sha,read,set(),set())
    authorities=parent._trust_registry(trust,bundle['tsa_trust_registry_original'],
                                       expected_trust_sha,lineage,read)
    return {'id':obs_id,'ref':ref,'bundle':bundle,'roster':roster,
            'trust':trust,'keys':keys,'authorities':authorities}


def _disjoint(primary, secondary, crossref, older_paths, crossbundle):
    need(primary['ref']['path']!=secondary['ref']['path'] and
         primary['ref']['sha256']!=secondary['ref']['sha256'],
         'SAME_OR_COPIED_EC391_OBSERVER_BUNDLE_DENIED','permission_denied')
    first=set(primary['keys'].values());second=set(secondary['keys'].values())
    need(not first.intersection(second) and
         not set(primary['keys']).intersection(secondary['keys']),
         'CROSS_OBSERVER_KEEPER_ID_OR_PUBLIC_KEY_REUSED','permission_denied')
    roots1={authority['root_sha'] for authority in primary['authorities'].values()}
    roots2={authority['root_sha'] for authority in secondary['authorities'].values()}
    need(not roots1.intersection(roots2),
         'CROSS_OBSERVER_TSA_ROOT_COPIED_NOT_INDEPENDENT','permission_denied')
    refs1=[primary['ref'],primary['bundle']['offsite_log_keeper_roster_original'],
           primary['bundle']['tsa_trust_registry_original'],*_refs(primary)]
    refs2=[secondary['ref'],secondary['bundle']['offsite_log_keeper_roster_original'],
           secondary['bundle']['tsa_trust_registry_original'],*_refs(secondary)]
    paths1=[r['path'] for r in refs1]
    paths2=[r['path'] for r in refs2]
    need(len(paths1)==len(set(paths1)) and len(paths2)==len(set(paths2)) and
         not set(paths1).intersection(paths2) and
         not (set(paths1)|set(paths2)).intersection(older_paths|{crossref['path']}),
         'CROSS_OBSERVER_OR_PARENT_EVIDENCE_PATH_REUSED','permission_denied')
    heads1={r['sha256'] for ep in primary['bundle']['epochs']
            for row in ep['channels'] for k,r in row.items()
            if k=='signed_prior_offsite_head_original' and r is not None}
    heads2={r['sha256'] for ep in secondary['bundle']['epochs']
            for row in ep['channels'] for k,r in row.items()
            if k=='signed_prior_offsite_head_original' and r is not None}
    need(not heads1.intersection(heads2),
         'COPIED_EC391_SIGNED_HEAD_CANNOT_BE_SECOND_OBSERVER','permission_denied')
    reserved=older_paths|set(paths1)|set(paths2)|{crossref['path']}
    originals=[]
    for epoch in crossbundle['epochs']:
        exact(epoch,EPOCH_FIELDS,'CROSSVIEW_EPOCH')
        for channel in epoch['channels']:
            exact(channel,CHANNEL_FIELDS,'CROSSVIEW_CHANNEL')
            for obs in ('primary','secondary'):
                row=channel[obs]
                exact(row,OBSERVATION_FIELDS,'CROSSVIEW_OBSERVER_ROW')
                for field in OBSERVATION_FIELDS:
                    ref=row[field]
                    if field=='tsa_authority_id':continue
                    if ref is not None:
                        parent.originals.prior.lineage.parent.ref_check(
                            ref,'EC392_CROSSVIEW_'+field)
                        originals.append(ref['path'])
    need(len(originals)<=MAX_EVIDENCE and
         len(originals)==len(set(originals)) and
         not set(originals).intersection(reserved),
         'NEW_CROSSVIEW_SIGNED_CHECKPOINT_AND_TOKEN_ORIGINALS_UNIQUE',
         'permission_denied')


def _heads(view, report, read, lineage, evaluation):
    """Re-authenticate the EC391 original Head and RFC3161 token as a separate view."""
    bundle=view['bundle'];countall=0;result=[]
    n=len(report['historical_prior_offsite_time_epoch_reviews'])
    need(type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'EC391_ORIGINAL_VIEW_EPOCH_COUNT_CHANGED','permission_denied')
    for idx, epoch in enumerate(bundle['epochs']):
        exact(epoch,parent.EPOCH_FIELDS,'EC391_REOPENED_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==idx and
             type(epoch['channels']) is list and 1<=len(epoch['channels'])<=2,
             'EC391_REOPENED_EPOCH_ORDER_DENIED','permission_denied')
        records={};heads=[];tokens=[];count=0;missing=0
        for row in epoch['channels']:
            exact(row,parent.CHANNEL_FIELDS,'EC391_REOPENED_CHANNEL')
            cid=row['tsa_channel_id']
            need(type(cid) is str and parent.prior.IDENT.fullmatch(cid) is not None
                 and cid not in records,
                 'EC391_VIEW_DUPLICATE_OR_INVALID_CHANNEL','permission_denied')
            href=row['signed_prior_offsite_head_original']
            tref=row['rfc3161_timestamp_original']
            aid=row['tsa_authority_id']
            need((href is None and tref is None and aid is None) or
                 (href is not None and ((tref is None and aid is None) or
                                        (tref is not None and aid in view['authorities']))),
                 'REOPENED_EC391_HEAD_TOKEN_AUTHORITY_INVALID','permission_denied')
            state={'head_sha':None,'pairs':None,'source_sha':None,'signer':None,
              'tsa_gen':None,'token_sha':None,'tsa_root_sha':None,
              'crl_current':False,'head_claim_utc':None}
            if href is not None:
                raw=read(href,'reopened_ec391_signed_prior_head',parent.MAX_SIGNED)
                signed=tr.strict_json(raw,'EC392_REOPEN_SIGNED_PRIOR_HEAD')
                need(type(signed) is dict and type(signed.get('claim')) is dict and
                     signed['claim'].get('offsite_keeper_id') in view['keys'],
                     'REOPENED_PRIOR_HEAD_SIGNER_NOT_IN_VERIFIED_VIEW','permission_denied')
                claim=parent.prior._signed(signed,parent.SIGNED_SCHEMA,
                  parent.CLAIM_SCHEMA,parent.CLAIM_FIELDS,
                  view['keys'][signed['claim']['offsite_keeper_id']],
                  parent.DOMAIN,'EC392_REOPEN_AUTHENTIC_EC391_HEAD')
                pairs=claim['ec389_signed_source_pairs']
                need(claim['directory_lineage_id']==lineage and
                  claim['tsa_channel_id']==cid and
                  type(claim['epoch_index']) is int and claim['epoch_index']==idx and
                  type(claim['log_sequence']) is int and claim['log_sequence']==idx+1 and
                  type(pairs) is list and len(pairs)<=8 and all(
                    type(pair) is dict and set(pair)==parent.prior.PAIR_FIELDS and
                    all(tr._sha(value) for value in pair.values()) for pair in pairs) and
                  len({p['ec389_signed_witness_original_sha256'] for p in pairs})==len(pairs) and
                  len({p['ec389_signed_custody_original_sha256'] for p in pairs})==len(pairs) and
                  parent.prior.old338._utc(claim['claimed_logged_utc']),
                  'REOPENED_EC391_HEAD_LINEAGE_OR_AUTHENTIC_PAIR_FORMAT_CHANGED',
                  'permission_denied')
                state.update(head_sha=href['sha256'],pairs=pairs,
                   source_sha=sha(canonical.canonical(pairs)),
                   signer=claim['offsite_keeper_id'],
                   head_claim_utc=claim['claimed_logged_utc'])
                if tref is not None:
                    root=view['authorities'][aid]
                    token=read(tref,'reopened_ec391_head_rfc3161',parent.MAX_DER)
                    verification=tsa._tsa_token(token,raw,root['root'],root['policy'])
                    crl=tsa._check_crls(verification['certificate_path'],root['crls'],
                                        verification['token_gen_time'],evaluation)
                    state.update(token_sha=tref['sha256'],
                       tsa_root_sha=verification['tsa_root_cert_der_sha256'],
                       tsa_gen=verification['token_gen_time'],
                       crl_current=(not crl['revoked_at_or_before_gen_time'] and
                         crl['all_chain_edges_have_single_fresh_crl_as_furnished']))
                    count+=1
            heads.append({'tsa_channel_id':cid,'signed_prior_offsite_head_sha256':state['head_sha'],
                          'signed_prior_source_snapshot_sha256':state['source_sha']})
            tokens.append({'tsa_channel_id':cid,'rfc3161_timestamp_sha256':state['token_sha'],
                           'tsa_root_der_sha256':state['tsa_root_sha']})
            if state['head_sha'] is None or state['tsa_gen'] is None:missing+=1
            records[cid]=state
        review=report['historical_prior_offsite_time_epoch_reviews'][idx]
        need(review['prior_offsite_signed_head_inventory_sha256']==
             sha(canonical.canonical(heads)) and
             review['prior_rfc3161_token_inventory_sha256']==
             sha(canonical.canonical(tokens)) and
             review['prior_timestamped_signed_head_count']==count and
             count<=len(records) and
             countall+count<=2*n,
             'TWO_LIVE_EC391_AUDITS_REREAD_INVENTORIES_DISAGREE','permission_denied')
        countall+=count;result.append({'channels':records,'missing_heads_or_tokens':missing})
    need(report['cryptographically_verified_timestamped_prior_head_count']==countall,
         'EC391_REREAD_TSA_COUNT_DISAGREES_WITH_REAL_AUDIT','permission_denied')
    return result


def _verify_checkpoint(ref, obs, peer_id, view, own, peer, cid, idx, previous,
                       read, lineage, evaluation, tokenref, authority_id,
                       alternate_ref, flags):
    """Authenticate one receipt; retain contradictory *valid* self/peer claims."""
    if ref is None:
        need(tokenref is None and authority_id is None and alternate_ref is None,
             'ORPHAN_RFC3161_OR_SIGNED_ALTERNATE_REQUIRES_PRIMARY_CHECKPOINT',
             'permission_denied')
        return {'observer_id':obs,'checkpoint_sha256':None,'alternate_sha256':None,
                'token_sha256':None,'timestamp_authenticated':False,
                'checkpoint_tsa_gen_time_utc':None,'bounded_crl_current':False,
                'claims_match_reopened_heads':False},previous
    need(own['head_sha'] is not None,
         'CROSSVIEW_CHECKPOINT_WITHOUT_VERIFIED_EC391_HEAD','permission_denied')
    data=read(ref,'signed_crossview_checkpoint',MAX_CHECKPOINT)
    signed=tr.strict_json(data,'EC392_SIGNED_CROSSVIEW_CHECKPOINT')
    claim=parent.prior._signed(signed,CHECKPOINT_SCHEMA,CLAIM_SCHEMA,CLAIM_FIELDS,
       view['keys'][own['signer']],DOMAIN,'EC392_CROSSVIEW_CHECKPOINT')
    need(claim['directory_lineage_id']==lineage and claim['observer_id']==obs and
         claim['peer_observer_id']==peer_id and
         claim['tsa_channel_id']==cid and type(claim['epoch_index']) is int and
         claim['epoch_index']==idx and type(claim['checkpoint_sequence']) is int and
         claim['checkpoint_sequence']==idx+1 and
         claim['offsite_keeper_id']==own['signer'] and
         parent.prior.old338._utc(claim['claimed_observed_utc']) and
         all(x is None or tr._sha(x) for x in (
           claim['own_prior_signed_head_original_sha256'],
           claim['observed_peer_prior_signed_head_original_sha256'])) and
         tr._sha(claim['own_signed_source_snapshot_sha256']) and
         (claim['previous_signed_crossview_checkpoint_original_sha256']==ZERO or
          tr._sha(claim['previous_signed_crossview_checkpoint_original_sha256'])),
         'SIGNED_CROSSVIEW_LINEAGE_ROLE_SEQUENCE_UTC_OR_SHA_INVALID','permission_denied')
    match=(claim['own_prior_signed_head_original_sha256']==own['head_sha'] and
           claim['observed_peer_prior_signed_head_original_sha256']==peer['head_sha'] and
           claim['own_signed_source_snapshot_sha256']==own['source_sha'])
    if not match:flags[FLAGS[5]]=True
    previous_sha=previous['sha'] if previous else ZERO
    if claim['previous_signed_crossview_checkpoint_original_sha256']!=previous_sha:
        flags[FLAGS[7]]=True
    claimed=tsa._utc(claim['claimed_observed_utc'])
    if previous and claimed<previous['claimed']:flags[FLAGS[7]]=True
    alternative=None
    if alternate_ref is not None:
        alt_raw=read(alternate_ref,'conflicting_signed_crossview_claim',MAX_CHECKPOINT)
        alt=tr.strict_json(alt_raw,'EC392_ALTERNATE_SIGNED_CROSSVIEW_CHECKPOINT')
        altclaim=parent.prior._signed(alt,CHECKPOINT_SCHEMA,CLAIM_SCHEMA,CLAIM_FIELDS,
           view['keys'][own['signer']],DOMAIN,'EC392_ALTERNATE_CROSSVIEW_CHECKPOINT')
        need(all(altclaim[k]==claim[k] for k in ('schema','directory_lineage_id',
          'observer_id','peer_observer_id','tsa_channel_id','epoch_index',
          'checkpoint_sequence','offsite_keeper_id')) and
          altclaim!=claim and alternate_ref['sha256']!=ref['sha256'] and
          parent.prior.old338._utc(altclaim['claimed_observed_utc']) and
          (altclaim['previous_signed_crossview_checkpoint_original_sha256']==ZERO or
            tr._sha(altclaim['previous_signed_crossview_checkpoint_original_sha256'])) and
          all(v is None or tr._sha(v) for v in (
            altclaim['own_prior_signed_head_original_sha256'],
            altclaim['observed_peer_prior_signed_head_original_sha256'])) and
          tr._sha(altclaim['own_signed_source_snapshot_sha256']),
          'SECOND_SAME_KEEPER_EPOCH_CLAIM_MUST_BE_DISTINCT_VALID_EQUIVOCATION',
          'permission_denied')
        alternative=alternate_ref['sha256'];flags[FLAGS[6]]=True
    need((tokenref is None and authority_id is None) or
         (tokenref is not None and authority_id in view['authorities']),
         'CHECKPOINT_TOKEN_REQUIRES_KNOWN_INDEPENDENT_TSA','permission_denied')
    state={'observer_id':obs,'checkpoint_sha256':ref['sha256'],
          'alternate_sha256':alternative,'token_sha256':None,
          'timestamp_authenticated':False,'checkpoint_tsa_gen_time_utc':None,
          'bounded_crl_current':False,'claims_match_reopened_heads':match}
    newprev={'sha':ref['sha256'],'claimed':claimed,
             'gen':previous['gen'] if previous else None}
    if tokenref is None:
        flags[FLAGS[2]]=True
        return state,newprev
    authority=view['authorities'][authority_id]
    token=read(tokenref,'signed_crossview_rfc3161_token',parent.MAX_DER)
    check=tsa._tsa_token(token,data,authority['root'],authority['policy'])
    revocation=tsa._check_crls(check['certificate_path'],authority['crls'],
                               check['token_gen_time'],evaluation)
    gen=check['token_gen_time'];gen_utc=gen.isoformat(timespec='seconds').replace('+00:00','Z')
    crl_current=(not revocation['revoked_at_or_before_gen_time'] and
                 revocation['all_chain_edges_have_single_fresh_crl_as_furnished'])
    if (not crl_current or gen>evaluation or gen<claimed or
        (own['tsa_gen'] is not None and gen<own['tsa_gen']) or
        (peer['tsa_gen'] is not None and gen<peer['tsa_gen']) or
        (previous and previous['gen'] and gen<previous['gen'])):
        flags[FLAGS[8]]=True
    state.update(token_sha256=tokenref['sha256'],timestamp_authenticated=True,
          checkpoint_tsa_gen_time_utc=gen_utc,bounded_crl_current=crl_current)
    newprev['gen']=gen
    return state,newprev


def _engine(derive, **opts):
    inherited=_inputs(opts,derive)
    primary_report=parent.audit(**inherited)  # Never accept a supplied parent report.
    primary_sha=_parent_report(primary_report,opts,opts[parent.NEW_SCALARS[1]])
    second_opts=_secondary_opts(inherited,opts)
    secondary_report=parent.audit(**second_opts)  # Full unchanged EC391->EC369 again.
    secondary_sha=_parent_report(secondary_report,opts,opts[NEW_SCALARS[3]])
    need(primary_report['verified_live_parent_ec390_canonical_result_sha256']==
         secondary_report['verified_live_parent_ec390_canonical_result_sha256'],
         'TWO_GENUINE_EC391_RECEIVERS_DISAGREE_ON_LIVE_EC390_PARENT','permission_denied')
    lineage=opts['claimed_historical_directory_lineage_id']
    evaluation=tsa._utc(opts['ec391_tsa_evaluation_utc'])
    read,doc,late=_reader()
    crossref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    cross=doc(crossref,'crossview_bundle',MAX_BUNDLE)
    exact(cross,BUNDLE_FIELDS,'CROSSVIEW_BUNDLE')
    need(cross['schema']==BUNDLE_SCHEMA and
         cross['claimed_directory_lineage_id']==lineage and
         cross['primary_observer_id']==opts[NEW_SCALARS[7]] and
         cross['secondary_observer_id']==opts[NEW_SCALARS[8]] and
         type(cross['epochs']) is list and
         len(cross['epochs'])==len(opts['historical_directory_root_shas']),
         'OUTSIDE_PINNED_OBSERVER_IDS_AND_EPOCH_COUNT_REQUIRED','permission_denied')
    primref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    secref={'path':opts[NEW_SCALARS[2]],'sha256':opts[NEW_SCALARS[3]]}
    need(cross['primary_ec391_offsite_bundle_original']==primref and
         cross['secondary_ec391_offsite_bundle_original']==secref,
         'CROSSVIEW_MUST_BIND_BOTH_ACTUAL_EC391_ORIGINAL_BUNDLES','permission_denied')
    primary=_view(cross['primary_observer_id'],primref,opts[parent.NEW_SCALARS[2]],
                  opts[parent.NEW_SCALARS[3]],read,doc,lineage)
    secondary=_view(cross['secondary_observer_id'],secref,opts[NEW_SCALARS[4]],
                    opts[NEW_SCALARS[5]],read,doc,lineage)
    oldpaths={value for key,value in opts.items() if key.endswith('_file') and
              type(value) is str}
    oldpaths-={primref['path'],secref['path'],crossref['path']}
    _disjoint(primary,secondary,crossref,oldpaths,cross)
    observed=[_heads(primary,primary_report,read,lineage,evaluation),
              _heads(secondary,secondary_report,read,lineage,evaluation)]
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=(not primary_report['local_prior_offsite_signatures_timestamp_chain_consistent']
      or not secondary_report['local_prior_offsite_signatures_timestamp_chain_consistent'])
    views=[primary,secondary]
    histories=[{},{}]
    prior_union={}
    inventories=[];reviews=[];forkcases=[];authenticated=0;equivocations=0
    for idx, epoch in enumerate(cross['epochs']):
        exact(epoch,EPOCH_FIELDS,'CROSSVIEW_EPOCH')
        expected=list(observed[0][idx]['channels'])
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==idx and
             type(epoch['channels']) is list and
             [c.get('tsa_channel_id') for c in epoch['channels']]==expected and
             list(observed[1][idx]['channels'])==expected,
             'CROSSVIEW_EPOCH_CHANNELS_MUST_MATCH_BOTH_GENUINE_EC391_VIEWS',
             'permission_denied')
        signed_inventory=[];token_inventory=[];channel_inventory=[];verified_here=0
        splits=0;nonprefix=0;alts=0
        for channel in epoch['channels']:
            exact(channel,CHANNEL_FIELDS,'CROSSVIEW_CHANNEL_ROW')
            cid=channel['tsa_channel_id']
            heads=[observed[i][idx]['channels'][cid] for i in (0,1)]
            one,two=heads
            if one['head_sha'] is None or two['head_sha'] is None or (
                one['tsa_gen'] is None or two['tsa_gen'] is None):
                flags[FLAGS[2]]=True
            split=(one['pairs'] is not None and two['pairs'] is not None and
                   one['pairs']!=two['pairs'])
            # Distinct authenticated log views may differ by append-only progress
            # (one list is a prefix), or by an incompatible signed history fork.
            incompatible=(split and not (
                one['pairs']==two['pairs'][:len(one['pairs'])] or
                two['pairs']==one['pairs'][:len(two['pairs'])]))
            if split:
                flags[FLAGS[3]]=True;splits+=1
            if incompatible:
                flags[FLAGS[4]]=True;nonprefix+=1
            pair_views=[h['pairs'] for h in heads if h['pairs'] is not None]
            previous_pairs=prior_union.get(cid,[])
            for pairset in pair_views:
                if previous_pairs and pairset[:len(previous_pairs)]!=previous_pairs:
                    flags[FLAGS[7]]=True
            # Track the longest previously seen append-only prefix without erasing
            # a fork: the detected fork is retained in signed SHA case output.
            if pair_views:
                newest=max(pair_views,key=len)
                if len(newest)>=len(previous_pairs):prior_union[cid]=newest
            statuses=[]
            for i,label in enumerate(('primary','secondary')):
                part=channel[label];exact(part,OBSERVATION_FIELDS,'OBSERVATION')
                v=views[i];own=heads[i];peer=heads[1-i]
                point=histories[i].get(cid)
                status,newprev=_verify_checkpoint(
                    part['signed_crossview_checkpoint_original'],v['id'],
                    views[1-i]['id'],v,
                    own,peer,cid,idx,point,read,lineage,evaluation,
                    part['rfc3161_crossview_checkpoint_token_original'],
                    part['tsa_authority_id'],
                    part['alternate_signed_crossview_checkpoint_original'],flags)
                if part['signed_crossview_checkpoint_original'] is None:
                    flags[FLAGS[2]]=True
                if status['alternate_sha256'] is not None:
                    alts+=1;equivocations+=1
                if newprev is not None:histories[i][cid]=newprev
                verified_here+=int(status['timestamp_authenticated']);statuses.append(status)
                signed_inventory.append({'tsa_channel_id':cid,'observer_id':v['id'],
                  'checkpoint_sha256':status['checkpoint_sha256'],
                  'alternate_signed_checkpoint_sha256':status['alternate_sha256']})
                token_inventory.append({'tsa_channel_id':cid,'observer_id':v['id'],
                  'timestamp_sha256':status['token_sha256']})
            channel_inventory.append({'tsa_channel_id':cid,
              'primary_prior_head_sha256':one['head_sha'],
              'secondary_prior_head_sha256':two['head_sha'],
              'primary_source_snapshot_sha256':one['source_sha'],
              'secondary_source_snapshot_sha256':two['source_sha'],
              'signed_source_snapshots_disagree':split,
              'nonprefix_signed_split_view':incompatible,
              'crossview_observers':statuses})
            if split or incompatible or any(
                s['checkpoint_sha256'] is not None and not s['claims_match_reopened_heads']
                or s['alternate_sha256'] is not None for s in statuses):
                forkcases.append({'epoch_index':idx,'tsa_channel_id':cid,
                  'primary_observer_id':primary['id'],'secondary_observer_id':secondary['id'],
                  'primary_prior_head_sha256':one['head_sha'],
                  'secondary_prior_head_sha256':two['head_sha'],
                  'primary_source_snapshot_sha256':one['source_sha'],
                  'secondary_source_snapshot_sha256':two['source_sha'],
                  'nonprefix_signed_split_view':incompatible,
                  'primary_alternate_checkpoint_sha256':statuses[0]['alternate_sha256'],
                  'secondary_alternate_checkpoint_sha256':statuses[1]['alternate_sha256']})
        signedsha=sha(canonical.canonical(signed_inventory))
        tokensha=sha(canonical.canonical(token_inventory))
        if (signedsha!=opts[NEW_REPEATS[3][0]][idx] or
            tokensha!=opts[NEW_REPEATS[4][0]][idx] or
            verified_here<opts[NEW_REPEATS[5][0]][idx]):
            flags[FLAGS[1]]=True
        authenticated+=verified_here
        reviews.append({'epoch_index':idx,'timestamp_authenticated_crossview_count':verified_here,
          'crossview_signed_checkpoint_inventory_sha256':signedsha,
          'crossview_rfc3161_token_inventory_sha256':tokensha,
          'signed_snapshot_disagreements':splits,
          'nonprefix_signed_split_views':nonprefix,
          'signed_self_equivocation_cases':alts})
        inventories.append({'epoch_index':idx,'channels':channel_inventory,
          'crossview_signed_checkpoint_inventory_sha256':signedsha,
          'crossview_rfc3161_token_inventory_sha256':tokensha})
    derived={'schema':INVENTORY_SCHEMA,
      'claimed_directory_lineage_id':lineage,
      'primary_observer_id':primary['id'],'secondary_observer_id':secondary['id'],
      'verified_primary_ec391_report_sha256':primary_sha,
      'verified_secondary_ec391_report_sha256':secondary_sha,
      'verified_live_ec390_parent_canonical_result_sha256':primary_report[
          'verified_live_parent_ec390_canonical_result_sha256'],
      'crossview_original_bundle_sha256':crossref['sha256'],
      'primary_original_ec391_bundle_sha256':primref['sha256'],
      'secondary_original_ec391_bundle_sha256':secref['sha256'],
      'primary_offsite_keeper_roster_sha256':opts[parent.NEW_SCALARS[2]],
      'secondary_offsite_keeper_roster_sha256':opts[NEW_SCALARS[4]],
      'primary_tsa_trust_registry_sha256':opts[parent.NEW_SCALARS[3]],
      'secondary_tsa_trust_registry_sha256':opts[NEW_SCALARS[5]],
      'epoch_crossview_history':inventories,
      'visible_signed_crossview_conflicts':forkcases}
    digest=sha(canonical.canonical(derived))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # End-of-run readback: not a TOCTOU-proof openat/handle scheme.
    for path,(pin,cap) in late.items():
        raw=io._read({'path':path,'sha256':pin},'ec392_final_reopen',cap,{}, {},set())
        need(sha(raw)==pin,'EC392_ORIGINAL_CHANGED_AFTER_CHECK',
             'permission_denied')
    flags[FLAGS[9]]=True;flags[FLAGS[10]]=True
    local=not any(flags[k] for k in FLAGS[:9])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':('derive-historical-ec339-crossview-inventory' if derive else
                 'audit-historical-ec339-crossview'),
      'status':next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'verified_primary_ec391_report_sha256':primary_sha,
      'verified_secondary_ec391_report_sha256':secondary_sha,
      'verified_live_parent_ec390_canonical_result_sha256':primary_report[
           'verified_live_parent_ec390_canonical_result_sha256'],
      'receiver_verified_crossview_inventory_sha256':digest,
      'historical_crossview_original_sha256':crossref['sha256'],
      'cryptographically_timestamped_crossview_checkpoint_count':authenticated,
      'valid_distinct_same_keeper_signed_equivocation_count':equivocations,
      'historical_crossview_epoch_reviews':reviews,
      'visible_crossview_conflict_cases':forkcases,
      'local_two_observer_signed_views_and_crossview_receipts_consistent':local,
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **flags, **{name:False for name in NEGATIVES},
      **({'unsigned_crossview_inventory':derived} if derive else {})}


def derive_inventory(**opts):
    return _engine(True,**opts)


def audit(**opts):
    return _engine(False,**opts)
