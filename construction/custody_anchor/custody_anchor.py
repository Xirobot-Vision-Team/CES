#!/usr/bin/env python3
"""EC393: read-only, independently countersigned custody + timestamped log anchor.

Replays the *actual* EC392 audit (and its two EC391->EC369 audits); then
verifies existing raw Ed25519 custody handoff signatures, an independently
signed RFC6962 log prefix and extension, exact-byte RFC3161 CMS timestamps
and offline CRLs. No signer, TSA, network or storage writes occur here.

A caller-supplied dispute cutoff, root/key roster and retained SHA are NOT
independent historical or legal provenance. Every lawful result is unresolved.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from historical_authority import authority_archive as io
from prior_time import prior_time as prior
from crossview import crossview as parent

RESULT_SCHEMA='ces.ec393.receiver_countersigned_custody_log_anchor_unresolved.v1'
DERIVE_SCHEMA='ces.ec393.unsigned_custody_log_anchor_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec393.receiver_custody_log_anchor_denial.v1'
BUNDLE_SCHEMA='ces.ec393.offsite_custody_and_timestamped_log_anchor_bundle.v1'
ROSTER_SCHEMA='ces.ec393.independent_custody_parties_and_log_roster.v1'
RECEIPT_SCHEMA='ces.ec393.original_dual_signed_custody_handoff.v1'
RECEIPT_CLAIM_SCHEMA='ces.ec393.original_custody_handoff_claim.v1'
HEAD_SCHEMA='ces.ec393.original_signed_custody_log_head.v1'
HEAD_CLAIM_SCHEMA='ces.ec393.signed_custody_log_head_claim.v1'
INVENTORY_SCHEMA='ces.ec393.unsigned_receiver_custody_anchor_inventory.v1'
RECEIPT_DOMAIN=b'CES/EC393/IndependentCustody/TwoPartyOriginalHandoff/v1\0'
SENDER_DOMAIN=RECEIPT_DOMAIN+b'sender\0'
RECEIVER_DOMAIN=RECEIPT_DOMAIN+b'receiver\0'
LOG_DOMAIN=b'CES/EC393/IndependentCustody/RFC6962SignedLogHead/v1\0'
ZERO='0'*64
MAX_BUNDLE=100_000
MAX_ROSTER=20_000
MAX_RECEIPT=14_000
MAX_HEAD=14_000
MAX_PROOF=64

PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS=(
  'historical_ec339_custody_anchor_bundle_file',
  'expected_historical_ec339_custody_anchor_bundle_sha256',
  'expected_outside_retained_ec393_custody_log_roster_sha256',
  'expected_outside_retained_ec393_tsa_registry_sha256',
  'expected_outside_retained_ec393_prior_log_head_sha256',
  'expected_outside_retained_ec393_dispute_cutoff_utc',
)
AUDIT_ONLY=('expected_retained_historical_ec339_custody_anchor_inventory_sha256',)
NEW_REPEATS=(
  ('historical_ec339_countersigned_custody_receipt_inventory_shas',
   '--historical-ec339-countersigned-custody-receipt-inventory-sha256'),
  ('historical_ec339_custody_log_inclusion_inventory_shas',
   '--historical-ec339-custody-log-inclusion-inventory-sha256'),
  ('minimum_historical_ec339_pre_cutoff_log_anchored_receipt_counts',
   '--minimum-historical-ec339-pre-cutoff-log-anchored-receipt-count'),
)
REPEAT_NAMES=tuple(key for key,_ in NEW_REPEATS)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id',
 'parent_ec392_crossview_bundle_original','custody_log_roster_original',
 'tsa_trust_registry_original','prior_signed_log_head_original',
 'prior_log_head_rfc3161_token_original','current_signed_log_head_original',
 'current_log_head_rfc3161_token_original','log_tsa_authority_id',
 'log_consistency_path_sha256','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','log_id',
 'log_operator_id','log_public_hex','log_public_key_original','custody_parties'}
PARTY_FIELDS={'observer_id','party_id','site_id','role','public_hex','public_key_original'}
HEAD_FIELDS={'schema','claim','signature_ed25519'}
HEAD_CLAIM_FIELDS={'schema','directory_lineage_id','log_id','log_sequence','tree_size',
 'merkle_root_sha256','previous_signed_log_head_original_sha256','claimed_integrated_utc'}
RECEIPT_FIELDS={'schema','claim','sender_signature_ed25519','receiver_signature_ed25519'}
RECEIPT_CLAIM_FIELDS={'schema','directory_lineage_id','log_id','observer_id',
 'peer_observer_id','tsa_channel_id','epoch_index','handoff_sequence',
 'sender_party_id','receiver_party_id','sender_site_id','receiver_site_id',
 'crossview_bundle_original_sha256','signed_crossview_checkpoint_original_sha256',
 'crossview_rfc3161_token_original_sha256','previous_signed_custody_handoff_original_sha256',
 'claimed_handoff_utc'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={'tsa_channel_id','primary','secondary'}
ROW_FIELDS={'signed_custody_handoff_original','rfc6962_leaf_index',
 'rfc6962_inclusion_path_sha256','alternate_signed_custody_handoff_original',
 'alternate_rfc6962_leaf_index','alternate_rfc6962_inclusion_path_sha256'}
FLAGS=(
 'inherited_two_real_ec391_and_ec392_signed_crossview_dispute',
 'outside_retained_custody_log_or_epoch_inventory_floor_disagrees',
 'pre_cutoff_signed_log_timestamp_or_countersigned_receipt_missing',
 'valid_dual_signed_receipt_disagrees_with_authentic_ec392_original',
 'two_valid_incompatible_countersigned_handoff_originals_visible',
 'signed_custody_log_prefix_inclusion_or_extension_unproven',
 'claimed_handoff_log_order_or_dispute_cutoff_not_bounded',
 'furnished_offline_tsa_crl_stale_ambiguous_or_revoked',
 'externally_proven_dispute_cutoff_real_world_site_key_and_prior_custody_missing',
 'global_log_fork_census_immutable_physical_worm_and_full_ocsp_not_proven',
)
OUTCOMES=(
 'ec393_inherited_ec392_signed_crossview_or_prior_audit_dispute',
 'ec393_outside_retained_custody_original_sha_or_counts_disagree',
 'ec393_pre_cutoff_signed_log_token_or_handoff_original_missing',
 'ec393_genuinely_countersigned_handoff_disagrees_with_verified_crossview_original',
 'ec393_two_valid_distinct_same_handoff_claims_visible_without_automatic_winner',
 'ec393_signed_rfc6962_log_inclusion_or_prefix_extension_unproven',
 'ec393_signed_custody_or_timestamp_utc_exceeds_declared_cutoff_or_rolls_back',
 'ec393_offline_tsa_crl_does_not_establish_current_clean_status',
 'ec393_legal_independence_external_cutoff_and_genuine_prior_custody_not_proven',
 'ec393_complete_global_worm_revocation_or_hidden_log_forks_not_proven',
)
NEGATIVES=(
 'newly_presented_sender_receiver_public_keys_prove_separate_legal_custody_sites',
 'caller_chosen_dispute_cutoff_or_roster_sha_is_genuinely_external_pre_dispute_evidence',
 'locally_generated_log_head_or_rfc3161_fixture_proves_qualified_independent_tsa',
 'signed_handoff_utc_or_log_claimed_integrated_utc_is_calibrated_true_wall_clock',
 'rfc6962_consistency_with_two_heads_proves_absence_of_other_forked_heads',
 'merkle_inclusion_and_cms_token_prove_physical_worm_or_external_retention',
 'contradictory_signed_custody_claims_choose_an_authoritative_history',
 'supplied_crls_prove_exhaustive_online_revocation_or_current_ocsp',
 'ec393_receiver_may_generate_a_custody_receipt_log_head_or_timestamp',
 'receiver_performed_signing_network_cas_worm_provider_git_ci_or_powershell_write',
 'ec339_issuer_authority_is_extended_by_newer_custody_claims',
 'unmocked_external_ec317_ec318_corpus_and_final_user_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC393_'+code,status)


def exact(doc,keys,code):
    need(type(doc) is dict and set(doc)==set(keys),code+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _hex_sig(sig):
    return type(sig) is str and len(sig)==128 and all(x in '0123456789abcdef' for x in sig)


def _signed(public_hex,signature,domain,claim,role):
    need(_hex_sig(signature) and type(public_hex) is str and
         prior.prior.HEX64.fullmatch(public_hex) is not None,
         role+'_ED25519_RAW_SIGNATURE_FORMAT_INVALID','permission_denied')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(signature),domain+canonical.canonical(claim))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise errors.AnchorError('EC393_'+role+'_GENUINE_SIGNATURE_REQUIRED',
                                 'permission_denied') from exc


def _inputs(opts,derive):
    required=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_EC392_AND_CUSTODY_INPUTS_REQUIRED')
    inherited={key:opts[key] for key in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                           'EC393_CUSTODY_BUNDLE')
    for name in NEW_SCALARS[2:5]:
        need(tr._sha(opts[name]),'OUTSIDE_'+name.upper()+'_INVALID')
    need(type(opts[NEW_SCALARS[5]]) is str and
         prior.prior.old338._utc(opts[NEW_SCALARS[5]]),
         'INDEPENDENTLY_DECLARED_DISPUTE_CUTOFF_UTC_REQUIRED')
    if not derive:
        need(tr._sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_WHOLE_CUSTODY_INVENTORY_SHA_INVALID')
    epochs=len(opts['historical_directory_root_shas'])
    need(1<=epochs<=3,'ONE_TO_THREE_EPOCHS_REQUIRED')
    for key in REPEAT_NAMES:
        vals=opts[key]
        need(type(vals) is list and len(vals)==epochs,'ONE_PER_EPOCH_RETAINED_CUSTODY_PIN_REQUIRED')
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=4 for v in vals),
                 'CUSTODY_COUNT_FLOOR_MUST_BE_0_TO_4')
        else:
            need(all(tr._sha(v) for v in vals),'RETAINED_CUSTODY_INVENTORY_SHA_INVALID')
    return inherited


def _parent_report(doc,opts):
    n=len(opts['historical_directory_root_shas'])
    fields={'schema','command','status','exit_code','offline_unresolved_exit_code',
      'verified_primary_ec391_report_sha256','verified_secondary_ec391_report_sha256',
      'verified_live_parent_ec390_canonical_result_sha256',
      'receiver_verified_crossview_inventory_sha256','historical_crossview_original_sha256',
      'cryptographically_timestamped_crossview_checkpoint_count',
      'valid_distinct_same_keeper_signed_equivocation_count','historical_crossview_epoch_reviews',
      'visible_crossview_conflict_cases',
      'local_two_observer_signed_views_and_crossview_receipts_consistent',
      'sender_origin_path_required_or_read',
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
      *parent.FLAGS,*parent.NEGATIVES}
    need(type(doc) is dict and set(doc)==fields and
      doc.get('schema')==parent.RESULT_SCHEMA and
      doc.get('command')=='audit-historical-ec339-crossview' and
      doc.get('exit_code')==2 and doc.get('offline_unresolved_exit_code')==2 and
      doc.get('sender_origin_path_required_or_read') is False and
      doc.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
      doc.get('historical_crossview_original_sha256')==opts[parent.NEW_SCALARS[1]] and
      all(tr._sha(doc.get(k)) for k in (
        'verified_primary_ec391_report_sha256','verified_secondary_ec391_report_sha256',
        'verified_live_parent_ec390_canonical_result_sha256',
        'receiver_verified_crossview_inventory_sha256')) and
      all(type(doc.get(k)) is bool for k in parent.FLAGS) and
      all(doc[k] is True for k in parent.FLAGS[-2:]) and
      all(doc.get(k) is False for k in parent.NEGATIVES) and
      type(doc.get('local_two_observer_signed_views_and_crossview_receipts_consistent')) is bool and
      doc['local_two_observer_signed_views_and_crossview_receipts_consistent']==(
        not any(doc[k] for k in parent.FLAGS[:9])) and
      doc.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
        if doc[k]),parent.OUTCOMES[-1])+'_unresolved',
      'ACTUAL_EC392_SIGNED_PARENT_AUDIT_REQUIRED','unavailable')
    reviews=doc['historical_crossview_epoch_reviews']
    cases=doc['visible_crossview_conflict_cases']
    need(type(reviews) is list and len(reviews)==n and type(cases) is list and
      len(cases)<=2*n and all(type(row) is dict and set(row)=={
         'epoch_index','timestamp_authenticated_crossview_count',
         'crossview_signed_checkpoint_inventory_sha256',
         'crossview_rfc3161_token_inventory_sha256',
         'signed_snapshot_disagreements','nonprefix_signed_split_views',
         'signed_self_equivocation_cases'} and
         type(row['epoch_index']) is int and row['epoch_index']==i and
         type(row['timestamp_authenticated_crossview_count']) is int and
         0<=row['timestamp_authenticated_crossview_count']<=4 and
         all(tr._sha(row[k]) for k in ('crossview_signed_checkpoint_inventory_sha256',
                                      'crossview_rfc3161_token_inventory_sha256'))
         for i,row in enumerate(reviews)) and
      type(doc['cryptographically_timestamped_crossview_checkpoint_count']) is int and
      doc['cryptographically_timestamped_crossview_checkpoint_count']==sum(
        r['timestamp_authenticated_crossview_count'] for r in reviews),
      'REAL_EC392_EPOCH_REPORT_INVALID','unavailable')
    return sha(canonical.canonical(doc))


def _reader():
    pins={};types={};cache={};late={}
    def read(ref,role,cap):
        prior.originals.prior.lineage.parent.ref_check(ref,'EC393_'+role)
        path=ref['path']
        if path in cache:
            old,data=cache[path]
            need(old==ref['sha256'] and len(data)<=cap,
                 'CUSTODY_REUSED_ORIGINAL_PATH_WRONG_PIN','permission_denied')
            return data
        raw=io._read(ref,'ec393_'+role,cap,pins,types,set())
        cache[path]=(ref['sha256'],raw);late[path]=(ref['sha256'],cap)
        return raw
    def doc(ref,role,cap):
        return tr.strict_json(read(ref,role,cap),'EC393_'+role)
    return read,doc,late


def _roster(roster,ref,expected,lineage,read,observer_ids,existing_keys):
    exact(roster,ROSTER_FIELDS,'CUSTODY_INDEPENDENT_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id']==lineage and
         ref['sha256']==expected and
         all(type(roster[k]) is str and prior.prior.IDENT.fullmatch(roster[k])
             for k in ('log_id','log_operator_id')) and
         type(roster['log_public_hex']) is str and
         prior.prior.HEX64.fullmatch(roster['log_public_hex']) and
         roster['log_public_hex']!='00'*32 and
         roster['log_public_hex'] not in existing_keys,
         'CUSTODY_LOG_ID_AND_OUTSIDE_ROSTER_MUST_BE_KEYED_INDEPENDENTLY',
         'permission_denied')
    logref=roster['log_public_key_original']
    logpub=read(logref,'genuine_log_ed25519_raw_public_key',32)
    need(len(logpub)==32 and logpub.hex()==roster['log_public_hex'],
         'LOG_OPERATOR_RAW_ED25519_KEY_COPY_INVALID','permission_denied')
    people=roster['custody_parties']
    need(type(people) is list and len(people)==4,
         'EXACT_TWO_OBSERVERS_TWO_CUSTODY_PARTIES_EACH_REQUIRED')
    parties={};seen_keys={roster['log_public_hex'],*existing_keys}
    ids={roster['log_operator_id']};sites=set();paths={logref['path']}
    for party in people:
        exact(party,PARTY_FIELDS,'CUSTODY_SIGNING_PARTY')
        who=party['observer_id'];role=party['role'];pid=party['party_id']
        site=party['site_id'];key=party['public_hex']
        need(who in observer_ids and role in ('sender','receiver') and
             (who,role) not in parties and
             all(type(x) is str and prior.prior.IDENT.fullmatch(x)
                 for x in (pid,site)) and
             pid not in ids and site not in sites and
             type(key) is str and prior.prior.HEX64.fullmatch(key) and
             key!='00'*32 and key not in seen_keys,
             'CUSTODY_SITE_PARTY_ID_AND_KEY_MUST_BE_DISTINCT','permission_denied')
        pubref=party['public_key_original']
        pub=read(pubref,'countersigner_ed25519_raw_public_key',32)
        need(len(pub)==32 and pub.hex()==key and pubref['path'] not in paths,
             'CUSTODY_PARTY_KEY_OR_ORIGINAL_PATH_COPIED','permission_denied')
        seen_keys.add(key);sites.add(site);ids.add(pid);paths.add(pubref['path'])
        parties[(who,role)]=party
    need(set(parties)=={(who,role) for who in observer_ids for role in ('sender','receiver')},
         'CUSTODY_ROLE_SET_MUST_MATCH_TWO_GENUINE_EC392_OBSERVERS','permission_denied')
    return {'log_id':roster['log_id'],'log_operator_id':roster['log_operator_id'],
            'log_key':roster['log_public_hex'],'parties':parties,'paths':paths}


def _log_head(ref,read,log,lineage,sequence):
    if ref is None:return None
    data=read(ref,'prior_or_current_signed_merkle_log_head',MAX_HEAD)
    obj=tr.strict_json(data,'EC393_SIGNED_LOG_HEAD')
    exact(obj,HEAD_FIELDS,'SIGNED_CUSTODY_LOG_HEAD')
    claim=obj['claim'];exact(claim,HEAD_CLAIM_FIELDS,'CUSTODY_LOG_HEAD_CLAIM')
    need(obj['schema']==HEAD_SCHEMA and claim['schema']==HEAD_CLAIM_SCHEMA and
         claim['directory_lineage_id']==lineage and claim['log_id']==log['log_id'] and
         type(claim['log_sequence']) is int and claim['log_sequence']==sequence and
         type(claim['tree_size']) is int and
         1<=claim['tree_size']<=tr.MAX_LOG_LEAVES and
         tr._sha(claim['merkle_root_sha256']) and
         (claim['previous_signed_log_head_original_sha256']==ZERO or
          tr._sha(claim['previous_signed_log_head_original_sha256'])) and
         prior.prior.old338._utc(claim['claimed_integrated_utc']),
         'SIGNED_CUSTODY_LOG_HEAD_LINEAGE_SIZE_SEQUENCE_OR_UTC_INVALID',
         'permission_denied')
    _signed(log['log_key'],obj['signature_ed25519'],LOG_DOMAIN,claim,'LOG_HEAD')
    return {'sha256':ref['sha256'],'ref':ref,'claim':claim,'raw':data,
            'size':claim['tree_size'],'root':bytes.fromhex(claim['merkle_root_sha256']),
            'claimed':tsa._utc(claim['claimed_integrated_utc'])}


def _timestamp(head,tokenref,authority,trust,read,evaluation,cutoff,flags):
    if head is None or tokenref is None:
        flags[FLAGS[2]]=True
        return None
    need(authority in trust,'SIGNED_LOG_TOKEN_AUTHORITY_NOT_OUTSIDE_REGISTERED',
         'permission_denied')
    entry=trust[authority]
    raw=read(tokenref,'genuine_log_head_timestamp_der',prior.MAX_DER)
    checked=tsa._tsa_token(raw,head['raw'],entry['root'],entry['policy'])
    crl=tsa._check_crls(checked['certificate_path'],entry['crls'],
                        checked['token_gen_time'],evaluation)
    gen=checked['token_gen_time']
    clean=(not crl['revoked_at_or_before_gen_time'] and
           crl['all_chain_edges_have_single_fresh_crl_as_furnished'])
    if not clean:flags[FLAGS[7]]=True
    if gen>evaluation or gen<head['claimed'] or (cutoff is not None and gen>cutoff):
        flags[FLAGS[6]]=True
    return {'sha256':tokenref['sha256'],'gen':gen,'crl_clean':clean,
            'gen_utc':gen.isoformat(timespec='seconds').replace('+00:00','Z')}


def _log_evidence(bundle,read,trust,log,lineage,evaluation,cutoff,flags,expected_prior):
    earlier=bundle['prior_signed_log_head_original']
    later=bundle['current_signed_log_head_original']
    if earlier is not None and earlier['sha256']!=expected_prior:flags[FLAGS[1]]=True
    if earlier is None or later is None:
        flags[FLAGS[2]]=True
    head0=_log_head(earlier,read,log,lineage,1)
    head1=_log_head(later,read,log,lineage,2)
    if head0 and head0['claim']['previous_signed_log_head_original_sha256']!=ZERO:
        flags[FLAGS[5]]=True
    if head1 and (head0 is None or
                  head1['claim']['previous_signed_log_head_original_sha256']!=head0['sha256']):
        flags[FLAGS[5]]=True
    aid=bundle['log_tsa_authority_id']
    need((aid is None and
          bundle['prior_log_head_rfc3161_token_original'] is None and
          bundle['current_log_head_rfc3161_token_original'] is None) or
         aid in trust,'LOG_TSA_AUTHORITY_TOKEN_PAIR_INCONSISTENT','permission_denied')
    t0=_timestamp(head0,bundle['prior_log_head_rfc3161_token_original'],
                  aid,trust,read,evaluation,cutoff,flags)
    t1=_timestamp(head1,bundle['current_log_head_rfc3161_token_original'],
                  aid,trust,read,evaluation,None,flags)
    if head0 and head1:
        if head1['size']<=head0['size']:flags[FLAGS[5]]=True
        if head1['claimed']<head0['claimed']:flags[FLAGS[6]]=True
    if t0 and t1 and t1['gen']<t0['gen']:flags[FLAGS[6]]=True
    proof=bundle['log_consistency_path_sha256']
    need(type(proof) is list and len(proof)<=MAX_PROOF and
         all(tr._sha(v) for v in proof),'SIGNED_LOG_CONSISTENCY_PROOF_HASHES_INVALID')
    # A Merkle prefix alone is not a signed log-head predecessor chain.
    consistent=bool(head0 and head1 and head0['sha256']==expected_prior and
        head0['claim']['previous_signed_log_head_original_sha256']==ZERO and
        head1['claim']['previous_signed_log_head_original_sha256']==head0['sha256'] and
        head1['size']>head0['size'] and
        tr.verify_consistency(head0['size'],head1['size'],
            head0['root'],head1['root'],[bytes.fromhex(x) for x in proof]))
    if not consistent:flags[FLAGS[5]]=True
    # The strict counting predicate requires BOTH actual TSA token chains,
    # readable clean offline CRLs and coherent cutoff/evaluation chronology.
    # Mere presence of one timestamp is not a historical custody anchor.
    anchored=bool(consistent and t0 and t1 and
        t0['crl_clean'] and t1['crl_clean'] and
        head0['claimed']<=t0['gen']<=cutoff and
        head1['claimed']<=t1['gen']<=evaluation and
        head0['claimed']<=head1['claimed'] and
        t0['gen']<=t1['gen'] and
        t0['gen']<=evaluation)
    return head0,head1,t0,t1,consistent,anchored


def _receipt(ref,obs,peer,cid,epoch,parties,log_id,read,lineage):
    raw=read(ref,'original_two_party_countersigned_handoff',MAX_RECEIPT)
    obj=tr.strict_json(raw,'EC393_CUSTODY_TWO_SIGNER_RECEIPT')
    exact(obj,RECEIPT_FIELDS,'CUSTODY_COUNTERSIGNED_ORIGINAL')
    claim=obj['claim'];exact(claim,RECEIPT_CLAIM_FIELDS,'SIGNED_CUSTODY_CLAIM')
    sender=parties[(obs,'sender')];receiver=parties[(obs,'receiver')]
    need(obj['schema']==RECEIPT_SCHEMA and claim['schema']==RECEIPT_CLAIM_SCHEMA and
         claim['directory_lineage_id']==lineage and claim['log_id']==log_id and
         claim['observer_id']==obs and claim['peer_observer_id']==peer and
         claim['tsa_channel_id']==cid and type(claim['epoch_index']) is int and
         claim['epoch_index']==epoch and type(claim['handoff_sequence']) is int and
         claim['handoff_sequence']==epoch+1 and
         claim['sender_party_id']==sender['party_id'] and
         claim['receiver_party_id']==receiver['party_id'] and
         claim['sender_site_id']==sender['site_id'] and
         claim['receiver_site_id']==receiver['site_id'] and
         tr._sha(claim['crossview_bundle_original_sha256']) and
         (claim['signed_crossview_checkpoint_original_sha256'] is None or
          tr._sha(claim['signed_crossview_checkpoint_original_sha256'])) and
         (claim['crossview_rfc3161_token_original_sha256'] is None or
          tr._sha(claim['crossview_rfc3161_token_original_sha256'])) and
         (claim['previous_signed_custody_handoff_original_sha256']==ZERO or
          tr._sha(claim['previous_signed_custody_handoff_original_sha256'])) and
         prior.prior.old338._utc(claim['claimed_handoff_utc']),
         'DUAL_SIGNED_CUSTODY_ROLES_SOURCE_SHA_OR_UTC_INVALID','permission_denied')
    _signed(sender['public_hex'],obj['sender_signature_ed25519'],SENDER_DOMAIN,
            claim,'CUSTODY_SENDER')
    _signed(receiver['public_hex'],obj['receiver_signature_ed25519'],RECEIVER_DOMAIN,
            claim,'CUSTODY_RECEIVER')
    return {'sha256':ref['sha256'],'raw':raw,'claim':claim,
            'claimed':tsa._utc(claim['claimed_handoff_utc'])}


def _proof(raw,index,proof,head):
    if head is None or index is None or proof is None:return False
    return tr.verify_inclusion(tr.leaf_hash(raw),index,head['size'],head['root'],
                               [bytes.fromhex(x) for x in proof])


def _row(refs,obs,peer,cid,epoch,parties,log_id,read,lineage,
         checkpoint,token_sha,crossview_sha,previous,earlier,t0,anchored_log_ready,
         cutoff,flags):
    exact(refs,ROW_FIELDS,'CUSTODY_RECEIPT_BUNDLE_ROW')
    ref=refs['signed_custody_handoff_original']
    alt=refs['alternate_signed_custody_handoff_original']
    primary_ix=refs['rfc6962_leaf_index'];primary_path=refs['rfc6962_inclusion_path_sha256']
    alternate_ix=refs['alternate_rfc6962_leaf_index']
    alternate_path=refs['alternate_rfc6962_inclusion_path_sha256']
    for index,path in ((primary_ix,primary_path),(alternate_ix,alternate_path)):
        need((index is None and path is None) or
             (type(index) is int and index>=0 and type(path) is list and
              len(path)<=MAX_PROOF and all(tr._sha(h) for h in path)),
             'ORIGINAL_CUSTODY_RFC6962_INDEX_PATH_MUST_PAIR')
    need((ref is None and alt is None and primary_ix is None and
          alternate_ix is None) or
         (ref is not None and (primary_ix is None or primary_path is not None) and
          (alt is not None or alternate_ix is None)),
         'ORPHAN_CUSTODY_HANDBACK_OR_MERKLE_PATH','permission_denied')
    if ref is None:
        flags[FLAGS[2]]=True
        return {'observer_id':obs,'receipt_sha256':None,'alternate_receipt_sha256':None,
          'primary_inclusion_authenticated':False,'alternate_inclusion_authenticated':False,
          'receipt_claim_matches_ec392_original':False,'claimed_handoff_utc':None,
          'counted_pre_cutoff_anchored':False},None,None
    signed=_receipt(ref,obs,peer,cid,epoch,parties,log_id,read,lineage)
    claim=signed['claim'];claimed=signed['claimed']
    match=(checkpoint is not None and token_sha is not None and
      claim['crossview_bundle_original_sha256']==crossview_sha and
      claim['signed_crossview_checkpoint_original_sha256']==checkpoint and
      claim['crossview_rfc3161_token_original_sha256']==token_sha)
    if not match:flags[FLAGS[3]]=True
    prev_sha=previous['sha256'] if previous else ZERO
    if epoch>0 and previous is None:flags[FLAGS[6]]=True
    if claim['previous_signed_custody_handoff_original_sha256']!=prev_sha:
        flags[FLAGS[6]]=True
    if previous and claimed<previous['claimed']:flags[FLAGS[6]]=True
    if earlier and claimed>earlier['claimed']:flags[FLAGS[6]]=True
    if claimed>cutoff:flags[FLAGS[6]]=True
    if t0 and claimed>t0['gen']:flags[FLAGS[6]]=True
    inclusion=_proof(signed['raw'],primary_ix,primary_path,earlier)
    if not inclusion:flags[FLAGS[5]]=True
    other=None;alt_inclusion=False
    if alt is not None:
        other=_receipt(alt,obs,peer,cid,epoch,parties,log_id,read,lineage)
        need(other['sha256']!=signed['sha256'] and other['claim']!=claim,
             'SECOND_RECEIPT_MUST_BE_DIFFERENT_VALID_COUNTERSIGNED_CLAIM',
             'permission_denied')
        alt_inclusion=_proof(other['raw'],alternate_ix,alternate_path,earlier)
        flags[FLAGS[4]]=True
        if not alt_inclusion:flags[FLAGS[5]]=True
    elif alternate_ix is not None:
        need(False,'ORPHAN_SECOND_CUSTODY_INCLUSION_PATH','permission_denied')
    bounded=(match and inclusion and anchored_log_ready and t0 is not None and
       t0['crl_clean'] and t0['gen']<=cutoff and claimed<=cutoff and
       earlier is not None and claimed<=earlier['claimed'] and claimed<=t0['gen'] and
       (epoch==0 or previous is not None) and
       (previous is None or (claim['previous_signed_custody_handoff_original_sha256']==
                              previous['sha256'] and claimed>=previous['claimed'])))
    return {'observer_id':obs,'receipt_sha256':signed['sha256'],
        'alternate_receipt_sha256':other['sha256'] if other else None,
        'primary_inclusion_authenticated':inclusion,
        'alternate_inclusion_authenticated':alt_inclusion,
        'receipt_claim_matches_ec392_original':match,
        'claimed_handoff_utc':claim['claimed_handoff_utc'],
        'counted_pre_cutoff_anchored':bool(bounded)},signed,other


def _engine(derive,**opts):
    inherited=_inputs(opts,derive)
    actual=parent.audit(**inherited)  # Never accept a caller-written EC392 verdict.
    actual_sha=_parent_report(actual,opts)
    lineage=opts['claimed_historical_directory_lineage_id']
    evaluation=tsa._utc(opts['ec391_tsa_evaluation_utc'])
    cutoff=tsa._utc(opts[NEW_SCALARS[5]])
    read,doc,late=_reader()
    original={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=doc(original,'custody_bundle_original',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'CUSTODY_LOG_BUNDLE')
    cross_ref={'path':opts[parent.NEW_SCALARS[0]],
               'sha256':opts[parent.NEW_SCALARS[1]]}
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec392_crossview_bundle_original']==cross_ref and
         type(bundle['epochs']) is list and
         len(bundle['epochs'])==len(opts['historical_directory_root_shas']),
         'CUSTODY_BUNDLE_REQUIRES_AUDITED_REAL_CROSSVIEW_ORIGINAL','permission_denied')
    cross=doc(cross_ref,'authenticated_ec392_crossview_bundle',parent.MAX_BUNDLE)
    exact(cross,parent.BUNDLE_FIELDS,'REOPEN_EC392_CROSSVIEW')
    obs_ids=(cross['primary_observer_id'],cross['secondary_observer_id'])
    need(obs_ids==(opts[parent.NEW_SCALARS[7]],opts[parent.NEW_SCALARS[8]]),
         'REOPENED_ACTUAL_CROSSVIEW_OBSERVER_IDS_DISAGREE','permission_denied')
    # Re-open both originally authenticated EC391 bundles for independent
    # key/root checks and strict path separation, not just EC392's summary.
    one=parent._view(obs_ids[0],cross['primary_ec391_offsite_bundle_original'],
        opts[prior.NEW_SCALARS[2]],opts[prior.NEW_SCALARS[3]],read,doc,lineage)
    two=parent._view(obs_ids[1],cross['secondary_ec391_offsite_bundle_original'],
        opts[parent.NEW_SCALARS[4]],opts[parent.NEW_SCALARS[5]],read,doc,lineage)
    ec392_keys=set(one['keys'].values())|set(two['keys'].values())
    rosterref=bundle['custody_log_roster_original']
    roster=doc(rosterref,'outside_original_custody_roster',MAX_ROSTER)
    log=_roster(roster,rosterref,opts[NEW_SCALARS[2]],lineage,read,obs_ids,ec392_keys)
    tsaref=bundle['tsa_trust_registry_original']
    authorities=prior._trust_registry(
        doc(tsaref,'outside_log_timestamp_trust_registry',prior.MAX_TRUST),
        tsaref,opts[NEW_SCALARS[3]],lineage,read)
    roots={a['root_sha'] for a in one['authorities'].values()}|{
           a['root_sha'] for a in two['authorities'].values()}
    need(not roots.intersection(a['root_sha'] for a in authorities.values()),
         'EC393_TSA_ROOT_REUSED_FROM_ONE_OF_TWO_EC391_OBSERVERS',
         'permission_denied')
    # No late-arriving receipt, key, log or token can alias a prior audited file.
    existing={v for k,v in opts.items() if k.endswith('_file') and type(v) is str}
    for view in (one,two):
        existing.update(r['path'] for r in (
            view['ref'],view['bundle']['offsite_log_keeper_roster_original'],
            view['bundle']['tsa_trust_registry_original'],*parent._refs(view)))
    existing.update([cross_ref['path'],original['path']])
    refs=[]
    for e in cross['epochs']:
        for c in e['channels']:
            for side in ('primary','secondary'):
                refs.extend(r for k,r in c[side].items() if k!='tsa_authority_id' and r is not None)
    existing.update(r['path'] for r in refs)
    newrefs=[rosterref,tsaref,roster['log_public_key_original']]
    newrefs.extend(p['public_key_original'] for p in roster['custody_parties'])
    for a in doc(tsaref,'tsa_trust_registry_check',prior.MAX_TRUST)['authorities']:
        newrefs.append(a['root_certificate_original']);newrefs.extend(a['crl_originals'])
    for field in ('prior_signed_log_head_original','prior_log_head_rfc3161_token_original',
                  'current_signed_log_head_original','current_log_head_rfc3161_token_original'):
        if bundle[field] is not None:newrefs.append(bundle[field])
    for e in bundle['epochs']:
        exact(e,EPOCH_FIELDS,'CUSTODY_EPOCH')
        need(type(e['channels']) is list and len(e['channels'])<=2,
             'CUSTODY_CHANNEL_COUNT_OUT_OF_BOUNDS')
        for c in e['channels']:
            exact(c,CHANNEL_FIELDS,'CUSTODY_CHANNEL')
            for side in ('primary','secondary'):
                exact(c[side],ROW_FIELDS,'CUSTODY_ROW')
                for field in ('signed_custody_handoff_original',
                              'alternate_signed_custody_handoff_original'):
                    if c[side][field] is not None:newrefs.append(c[side][field])
    need(len(newrefs)==len({r['path'] for r in newrefs}) and
         not {r['path'] for r in newrefs}.intersection(existing),
         'INDEPENDENT_CUSTODY_SITE_AND_LOG_ORIGINAL_PATHS_MUST_BE_DISJOINT',
         'permission_denied')
    flags={flag:False for flag in FLAGS}
    flags[FLAGS[0]]=not actual['local_two_observer_signed_views_and_crossview_receipts_consistent']
    old,new,oldtoken,newtoken,consistent,anchored_log_ready=_log_evidence(
        bundle,read,authorities,log,lineage,evaluation,cutoff,flags,
        opts[NEW_SCALARS[4]])
    predecessor={};inventories=[];reviews=[];cases=[];count=0;conflicts=0
    for idx,(epoch,ec392_epoch) in enumerate(zip(bundle['epochs'],cross['epochs'],strict=True)):
        exact(ec392_epoch,parent.EPOCH_FIELDS,'PARENT_CROSSVIEW_EPOCH')
        expected_channels=ec392_epoch['channels']
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==idx and
             type(epoch['channels']) is list and len(epoch['channels'])==len(expected_channels) and
             [c.get('tsa_channel_id') for c in epoch['channels']]==[
                 c['tsa_channel_id'] for c in expected_channels],
             'CUSTODY_EPOCH_CHANNELS_MUST_MATCH_AUDITED_CROSSVIEW','permission_denied')
        inventory_receipts=[];inventory_inclusions=[];channels=[];epoch_count=0;epoch_conflicts=0
        for c,source in zip(epoch['channels'],expected_channels,strict=True):
            exact(c,CHANNEL_FIELDS,'CUSTODY_AUDITED_CHANNEL')
            cid=c['tsa_channel_id'];statuses=[]
            for side in ('primary','secondary'):
                own=obs_ids[0 if side=='primary' else 1]
                peer=obs_ids[1 if side=='primary' else 0]
                cp=source[side]['signed_crossview_checkpoint_original']
                token=source[side]['rfc3161_crossview_checkpoint_token_original']
                cp_sha=cp['sha256'] if cp else None
                tok_sha=token['sha256'] if token else None
                prev=predecessor.get((side,cid))
                status,signed,alternate=_row(c[side],own,peer,cid,idx,
                  log['parties'],log['log_id'],read,lineage,cp_sha,tok_sha,
                  cross_ref['sha256'],prev,old,oldtoken,anchored_log_ready,cutoff,flags)
                if signed is not None:predecessor[(side,cid)]=signed
                epoch_count+=int(status['counted_pre_cutoff_anchored'])
                if alternate:
                    epoch_conflicts+=1
                    cases.append({'epoch_index':idx,'tsa_channel_id':cid,'observer_id':own,
                        'primary_countersigned_receipt_original_sha256':signed['sha256'],
                        'alternate_countersigned_receipt_original_sha256':alternate['sha256'],
                        'alternate_inclusion_authenticated':status['alternate_inclusion_authenticated']})
                inventory_receipts.append({'tsa_channel_id':cid,'observer_id':own,
                    'receipt_sha256':status['receipt_sha256'],
                    'alternate_receipt_sha256':status['alternate_receipt_sha256']})
                inventory_inclusions.append({'tsa_channel_id':cid,'observer_id':own,
                    'primary_log_leaf_index':c[side]['rfc6962_leaf_index'],
                    'primary_path_sha256':c[side]['rfc6962_inclusion_path_sha256'],
                    'alternate_log_leaf_index':c[side]['alternate_rfc6962_leaf_index'],
                    'alternate_path_sha256':c[side]['alternate_rfc6962_inclusion_path_sha256'],
                    'primary_inclusion_authenticated':status['primary_inclusion_authenticated'],
                    'alternate_inclusion_authenticated':status['alternate_inclusion_authenticated']})
                statuses.append(status)
            channels.append({'tsa_channel_id':cid,'primary':statuses[0],'secondary':statuses[1]})
        receipts_sha=sha(canonical.canonical(inventory_receipts))
        inclusion_sha=sha(canonical.canonical(inventory_inclusions))
        if (receipts_sha!=opts[NEW_REPEATS[0][0]][idx] or
            inclusion_sha!=opts[NEW_REPEATS[1][0]][idx] or
            epoch_count<opts[NEW_REPEATS[2][0]][idx]):flags[FLAGS[1]]=True
        count+=epoch_count;conflicts+=epoch_conflicts
        reviews.append({'epoch_index':idx,'pre_cutoff_log_anchored_handoff_count':epoch_count,
            'genuine_double_countersigned_conflict_cases':epoch_conflicts,
            'countersigned_receipt_inventory_sha256':receipts_sha,
            'rfc6962_inclusion_inventory_sha256':inclusion_sha})
        inventories.append({'epoch_index':idx,'channels':channels,
            'countersigned_receipt_inventory_sha256':receipts_sha,
            'rfc6962_inclusion_inventory_sha256':inclusion_sha})
    inventory={'schema':INVENTORY_SCHEMA,'claimed_directory_lineage_id':lineage,
       'authenticated_parent_ec392_report_sha256':actual_sha,
       'authenticated_parent_ec392_inventory_sha256':actual['receiver_verified_crossview_inventory_sha256'],
       'custody_bundle_original_sha256':original['sha256'],
       'parent_crossview_bundle_original_sha256':cross_ref['sha256'],
       'custody_roster_original_sha256':rosterref['sha256'],
       'tsa_registry_original_sha256':tsaref['sha256'],
       'outside_retained_prior_log_head_sha256':opts[NEW_SCALARS[4]],
       'declared_dispute_cutoff_utc':opts[NEW_SCALARS[5]],
       'signed_prior_log_head_sha256':old['sha256'] if old else None,
       'prior_rfc3161_token_sha256':oldtoken['sha256'] if oldtoken else None,
       'signed_current_log_head_sha256':new['sha256'] if new else None,
       'current_rfc3161_token_sha256':newtoken['sha256'] if newtoken else None,
       'rfc6962_prefix_consistency_proven':consistent,
       'signed_custody_log_epoch_history':inventories,
       'visible_dual_signed_custody_conflicts':cases}
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # Readback catches observable changes but is not openat atomicity or remote WORM.
    for path,(pin,cap) in late.items():
        new_raw=io._read({'path':path,'sha256':pin},'ec393_final_readback',
                         cap,{}, {},set())
        need(sha(new_raw)==pin,'CUSTODY_ORIGINAL_CHANGED_DURING_AUDIT',
             'permission_denied')
    flags[FLAGS[8]]=True;flags[FLAGS[9]]=True
    local=not any(flags[k] for k in FLAGS[:8])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':('derive-historical-ec339-custody-anchor-inventory' if derive else
                 'audit-historical-ec339-custody-anchor'),
      'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'verified_live_ec392_report_sha256':actual_sha,
      'verified_live_ec392_inventory_sha256':actual['receiver_verified_crossview_inventory_sha256'],
      'historical_custody_anchor_original_sha256':original['sha256'],
      'receiver_verified_custody_anchor_inventory_sha256':digest,
      'cryptographically_bounded_pre_cutoff_handoff_count':count,
      'valid_distinct_dual_countersigned_conflict_count':conflicts,
      'signed_log_prior_and_current_sha256':[
         old['sha256'] if old else None,new['sha256'] if new else None],
      'signed_rfc6962_append_only_extension_verified':consistent,
      'custody_anchor_epoch_reviews':reviews,'visible_custody_conflict_cases':cases,
      'local_custody_counter_signatures_log_and_timestamps_consistent':local,
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **flags,**{x:False for x in NEGATIVES},
      **({'unsigned_custody_anchor_inventory':inventory} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
