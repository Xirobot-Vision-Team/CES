#!/usr/bin/env python3
"""EC373: real old EC360 RFC6962 inclusions + EC359 signed owner-distribution originals.

No result is an EC359/EC360/EC365 full-parent result. Every call replays the
production EC372->EC371->EC370->EC369 receiver audit. New Merkle paths are
verified against EXACT already-pinned EC371 signed directory checkpoint bytes;
not against an arbitrary later or self-certified root. The EC359 wire/domain
is unchanged, but its EC358->EC337 ancestors remain signed CLAIMS only.
"""
from __future__ import annotations

from collections import defaultdict

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from owner_distribution import distribution as owner_distribution
from authority_directory import authority
from publication_custody import custody
from historical_authority import authority_archive as parent

RESULT_SCHEMA='ces.ec373.receiver_historical_inclusion_issuer_ancestry_unresolved.v1'
DERIVE_SCHEMA='ces.ec373.unsigned_historical_inclusion_issuer_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec373.receiver_historical_inclusion_issuer_ancestry_denial.v1'
BUNDLE_SCHEMA='ces.ec373.receiver_historical_inclusion_issuer_originals.v1'
INVENTORY_SCHEMA='ces.ec373.receiver_verified_directory_inclusion_issuer_sha_inventory.v1'
MAX_BUNDLE=52_000
MAX_PROOF_NODES=7
NEW_SCALARS=('historical_inclusion_bundle_file',
             'expected_historical_inclusion_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_inclusion_inventory_sha256',)
NEW_REPEATS=(
 ('historical_distribution_a_head_shas','--historical-distribution-a-head-sha256'),
 ('historical_distribution_b_head_shas','--historical-distribution-b-head-sha256'),
 ('minimum_historical_distribution_a_sequences','--minimum-historical-distribution-a-sequence'),
 ('minimum_historical_distribution_b_sequences','--minimum-historical-distribution-b-sequence'),
 ('minimum_historical_inclusion_tree_sizes','--minimum-historical-inclusion-tree-size'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
BUNDLE_FIELDS={'schema','parent_ec372_canonical_result_sha256',
               'ec371_historical_archive_original_sha256',
               'ec372_historical_authority_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','signed_directory_checkpoint_original_sha256',
              'source_a','source_b'}
SOURCE_FIELDS={'delegation_inclusion','snapshot_inclusions',
               'owner_public_key_original','claimed_owner_id',
               'signed_parent_ec358_canonical_result_sha256',
               'issuer_signed_owner_distribution_originals',
               'selected_owner_distribution_head_sha256'}
PROOF_FIELDS={'original_sha256','leaf_index','audit_path_sha256'}
FLAGS=(
 'inherited_ec372_ec371_ec370_ec369_receiver_or_authority_dispute_unresolved',
 'external_historical_inclusion_inventory_or_distribution_head_floor_mismatch',
 'historical_genuine_directory_inclusion_proof_invalid',
 'historical_issuer_signed_distribution_fork_revoke_rotate_or_rollback',
 'historical_issuer_owner_scope_or_authentic_ancestor_disagreement',
 'historical_signed_distribution_utc_is_untrusted',
 'historical_source_issuer_distribution_or_directory_history_disagrees',
 'historical_inclusion_and_distribution_only_partially_recover_ec359_to_ec337',
)
OUTCOMES=(
 'ec373_inherited_receiver_historical_authority_or_directory_dispute',
 'ec373_external_inclusion_inventory_or_distribution_floor_mismatch',
 'ec373_real_rfc6962_signed_checkpoint_inclusion_invalid',
 'ec373_genuine_ec359_issuer_signed_fork_revoke_rotate_or_rollback',
 'ec373_owner_issuer_signed_ancestor_or_scope_disagreement',
 'ec373_ec359_signed_distribution_clock_claim_untrusted',
 'ec373_historical_issuer_distribution_or_directory_cross_epoch_conflict',
 'ec373_partial_historical_inclusion_and_issuer_originals_only',
)
NEGATIVES=(
 'complete_ec365_to_ec337_historical_parent_originals_replayed',
 'ec360_or_ec359_canonical_result_reproduced_from_original_inputs',
 'ec358_through_ec337_owner_authorization_originals_authenticated',
 'historical_directory_inclusion_proves_global_log_or_hidden_fork_absence',
 'historical_signed_distribution_proves_issuer_legal_identity',
 'original_ec362_sender_and_other_old_source_copy_labels_opened',
 'root_signed_revocations_repaired_or_overridden_by_ec359_records',
 'official_caller_pinned_directory_root_or_witness_status_authenticated',
 'trusted_utc_physical_custody_or_external_publication_verified',
 'private_signing_remote_network_cas_worm_provider_or_powershell_used',
 'old_deep_historical_mock_removed_or_final_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC373_'+code,status)


def exact(value,fields,kind):
    need(type(value) is dict and set(value)==set(fields),kind+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    # Audit (not derive) of the EC372 parent is compulsory on both entrypoints.
    historical=(*parent.current.prior.SCALARS,*parent.current.prior.REPEAT_NAMES,
                *parent.current.NEW_SCALARS,*parent.current.NEW_REPEAT_NAMES,
                *parent.prior.NEW_SCALARS,*parent.prior.REPEAT_NAMES,
                *parent.prior.AUDIT_ONLY,*parent.NEW_SCALARS,
                *parent.NEW_REPEAT_NAMES,*parent.AUDIT_ONLY)
    wanted=set(historical)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:wanted.update(AUDIT_ONLY)
    need(set(opts)==wanted,'EXACT_LIVE_EC372_AND_NEW_INPUTS_REQUIRED')
    prior={k:opts[k] for k in historical}
    parent._inputs(prior,False)
    authority.outer_pin(opts['historical_inclusion_bundle_file'],
                        opts['expected_historical_inclusion_bundle_sha256'],
                        'EC373_RECEIVER_INCLUSION_BUNDLE')
    need(opts['historical_inclusion_bundle_file'] is not None and
         opts['expected_historical_inclusion_bundle_sha256'] is not None,
         'INDEPENDENT_INCLUSION_RECEIVER_SHA_REQUIRED')
    if not derive:
        need(tr._sha(opts[AUDIT_ONLY[0]]),'EXTERNAL_INCLUSION_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    for key in REPEAT_NAMES:
        values=opts[key]
        need(type(values) is list and len(values)==n,
             key.upper()+'_ONE_PER_DIRECTORY_EPOCH_REQUIRED')
        if key.endswith('_shas'):
            need(all(tr._sha(v) for v in values),key.upper()+'_STRICT_SHA_STREAM')
        elif key=='minimum_historical_inclusion_tree_sizes':
            need(all(type(v) is int and 1<=v<=authority.MAX_DIRECTORY_LEAVES
                     for v in values),'DIRECTORY_TREE_SIZE_FLOOR_OUT_OF_BOUNDS')
        else:
            need(all(type(v) is int and 0<=v<owner_distribution.MAX_RECORDS
                     for v in values),'DISTRIBUTION_SEQUENCE_FLOOR_OUT_OF_BOUNDS')
    return prior


def _open_historical(prior_opts,read,forbidden):
    directory,manifests=parent._historical_custody(prior_opts,read,forbidden)
    # EC371 also permits competing correctly signed custodian manifests: their
    # source-origin paths are labels too. Never open one as EC373 new evidence.
    for row in directory['competing_signed_source_manifests']:
        ref=row['signed_source_manifest_original']
        raw=read(ref,'competing_historical_source_manifest',custody.MAX_MANIFEST)
        m=tr.strict_json(raw,'EC373_REOPEN_SIGNED_COMPETING_SOURCE_MANIFEST')
        exact(m,custody.MANIFEST_FIELDS,'COMPETING_HISTORICAL_SOURCE_MANIFEST')
        for copyref in m['copies'].values():
            parent.prior.lineage.parent.ref_check(copyref,
                                                'EC373_UNOPENED_SIGNED_COPY_LABEL')
            forbidden.add(copyref['path'])
    return directory,manifests


def _proof(item,expected_sha,raw,checkpoint,used_sha,used_index):
    exact(item,PROOF_FIELDS,'RFC6962_INCLUSION')
    path=item['audit_path_sha256'];idx=item['leaf_index']
    need(item['original_sha256']==expected_sha and tr._sha(expected_sha) and
         type(idx) is int and 0<=idx<checkpoint['tree_size'] and
         type(path) is list and len(path)<=MAX_PROOF_NODES and
         all(tr._sha(h) for h in path),
         'PROOF_MUST_BIND_EXACT_REOPENED_ORIGINAL_AND_SIGNED_TREE',
         'permission_denied')
    need(expected_sha not in used_sha and idx not in used_index,
         'DUPLICATE_OR_CONFLICTING_ORIGINAL_LEAF_INDEX','permission_denied')
    used_sha.add(expected_sha);used_index.add(idx)
    return tr.verify_inclusion(tr.leaf_hash(raw),idx,checkpoint['tree_size'],
          bytes.fromhex(checkpoint['root_sha256']),[bytes.fromhex(h) for h in path])


def _distribution(i,slot,row,delegation,issuer_key,owner_key,opts,now,read):
    refs=row['issuer_signed_owner_distribution_originals']
    need(type(refs) is list and 1<=len(refs)<=owner_distribution.MAX_RECORDS,
         'AT_LEAST_ONE_BOUNDED_TRUE_EC359_SIGNED_ISSUER_RECORD_REQUIRED')
    issuer_sha=delegation['issuer_public_key_original_sha256']
    owner_sha=sha(owner_key)
    claimed_owner=row['claimed_owner_id']
    parent358=row['signed_parent_ec358_canonical_result_sha256']
    need(tr._ident(claimed_owner) and tr._sha(parent358),
         'OLD_OWNER_ID_AND_PARENT_EC358_SIGNED_CLAIM_REQUIRED')
    owner={'owner_id_as_signed_claim':claimed_owner,
          'owner_public_key_original_sha256':owner_sha,
          'expected_head_sha256_as_caller_pin':delegation[
                       'parent_owner_head_event_sha256']}
    events={};children=defaultdict(list);genesis=[];identities=set()
    adverse=False;clock=False
    for ref in refs:
        raw=read(ref,'ec359_distribution_'+slot+'_'+ref['sha256'],
                 owner_distribution.MAX_RECORD)
        digest=sha(raw)
        need(digest not in events,'DUPLICATE_REAL_EC359_ORIGINAL','permission_denied')
        doc,start,end=owner_distribution._verify(raw,issuer_key,slot,issuer_sha,
                                                 owner,parent358)
        need(doc['issuer_id']==delegation['issuer_id_as_signed_claim'],
             'EC359_SIGNED_ISSUER_ID_MUST_EQUAL_ROOT_DELEGATED_ID',
             'permission_denied')
        events[digest]=(doc,start,end)
        identities.add(doc['issuer_id'])
        if doc['operation'] in ('revoke','rotate'):adverse=True
        prev=doc['previous_record_original_sha256']
        if prev is None:genesis.append(digest)
        else:children[prev].append(digest)
        if start>now or end<now or now-start>owner_distribution.MAX_FRESH:
            clock=True
    need(bool(genesis),'ORIGINAL_ISSUER_DISTRIBUTION_GENESIS_MISSING',
         'permission_denied')
    for digest,(doc,start,_) in events.items():
        pred=doc['previous_record_original_sha256']
        if pred is not None:
            need(pred in events,'REAL_ISSUER_DISTRIBUTION_PREDECESSOR_MISSING',
                 'permission_denied')
            old,old_start,_=events[pred]
            need(old['operation']=='authorize' and
                 doc['sequence']==old['sequence']+1,
                 'REAL_ISSUER_SIGNED_DISTRIBUTION_SEQUENCE_OR_TERMINAL_PARENT',
                 'permission_denied')
            if start<old_start:adverse=True
        visited=set();cursor=digest
        while cursor is not None:
            need(cursor not in visited,'REAL_ISSUER_HISTORY_CYCLE','permission_denied')
            visited.add(cursor)
            cursor=events[cursor][0]['previous_record_original_sha256']
    if len(genesis)!=1 or any(len(xs)>1 for xs in children.values()) or len(identities)!=1:
        adverse=True
    heads=[h for h in events if not children.get(h)]
    if len(heads)!=1:adverse=True
    selected=row['selected_owner_distribution_head_sha256']
    need(tr._sha(selected) and selected in events and selected==delegation[
                'parent_distribution_head_original_sha256'],
         'SIGNED_EC360_DELEGATION_MUST_POINT_TO_REAL_EC359_SIGNED_ORIGINAL',
         'permission_denied')
    chosen=events[selected][0]
    if chosen['operation']!='authorize' or children.get(selected):adverse=True
    pinned=opts['historical_distribution_'+slot+'_head_shas'][i]
    rollback=(pinned!=selected or chosen['sequence']<opts[
                   'minimum_historical_distribution_'+slot+'_sequences'][i])
    # True issuer signature authenticates the issuer key and quoted EC358 SHA,
    # not the EC358 result or prior owner signing authority.
    return {'epoch_index':i,'slot':slot,'issuer_sha':issuer_sha,
        'owner_sha':owner_sha,'claimed_owner_id':claimed_owner,
        'parent_ec358_claim_sha':parent358,
        'parent_owner_event_claim_sha':delegation['parent_owner_head_event_sha256'],
        'distribution_original_shas':sorted(events),
        'selected_head':selected,'selected_sequence':chosen['sequence'],
        'selected_operation':chosen['operation'],'fork_or_terminal':adverse,
        'rollback':rollback,'clock':clock}


def _engine(derive,**opts):
    previous=_inputs(opts,derive)
    # A saved parent report is not accepted: this replays true production EC372,
    # including each current EC371/370/369 original audit in the same call.
    inherited=parent.audit(**previous)
    need(type(inherited) is dict and inherited.get('schema')==parent.RESULT_SCHEMA
         and inherited.get('exit_code')==2 and
         inherited.get('sender_origin_path_required_or_read') is False,
         'REAL_EC372_RECEIVER_HISTORIC_PARENT_REPLAY_REQUIRED','unavailable')
    now=tr._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set()
    def read(ref,role,cap):
        return parent._read(ref,'ec373_'+role,cap,pins,categories,forbidden)
    hb,manifests=_open_historical(previous,read,forbidden)
    need(hb['claimed_directory_lineage_id']==opts[
                'claimed_historical_directory_lineage_id'],
         'HISTORICAL_DIRECTORY_LINEAGE_MISMATCH','permission_denied')
    # Reopen EC372 receiver bundle bytes, not a caller-written JSON summary.
    aref={'path':opts['historical_authority_bundle_file'],
          'sha256':opts['expected_historical_authority_bundle_sha256']}
    historic=tr.strict_json(read(aref,'ec372_authority_bundle',parent.MAX_BUNDLE),
                            'EC373_REOPEN_EC372_HISTORIC_AUTHORITY')
    exact(historic,parent.BUNDLE_FIELDS,'HISTORIC_EC372_AUTHORITY_BUNDLE')
    need(historic['schema']==parent.BUNDLE_SCHEMA and
         historic['historical_directory_archive_original_sha256']==opts[
            'expected_historical_archive_bundle_sha256'] and
         historic['claimed_directory_lineage_id']==opts[
            'claimed_historical_directory_lineage_id'],
         'TRUE_PARENT_HISTORIC_AUTHORITY_BUNDLE_BINDING_INVALID',
         'permission_denied')
    bref={'path':opts['historical_inclusion_bundle_file'],
          'sha256':opts['expected_historical_inclusion_bundle_sha256']}
    b=tr.strict_json(read(bref,'ec373_inclusion_bundle',MAX_BUNDLE),
                     'EC373_REAL_RECEIVER_INCLUSION_BUNDLE')
    exact(b,BUNDLE_FIELDS,'HISTORICAL_INCLUSION_BUNDLE')
    parent_sha=sha(canonical.canonical(inherited))
    need(b['schema']==BUNDLE_SCHEMA and
         b['parent_ec372_canonical_result_sha256']==parent_sha and
         b['ec371_historical_archive_original_sha256']==opts[
                            'expected_historical_archive_bundle_sha256'] and
         b['ec372_historical_authority_original_sha256']==aref['sha256'] and
         b['claimed_directory_lineage_id']==opts[
                            'claimed_historical_directory_lineage_id'],
         'HISTORICAL_INCLUSION_REAL_EC372_PARENT_SHA_BINDING_INVALID',
         'permission_denied')
    rows=b['epochs'];aepochs=historic['epochs'];hepochs=hb['epochs']
    need(type(rows) is list and len(rows)==len(aepochs)==len(hepochs) and
         1<=len(rows)<=parent.MAX_EPOCHS,
         'EXACT_AUTHORITY_DIRECTORY_EPOCH_COVERAGE_REQUIRED')
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not inherited['local_pinned_historical_authority_slice_consistent']
    # Prevent a newly supplied EC359 owner key from impersonating ANY known
    # signer role, including the other epoch's issuer, a source custodian or
    # the current receiver's independent publication/distribution parties.
    established_signers=set(opts['institution_root_public_key_shas']+
       opts['witness_public_key_shas']+opts['historical_directory_root_shas']+
       [opts['expected_sender_public_key_sha256'],
        opts['expected_receiver_public_key_sha256'],
        opts['expected_publisher_public_key_sha256'],
        opts['expected_publication_observer_public_key_sha256']])
    for e in aepochs:
        for slot in ('a','b'):
            auth=e['source_'+slot]
            established_signers.update(auth[name]['sha256'] for name in (
              'authority_root_public_key_original',
              'origin_witness_public_key_original','issuer_public_key_original'))
    for e in hepochs:
        established_signers.update(e['source_'+slot+
                 '_custodian_public_key_original']['sha256'] for slot in ('a','b'))
    verified_inclusions=0;attempted=0;distributions=[];summaries=[]
    for i,epoch in enumerate(rows):
        exact(epoch,EPOCH_FIELDS,'INCLUSION_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i,
             'INCLUSION_EPOCH_NOT_CONTIGUOUS')
        ec371=hepochs[i]
        cpref=ec371['signed_directory_checkpoint_original']
        keyref=ec371['directory_public_key_original']
        need(epoch['signed_directory_checkpoint_original_sha256']==cpref['sha256']
             and cpref['sha256']==opts['historical_signed_checkpoint_shas'][i]
             and keyref['sha256']==opts['historical_directory_root_shas'][i],
             'INCLUSION_MUST_USE_EXACT_EC371_EXTERNALLY_PINNED_CHECKPOINT',
             'permission_denied')
        pub=read(keyref,'ec371_directory_public_key_'+str(i),32)
        need(len(pub)==32,'TRUE_HISTORICAL_DIRECTORY_PUBLIC_KEY_LENGTH',
             'permission_denied')
        cpraw=read(cpref,'ec371_directory_checkpoint_'+str(i),
                   authority.MAX_ORIGINAL)
        cp,clk=authority.directory_checkpoint(cpraw,pub,keyref['sha256'],now)
        need(cp['directory_id']==opts['claimed_historical_directory_lineage_id'],
             'INCLUSION_DIRECTORY_ID_NOT_SAME_SIGNED_SOURCE','permission_denied')
        if clk:flags[FLAGS[5]]=True
        if cp['tree_size']<opts['minimum_historical_inclusion_tree_sizes'][i]:
            flags[FLAGS[1]]=True
        seen_sha=set();seen_index=set()
        claimed_parents=[]
        for slot in ('a','b'):
            source=epoch['source_'+slot]
            exact(source,SOURCE_FIELDS,'SOURCE_'+slot.upper()+'_INCLUSION_ISSUER')
            auth=aepochs[i]['source_'+slot]
            parent.exact(auth,parent.SOURCE_FIELDS,
                         'EC372_HISTORICAL_SOURCE_'+slot.upper())
            # Defend against an EC373 archive pointing to some other CP not
            # advertised by the previously verified EC362 custodian manifest.
            m=manifests[i][slot]['manifest']
            need(m['advertised_checkpoint_original_sha256']==cpref['sha256'] and
                 m['advertised_tree_size']==cp['tree_size'] and
                 m['advertised_root_sha256']==cp['root_sha256'],
                 'INCLUSION_TREE_NOT_ACTUAL_CUSTODIAN_ADVERTISED_CHECKPOINT',
                 'permission_denied')
            dref=auth['root_signed_delegation_original']
            draw=read(dref,'old_delegation_'+slot,authority.MAX_ORIGINAL)
            deleg=tr.strict_json(draw,'EC373_OLD_VERIFIED_ROOT_DELEGATION')
            parent.exact(deleg,authority.DELEGATION_FIELDS,
                         'OLD_ROOT_DELEGATION')
            # EC372 already verified this exact delegation under the original
            # genuine root key; reopening assures exact proof leaf bytes.
            need(deleg['schema']==authority.DELEGATION_SCHEMA and
                 deleg['slot']==slot and
                 deleg['issuer_public_key_original_sha256']==auth[
                                    'issuer_public_key_original']['sha256'] and
                 deleg['root_public_key_original_sha256']==auth[
                                    'authority_root_public_key_original']['sha256'],
                 'REOPENED_DELEGATION_NOT_TRUE_EC372_SIGNED_ORIGINAL',
                 'permission_denied')
            good=_proof(source['delegation_inclusion'],dref['sha256'],draw,cp,
                        seen_sha,seen_index)
            attempted+=1;verified_inclusions+=int(good)
            if not good:flags[FLAGS[2]]=True
            snaprefs=auth['root_signed_revocation_snapshot_originals']
            proofrows=source['snapshot_inclusions']
            need(type(snaprefs) is list and type(proofrows) is list and
                 len(proofrows)==len(snaprefs) and
                 len(snaprefs)<=authority.MAX_SNAPSHOTS,
                 'ALL_ACTUALLY_PRESENTED_EC372_SNAPSHOTS_REQUIRE_INCLUSION')
            # The wire list is positional only for readability; every proof
            # must name the exact corresponding SHA, no omitted adverse fork.
            for sref,proof in zip(snaprefs,proofrows):
                sraw=read(sref,'old_revocation_'+slot+'_'+sref['sha256'],
                          authority.MAX_ORIGINAL)
                good=_proof(proof,sref['sha256'],sraw,cp,seen_sha,seen_index)
                attempted+=1;verified_inclusions+=int(good)
                if not good:flags[FLAGS[2]]=True
            oref=source['owner_public_key_original']
            owner=read(oref,'ec359_original_owner_'+slot,32)
            need(len(owner)==32 and oref['sha256']==sha(owner) and
                 oref['sha256']==deleg['owner_public_key_original_sha256'],
                 'EC359_OLD_OWNER_PUBLIC_KEY_NOT_GENUINELY_ROOT_DELEGATED',
                 'permission_denied')
            need(oref['sha256'] not in established_signers,
                 'HISTORICAL_OWNER_KEY_REUSES_KNOWN_SIGNING_ROLE',
                 'permission_denied')
            issuerref=auth['issuer_public_key_original']
            issuer=read(issuerref,'ec360_original_issuer_'+slot,32)
            need(len(issuer)==32 and sha(issuer)==issuerref['sha256'] and
                 sha(owner)!=sha(issuer) and
                 sha(owner)!=auth['authority_root_public_key_original']['sha256'] and
                 sha(owner)!=auth['origin_witness_public_key_original']['sha256'] and
                 sha(owner)!=keyref['sha256'],
                 'OLD_OWNER_ISSUER_ROOT_WITNESS_DIRECTORY_KEY_ROLE_COLLISION',
                 'permission_denied')
            state=_distribution(i,slot,source,deleg,issuer,owner,opts,now,read)
            state['delegation_sha']=dref['sha256']
            state['checkpoint_sha']=cpref['sha256']
            state['tree_size']=cp['tree_size']
            state['included_original_shas']=[dref['sha256']]+[
                                                ref['sha256'] for ref in snaprefs]
            distributions.append(state)
            claimed_parents.append(state['parent_ec358_claim_sha'])
            if state['rollback']:flags[FLAGS[1]]=True
            if state['fork_or_terminal']:flags[FLAGS[3]]=True
            if state['clock']:flags[FLAGS[5]]=True
        if claimed_parents[0]!=claimed_parents[1]:flags[FLAGS[4]]=True
        if (distributions[-2]['owner_sha']==distributions[-1]['owner_sha'] or
            distributions[-2]['claimed_owner_id']==distributions[-1]['claimed_owner_id']):
            flags[FLAGS[4]]=True
        summaries.append({'epoch_index':i,'checkpoint_sha':cpref['sha256'],
                          'tree_size':cp['tree_size'],
                          'inclusion_proofs_attempted':len(seen_sha),
                          'unique_included_original_shas':sorted(seen_sha)})
    # Persist all original receiver inode/SHA checks through final processing.
    need(not set(pins).intersection(forbidden),
         'VERIFIER_TOUCHED_FORBIDDEN_OLD_SIGNED_SENDER_SOURCE_LABEL',
         'permission_denied')
    tsa._check_late(pins)
    # Even a genuine new signed issuer successor cannot disavow an observed
    # earlier signed revoke/rotate; old EC372 authority adverse flags persist.
    for slot in ('a','b'):
        sequence=[d for d in distributions if d['slot']==slot]
        for prev,nxt in zip(sequence,sequence[1:]):
            if (prev['issuer_sha']!=nxt['issuer_sha'] or
                prev['owner_sha']!=nxt['owner_sha'] or
                prev['claimed_owner_id']!=nxt['claimed_owner_id'] or
                prev['parent_ec358_claim_sha']!=nxt['parent_ec358_claim_sha'] or
                prev['parent_owner_event_claim_sha']!=nxt['parent_owner_event_claim_sha']):
                flags[FLAGS[6]]=True
            if (prev['selected_head']!=nxt['selected_head'] and
                (prev['selected_head'] not in nxt['distribution_original_shas'] or
                 nxt['selected_sequence']<=prev['selected_sequence'])):
                flags[FLAGS[6]]=True
    flags[FLAGS[7]]=True  # No finite receiver slice certifies absent ancestors.
    inventory={'schema':INVENTORY_SCHEMA,
        'verified_live_ec372_canonical_result_sha256':parent_sha,
        'ec371_historical_archive_original_sha256':opts[
                         'expected_historical_archive_bundle_sha256'],
        'ec372_historical_authority_original_sha256':aref['sha256'],
        'ec373_historical_inclusion_bundle_original_sha256':bref['sha256'],
        'claimed_directory_lineage_id':opts['claimed_historical_directory_lineage_id'],
        'verified_original_signatures_and_inclusions':[
            {k:rec[k] for k in ('epoch_index','slot','checkpoint_sha','tree_size',
                 'issuer_sha','owner_sha','claimed_owner_id','delegation_sha',
                 'included_original_shas','distribution_original_shas',
                 'selected_head','selected_sequence','selected_operation',
                 'parent_ec358_claim_sha','parent_owner_event_claim_sha')}
            for rec in distributions]}
    digest=sha(canonical.canonical(inventory))
    if not derive and opts[AUDIT_ONLY[0]]!=digest:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:-1])
    status=next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                OUTCOMES[-1])+'_unresolved'
    result={'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
         'command':'derive-historical-inclusion-inventory' if derive else
                   'audit-historical-inclusion-archive',
         'status':status,'exit_code':2,'offline_unresolved_exit_code':2,
         'historical_inclusion_bundle_original_sha256':bref['sha256'],
         'verified_live_parent_ec372_canonical_result_sha256':parent_sha,
         'receiver_verified_historical_inclusion_inventory_sha256':digest,
         'verified_exact_ec371_signed_checkpoint_count':len(rows),
         'recomputed_actual_rfc6962_inclusion_proof_count':verified_inclusions,
         'attempted_rfc6962_inclusion_proof_count':attempted,
         'replayed_genuine_ec359_issuer_signed_record_count':sum(
                         len(r['distribution_original_shas']) for r in distributions),
         'historical_inclusion_epoch_reviews':summaries,
         'historical_issuer_source_epoch_reviews':[
           {k:r[k] for k in ('epoch_index','slot','issuer_sha','owner_sha',
              'selected_head','selected_sequence','selected_operation',
              'fork_or_terminal','rollback','clock')}
           for r in distributions],
         'local_pinned_historical_inclusion_and_issuer_slice_consistent':local,
         'sender_origin_path_required_or_read':False,
         'ec365_to_ec337_full_parent_original_replay_performed':False,
         **flags,**{k:False for k in NEGATIVES}}
    if derive:
        result['unsigned_verified_historical_inclusion_inventory']=inventory
        result['caller_external_inventory_pin_created_or_certified']=False
    return result


def audit(**opts):return _engine(False,**opts)


def derive_inventory(**opts):return _engine(True,**opts)
