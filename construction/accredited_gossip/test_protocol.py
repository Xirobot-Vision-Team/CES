#!/usr/bin/env python3
"""Focused EC395 genuine Ed25519/original byte tests.

Timestamp _stamp is mocked only in these isolated tests to test the business
protocol without manufacturing or claiming a qualified RFC3161 public issuer.
The unchanged EC394->EC317 production acceptance is NOT run by this suite.
"""
from __future__ import annotations

from datetime import datetime,timedelta,timezone
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from . import protocol as core


class SignedGossipAndOffsiteTests(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='ec395_local_')
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name)
        self.serial=0
        self.keys={name:Ed25519PrivateKey.generate() for name in ('wa','wb','ia','ib','ar1','ar2','registrar','dispute','oldsite')}
        self.roles={name:self.role(name) for name in self.keys}
        self.parentref=self.archive({'source':'actual and immutable EC394 original'},'parent')
        self.rosterref=self.archive({'source':'actual and immutable EC394 roster'},'roster')
        self.notice=self.archive({'source':'genuine signed cutoff'},'cutoff')
        self.status=self.archive({'source':'genuine signed status'},'status')
        self.oldobs_a=self.archive({'source':'actual genuine EC394 signed witness A'},'obs-a')
        self.oldobs_b=self.archive({'source':'actual genuine EC394 signed witness B'},'obs-b')
        self.head=self.archive({'source':'genuine EC393 signed Head'},'head')
        self.oldregistration=self.archive({'source':'authentic original signed registration'},'registration')
        self.lineage='LineageLocal395'
        self.parentdigest='c'*64
        self.cutoff=datetime(2026,10,25,15,0,tzinfo=timezone.utc)
        self.evaluation=datetime(2026,10,26,11,0,tzinfo=timezone.utc)
        self.witnesses=[self.roles['wa'],self.roles['wb']]
        self.anchor={'ec394_roster':{'witnesses':self.witnesses}}
        self.parent_source={'parent_ec393_custody_bundle_original':
             self.archive({'source':'actual genuine ec393 parent'},'ec393'),
          'witness_tsa_registry_original':self.archive({'source':'original real tsa roster'},'tsa'),
          'external_trust_roster_original':self.rosterref,
          'original_dispute_case_file':self.archive({'source':'external case'},'case'),
          'dispute_notice_rfc3161_token_original':self.archive(b'old signed-token-original','old-tsa'),
          'key_status_snapshot_rfc3161_token_original':self.archive(b'old-status-token','old-status-tsa'),
          'epochs':[{'epoch_index':0,
             'witnesses':[{'witness_id':self.roles['wa']['role_id'],
                           'observations':[self.obs(self.oldobs_a,self.head)]},
                          {'witness_id':self.roles['wb']['role_id'],
                           'observations':[self.obs(self.oldobs_b,self.head)]}]}],
          'signed_dispute_notice_original':self.notice,
          'key_status_snapshot_original':self.status,
          'site_key_histories':[{'observer_id':'Obs0','role':'receiver',
             'party_id':'Party0','site_id':'Site0',
             'registered_site_identity_original':self.rosterref,
             'generations':[{'signed_site_key_registration_original':self.oldregistration,
                'registered_public_key_original':self.oldregistration,
                'rfc3161_registration_token_original':None}]}]}
        self.flags={name:False for name in core.FLAGS}

    def role(self,name):
        raw=self.keys[name].public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return {'role_id':'Role'+name,'site_id':'Site'+name,'public_hex':raw.hex(),
                'public_key_original':self.archive(raw,'rawkey-'+name)}

    def archive(self,doc,name):
        self.serial+=1
        path=self.root/(name+'-'+str(self.serial))
        if isinstance(doc,bytes):raw=doc
        else:raw=canonical.canonical(doc)
        path.write_bytes(raw)
        return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}

    def read(self,ref,role,cap):
        raw=Path(ref['path']).read_bytes()
        self.assertLessEqual(len(raw),cap)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),ref['sha256'])
        return raw

    @staticmethod
    def obs(signed,head):
        return {'signed_witness_observation_original':signed,
                'rfc3161_witness_token_original':None,
                'observed_signed_log_head_original':head}

    def timestamp(self,raw,ref,trust,aid,read,evaluation,cutoff,claimed,flags):
        return {'sha256':ref['sha256'] if ref else 'f'*64,
                'gen':claimed+timedelta(seconds=1),'clean':True}

    def sign(self,name,domain,claim,schema,file):
        return self.archive({'schema':schema,'claim':claim,'signature_ed25519':
            self.keys[name].sign(domain+canonical.canonical(claim)).hex()},file)

    def one_stage(self,stage,name,peer,prev,minute,own=None,peerobs=None):
        if own is None:own=[self.oldobs_a['sha256']] if name=='wa' else [self.oldobs_b['sha256']]
        if peerobs is None:peerobs=[self.oldobs_a['sha256']] if peer=='wa' else [self.oldobs_b['sha256']]
        claim={'schema':core.GOSSIP_CLAIM_SCHEMA,'directory_lineage_id':self.lineage,
            'parent_ec394_bundle_original_sha256':self.parentref['sha256'],
            'parent_ec394_verified_inventory_sha256':self.parentdigest,
            'ec394_signed_dispute_notice_sha256':self.notice['sha256'],
            'epoch_index':0,'stage':stage,'witness_id':self.roles[name]['role_id'],
            'peer_witness_id':self.roles[peer]['role_id'],
            'own_observation_shas':own,'peer_observation_shas':peerobs,
            'previous_stage_signed_original_sha256':prev,
            'claimed_exchange_utc':f'2026-10-25T14:{minute:02d}:00Z'}
        sig=self.sign(name,core.GOSSIP_DOMAINS[stage],claim,core.GOSSIP_SCHEMA,stage)
        return {'signed_original':sig,
                'rfc3161_token_original':self.archive(b'fixture-not-der-'+stage.encode(),stage+'-stamp')}

    def exchange(self,omit_peer=False):
        offer=self.one_stage('offer','wa','wb',core.ZERO,0,
             peerobs=[] if omit_peer else None)
        ack=self.one_stage('acknowledge','wb','wa',offer['signed_original']['sha256'],1)
        confirm=self.one_stage('confirm','wa','wb',ack['signed_original']['sha256'],2)
        return {'offer':offer,'acknowledge':ack,'confirm':confirm}

    def gos(self,exchange):
        return core._gossip(exchange,0,self.anchor,self.parent_source,self.parentref,
               self.parentdigest,self.notice['sha256'],self.lineage,self.read,{},'TSA395',
               self.evaluation,self.cutoff,self.flags)

    def pairs(self,required,site):
        rows=[]
        for source in required:
            copied=self.archive(Path(source['path']).read_bytes(),'replica-'+site)
            rows.append({'source_original':source,'offsite_copy_original':copied})
        return rows

    def signed_archive(self,site,required,gossip,previous=core.ZERO,epoch=0,basis_sha=None):
        role=self.roles[site]
        copies=self.pairs(required,site)
        rows=sorted(copies,key=lambda r:(r['source_original']['sha256'],
                                          r['source_original']['path']))
        claim={'schema':core.RECEIPT_CLAIM_SCHEMA,'directory_lineage_id':self.lineage,
          'parent_ec394_bundle_original_sha256':self.parentref['sha256'],
          'parent_ec394_verified_inventory_sha256':self.parentdigest,
          'ec394_signed_dispute_notice_sha256':self.notice['sha256'],
          'epoch_index':epoch,'archivist_id':role['role_id'],
          'archivist_site_id':role['site_id'],
          'previous_epoch_signed_receipt_sha256':previous,
          'confirmed_gossip_original_sha256':gossip['confirmed_original_sha256'],
          'original_to_replica_inventory_sha256':core.cdigest(rows),
          'external_licensing_basis_original_sha256':basis_sha or 'e'*64,
          'claimed_sealed_utc':'2026-10-25T14:04:00Z'}
        signed=self.sign(site,core.RECEIPT_DOMAIN,claim,core.RECEIPT_SCHEMA,'receipt-'+site)
        return {'archivist_id':role['role_id'],'signed_receipt_original':signed,
              'rfc3161_receipt_token_original':self.archive(b'fixture-stamp-'+site.encode(),'receipt-ts'),
              'copies':copies}

    def credentials_fixture(self,wrong_basis=False,reverse=False):
        roles={r['role_id']:r for r in (self.roles['ia'],self.roles['ib'],
                                       self.roles['ar1'],self.roles['ar2'])}
        anchor={'ec394_roster':{
           'registrar':self.roles['registrar'],
           'dispute_authority':self.roles['dispute'],
           'witnesses':self.witnesses},
           'ec393_roster':{'custody_parties':[
             {'party_id':'CustodySite0','public_hex':self.roles['oldsite']['public_hex']}]},
           'ec394_roster_ref':self.rosterref,
           'ec393_roster_ref':self.archive({'source':'true old roster'},'ec393-roster'),
           'tsa_root_sha':'d'*64,'tsa_policy':'1.2.3.395'}
        licenseref=self.archive(b'untrusted credential register byte original','licenses')
        pairs=[]
        for idx,name in enumerate(('ia','ib')):
            claim={'schema':core.CREDENTIAL_CLAIM_SCHEMA,
              'directory_lineage_id':self.lineage,
              'issuer_id':self.roles[name]['role_id'],
              'issuer_site_id':self.roles[name]['site_id'],
              'ec394_external_roster_original_sha256':self.rosterref['sha256'],
              'ec393_custody_roster_original_sha256':anchor['ec393_roster_ref']['sha256'],
              'parent_ec394_registered_bundle_original_sha256':self.parentref['sha256'],
              'external_licensing_basis_original_sha256':(
                   'e'*64 if wrong_basis and name=='ib' else licenseref['sha256']),
              'ec394_tsa_root_certificate_der_sha256':anchor['tsa_root_sha'],
              'ec394_tsa_policy_oid':anchor['tsa_policy'],
              'credential_subject_key_digest_sha256':core.cdigest(core._subjects(anchor,roles)),
              'claimed_accreditation_scope':'local_evidence_custody_and_timestamp_origins',
              'claimed_issued_utc':'2026-10-25T13:00:00Z',
              'claimed_valid_from_utc':'2026-10-24T00:00:00Z',
              'claimed_valid_until_utc':'2026-10-26T00:00:00Z'}
            original=self.sign(name,core.CREDENTIAL_DOMAIN,claim,
                               core.CREDENTIAL_SCHEMA,'accreditation-'+name)
            pairs.append({'issuer_id':self.roles[name]['role_id'],
              'signed_credential_original':original,
              'rfc3161_credential_token_original':self.archive(
                b'untrusted-test-tsa-original-'+name.encode(),'credential-stamp')})
        if reverse:pairs.reverse()
        opts={core.NEW_SCALARS[4]:next(c['signed_credential_original']['sha256']
               for c in pairs if c['issuer_id']==self.roles['ia']['role_id']),
              core.NEW_SCALARS[6]:self.roles['ia']['public_hex'],
              core.NEW_SCALARS[7]:self.roles['ib']['public_hex']}
        return {'external_credential_attestations':pairs},roles,anchor,licenseref,opts

    def run_credentials(self,bundle,roles,anchor,license_ref,opts):
        return core._credentials(bundle,roles,anchor,opts,self.read,{},'TSA395',
           self.evaluation,self.cutoff,self.flags,self.parentref,license_ref,self.lineage)

    def run_arch(self,entry,gossip,required,used=None,previous=core.ZERO,epoch=0,prior_chain_ok=True):
        site=entry['archivist_id']
        role=next(v for v in self.roles.values() if v['role_id']==site)
        protected={ref['path'] for ref in required}
        return core._archive(entry,epoch,role,previous,
            gossip['confirmed_original_sha256'],gossip['confirmed_token_generation_time'],
            datetime(2026,10,25,13,0,tzinfo=timezone.utc),None,
            self.parentref,self.parentdigest,self.notice['sha256'],'e'*64,required,
            self.read,{},'TSA395',self.evaluation,self.cutoff,protected,
            used if used is not None else set(),self.lineage,self.flags,prior_chain_ok)

    @patch.object(core,'_stamp',autospec=False)
    def test_genuine_reciprocal_offer_ack_confirm(self,stamp):
        stamp.side_effect=self.timestamp
        g=self.gos(self.exchange())
        self.assertTrue(g['complete'])
        self.assertEqual(len(g['rows']),3)
        self.assertFalse(g['divergences'])
        self.assertFalse(self.flags[core.FLAGS[3]])

    @patch.object(core,'_stamp',autospec=False)
    def test_signed_suppression_retained_as_adverse_disclosure(self,stamp):
        stamp.side_effect=self.timestamp
        g=self.gos(self.exchange(omit_peer=True))
        self.assertFalse(g['complete'])
        self.assertEqual(g['divergences'][0]['stage'],'offer')
        self.assertTrue(self.flags[core.FLAGS[4]])

    @patch.object(core,'_stamp',autospec=False)
    def test_forged_witness_is_denied_not_listed_as_valid_fork(self,stamp):
        stamp.side_effect=self.timestamp
        group=self.exchange()
        signedref=group['acknowledge']['signed_original']
        import json
        original=json.loads(Path(signedref['path']).read_text())
        original['signature_ed25519']='00'*64
        group['acknowledge']['signed_original']=self.archive(original,'forged-ack')
        with self.assertRaises(errors.AnchorError):self.gos(group)

    @patch.object(core,'_stamp',autospec=False)
    def test_double_recovery_requires_distinct_real_identical_bytes(self,stamp):
        stamp.side_effect=self.timestamp
        gossip=self.gos(self.exchange())
        required=core._required_archive_sources(self.parentref,
            {'ec394_roster_ref':self.rosterref},self.parent_source,gossip)
        used=set()
        a=self.run_arch(self.signed_archive('ar1',required,gossip),gossip,required,used)
        b=self.run_arch(self.signed_archive('ar2',required,gossip),gossip,required,used)
        self.assertTrue(a['pre_cutoff_signed_copy_readback'])
        self.assertTrue(b['pre_cutoff_signed_copy_readback'])
        self.assertEqual(a['recovered_originals'],len(required))
        self.assertEqual(len(used),2*len(required))

    @patch.object(core,'_stamp',autospec=False)
    def test_missing_previous_epoch_receipt_cannot_be_bounded(self,stamp):
        stamp.side_effect=self.timestamp
        gossip=self.gos(self.exchange())
        required=core._required_archive_sources(self.parentref,
            {'ec394_roster_ref':self.rosterref},self.parent_source,gossip)
        arch=self.signed_archive('ar1',required,gossip,epoch=1)
        result=self.run_arch(arch,gossip,required,epoch=1)
        self.assertFalse(result['pre_cutoff_signed_copy_readback'])
        self.assertTrue(self.flags[core.FLAGS[5]])

    @patch.object(core,'_stamp',autospec=False)
    def test_prior_invalid_receipt_cannot_regain_credit_later(self,stamp):
        stamp.side_effect=self.timestamp
        gossip=self.gos(self.exchange())
        required=core._required_archive_sources(self.parentref,
            {'ec394_roster_ref':self.rosterref},self.parent_source,gossip)
        earlier_signed_sha='f'*64
        later=self.signed_archive('ar1',required,gossip,previous=earlier_signed_sha,epoch=2)
        # A currently valid signature is not enough to repair an absent or
        # cryptographically unbounded intermediate period.
        would_pass=self.run_arch(later,gossip,required,previous=earlier_signed_sha,
                                 epoch=2,prior_chain_ok=True)
        self.assertTrue(would_pass['pre_cutoff_signed_copy_readback'])
        checked=self.run_arch(later,gossip,required,previous=earlier_signed_sha,
                              epoch=2,prior_chain_ok=False)
        self.assertFalse(checked['pre_cutoff_signed_copy_readback'])
        self.assertTrue(self.flags[core.FLAGS[5]])

    @patch.object(core,'_stamp',autospec=False)
    def test_archive_byte_mutation_denied(self,stamp):
        stamp.side_effect=self.timestamp
        gossip=self.gos(self.exchange())
        required=core._required_archive_sources(self.parentref,
            {'ec394_roster_ref':self.rosterref},self.parent_source,gossip)
        arch=self.signed_archive('ar1',required,gossip)
        copyref=arch['copies'][0]['offsite_copy_original']
        Path(copyref['path']).write_bytes(b'mutated copy not original')
        with self.assertRaises(AssertionError):self.run_arch(arch,gossip,required)

    @patch.object(core,'_stamp',autospec=False)
    def test_two_real_independent_credential_signatures_even_in_reverse_order(self,stamp):
        stamp.side_effect=self.timestamp
        bundle,roles,anchor,license_ref,opts=self.credentials_fixture(reverse=True)
        rows,clean,_=self.run_credentials(bundle,roles,anchor,license_ref,opts)
        self.assertTrue(clean)
        self.assertEqual(sum(x['bounded_before_cutoff'] for x in rows),2)
        self.assertFalse(self.flags[core.FLAGS[1]])

    @patch.object(core,'_stamp',autospec=False)
    def test_genuinely_signed_license_with_wrong_parent_basis_denied(self,stamp):
        stamp.side_effect=self.timestamp
        bundle,roles,anchor,license_ref,opts=self.credentials_fixture(wrong_basis=True)
        with self.assertRaises(errors.AnchorError):
            self.run_credentials(bundle,roles,anchor,license_ref,opts)

    @patch.object(core,'_stamp',autospec=False)
    def test_late_credential_stays_unresolved_despite_valid_ed25519(self,stamp):
        stamp.return_value={'sha256':'a'*64,'gen':self.cutoff+timedelta(seconds=2),'clean':True}
        bundle,roles,anchor,license_ref,opts=self.credentials_fixture()
        rows,clean,_=self.run_credentials(bundle,roles,anchor,license_ref,opts)
        self.assertFalse(clean)
        self.assertEqual(sum(x['bounded_before_cutoff'] for x in rows),0)
        self.assertTrue(self.flags[core.FLAGS[2]])

    def test_independent_four_external_roles_reject_old_key_or_site_reuse(self):
        doc={'schema':core.ROSTER_SCHEMA,'claimed_directory_lineage_id':self.lineage,
             'credential_issuers':[self.roles['ia'],self.roles['ib']],
             'offsite_archivists':[self.roles['ar1'],self.roles['ar2']]}
        ref=self.archive(doc,'outside-roles')
        opts={core.NEW_SCALARS[2]:ref['sha256'],
              core.NEW_SCALARS[6]:self.roles['ia']['public_hex'],
              core.NEW_SCALARS[7]:self.roles['ib']['public_hex']}
        found,_=core._roster(doc,ref,opts,self.lineage,self.read,
                     {self.roles['wa']['public_hex']},
                     {self.roles['wa']['site_id']},{self.roles['wa']['role_id']})
        self.assertEqual(len(found),4)
        with self.assertRaises(errors.AnchorError):
            core._roster(doc,ref,opts,self.lineage,self.read,
                         {self.roles['ia']['public_hex']},set(),set())

    @patch.object(core,'_stamp',autospec=False)
    def test_synthetic_full_ec395_derive_then_audit_with_mocked_parent_only(self,stamp):
        """Actual child engine, true child signatures and bytes; ONLY parent is mocked."""
        stamp.side_effect=self.timestamp
        from unittest.mock import patch as localpatch
        import copy
        now='2026-10-25T15:00:00Z'
        oldparties=[]
        for n,name in enumerate(('oldsite','registrar','dispute','wa')):
            oldparties.append({'observer_id':'Observer'+str(n),
              'party_id':'Custodian'+str(n),'site_id':'PhysicalClaim'+str(n),
              'role':'receiver' if n%2 else 'sender',
              'public_hex':self.roles[name]['public_hex'],
              'public_key_original':self.roles[name]['public_key_original']})
        oldroster={'schema':core.prior.parent.ROSTER_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,'log_id':'OldLog395',
          'log_operator_id':'OldLogOperator','log_public_hex':'b'*64,
          'log_public_key_original':self.roles['oldsite']['public_key_original'],
          'custody_parties':oldparties}
        oldroster_ref=self.archive(oldroster,'actual-ec393-roster-fixture')
        oldbundle=dict.fromkeys(core.prior.parent.BUNDLE_FIELDS)
        oldbundle.update({'schema':core.prior.parent.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id':self.lineage,
            'custody_log_roster_original':oldroster_ref,
            'prior_signed_log_head_original':self.head,'epochs':[{'epoch_index':0,'channels':[]}]})
        oldbundle_ref=self.archive(oldbundle,'authentic-source-ec393-fixture')
        external_roster={'schema':core.prior.ROSTER_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'registrar':self.roles['registrar'],'dispute_authority':self.roles['dispute'],
          'witnesses':self.witnesses}
        external_roster_ref=self.archive(external_roster,'real-external-ec394-roster-fixture')
        trustref=self.archive({'source':'independent genuine trust roster fixture'},'trust-ec394')
        self.parent_source.update({
          'schema':core.prior.BUNDLE_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'parent_ec393_custody_bundle_original':oldbundle_ref,
          'external_trust_roster_original':external_roster_ref,
          'witness_tsa_registry_original':trustref,
          'witness_tsa_authority_id':'TSA395',
        })
        self.parentref=self.archive(self.parent_source,'signed-ec394-original-fixture')
        report={k:False for k in (*core.prior.FLAGS,*core.prior.NEGATIVES)}
        for key in core.prior.FLAGS[-3:]:report[key]=True
        report.update({'schema':core.prior.RESULT_SCHEMA,
          'command':'audit-historical-ec339-registered-witness',
          'status':core.prior.OUTCOMES[-3]+'_unresolved',
          'exit_code':2,'offline_unresolved_exit_code':2,
          'verified_live_ec393_report_sha256':'a'*64,
          'verified_live_ec393_inventory_sha256':'b'*64,
          'historical_registered_witness_original_sha256':self.parentref['sha256'],
          'receiver_verified_registered_witness_inventory_sha256':self.parentdigest,
          'cryptographically_timestamped_pre_handoff_registered_site_role_count':0,
          'cryptographically_timestamped_pre_cutoff_independent_witness_count':2,
          'visible_genuine_signed_log_fork_count':0,
          'signed_key_status_snapshot_sha256':self.status['sha256'],
          'furnished_signed_key_revocation_count':0,
          'registered_witness_epoch_reviews':[{
            'epoch_index':0,'pre_handoff_registered_site_roles':0,
            'pre_cutoff_independent_log_witnesses':2,
            'site_key_registration_inventory_sha256':'a'*64,
            'third_party_witness_inventory_sha256':'b'*64,
            'visible_valid_signed_log_fork_count':0}],
          'visible_signed_log_fork_cases':[],
          'local_registered_key_and_independent_witness_consistency':True,
          'sender_origin_path_required_or_read':False,
          'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False})
        self.assertTrue(core._parent_report(report,{
             core.prior.NEW_SCALARS[1]:self.parentref['sha256'],
             core.prior.AUDIT_ONLY[0]:self.parentdigest,
             'historical_directory_root_shas':['1'*64]}))
        new_roles={r['role_id']:r for r in (self.roles['ia'],self.roles['ib'],
                                           self.roles['ar1'],self.roles['ar2'])}
        new_roster={'schema':core.ROSTER_SCHEMA,
             'claimed_directory_lineage_id':self.lineage,
             'credential_issuers':[self.roles['ia'],self.roles['ib']],
             'offsite_archivists':[self.roles['ar1'],self.roles['ar2']]}
        new_roster_ref=self.archive(new_roster,'new-four-role-roster-fixture')
        license_ref=self.archive(b'external opaque license basis not officially authenticated',
                                 'license-basis-original')
        anchor={'ec394_roster':external_roster,
           'ec394_roster_ref':external_roster_ref,
           'ec393_roster':oldroster,'ec393_roster_ref':oldroster_ref,
           'tsa_root_sha':'d'*64,'tsa_policy':'1.2.3.395'}
        cred=[]
        for name in ('ia','ib'):
            c={'schema':core.CREDENTIAL_CLAIM_SCHEMA,
               'directory_lineage_id':self.lineage,
               'issuer_id':self.roles[name]['role_id'],
               'issuer_site_id':self.roles[name]['site_id'],
               'ec394_external_roster_original_sha256':external_roster_ref['sha256'],
               'ec393_custody_roster_original_sha256':oldroster_ref['sha256'],
               'parent_ec394_registered_bundle_original_sha256':self.parentref['sha256'],
               'external_licensing_basis_original_sha256':license_ref['sha256'],
               'ec394_tsa_root_certificate_der_sha256':'d'*64,
               'ec394_tsa_policy_oid':'1.2.3.395',
               'credential_subject_key_digest_sha256':core.cdigest(core._subjects(anchor,new_roles)),
               'claimed_accreditation_scope':'local_evidence_custody_and_timestamp_origins',
               'claimed_issued_utc':'2026-10-25T13:00:00Z',
               'claimed_valid_from_utc':'2026-10-24T00:00:00Z',
               'claimed_valid_until_utc':'2026-10-26T00:00:00Z'}
            ref=self.sign(name,core.CREDENTIAL_DOMAIN,c,core.CREDENTIAL_SCHEMA,'credential-full-'+name)
            cred.append({'issuer_id':self.roles[name]['role_id'],
               'signed_credential_original':ref,
               'rfc3161_credential_token_original':self.archive(b'untrusted-tsa-fixture-'+name.encode(),
                                                                 'credential-tsa-fixture')})
        exchange=self.exchange()
        gossip=self.gos(exchange)
        required=core._required_archive_sources(self.parentref,
             {'ec394_roster_ref':external_roster_ref},self.parent_source,gossip,
             [new_roster_ref,license_ref,*[r[k] for r in cred
                 for k in ('signed_credential_original','rfc3161_credential_token_original')]])
        a=self.signed_archive('ar1',required,gossip,basis_sha=license_ref['sha256'])
        b=self.signed_archive('ar2',required,gossip,basis_sha=license_ref['sha256'])
        fullbundle={'schema':core.BUNDLE_SCHEMA,'claimed_directory_lineage_id':self.lineage,
           'parent_ec394_registered_witness_bundle_original':self.parentref,
           'external_role_roster_original':new_roster_ref,
           'external_licensing_basis_original':license_ref,
           'external_credential_attestations':cred,
           'epochs':[{'epoch_index':0,'gossip':exchange,'archives':[a,b]}]}
        newbundle_ref=self.archive(fullbundle,'ec395-complete-bundle-fixture')
        opts={k:'1'*64 for k in (*core.PARENT_SCALARS,*core.NEW_SCALARS)}
        for key in (*core.PARENT_REPEATS,*core.REPEAT_NAMES):
            opts[key]=['1'*64]
        opts.update({
          'historical_directory_root_shas':['1'*64],
          'claimed_historical_directory_lineage_id':self.lineage,
          'ec391_tsa_evaluation_utc':'2026-10-26T11:00:00Z',
          core.prior.parent.NEW_SCALARS[5]:now,
          core.prior.NEW_SCALARS[0]:self.parentref['path'],
          core.prior.NEW_SCALARS[1]:self.parentref['sha256'],
          core.prior.NEW_SCALARS[3]:trustref['sha256'],
          core.prior.AUDIT_ONLY[0]:self.parentdigest,
          core.NEW_SCALARS[0]:newbundle_ref['path'],
          core.NEW_SCALARS[1]:newbundle_ref['sha256'],
          core.NEW_SCALARS[2]:new_roster_ref['sha256'],
          core.NEW_SCALARS[3]:license_ref['sha256'],
          core.NEW_SCALARS[4]:cred[0]['signed_credential_original']['sha256'],
          core.NEW_SCALARS[5]:a['signed_receipt_original']['sha256'],
          core.NEW_SCALARS[6]:self.roles['ia']['public_hex'],
          core.NEW_SCALARS[7]:self.roles['ib']['public_hex'],
          core.REPEAT_NAMES[0]:['1'*64],core.REPEAT_NAMES[1]:['1'*64],
          core.REPEAT_NAMES[2]:[0],core.REPEAT_NAMES[3]:[0],
        })
        trust={'TSA395':{'root_sha':'d'*64,'policy':'1.2.3.395',
                         'root':object(),'crls':[]}}
        with localpatch.object(core.prior,'audit',return_value=report),\
             localpatch.object(core.prior,'_inputs',return_value=None),\
             localpatch.object(core.prior.parent.prior,'_trust_registry',return_value=trust):
            first=core.derive_inventory(**opts)
            self.assertEqual(first['exit_code'],2)
            self.assertEqual(first['original_independently_signed_credential_count'],2)
            self.assertEqual(first['cryptographically_bounded_reciprocal_gossip_count'],1)
            self.assertEqual(first['cryptographically_bounded_two_site_archive_replica_count'],2)
            row=first['credential_gossip_archive_epoch_reviews'][0]
            opts[core.REPEAT_NAMES[0]]=[row['reciprocal_signed_gossip_inventory_sha256']]
            opts[core.REPEAT_NAMES[1]]=[row['offsite_signed_recovery_inventory_sha256']]
            opts[core.REPEAT_NAMES[2]]=[1]
            opts[core.REPEAT_NAMES[3]]=[2]
            second=core.derive_inventory(**opts)
            opts[core.AUDIT_ONLY[0]]=second[
               'receiver_verified_credential_gossip_archive_inventory_sha256']
            result=core.audit(**opts)
            self.assertEqual(result['exit_code'],2)
            self.assertEqual(result['status'],core.OUTCOMES[7]+'_unresolved')
            self.assertTrue(result['local_credential_gossip_and_readback_consistency'])
            self.assertFalse(result['physical_independent_worm_prior_publication_and_dispute_cutoff_unproven'] is False)

    def test_malformed_outside_pin_and_parent_success_fabrication_denied(self):
        fake={'schema':core.prior.RESULT_SCHEMA,'status':'PASS','exit_code':0}
        with self.assertRaises(errors.AnchorError):core._parent_report(fake,{})
        with self.assertRaises(errors.AnchorError):core._rawref(
            {'path':str(self.root/'missing'),'sha256':core.ZERO})


if __name__=='__main__':unittest.main()
