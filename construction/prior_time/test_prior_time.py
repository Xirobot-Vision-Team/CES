#!/usr/bin/env python3
"""EC391 genuine local Ed25519 + OpenSSL DER RFC3161 checks; external parent MOCKED.

Fixture TSA, keys and timestamps are CREATED here for tests only. They are not
independent offsite authority, proven legal provenance or actual external UTC.
"""
from __future__ import annotations

import copy
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as ts
from tsa_timestamp.test_timestamp import local_test_certs
from external_revocation import test_witness_custody as ptest
from independent_archive import test_retained_heads as ec390fixture
from independent_archive import retained_heads as prev
from . import prior_time as core

POLICY='1.2.3.4.5.391'


class PriorTimeTests(ec390fixture.ArchivedHistoryTests):
    # Inherit robust nested old-key and original-source fixtures; run only EC391.
    def setUp(self):
        super().setUp()
        self.keeper_priv=Ed25519PrivateKey.generate()
        keeper_pub=self.keeper_priv.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        p=self.root/('ec391-keeper-'+self._testMethodName+'.raw')
        p.write_bytes(keeper_pub)
        self.keeper_roster={'schema':core.ROSTER_SCHEMA,
            'claimed_directory_lineage_id':'Lineage388',
            'log_keepers':[{'signer_id':'PriorKeeper1','public_hex':keeper_pub.hex(),
                            'public_key_original':ptest.ref(p)}]}
        self.keeper_ref=self._archive('ec391-keeper-roster-'+self._testMethodName+'.json',
                                      self.keeper_roster)
        self.prior_claim={'schema':core.CLAIM_SCHEMA,
            'directory_lineage_id':'Lineage388',
            'tsa_channel_id':self.channel['tsa_channel_id'],
            'epoch_index':0,'offsite_keeper_id':'PriorKeeper1','log_sequence':1,
            'previous_signed_offsite_head_original_sha256':core.ZERO,
            'ec389_signed_source_pairs':copy.deepcopy(self.signed_source),
            'claimed_logged_utc':'2026-10-25T11:26:00Z'}
        self.roster_keys={'PriorKeeper1':keeper_pub.hex()}
        self.authorities={}
        self.current_entry=self.sign_prior()
        self.source={'pairs':copy.deepcopy(self.signed_source),
            'last_deposit':prev.old339._time('2026-10-25T11:25:00Z'),
            'witness_head_sha256':self.pair['signed_witness_original']['sha256'],
            'custody_head_sha256':self.pair['signed_custody_original']['sha256']}
        self.old_row=copy.deepcopy(self.entry)
        self.flags={k:False for k in core.FLAGS}
        self.test_tsa_serial=0

    def sign_prior(self,claim=None,*,name=None,priv=None,tokenref=None,aid=None):
        claim=copy.deepcopy(self.prior_claim if claim is None else claim)
        signed={'schema':core.SIGNED_SCHEMA,'claim':claim,
            'signature_ed25519':(priv or self.keeper_priv).sign(
                core.DOMAIN+canonical.canonical(claim)).hex()}
        href=self._archive(name or ('ec391-prior-'+self._testMethodName+'.json'),signed)
        return {'tsa_channel_id':self.channel['tsa_channel_id'],
            'signed_prior_offsite_head_original':href,
            'rfc3161_timestamp_original':tokenref,'tsa_authority_id':aid}

    def _run_channel(self,entry=None,oldrow=None,idx=0,previous=None,source=None):
        flags={k:False for k in core.FLAGS}
        out,nextprev=core._channel(entry or self.current_entry,source or self.source,
              oldrow or self.old_row,self.roster_keys,self.authorities,self.read,
              'Lineage388',idx,previous,flags,
              datetime.now(timezone.utc)+timedelta(days=1))
        return out,nextprev,flags

    def deny_channel(self,entry=None,**kw):
        with self.assertRaises(errors.AnchorError):self._run_channel(entry,**kw)

    def real_token(self,entry=None,*,with_crl=True,wrong_source=False,stale=False,
                   revoked=False,token_response=False):
        if not shutil.which('openssl'):
            self.skipTest('OpenSSL not installed for local synthetic RFC3161 fixture')
        self.test_tsa_serial+=1;n=self.test_tsa_serial
        base=Path(self.root)
        root,cert,priv,crl=local_test_certs(base,n,revoked=revoked,stale=stale)
        serial=base/f'ec391-serial-{n}.txt';serial.write_text('01\n',encoding='ascii')
        conf=base/f'ec391-tsa-{n}.conf';conf.write_text(
            '[tsa_config]\nserial = '+str(serial)+'\nsigner_cert = '+str(cert)+
            '\nsigner_key = '+str(priv)+'\ncerts = '+str(root)+
            '\nsigner_digest = sha256\ndefault_policy = '+POLICY+
            '\ndigests = sha256, sha384, sha512\naccuracy = secs:1\n'+
            'ordering = yes\ntsa_name = yes\ness_cert_id_chain = no\n'+
            'ess_cert_id_alg = sha256\n',encoding='ascii')
        query=base/f'ec391-query-{n}.tsq';response=base/f'ec391-token-{n}.der'
        entry=entry or self.current_entry
        signed_source=entry['signed_prior_offsite_head_original']['path']
        if wrong_source:
            signed_source=str(base/('ec391-wrong-imprint-'+str(n)+'.bin'))
            Path(signed_source).write_bytes(b'wrong-input-for-imprint')
        commands=[['openssl','ts','-query','-data',signed_source,'-sha256','-cert',
                   '-out',str(query)],
                  ['openssl','ts','-reply','-queryfile',str(query),'-config',str(conf),
                   '-section','tsa_config','-out',str(response)]]
        if not token_response:commands[1].insert(-2,'-token_out')
        for argv in commands:
            p=subprocess.run(argv,capture_output=True,text=True,timeout=20)
            if p.returncode:
                raise AssertionError(f'local OpenSSL fixture generation failed: {p.stderr}')
        rootref=ptest.ref(root);crlref=ptest.ref(crl)
        authority={'authority_id':'PriorTSA1','root_certificate_original':rootref,
            'root_certificate_der_sha256':ts._certificate(root.read_bytes()).fingerprint(
                hashes.SHA256()).hex(),
            'expected_tsa_policy_oid':POLICY,
            'crl_originals':[crlref] if with_crl else []}
        registry={'schema':core.TRUST_SCHEMA,'claimed_directory_lineage_id':'Lineage388',
                  'authorities':[authority]}
        registryref=self._archive('ec391-trust-'+self._testMethodName+'-'+str(n)+'.json',
                                  registry)
        self.authorities={'PriorTSA1':{'root':ts._certificate(root.read_bytes()),
            'root_sha':authority['root_certificate_der_sha256'],
            'policy':POLICY,'crls':[ts._crl(crl.read_bytes())] if with_crl else [],
            'crl_refs':authority['crl_originals']}}
        entry=copy.deepcopy(entry)
        entry['rfc3161_timestamp_original']=ptest.ref(response)
        entry['tsa_authority_id']='PriorTSA1'
        return entry,registry,registryref

    def test_ec391_01_new_prior_signed_domain_verified(self):
        result,_,flags=self._run_channel()
        self.assertTrue(result['prior_head_matches_authentic_ec389_sources'])
        self.assertTrue(result['prior_head_matches_ec390_signed_snapshot'])
        self.assertTrue(flags[core.FLAGS[2]])
        self.assertFalse(flags[core.FLAGS[3]])

    def test_ec391_02_invalid_signed_offsite_head_rejected(self):
        claim=copy.deepcopy(self.prior_claim)
        entry=self.sign_prior(claim,priv=Ed25519PrivateKey.generate(),
                              name='ec391-wrong-signer-'+self._testMethodName+'.json')
        self.deny_channel(entry)

    def test_ec391_03_signed_source_mismatch_kept_as_two_adverse_views(self):
        claim=copy.deepcopy(self.prior_claim)
        claim['ec389_signed_source_pairs'][0]['ec339_revoked_status_original_sha256']='f1'*32
        entry=self.sign_prior(claim,name='ec391-signed-different-'+self._testMethodName+'.json')
        r,_,f=self._run_channel(entry)
        self.assertFalse(r['prior_head_matches_authentic_ec389_sources'])
        self.assertFalse(r['prior_head_matches_ec390_signed_snapshot'])
        self.assertTrue(f[core.FLAGS[3]] and f[core.FLAGS[4]])

    def test_ec391_04_old_source_authority_not_rewritten_by_prior_claim(self):
        claim=copy.deepcopy(self.prior_claim);claim['directory_lineage_id']='DifferentLineage'
        self.deny_channel(self.sign_prior(claim,name='ec391-wrong-lineage-'+self._testMethodName+'.json'))

    def test_ec391_05_offsite_signed_previous_sha_wrong_is_adverse(self):
        _,previous,_=self._run_channel()
        claim=copy.deepcopy(self.prior_claim)
        claim.update(epoch_index=1,log_sequence=2,
                     previous_signed_offsite_head_original_sha256='aa'*32)
        second=self.sign_prior(claim,name='ec391-epoch2-'+self._testMethodName+'.json')
        _,_,f=self._run_channel(second,previous=previous,idx=1)
        self.assertTrue(f[core.FLAGS[5]])

    def test_ec391_06_offsite_source_prefix_rollback_adverse(self):
        _,previous,_=self._run_channel()
        claim=copy.deepcopy(self.prior_claim)
        claim.update(epoch_index=1,log_sequence=2,
                     previous_signed_offsite_head_original_sha256=previous['head'],
                     ec389_signed_source_pairs=[])
        second=self.sign_prior(claim,name='ec391-rollback-'+self._testMethodName+'.json')
        _,_,f=self._run_channel(second,previous=previous,idx=1)
        self.assertTrue(f[core.FLAGS[5]])

    def test_ec391_07_real_rfc3161_signed_cms_and_pinned_cert_path(self):
        e,_,_=self.real_token()
        result,_,flags=self._run_channel(e)
        self.assertTrue(result['rfc3161_chain_verified_under_supplied_root'])
        self.assertTrue(result['bounded_crl_current_and_not_revoked'])
        self.assertGreaterEqual(result['tsa_cert_path_count'],2)
        self.assertTrue(flags[core.FLAGS[6]]) # today's signed time, older EC390 claimed time
        self.assertFalse(flags[core.FLAGS[7]])

    def test_ec391_08_real_full_timestamp_response_wrapper_supported(self):
        e,_,_=self.real_token(token_response=True)
        self.assertTrue(self._run_channel(e)[0]['rfc3161_chain_verified_under_supplied_root'])

    def test_ec391_09_imprint_must_hash_actual_signed_prior_head_bytes(self):
        e,_,_=self.real_token(wrong_source=True)
        self.deny_channel(e)

    def test_ec391_10_cms_wrong_expected_policy_denied(self):
        e,_,_=self.real_token()
        self.authorities['PriorTSA1']['policy']='1.2.3.4.5.999'
        self.deny_channel(e)

    def test_ec391_11_wrong_pinned_tsa_root_cannot_replace_chain(self):
        e,_,_=self.real_token()
        _,_,_=self.real_token()
        # The first token's certificate was issued by first root, not second.
        self.deny_channel(e)

    def test_ec391_12_missing_crl_does_not_create_false_pass(self):
        e,_,_=self.real_token(with_crl=False)
        result,_,flags=self._run_channel(e)
        self.assertTrue(result['rfc3161_chain_verified_under_supplied_root'])
        self.assertFalse(result['bounded_crl_current_and_not_revoked'])
        self.assertTrue(flags[core.FLAGS[7]])

    def test_ec391_13_stale_crl_is_separate_unresolved_flag(self):
        e,_,_=self.real_token(stale=True)
        self.assertTrue(self._run_channel(e)[2][core.FLAGS[7]])

    def test_ec391_14_revoked_tsa_signer_keeps_adverse_evidence(self):
        e,_,_=self.real_token(revoked=True)
        result,_,flags=self._run_channel(e)
        self.assertTrue(result['rfc3161_chain_verified_under_supplied_root'])
        self.assertTrue(flags[core.FLAGS[7]])

    def test_ec391_15_token_without_head_must_be_denied(self):
        e,_,_=self.real_token()
        e['signed_prior_offsite_head_original']=None
        self.deny_channel(e)

    def test_ec391_16_missing_head_and_timestamp_visible(self):
        empty={'tsa_channel_id':self.channel['tsa_channel_id'],
            'signed_prior_offsite_head_original':None,'rfc3161_timestamp_original':None,
            'tsa_authority_id':None}
        result,_,flags=self._run_channel(empty)
        self.assertIsNone(result['prior_signed_head_sha256'])
        self.assertTrue(flags[core.FLAGS[2]])

    def test_ec391_17_keeper_cannot_reuse_ec390_archivist_key(self):
        copyroster=copy.deepcopy(self.keeper_roster)
        copyroster['log_keepers'][0]['public_hex']=self.new_roster['archivists'][0]['public_hex']
        with self.assertRaises(errors.AnchorError):core._keeper_roster(
            copyroster,self.keeper_ref,self.keeper_ref['sha256'],self.read,set(),
            {self.new_roster['archivists'][0]['public_hex']})

    def test_ec391_18_keeper_public_sha_outside_pin_mismatch_rejected(self):
        with self.assertRaises(errors.AnchorError):core._keeper_roster(
            self.keeper_roster,self.keeper_ref,'ff'*32,self.read,set(),set())

    def test_ec391_19_tsa_trust_registry_root_der_sha_mismatch_rejected(self):
        _,registry,registryref=self.real_token()
        registry['authorities'][0]['root_certificate_der_sha256']='ff'*32
        with self.assertRaises(errors.AnchorError):core._trust_registry(
            registry,registryref,registryref['sha256'],'Lineage388',self.read)

    def test_ec391_20_tsa_trust_registry_outside_sha_pin_mandatory(self):
        _,registry,registryref=self.real_token()
        with self.assertRaises(errors.AnchorError):core._trust_registry(
            registry,registryref,'00'*32,'Lineage388',self.read)

    def test_ec391_21_parent_fabricated_pass_not_accepted(self):
        with self.assertRaises(errors.AnchorError):core._parent({'status':'passed'},1)

    def _outer_ec391(self,*,include_token=True,missing=False,crl=True):
        # Creates a legitimate EC390 signed archive and real EC389 source,
        # but EC389 and deeper outside parent audits are explicitly MOCKED.
        real389,oldopts=self._outer_ec390()
        a,b,c=self._outer_ctx(real389)
        with a,b,c:
            derived=prev.derive_inventory(**oldopts)
            ec390ep=derived['historical_independent_archive_epoch_reviews'][0]
            oldopts['historical_ec339_independent_signed_head_inventory_shas']=[
                ec390ep['independent_signed_head_inventory_sha256']]
            oldopts['historical_ec339_independent_signed_receipt_inventory_shas']=[
                ec390ep['independent_signed_receipt_inventory_sha256']]
            oldopts['expected_retained_historical_ec339_independent_archive_inventory_sha256']=(
                derived['receiver_verified_independent_archive_inventory_sha256'])
            real390=prev.audit(**oldopts)
        if missing:
            entry={'tsa_channel_id':self.channel['tsa_channel_id'],
                'signed_prior_offsite_head_original':None,'rfc3161_timestamp_original':None,
                'tsa_authority_id':None}
        else:
            entry=self.current_entry
        if include_token and not missing:
            entry,registry,registryref=self.real_token(entry,with_crl=crl)
        else:
            _,registry,registryref=self.real_token(entry=self.current_entry,with_crl=crl)
        parenthash=core.sha(canonical.canonical(real390))
        archive={'schema':core.BUNDLE_SCHEMA,
            'parent_ec390_independent_archive_original_sha256':oldopts[prev.NEW_SCALARS[1]],
            'parent_ec390_canonical_result_sha256':parenthash,
            'claimed_directory_lineage_id':'Lineage388',
            'offsite_log_keeper_roster_original':self.keeper_ref,
            'tsa_trust_registry_original':registryref,
            'epochs':[{'epoch_index':0,'channels':[entry]}]}
        ref=self._archive('ec391-archive-'+self._testMethodName+'.json',archive)
        opts=dict(oldopts)
        opts.update({core.NEW_SCALARS[0]:ref['path'],core.NEW_SCALARS[1]:ref['sha256'],
                     core.NEW_SCALARS[2]:self.keeper_ref['sha256'],
                     core.NEW_SCALARS[3]:registryref['sha256'],
                     core.NEW_SCALARS[4]:(datetime.now(timezone.utc)+timedelta(minutes=2))
                         .strftime('%Y-%m-%dT%H:%M:%SZ'),
                     core.NEW_REPEATS[0][0]:['a2'*32],
                     core.NEW_REPEATS[1][0]:['a3'*32],
                     core.NEW_REPEATS[2][0]:[1 if include_token and not missing else 0]})
        return real390,opts

    def _outer_context(self,report):
        return (patch.object(core,'_inputs',return_value=({},datetime.now(timezone.utc)+timedelta(minutes=2))),
                patch.object(core.prior,'audit',return_value=report),
                patch.object(core.prior.oldsource,'_old_sender_labels'))

    def test_ec391_22_outer_live_ec390_mock_real_original_offsite_and_cms(self):
        actual,opts=self._outer_ec391()
        a,b,c=self._outer_context(actual)
        with a,b,c:result=core.derive_inventory(**opts)
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['cryptographically_verified_timestamped_prior_head_count'],1)
        self.assertTrue(result[core.FLAGS[1]])
        self.assertTrue(result[core.FLAGS[6]])
        self.assertTrue(result[core.FLAGS[8]] and result[core.FLAGS[9]])

    def test_ec391_23_outer_exact_pins_audit_remains_unresolved(self):
        actual,opts=self._outer_ec391()
        a,b,c=self._outer_context(actual)
        with a,b,c:derived=core.derive_inventory(**opts)
        row=derived['historical_prior_offsite_time_epoch_reviews'][0]
        opts[core.NEW_REPEATS[0][0]]=[row['prior_offsite_signed_head_inventory_sha256']]
        opts[core.NEW_REPEATS[1][0]]=[row['prior_rfc3161_token_inventory_sha256']]
        opts[core.AUDIT_ONLY[0]]=derived['receiver_verified_prior_offsite_time_inventory_sha256']
        with a,b,c:result=core.audit(**opts)
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['cryptographically_verified_timestamped_prior_head_count'],1)
        self.assertFalse(result[core.FLAGS[1]])
        self.assertNotIn('unsigned_prior_offsite_time_inventory',result)

    def test_ec391_24_outer_missing_offsite_signed_head_visible(self):
        actual,opts=self._outer_ec391(missing=True)
        a,b,c=self._outer_context(actual)
        with a,b,c:result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[2]])
        self.assertEqual(result['cryptographically_verified_timestamped_prior_head_count'],0)

    def test_ec391_25_outer_pinned_bundle_source_tamper_denied(self):
        actual,opts=self._outer_ec391()
        opts[core.NEW_SCALARS[1]]='22'*32
        a,b,c=self._outer_context(actual)
        with a,b,c:
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec391_26_outer_signer_roster_external_pin_replaced_denied(self):
        actual,opts=self._outer_ec391()
        opts[core.NEW_SCALARS[2]]='ef'*32
        a,b,c=self._outer_context(actual)
        with a,b,c:
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec391_27_outer_unsupported_extra_schema_fields_denied(self):
        actual,opts=self._outer_ec391()
        ref=opts[core.NEW_SCALARS[0]]
        doc=json.loads(Path(ref).read_text(encoding='utf-8'))
        doc['accept_global_fork_finality']=True
        copyref=self._archive('ec391-extra-'+self._testMethodName+'.json',doc)
        opts[core.NEW_SCALARS[0]]=copyref['path'];opts[core.NEW_SCALARS[1]]=copyref['sha256']
        a,b,c=self._outer_context(actual)
        with a,b,c:
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec391_28_standalone_and_unified_help_fixed_readonly(self):
        root=Path(__file__).resolve().parents[2]
        for name in ('ces_cas_historical_prior_offsite_time.py','ces_next.py'):
            cmd=['audit-historical-ec339-prior-offsite-time']
            result=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/name),
                                   *cmd,'--help'],capture_output=True,text=True,timeout=25)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('--historical-ec339-prior-rfc3161-token-inventory-sha256',result.stdout)
            self.assertNotIn('--private-key',result.stdout)


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(PriorTimeTests(name) for name in sorted(
        key for key in dir(PriorTimeTests) if key.startswith('test_ec391_')))

if __name__=='__main__':
    unittest.TextTestRunner(verbosity=2).run(load_tests(None,None,None))
