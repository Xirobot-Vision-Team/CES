#!/usr/bin/env python3
"""EC379 focused REAL Ed25519 EC351 originals, signed EC352 registry binding,
real X509 TSA root DER, and formerly signed EC353 two-log Merkle fixture.
Inherited EC366->EC337 deep parent fixture is MOCKED, not legal authority.
"""
from __future__ import annotations
import copy
from datetime import datetime,timezone
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,rsa
from cryptography.x509.oid import NameOID
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as old350
from tsa_provenance import provenance as old351
from key_registry import registry as old352
from transparency import transparency as old353
from transparency import test_transparency as merkle
from witness_distribution import test_distribution as util
from historical_transparency import test_transparency_archive as old_fixture
from historical_registry import test_registry_archive as fx378
from . import source_archive as core

ROOT=Path(__file__).resolve().parents[2]
ORIGINAL_EC377_UPGRADE=fx378.ORIGINAL_EC377_UPGRADE

def genuine_source_origins(fx):
    """Inject unchanged genuine EC352 Ed25519 originals *before* old EC353
    checkpoint/gossip/receipt/EC356 ACK signing, never after. This preserves
    actual signed parent SHA/copy causality through all newer parent layers.
    """
    save=fx.store
    def intercept(name,obj):
        if name=='ec377_original_old_ec353_unsigned_publication_bundle':
            keys=[];origins=[];registries=[]
            sources=[];entries=[]
            # REAL Ed25519 EC351 statements, real source document bytes and
            # real self-signed X509 TSA root DER.  These are LOCAL FIXTURES,
            # not an external qualified issuer or trusted clock.
            for idx,channel in enumerate(('HistoricTsaChannelA','HistoricTsaChannelB')):
                priv=ed25519.Ed25519PrivateKey.generate()
                attpub=save('ec379_actual_old_ec351_attester_key_'+channel,util.pub(priv))
                src=save('ec379_actual_old_ec351_policy_source_'+channel,
                         ('Original policy document for '+channel).encode())
                ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
                nm=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                               'Historical Root Test '+str(idx))])
                cert=(x509.CertificateBuilder().subject_name(nm).issuer_name(nm)
                  .public_key(ca_key.public_key()).serial_number(1010+idx)
                  .not_valid_before(datetime(2026,10,25,tzinfo=timezone.utc))
                  .not_valid_after(datetime(2026,11,1,tzinfo=timezone.utc))
                  .add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True)
                  .add_extension(x509.KeyUsage(digital_signature=False,
                     content_commitment=False,key_encipherment=False,data_encipherment=False,
                     key_agreement=False,key_cert_sign=True,crl_sign=True,
                     encipher_only=False,decipher_only=False),critical=True)
                  .sign(ca_key,hashes.SHA256()))
                root=save('ec379_actual_old_ec351_tsa_root_der_'+channel,
                          cert.public_bytes(serialization.Encoding.DER))
                body={'schema':old351.ATTESTATION_SCHEMA,'channel_id':channel,
                  'tsa_root_original_sha256':root['sha256'],
                  'tsa_root_certificate_der_sha256':root['sha256'],
                  'tsa_policy_oid':'1.2.3.4.100'+str(idx),
                  'source_document_original_sha256':src['sha256'],
                  'attester_public_key_original_sha256':attpub['sha256'],
                  'claimed_source_organization':'Historic Claimed TSA '+str(idx),
                  'claimed_source_uri':'https://tsa'+str(idx)+'.example.invalid/policy',
                  'issued_utc':util.UTC,'expires_utc':util.EXP}
                att=save('ec379_actual_old_ec351_source_attestation_'+channel,{
                    **body,'signature_ed25519_hex':priv.sign(
                         old351.DOMAIN+canonical.canonical(body)).hex()})
                sources.append({'tsa_channel_id':channel,
                    'source_attestation_original':att,
                    'attester_public_key_original':attpub,
                    'policy_source_document_original':src,
                    'tsa_root_certificate_original':root})
                entries.append({'tsa_channel_id':channel,
                    'source_attestation_original_sha256':att['sha256'],
                    'attester_public_key_original_sha256':attpub['sha256'],
                    'source_document_original_sha256':src['sha256'],
                    'tsa_root_original_sha256':root['sha256'],
                    'tsa_root_der_sha256':root['sha256'],
                    'tsa_policy_oid':body['tsa_policy_oid'],
                    'authorization':'authorized',
                    'not_before_utc':util.UTC,'not_after_utc':util.EXP})
            for i,ch in enumerate(('HistoricRegistryA','HistoricRegistryB')):
                rootpriv=ed25519.Ed25519PrivateKey.generate()
                signerpriv=ed25519.Ed25519PrivateKey.generate()
                rootkey=save('ec378_real_old_ec352_root_key_'+ch,util.pub(rootpriv))
                signerkey=save('ec378_real_old_ec352_operator_key_'+ch,util.pub(signerpriv))
                body={'schema':old352.ROOT_SCHEMA,'registry_channel_id':ch,
                  'root_public_key_original_sha256':rootkey['sha256'],
                  'claimed_issuer_organization':'Historical Issuer '+str(i),
                  'claimed_issuer_document_uri':'https://issuer'+str(i)+'.example.invalid/',
                  'valid_from_utc':util.UTC,'valid_until_utc':util.EXP}
                rootref=save('ec378_original_old_ec352_signed_root_ref_'+ch,{
                    **body,'self_signature_ed25519_hex':rootpriv.sign(
                        old352.ROOT_DOMAIN+canonical.canonical(body)).hex()})
                eventbody={'schema':old352.EVENT_SCHEMA,
                    'registry_channel_id':ch,'sequence':1,
                    'previous_event_sha256':old352.GENESIS,
                    'event_kind':'activate',
                    'root_reference_original_sha256':rootref['sha256'],
                    'root_public_key_original_sha256':rootkey['sha256'],
                    'signer_public_key_original_sha256':signerkey['sha256'],
                    'issued_utc':util.UTC,'valid_until_utc':util.EXP,
                    'entries':entries}
                event=save('ec378_original_old_ec352_signed_event_'+ch,{
                    **eventbody,'root_signature_ed25519_hex':rootpriv.sign(
                        old352.EVENT_DOMAIN+canonical.canonical(eventbody)).hex(),
                    'previous_signer_signature_ed25519_hex':old352.NONE,
                    'current_signer_signature_ed25519_hex':signerpriv.sign(
                        old352.OPERATOR_DOMAIN+canonical.canonical(eventbody)).hex()})
                keys.append((rootpriv,signerpriv))
                registries.append({'registry_channel_id':ch,
                    'root_public_key_original':rootkey,
                    'root_reference_original':rootref,
                    'events':[{'signed_event_original':event,
                               'signer_public_key_original':signerkey}]})
                origins.extend([('registry_root_reference',rootref),
                                ('registry_event',event)])
            fx.ec378_registries=registries
            fx.ec379_sources=sources
            fx.ec378_private=keys
            leaves=[Path(ref['path']).read_bytes() for _,ref in origins]
            for index,(oldlog,received) in enumerate(zip(fx.logs,fx.pub_receiver_logs)):
                logid=oldlog['log_id'];logpriv,witpriv=fx.new_log_private[logid]
                logref=received['log_reference_original']
                witref=received['witness_reference_original']
                body={'schema':old353.CHECKPOINT_SCHEMA,'log_id':logid,
                    'log_reference_original_sha256':logref['sha256'],
                    'previous_checkpoint_original_sha256':old353.GENESIS,
                    'tree_size':len(origins),
                    'root_hash_sha256':merkle.root(leaves).hex(),
                    'issued_utc':util.UTC}
                cp=save('ec378_ec353_real_signed_checkpoint_'+str(index),{
                   **body,'log_signature_ed25519_hex':logpriv.sign(
                         old353.CHECKPOINT_DOMAIN+canonical.canonical(body)).hex()})
                witbody={'schema':old353.WITNESS_SCHEMA,'log_id':logid,
                    'checkpoint_original_sha256':cp['sha256'],
                    'witness_reference_original_sha256':witref['sha256'],
                    'tree_size':len(origins),'root_hash_sha256':body['root_hash_sha256'],
                    'witnessed_utc':util.UTC}
                wit=save('ec378_ec353_real_signed_witness_'+str(index),{
                    **witbody,'witness_signature_ed25519_hex':witpriv.sign(
                        old353.WITNESS_DOMAIN+canonical.canonical(witbody)).hex()})
                oldlog['checkpoints']=[{'checkpoint':fx.old_label(cp),
                       'witness_statement':fx.old_label(wit),'consistency_proof':None}]
                received['checkpoints']=[{'signed_checkpoint_original':cp,
                       'signed_witness_original':wit,'consistency_original':None}]
                oldlog['inclusions']=[];received['inclusions']=[]
                for j,(kind,ref) in enumerate(origins):
                    proof=save('ec378_ec353_real_inclusion_'+str(index)+'_'+str(j),{
                      'schema':old353.INCLUSION_SCHEMA,'log_id':logid,
                      'checkpoint_original_sha256':cp['sha256'],
                      'artifact_kind':kind,'artifact_original_sha256':ref['sha256'],
                      'leaf_index':j,'audit_path_sha256_hex':[
                          h.hex() for h in merkle.inclusion(leaves,j)]})
                    oldlog['inclusions'].append(fx.old_label(proof))
                    received['inclusions'].append({'proof_original':proof,
                         'artifact_original':ref})
            obj={'schema':old353.BUNDLE_SCHEMA,'logs':fx.logs}
        return save(name,obj)
    sign=fx.sign
    def resized_sign(name,body,key,domain):
        if (name=='ec377_true_gossip_challenge' or
            name=='ec377_true_gossip_reply'):
            body={**body,'tree_size':4}
        elif name.startswith('ec377_reissued_true_ec355_request_'):
            body={**body,'claimed_tree_size':4}
        return sign(name,body,key,domain)
    fx.store=intercept
    fx.sign=resized_sign
    try:ORIGINAL_EC377_UPGRADE(fx)
    finally:
        fx.store=save
        fx.sign=sign


class AuthenticOldEc351SourceUnderRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fx378.OriginalEc352RegistryUnderEc353Tests.setUpClass()

    @classmethod
    def tearDownClass(cls):fx378.OriginalEc352RegistryUnderEc353Tests.tearDownClass()

    def setUp(self):
        self.fixture=fx378.OriginalEc352RegistryUnderEc353Tests(
            'test_01_true_signed_ec352_roots_and_event_originals_in_both_logs')
        with patch.object(fx378,'genuine_registry_origins',genuine_source_origins):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.sources=copy.deepcopy(self.fixture.fx.prev.ec379_sources)
        self.parent=self.fixture.audit()  # EC378 verifies real registry signs and Merkle
        self.assertTrue(self.parent[
            'local_signed_ec352_registry_signatures_and_dual_log_links_consistent'])
        self.epochs=[{'epoch_index':i,'sources':copy.deepcopy(self.sources)} for i in range(2)]
        self.rebuild()

    def store(self,name,obj):return self.fixture.fx.store(name,obj)

    def rebuild(self):
        self.archive=self.store('ec379_signed_source_receiver_bundle',{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec378_canonical_result_sha256':core.sha(canonical.canonical(self.parent)),
          'ec378_historical_registry_archive_original_sha256':self.fixture.archive['sha256'],
          'claimed_directory_lineage_id':self.fixture.fx.prev.fx.old.ec373.old.lineage,
          'epochs':self.epochs})

    def hashes(self,epoch):
        keyrows=[];bindrows=[]
        for source in epoch['sources']:
            doc=json.loads(Path(source['source_attestation_original']['path']).read_text())
            binding={'source_attestation_original_sha256':source['source_attestation_original']['sha256'],
              'attester_public_key_original_sha256':source['attester_public_key_original']['sha256'],
              'source_document_original_sha256':source['policy_source_document_original']['sha256'],
              'tsa_root_original_sha256':source['tsa_root_certificate_original']['sha256'],
              'tsa_root_der_sha256':source['tsa_root_certificate_original']['sha256'],
              'tsa_policy_oid':doc['tsa_policy_oid']}
            keyrows.append({'tsa_channel_id':source['tsa_channel_id'],**binding})
            bindrows.append({'tsa_channel_id':source['tsa_channel_id'],
              'signed_attestation_original_sha256':source['source_attestation_original']['sha256'],
              'signed_registry_statuses':[{'registry_channel_id':k,
                'real_signed_ec352_binding_status':'authorized_claim_exact_binding'}
                for k in ('HistoricRegistryA','HistoricRegistryB')]})
        return core.sha(canonical.canonical(keyrows)),core.sha(canonical.canonical(bindrows))

    def opts(self,**overrides):
        a=self.fixture.opts(expected_retained_historical_registry_inventory_sha256=
           self.fixture.derive()['receiver_verified_historical_registry_inventory_sha256'])
        pairs=[self.hashes(x) for x in self.epochs]
        a.update(historical_source_archive_bundle_file=self.archive['path'],
          expected_historical_source_archive_bundle_sha256=self.archive['sha256'],
          historical_source_attestation_inventory_shas=[x for x,_ in pairs],
          historical_source_registry_binding_inventory_shas=[x for _,x in pairs],
          minimum_historical_signed_source_counts=[2,2],
          minimum_historical_authorized_registry_match_counts=[4,4])
        a.update(overrides)
        return a

    def derive(self,**overrides):
        with patch.object(core.previous,'audit',return_value=self.parent):
            return core.derive_inventory(**self.opts(**overrides))

    def audit(self,**overrides):
        pin=self.derive()['receiver_verified_historical_source_inventory_sha256']
        opts=self.opts(expected_retained_historical_source_inventory_sha256=pin)
        opts.update(overrides)
        with patch.object(core.previous,'audit',return_value=self.parent):
            return core.audit(**opts)

    def argv(self,unified=False):
        from publication_accountability import accountability as p370
        from historical_archive import archive as p371
        from historical_authority import authority_archive as p372
        from historical_inclusion import inclusion_archive as p373
        from historical_owner import owner_archive as p374
        from historical_custody import custody_archive as p375
        from historical_disclosure import disclosure_archive as p376
        from historical_transparency import transparency_archive as p377
        from historical_registry import registry_archive as p378
        opts=self.opts(expected_retained_historical_source_inventory_sha256=
                       self.derive()['receiver_verified_historical_source_inventory_sha256'])
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,*p371.NEW_SCALARS,
            *p371.AUDIT_ONLY,*p372.NEW_SCALARS,*p372.AUDIT_ONLY,
            *p373.NEW_SCALARS,*p373.AUDIT_ONLY,*p374.NEW_SCALARS,*p374.AUDIT_ONLY,
            *p375.NEW_SCALARS,*p375.AUDIT_ONLY,*p376.NEW_SCALARS,*p376.AUDIT_ONLY,
            *p377.NEW_SCALARS,*p377.AUDIT_ONLY,*p378.NEW_SCALARS,*p378.AUDIT_ONLY,
            *core.NEW_SCALARS,*core.AUDIT_ONLY)
        repeats=(*p370.prior.REPEATS,*p370.NEW_REPEATS,*p371.NEW_REPEATS,
            *p372.NEW_REPEATS,*p373.NEW_REPEATS,*p374.NEW_REPEATS,
            *p375.NEW_REPEATS,*p376.NEW_REPEATS,*p377.NEW_REPEATS,
            *p378.NEW_REPEATS,*core.NEW_REPEATS)
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/('ces_next.py' if unified
                 else 'ces_cas_historical_source_archive.py')),
                 'audit-historical-source-archive']
        if unified:cmd+=['DeliveryAudit','AuditHistoricalSourceArchive']
        for k in scalars:cmd+=['--'+k.replace('_','-'),str(opts[k])]
        for k,flag in repeats:
            for v in opts[k]:cmd.extend((flag,'none' if v is None else str(v)))
        return cmd

    def test_01_true_ec351_signer_source_root_der_under_both_registries(self):
        r=self.audit()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['verified_old_ec351_signed_source_statement_count'],4)
        self.assertEqual(r['verified_old_ec351_signed_registry_authorization_match_count'],8)
        self.assertEqual(r['missing_old_ec351_channel_source_original_count'],0)
        self.assertTrue(r['local_pinned_ec351_source_signatures_and_old_registry_binding_consistent'])
        self.assertTrue(r[core.FLAGS[-1]])
        self.assertTrue(r[core.FLAGS[-2]])
        self.assertFalse(r['complete_old_ec350_through_ec337_canonical_parent_replay_performed'])
        self.assertFalse(r['real_rfc3161_tstinfo_signed_token_and_ec349_receipt_replayed'])

    def test_02_verified_original_inventory_proves_sha_not_official_identity(self):
        d=self.derive()
        self.assertEqual(d['unsigned_verified_historical_source_inventory']['schema'],core.INVENTORY_SCHEMA)
        self.assertFalse(d['caller_external_inventory_pin_created_or_certified'])
        self.assertTrue(all(x['original_ec351_ed25519_source_attestation_verified']
          for e in d['unsigned_verified_historical_source_inventory'][
             'historical_old_ec351_signed_source_epoch_rows']
          for x in e['signed_ec351_source_originals']))
        self.assertFalse(d['attester_public_key_proves_official_issuer_or_independent_institution'])

    def test_03_actual_attestation_forged_signature_with_matching_sha_denied(self):
        d=json.loads(Path(self.sources[0]['source_attestation_original']['path']).read_text())
        d['signature_ed25519_hex']='f'*128
        self.epochs[0]['sources'][0]['source_attestation_original']=self.store('forged_ec351',d)
        self.rebuild()
        with self.assertRaises(errors.AnchorError) as e:self.derive()
        self.assertIn('SIGNATURE_INVALID',e.exception.code)

    def test_04_actual_policy_source_byte_mutation_denied(self):
        p=Path(self.sources[0]['policy_source_document_original']['path'])
        p.write_bytes(b'MUTATED_NON_ORIGINAL_POLICY')
        with self.assertRaises(errors.AnchorError) as e:self.derive()
        self.assertIn('SHA',e.exception.code)

    def test_05_original_tsa_root_cert_der_byte_mutation_denied(self):
        Path(self.sources[0]['tsa_root_certificate_original']['path']).write_bytes(b'WRONG')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_sha_consistent_different_tsa_root_denied_by_signed_ec351(self):
        b=self.store('wrong_root',Path(self.sources[1]['tsa_root_certificate_original']['path']).read_bytes())
        self.epochs[0]['sources'][0]['tsa_root_certificate_original']=b
        self.rebuild()
        with self.assertRaises(errors.AnchorError) as e:self.derive()
        self.assertIn('SOURCE_ROOT_DER_POLICY',e.exception.code)

    def test_07_actual_ec351_signed_attester_key_substitution_denied(self):
        self.epochs[0]['sources'][0]['attester_public_key_original']=self.sources[1][
            'attester_public_key_original']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_08_exact_signed_ec351_source_document_sha_mismatch_denied(self):
        self.epochs[0]['sources'][0]['policy_source_document_original']=self.sources[1][
            'policy_source_document_original']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_09_missing_original_source_is_explicit_unresolved(self):
        for e in self.epochs:e['sources'].pop()
        self.rebuild()
        r=self.audit()
        self.assertTrue(r[core.FLAGS[2]])
        self.assertEqual(r['missing_old_ec351_channel_source_original_count'],2)
        self.assertFalse(r['local_pinned_ec351_source_signatures_and_old_registry_binding_consistent'])

    def test_10_missing_all_sources_does_not_forge_signed_authority(self):
        for e in self.epochs:e['sources']=[]
        self.rebuild()
        r=self.audit()
        self.assertEqual(r['verified_old_ec351_signed_source_statement_count'],0)
        self.assertTrue(r[core.FLAGS[2]])
        self.assertEqual(r['missing_old_ec351_channel_source_original_count'],4)

    def test_11_independent_source_inventory_pin_mismatch_is_adverse(self):
        r=self.audit(historical_source_attestation_inventory_shas=['f'*64]*2)
        self.assertTrue(r[core.FLAGS[1]])

    def test_12_outside_authorization_binding_inventory_pin_mismatch(self):
        r=self.audit(historical_source_registry_binding_inventory_shas=['f'*64]*2)
        self.assertTrue(r[core.FLAGS[1]])

    def test_13_source_count_floor_mismatch_is_adverse(self):
        r=self.audit(minimum_historical_signed_source_counts=[3,3])
        self.assertTrue(r[core.FLAGS[1]])

    def test_14_signed_registry_count_floor_mismatch_adverse(self):
        r=self.audit(minimum_historical_authorized_registry_match_counts=[8,8])
        self.assertTrue(r[core.FLAGS[1]])

    def test_15_retained_unsigned_inventory_mismatch_adverse(self):
        r=self.audit(expected_retained_historical_source_inventory_sha256='f'*64)
        self.assertTrue(r[core.FLAGS[1]])

    def test_16_source_cannot_alias_signed_ec352_registry_key_role(self):
        self.epochs[0]['sources'][0]['attester_public_key_original']=self.fixture.registries[0][
            'root_public_key_original']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_17_new_receiver_source_cannot_alias_parent_file(self):
        self.epochs[0]['sources'][0]['policy_source_document_original']={
            'path':self.fixture.archive['path'],'sha256':self.fixture.archive['sha256']}
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_18_legacy_unsigned_sender_path_is_not_read(self):
        p=self.fixture.fx.prev.logs[0]['log_reference']['path']
        self.assertFalse(Path(p).exists())
        self.assertFalse(self.derive()['sender_origin_path_required_or_read'])

    def test_19_sender_path_collision_denied_before_io(self):
        self.epochs[0]['sources'][0]['policy_source_document_original']={
            'path':self.fixture.fx.prev.logs[0]['log_reference']['path'],
            'sha256':self.sources[0]['policy_source_document_original']['sha256']}
        self.rebuild()
        with self.assertRaises(errors.AnchorError) as e:self.derive()
        self.assertIn('SENDER',e.exception.code)

    def test_20_signed_source_channel_cannot_be_renamed(self):
        self.epochs[0]['sources'][0]['tsa_channel_id']='PretendIndependentSource'
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_21_source_original_type_and_unknown_fields_denied(self):
        self.epochs[0]['sources'][0]['injected_external_path']='/tmp/sender'
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_22_caller_authored_parent_result_cannot_substitute(self):
        with patch.object(core.previous,'audit',return_value={'status':'PASS','exit_code':0}):
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**self.opts())

    def test_23_fixed_router_accepts_exact_lawful_unresolved(self):
        from scripts import ces_next
        good=self.audit()
        opts=self.opts(expected_retained_historical_source_inventory_sha256=
                      self.derive()['receiver_verified_historical_source_inventory_sha256'])
        with patch.object(ces_next,'_command',return_value=(2,good)),redirect_stdout(io.StringIO()) as out:
            rc=ces_next.audit_historical_source_archive(
                'DeliveryAudit','AuditHistoricalSourceArchive',**opts)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(out.getvalue())['schema'],core.RESULT_SCHEMA)

    def test_24_router_rejects_fake_success_exit_zero(self):
        from scripts import ces_next
        opts=self.opts(expected_retained_historical_source_inventory_sha256='a'*64)
        with patch.object(ces_next,'_command',return_value=(0,{'exit_code':0})):
            with self.assertRaises(Exception):ces_next.audit_historical_source_archive(
                'DeliveryAudit','AuditHistoricalSourceArchive',**opts)

    def test_25_router_rejects_forged_source_count(self):
        from scripts import ces_next
        opts=self.opts(expected_retained_historical_source_inventory_sha256=
                      self.derive()['receiver_verified_historical_source_inventory_sha256'])
        bad={**self.audit(),'verified_old_ec351_signed_source_statement_count':999}
        with patch.object(ces_next,'_command',return_value=(2,bad)):
            with self.assertRaises(Exception):ces_next.audit_historical_source_archive(
                'DeliveryAudit','AuditHistoricalSourceArchive',**opts)

    def test_26_router_action_is_fixed_readonly(self):
        from scripts import ces_next
        with self.assertRaises(Exception):ces_next.audit_historical_source_archive(
            'DeliverySend','Send',**self.opts(
                expected_retained_historical_source_inventory_sha256='a'*64))

    @unittest.skipUnless(os.getenv('CES_EC379_REAL_DEEP')=='1',
        'Deferred opt-in deep real EC378->EC369 isolated children; old EC366->337 mocked')
    def test_27_real_fixed_isolated_child_subprocess(self):
        for unified in (False,True):
            p=subprocess.run(self.argv(unified),capture_output=True,text=True,
                             cwd=ROOT,timeout=180)
            self.assertEqual(p.returncode,2,p.stderr+'\n'+p.stdout[-500:])
            d=json.loads(p.stdout)
            self.assertTrue(d['local_pinned_ec351_source_signatures_and_old_registry_binding_consistent'])

    @unittest.skipUnless(os.getenv('CES_EC379_REAL_DEEP')=='1',
        'Deferred opt-in mutated original fixed isolated child')
    def test_28_mutated_source_real_isolated_child_denied(self):
        Path(self.sources[0]['source_attestation_original']['path']).write_bytes(b'BAD')
        p=subprocess.run(self.argv(),capture_output=True,text=True,cwd=ROOT,timeout=180)
        self.assertIn(p.returncode,(3,4,5),p.stderr+'\n'+p.stdout[-500:])

if __name__=='__main__':unittest.main()
