#!/usr/bin/env python3
"""EC352 synthetic Ed25519 root/event/rotation/revocation integration fixtures.

All alleged institutions, roots, signers, timestamps, OCSP/CMS and SHA pins
are minted in this one local process. Tests verify code, not external trust.
"""
from __future__ import annotations

from datetime import timedelta
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as reg
from tsa_provenance import test_provenance as fixture
from . import registry as core
from . import operator as cli

ROOT=Path(__file__).resolve().parents[2]


def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def ut(dt):return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
def pub(k):return k.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('OpenSSL test fixture tool unavailable')
        fixture.ProvenanceTests.setUpClass()
        cls.f=fixture.ProvenanceTests.f
        cls.root=fixture.ProvenanceTests.root

    @classmethod
    def tearDownClass(cls):
        fixture.ProvenanceTests.tearDownClass()

    def setUp(self):
        fixture.ProvenanceTests.setUp(self)
        self.registries={};self.reg_events=[]

    def make_root(self,identity='registry_a'):
        d=Path(self.w)
        key=ed25519.Ed25519PrivateKey.generate()
        p=d/f'ec352-{identity}-root.pub';p.write_bytes(pub(key))
        body={'schema':core.ROOT_SCHEMA,'registry_channel_id':identity,
              'root_public_key_original_sha256':digest(p),
              'claimed_issuer_organization':f'LOCAL FAKE {identity} NOT OFFICIAL',
              'claimed_issuer_document_uri':'https://invalid.example.test/synthetic',
              'valid_from_utc':ut(self.now-timedelta(days=1)),
              'valid_until_utc':ut(self.now+timedelta(days=2))}
        doc={**body,'self_signature_ed25519_hex':key.sign(
            core.ROOT_DOMAIN+reg.canonical(body)).hex()}
        ref=d/f'ec352-{identity}-root-reference.json';ref.write_bytes(reg.canonical(doc))
        opkey=ed25519.Ed25519PrivateKey.generate()
        op=d/f'ec352-{identity}-operator-1.pub';op.write_bytes(pub(opkey))
        self.registries[identity]={'root_private':key,'operator_private':opkey,
                                   'root_ref':str(ref),'root_file':str(p),
                                   'op_file':str(op),'head':None,'events':[]}
        return identity

    def make_entry(self,channel=0,**changes):
        stmt,stmtsha,key,keysha,source,sourcesha=self.auths[channel]
        claim=json.loads(Path(stmt).read_bytes())
        tok=self.tokens[channel]
        d={'tsa_channel_id':f'channel_{channel}',
           'source_attestation_original_sha256':stmtsha,
           'attester_public_key_original_sha256':keysha,
           'source_document_original_sha256':sourcesha,
           'tsa_root_original_sha256':tok[3],
           'tsa_root_der_sha256':claim['tsa_root_certificate_der_sha256'],
           'tsa_policy_oid':fixture.POLICY,'authorization':'authorized',
           'not_before_utc':ut(self.now-timedelta(minutes=20)),
           'not_after_utc':ut(self.now+timedelta(hours=3))}
        d.update(changes)
        return d

    def make_event(self,identity='registry_a',*,kind='activate',previous=None,
                   entries=None,wrong_root_sig=False,wrong_op_sig=False,
                   wrong_prev_sig=False,new_operator=None,issued_minutes=None,
                   tamper_body=None,expiry_minutes=None):
        r=self.registries[identity]
        if previous is None and kind!='activate':previous=r['head']
        predecessor=previous['body'] if previous else None
        seq=predecessor['sequence']+1 if predecessor else 1
        if new_operator is not None:
            opkey=new_operator
            opfile=Path(self.w)/f'ec352-{identity}-operator-{len(r["events"])+2}.pub'
            opfile.write_bytes(pub(opkey))
        else:opkey,opfile=r['operator_private'],Path(r['op_file'])
        ref=Path(r['root_ref']);rootfile=Path(r['root_file'])
        body={'schema':core.EVENT_SCHEMA,'registry_channel_id':identity,
              'sequence':seq,'previous_event_sha256':previous['sha'] if previous else core.GENESIS,
              'event_kind':kind,'root_reference_original_sha256':digest(ref),
              'root_public_key_original_sha256':digest(rootfile),
              'signer_public_key_original_sha256':digest(opfile),
              'issued_utc':ut(self.now-timedelta(minutes=10-seq if issued_minutes is None
                                                else issued_minutes)),
              'valid_until_utc':ut(self.now+timedelta(
                  minutes=expiry_minutes) if expiry_minutes is not None else
                  self.now+timedelta(hours=2)),
              'entries':[] if kind=='revoke' else (entries if entries is not None
                                                   else [self.make_entry()])}
        if tamper_body:body.update(tamper_body)
        rootsig=r['root_private'].sign(core.EVENT_DOMAIN+reg.canonical(body))
        cursig=opkey.sign(core.OPERATOR_DOMAIN+reg.canonical(body)) if kind!='revoke' else None
        prevsig=(r['operator_private'].sign(core.PRIOR_DOMAIN+reg.canonical(body))
                 if kind=='rotate' else None)
        if wrong_root_sig:rootsig=bytes([rootsig[0]^1])+rootsig[1:]
        if wrong_op_sig and cursig:cursig=bytes([cursig[0]^1])+cursig[1:]
        if wrong_prev_sig and prevsig:prevsig=bytes([prevsig[0]^1])+prevsig[1:]
        doc={**body,'root_signature_ed25519_hex':rootsig.hex(),
             'previous_signer_signature_ed25519_hex':prevsig.hex() if prevsig else 'NONE',
             'current_signer_signature_ed25519_hex':cursig.hex() if cursig else 'NONE'}
        file=Path(self.w)/f'ec352-{identity}-event-{len(r["events"])+1}.json'
        file.write_bytes(reg.canonical(doc))
        item={'id':identity,'sha':digest(file),'file':str(file),
              'signer_file':str(opfile),'body':body}
        self.reg_events.append(item);r['events'].append(item);r['head']=item
        if kind=='rotate':r['operator_private'],r['op_file']=opkey,str(opfile)
        return item

    def prepare(self,*,two_tokens=False):
        targets=(0,1) if two_tokens else (0,)
        for ch in targets:
            self.make_token(ch);self.make_authority(ch);self.make_ocsp(ch)

    def args352(self,**overrides):
        base=self.args()
        roots=sorted(self.registries)
        base.update(registry_evaluation_utc=ut(self.now+timedelta(minutes=4)),
            registry_channel_ids=roots,
            registry_root_reference_files=[self.registries[i]['root_ref'] for i in roots],
            registry_root_reference_shas=[digest(self.registries[i]['root_ref']) for i in roots],
            registry_root_key_files=[self.registries[i]['root_file'] for i in roots],
            registry_root_key_shas=[digest(self.registries[i]['root_file']) for i in roots],
            registry_event_channel_ids=[e['id'] for e in self.reg_events],
            registry_event_files=[e['file'] for e in self.reg_events],
            registry_event_shas=[e['sha'] for e in self.reg_events],
            registry_signer_key_files=[e['signer_file'] for e in self.reg_events],
            registry_signer_key_shas=[digest(e['signer_file']) for e in self.reg_events])
        base.update(overrides)
        return base

    def two_active(self):
        for id in ('registry_a','registry_b'):
            self.make_root(id)
            self.make_event(id)

    def denied(self,fragment,**overrides):
        with self.assertRaises(errors.AnchorError) as e:
            core.audit(**self.args352(**overrides))
        self.assertIn(fragment,e.exception.code)

    def test_01_real_dual_ed25519_registry_claims_no_official_authority(self):
        self.prepare();self.two_active()
        r=core.audit(**self.args352())
        row=r['channel_evidence'][0]
        self.assertEqual(row['outcome'],core.OUTCOMES[6])
        self.assertEqual([o['key_binding_status'] for o in row['registries']],
                         ['authorized_claim_exact_binding']*2)
        self.assertTrue(r['ec351_to_ec337_actual_signed_originals_replayed'])
        self.assertFalse(r['caller_selected_registry_root_key_proves_official_institution_identity'])
        self.assertFalse(r['two_registry_files_or_names_prove_two_external_institutions'])
        self.assertEqual(r['exit_code'],2)

    def test_02_absent_two_independent_registries_unresolved(self):
        self.prepare()
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_03_one_registry_is_not_two_and_does_not_pass(self):
        self.prepare();self.make_root();self.make_event()
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_04_two_root_refs_but_missing_history_is_visible(self):
        self.prepare();self.make_root('registry_a');self.make_root('registry_b')
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_05_tampered_root_self_signature_rejected(self):
        self.prepare();self.two_active()
        ref=Path(self.registries['registry_a']['root_ref']);doc=json.loads(ref.read_bytes())
        doc['self_signature_ed25519_hex']='11'*64;ref.write_bytes(reg.canonical(doc))
        self.denied('ROOT_SELF_SIGNATURE_INVALID')

    def test_06_bad_new_operator_event_signature_rejected(self):
        self.prepare();self.make_root();self.make_event(wrong_op_sig=True)
        self.denied('EVENT_OPERATOR_SIGNATURE_INVALID')

    def test_07_bad_root_event_signature_rejected(self):
        self.prepare();self.make_root();self.make_event(wrong_root_sig=True)
        self.denied('EVENT_ROOT_SIGNATURE_INVALID')

    def test_08_key_rotation_requires_true_prior_and_new_signatures(self):
        self.prepare();self.two_active()
        self.make_event('registry_a',kind='rotate',
                        new_operator=ed25519.Ed25519PrivateKey.generate())
        self.make_event('registry_b',kind='renew')
        r=core.audit(**self.args352())
        obs=r['channel_evidence'][0]['registries'][0]
        self.assertEqual(obs['latest_event_kind'],'rotate')
        self.assertEqual(len(obs['event_history_original_shas']),2)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[6])

    def test_09_rotation_fake_previous_signer_rejected(self):
        self.prepare();self.make_root();self.make_event()
        self.make_event(kind='rotate',new_operator=ed25519.Ed25519PrivateKey.generate(),
                        wrong_prev_sig=True)
        self.denied('ROTATION_PREVIOUS_SIGNER_SIGNATURE_INVALID')

    def test_10_renewal_cannot_change_operational_key_without_rotation(self):
        self.prepare();self.make_root();self.make_event()
        self.make_event(kind='renew',new_operator=ed25519.Ed25519PrivateKey.generate())
        self.denied('NONROTATION_MUST_KEEP_SIGNER_KEY')

    def test_11_signed_fork_two_valid_siblings_no_winner(self):
        self.prepare();self.two_active()
        prior=self.registries['registry_a']['head']
        self.make_event('registry_a',kind='renew',previous=prior,
                        issued_minutes=7)
        self.make_event('registry_a',kind='renew',previous=prior,
                        issued_minutes=6)
        r=core.audit(**self.args352())
        obs=r['channel_evidence'][0]['registries'][0]
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        self.assertEqual(obs['key_binding_status'],'fork_no_winner')
        self.assertEqual(len(obs['furnished_terminal_event_original_shas']),2)

    def test_12_presented_event_with_missing_predecessor_refused(self):
        self.prepare();self.make_root();base=self.make_event()
        other=self.make_event(kind='renew',previous=base)
        arg=self.args352()
        for key in ('registry_event_channel_ids','registry_event_files',
                    'registry_event_shas','registry_signer_key_files',
                    'registry_signer_key_shas'):
            arg[key]=arg[key][1:]
        with self.assertRaises(errors.AnchorError) as cm:core.audit(**arg)
        self.assertIn('PREDECESSOR_NOT_PRESENTED',cm.exception.code)

    def test_13_signed_attester_revocation_does_not_get_promoted(self):
        self.prepare();self.two_active()
        self.make_event(kind='renew',entries=[self.make_entry(authorization='revoked')])
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])
        self.assertEqual(r['channel_evidence'][0]['registries'][0]['key_binding_status'],
                         'attester_key_revoked_in_signed_history')

    def test_14_signed_revoked_attester_cannot_be_silently_reauthorized(self):
        self.prepare();self.make_root();self.make_event()
        self.make_event(kind='renew',entries=[self.make_entry(authorization='revoked')])
        self.make_event(kind='renew',entries=[self.make_entry()])
        self.denied('REVOKED_ATTESTER_REAUTHORIZATION_FORBIDDEN')

    def test_15_emergency_root_signed_operator_revocation_terminal(self):
        self.prepare();self.two_active();self.make_event(kind='revoke')
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])
        self.assertEqual(r['channel_evidence'][0]['registries'][0]['key_binding_status'],
                         'registry_signer_revoked')

    def test_16_missing_current_snapshot_record_cannot_inherit_a_prior_grant(self):
        self.prepare();self.two_active()
        # Re-authorize both channels, but every activation is too late to prove
        # that the EC351 statement issuer possessed this role *at signing*.
        for id in ('registry_a','registry_b'):
            # A genuine signed renewal that omits the attester key must not
            # silently inherit the previous authorization.
            self.make_event(id,kind='renew',entries=[])
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertEqual(r['channel_evidence'][0]['registries'][0]['key_binding_status'],
                         'missing_attester_record')

    def test_16b_registry_history_gap_not_promoted(self):
        self.prepare()
        self.make_root('registry_a');self.make_root('registry_b')
        self.make_event('registry_a',issued_minutes=60,expiry_minutes=-20)
        self.make_event('registry_b')
        self.make_event('registry_a',kind='renew')
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertEqual(r['channel_evidence'][0]['registries'][0]['key_binding_status'],
                         'signed_registry_history_freshness_gap')

    def test_16c_registration_issued_after_statement_is_retrospective_only(self):
        self.prepare()
        for id in ('registry_a','registry_b'):
            self.make_root(id);self.make_event(id,issued_minutes=-1)
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])
        self.assertEqual(r['channel_evidence'][0]['registries'][0]['key_binding_status'],
                         'retroactive_registry_claim_only')

    def test_16d_fake_signature_amid_valid_signed_fork_cannot_hide(self):
        self.prepare();self.two_active()
        previous=self.registries['registry_a']['head']
        self.make_event('registry_a',kind='renew',previous=previous,
                        issued_minutes=7)
        self.make_event('registry_a',kind='renew',previous=previous,
                        issued_minutes=6,wrong_op_sig=True)
        self.denied('EVENT_OPERATOR_SIGNATURE_INVALID')

    def test_16e_root_signed_revoke_cannot_have_later_valid_successor(self):
        self.prepare();self.make_root();self.make_event()
        self.make_event(kind='revoke')
        self.make_event(kind='renew')
        self.denied('REGISTRY_SEQUENCE_CAUSALITY_OR_REVOKED_SIGNER_INVALID')

    def test_16f_historical_attester_key_change_requires_signed_revocation(self):
        self.prepare();self.make_root('registry_a');self.make_root('registry_b')
        old_key='c'*64
        former=self.make_entry(attester_public_key_original_sha256=old_key)
        for id in ('registry_a','registry_b'):
            self.make_event(id,entries=[former])
            self.make_event(id,kind='renew',entries=[self.make_entry()])
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertEqual(r['channel_evidence'][0]['registries'][0]['key_binding_status'],
                         'former_attester_key_not_signed_revoked')

    def test_16g_signed_former_key_retirement_and_new_key_grant(self):
        self.prepare();self.make_root('registry_a');self.make_root('registry_b')
        old_key='c'*64
        former=self.make_entry(attester_public_key_original_sha256=old_key)
        for id in ('registry_a','registry_b'):
            self.make_event(id,entries=[former])
            self.make_event(id,kind='renew',entries=[self.make_entry(
                attester_public_key_original_sha256=old_key,
                authorization='revoked')])
            self.make_event(id,kind='renew',entries=[self.make_entry()])
        out=core.audit(**self.args352())
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[6])
        self.assertEqual(out['channel_evidence'][0]['registries'][0][
            'historical_other_attester_key_sha_claims'],[old_key])
        self.assertFalse(out['historical_registry_claims_prove_globally_complete_rotation_or_revocations'])

    def test_17_complete_bound_bytes_required_even_with_true_signature(self):
        self.prepare();self.two_active()
        bad=self.make_entry(source_document_original_sha256='f'*64)
        self.make_event(kind='renew',entries=[bad])
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        self.assertEqual(r['channel_evidence'][0]['registries'][0]['key_binding_status'],
                         'contradictory_signed_binding')

    def test_18_original_sha_file_modified_rejected(self):
        self.prepare();self.two_active()
        p=Path(self.registries['registry_a']['events'][0]['file'])
        old=self.args352();p.write_bytes(p.read_bytes()+b'\n')
        self.denied('WHOLE_ORIGINAL_SHA_MISMATCH_REGISTRY_SIGNED_EVENT',
                    **{k:old[k] for k in ('registry_event_shas',)})

    def test_19_ec351_stale_or_missing_ocsp_parent_cannot_be_repaired(self):
        self.make_token();self.make_authority()
        self.two_active()
        r=core.audit(**self.args352())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[0])
        self.assertEqual(r['channel_evidence'][0]['parent_ec351_outcome'],
                         'ec351_ocsp_missing_stale_or_ambiguous_unresolved')

    def test_20_distinct_root_signers_required(self):
        self.prepare();self.two_active()
        r=self.registries['registry_a'];r2=self.registries['registry_b']
        args=self.args352()
        args['registry_root_key_files'][1]=args['registry_root_key_files'][0]
        args['registry_root_key_shas'][1]=args['registry_root_key_shas'][0]
        # Even before parsing the second self-signed document, the SHA binding
        # to an independent root will be checked and denied.
        with self.assertRaises(errors.AnchorError):core.audit(**args)

    def test_21_fixed_isolated_standalone_and_unified_readonly_execution(self):
        self.prepare();self.two_active();values=self.args352()
        from scripts import ces_next
        command=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_attester_registry.py'),
                 'audit-registry-history']
        for k in ces_next.EC352_KEYS:
            command.extend(['--'+k.replace('_','-'),str(values[k])])
        for k,flag in ces_next.EC352_REPEATS:
            for x in values[k]:command.extend([flag,str(x)])
        child=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=360)
        self.assertEqual(child.returncode,2,child.stdout+child.stderr)
        result=json.loads(child.stdout)
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[6])
        outer=[sys.executable,'-B',str(ROOT/'scripts'/'ces_next.py'),
               'audit-attester-key-registries','DeliveryAudit',
               'AuditOfflineAttesterKeyRegistryHistory',*command[5:]]
        unified=subprocess.run(outer,cwd=ROOT,capture_output=True,text=True,timeout=360)
        self.assertEqual(unified.returncode,2,unified.stdout+unified.stderr)
        self.assertEqual(json.loads(unified.stdout)['registry_signed_event_original_count'],2)
        outer[4]='IssueNewKeys'
        denied=subprocess.run(outer,cwd=ROOT,capture_output=True,text=True,timeout=360)
        self.assertEqual(denied.returncode,3,denied.stdout+denied.stderr)
        options={v for a in ces_next.build_parser()._subparsers._group_actions[0]
                 .choices['audit-attester-key-registries']._actions
                 for v in a.option_strings}
        for x in ('--private-key-file','--sign','--output','--network',
                  '--remote-provider-write'):
            self.assertNotIn(x,options)

    def test_22_unsigned_handoff_really_replays_parent(self):
        self.prepare()
        out=core.checklist(**self.args())
        self.assertEqual(out['command'],'derive-registry-handoff')
        self.assertEqual(out['exit_code'],2)
        self.assertEqual(out['source_statement_key_and_policy_bindings'][0][
            'attester_key_sha256'],self.auths[0][3])




# Reuse the rich, *actual* EC351 -> EC337 fixture builder without inheriting
# its 24 tests into this focused suite.
for method in ('make_token','make_authority','make_ocsp','args',
               'capture_both','dual_arguments','make_channel_directory',
               'sign_anchor','sign_time','configure','sign','parameters','audit',
               'copies','observation','show','challenge','response','kw','nonce_sha',
               'issue','reply','params','write','sign_document','make_directory',
               'record','options','present','arguments','actor'):
    setattr(RegistryTests,method,getattr(fixture.ProvenanceTests,method))

if __name__=='__main__':unittest.main()
