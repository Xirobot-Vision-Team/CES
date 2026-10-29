#!/usr/bin/env python3
"""EC353 real signed Ed25519/RFC6962 tests; external actors all synthetic.

Underlying EC352 fixture actually replays EC351->EC337 RSA CMS / OCSP / CRL,
then genuinely signed EC352 registry originals. Log, witness and Merkle
originals are independently generated in this one local process only.
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

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec352_key_registry import test_registry as oldfixture
from ec351_tsa_provenance import test_provenance as deep_fixture
from . import transparency as core

ROOT=Path(__file__).resolve().parents[2]


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def ut(dt):return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
def pub(key):return key.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw)
def split(n):return 1<<(n.bit_length()-1) if n&(n-1) else n//2


def root(leaves):
    assert leaves
    if len(leaves)==1:return core.leaf_hash(leaves[0])
    k=split(len(leaves));return core.node_hash(root(leaves[:k]),root(leaves[k:]))


def inclusion(leaves,index):
    if len(leaves)==1:return []
    k=split(len(leaves))
    if index<k:return inclusion(leaves[:k],index)+[root(leaves[k:])]
    return inclusion(leaves[k:],index-k)+[root(leaves[:k])]


def consistency(leaves,size,complete=True):
    if len(leaves)==size:return [] if complete else [root(leaves)]
    k=split(len(leaves))
    if size<=k:return consistency(leaves[:k],size,complete)+[root(leaves[k:])]
    return consistency(leaves[k:],size-k,False)+[root(leaves[:k])]


class MerkleAlgorithmTests(unittest.TestCase):
    def test_all_indices_and_prefixes_up_to_48(self):
        for n in range(1,49):
            leaves=[f'domain-separated-original-{i}'.encode() for i in range(n)]
            for i in range(n):
                proof=inclusion(leaves,i)
                self.assertTrue(core.verify_inclusion(core.leaf_hash(leaves[i]),i,n,
                                                      root(leaves),proof))
                self.assertFalse(core.verify_inclusion(core.leaf_hash(leaves[i]),n,n,
                                                       root(leaves),proof))
            for m in range(1,n+1):
                proof=consistency(leaves,m)
                self.assertTrue(core.verify_consistency(m,n,root(leaves[:m]),
                                                        root(leaves),proof))
                if proof:
                    corrupt=[*proof];corrupt[-1]=b'\x44'*32
                    self.assertFalse(core.verify_consistency(m,n,root(leaves[:m]),
                                                             root(leaves),corrupt))

    def test_bad_or_extra_inclusion_nodes_not_accepted(self):
        raw=[b'a',b'b',b'c']
        p=inclusion(raw,1)
        self.assertFalse(core.verify_inclusion(core.leaf_hash(raw[1]),1,3,root(raw),p+[b'X'*32]))
        self.assertFalse(core.verify_inclusion(core.leaf_hash(raw[1]),1,3,root(raw),p[:-1]))
        self.assertFalse(core.verify_inclusion(core.leaf_hash(raw[1]),True,3,root(raw),p))
        self.assertFalse(core.verify_consistency(True,3,root(raw[:1]),root(raw),[]))


class TransparencyTests(oldfixture.RegistryTests):
    # Retain the complete deep fixture methods while not double-counting old
    # RegistryTests cases in the focused EC353 suite.
    for _old_name in dir(oldfixture.RegistryTests):
        if _old_name.startswith('test_'):
            locals()[_old_name]=None

    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('OpenSSL required to synthesize signed TSA evidence')
        oldfixture.RegistryTests.setUpClass()
        cls.f=oldfixture.RegistryTests.f;cls.root=oldfixture.RegistryTests.root

    @classmethod
    def tearDownClass(cls):
        oldfixture.RegistryTests.tearDownClass()

    def setUp(self):
        oldfixture.RegistryTests.setUp(self)
        self.logs={};self.file_no=0

    def write353(self,stem,raw):
        self.file_no+=1
        path=Path(self.w)/f'ec353-{self.file_no:03d}-{stem}'
        path.write_bytes(raw if type(raw) is bytes else canonical.canonical(raw))
        return {'path':str(path),'sha256':digest(path)}

    def signed(self,stem,body,private,domain,signature_field='signature_ed25519_hex'):
        doc={**body,signature_field:private.sign(domain+canonical.canonical(body)).hex()}
        return self.write353(stem+'.json',doc)

    def baseline(self,two_channels=False):
        self.prepare(two_tokens=two_channels)
        for ident in ('registry_a','registry_b'):
            self.make_root(ident)
            entries=[self.make_entry(0)]
            if two_channels:entries.append(self.make_entry(1))
            self.make_event(ident,entries=entries)

    def inventory(self):
        rows=[]
        for id in sorted(self.registries):
            p=self.registries[id]['root_ref']
            rows.append(('registry_root_reference',digest(p),Path(p).read_bytes(),
                         json.loads(Path(p).read_bytes())['valid_from_utc']))
        for item in self.reg_events:
            p=item['file']
            rows.append(('registry_event',digest(p),Path(p).read_bytes(),
                         json.loads(Path(p).read_bytes())['issued_utc']))
        return rows

    def make_log(self,log_id='log_a',*,add_inclusions=True,reuse_key=None,
                 reverse=False,claimed_org_match=False):
        key=reuse_key or ed25519.Ed25519PrivateKey.generate()
        witness=ed25519.Ed25519PrivateKey.generate()
        logkey=self.write353(log_id+'-log.pub',pub(key))
        witnesskey=self.write353(log_id+'-witness.pub',pub(witness))
        base={'schema':core.LOG_REF_SCHEMA,'log_id':log_id,
              'log_public_key_original_sha256':logkey['sha256'],
              'claimed_log_organization':f'SYNTHETIC {log_id} operator',
              'claimed_log_publication_uri':'https://invalid.example.test/log',
              'valid_from_utc':ut(self.now-timedelta(days=2)),
              'valid_until_utc':ut(self.now+timedelta(days=20))}
        logref=self.signed(log_id+'-log-ref',base,key,core.LOG_REF_DOMAIN)
        wbase={'schema':core.WITNESS_REF_SCHEMA,'log_id':log_id,
               'witness_public_key_original_sha256':witnesskey['sha256'],
               'claimed_witness_organization':(base['claimed_log_organization'] if claimed_org_match
                                               else f'SYNTHETIC {log_id} witness'),
               'claimed_witness_document_uri':'https://invalid.example.test/witness',
               'valid_from_utc':base['valid_from_utc'],
               'valid_until_utc':base['valid_until_utc']}
        witnessref=self.signed(log_id+'-witness-ref',wbase,witness,core.WITNESS_REF_DOMAIN)
        info={'id':log_id,'private':key,'w_private':witness,
              'log_ref':logref,'witness_ref':witnessref,'leaves':[],
              'targets':[],'latest':None,'headers':[],
              'bundle':{'log_id':log_id,'log_reference':logref,'log_public_key':logkey,
                        'witness_reference':witnessref,'witness_public_key':witnesskey,
                        'checkpoints':[],'inclusions':[]}}
        rows=self.inventory()
        if reverse:rows=list(reversed(rows))
        info['targets']=[(k,h,raw,issued) for k,h,raw,issued in rows]
        info['leaves']=[raw for _,_,raw,_ in rows]
        self.logs[log_id]=info
        self.add_checkpoint(log_id)
        if add_inclusions:self.add_inclusions(log_id)
        return info

    def add_checkpoint(self,id='log_a',*,previous='latest',leaves=None,
                       log_sig_corrupt=False,witness_sig_corrupt=False,
                       with_consistency=True,issue_minutes=5):
        info=self.logs[id]
        older=info['latest'] if previous=='latest' else previous
        contents=info['leaves'] if leaves is None else leaves
        prevsha=older['file']['sha256'] if older else core.GENESIS
        base={'schema':core.CHECKPOINT_SCHEMA,'log_id':id,
              'log_reference_original_sha256':info['log_ref']['sha256'],
              'previous_checkpoint_original_sha256':prevsha,
              'tree_size':len(contents),'root_hash_sha256':root(contents).hex(),
              'issued_utc':ut(self.now+timedelta(minutes=issue_minutes))}
        cp=self.signed(id+'-checkpoint',base,info['private'],core.CHECKPOINT_DOMAIN,
                       'log_signature_ed25519_hex')
        if log_sig_corrupt:
            doc=json.loads(Path(cp['path']).read_bytes());doc['log_signature_ed25519_hex']='1'*128
            Path(cp['path']).write_bytes(canonical.canonical(doc));cp['sha256']=digest(cp['path'])
        witness_body={'schema':core.WITNESS_SCHEMA,'log_id':id,
                      'checkpoint_original_sha256':cp['sha256'],
                      'witness_reference_original_sha256':info['witness_ref']['sha256'],
                      'tree_size':len(contents),'root_hash_sha256':base['root_hash_sha256'],
                      'witnessed_utc':ut(self.now+timedelta(minutes=issue_minutes+1))}
        statement=self.signed(id+'-witness',witness_body,info['w_private'],
                              core.WITNESS_DOMAIN,'witness_signature_ed25519_hex')
        if witness_sig_corrupt:
            doc=json.loads(Path(statement['path']).read_bytes())
            doc['witness_signature_ed25519_hex']='2'*128
            Path(statement['path']).write_bytes(canonical.canonical(doc))
            statement['sha256']=digest(statement['path'])
        consistency_pin=None
        if older and with_consistency and len(contents)>len(older['leaves']):
            proof={'schema':core.CONSISTENCY_SCHEMA,'log_id':id,
                   'previous_checkpoint_original_sha256':prevsha,
                   'next_checkpoint_original_sha256':cp['sha256'],
                   'previous_tree_size':len(older['leaves']),
                   'next_tree_size':len(contents),
                   'audit_path_sha256_hex':[p.hex() for p in consistency(
                       contents,len(older['leaves']))]}
            consistency_pin=self.write353(id+'-consistency.json',proof)
        manifest={'checkpoint':cp,'witness_statement':statement,
                  'consistency_proof':consistency_pin}
        info['bundle']['checkpoints'].append(manifest)
        item={'file':cp,'witness_file':statement,'leaves':list(contents),
              'body':base,'manifest':manifest}
        info['headers'].append(item);info['latest']=item
        return item

    def add_inclusions(self,id='log_a',*,checkpoint=None,corrupt_index=False,
                       omit_kind=None):
        info=self.logs[id]
        cp=checkpoint or info['latest'];leaves=cp['leaves']
        for kind,h,raw,issued in info['targets']:
            if kind==omit_kind:continue
            idx=leaves.index(raw)
            proof={'schema':core.INCLUSION_SCHEMA,'log_id':id,
                   'checkpoint_original_sha256':cp['file']['sha256'],
                   'artifact_kind':kind,'artifact_original_sha256':h,
                   'leaf_index':len(leaves) if corrupt_index else idx,
                   'audit_path_sha256_hex':[p.hex() for p in inclusion(leaves,idx)]}
            info['bundle']['inclusions'].append(self.write353(id+'-inclusion.json',proof))

    def bundle(self,**overrides):
        logs=[self.logs[k]['bundle'] for k in sorted(self.logs)]
        return self.write353('publication-bundle.json',{'schema':core.BUNDLE_SCHEMA,
                                                       'logs':overrides.get('logs',logs)})

    def values(self,**overrides):
        b=self.bundle()
        vals=self.args352()
        vals.update(publication_evaluation_utc=ut(self.now+timedelta(minutes=30)),
                    publication_bundle_file=b['path'],
                    expected_publication_bundle_sha256=b['sha256'])
        vals.update(overrides)
        return vals

    def deny(self,code,**overrides):
        with self.assertRaises(errors.AnchorError) as cm:
            core.audit(**self.values(**overrides))
        self.assertIn(code,cm.exception.code)

    def test_01_two_real_log_witness_ed25519_and_merkle_proofs_unresolved(self):
        self.baseline(two_channels=True)
        self.make_log('log_a');self.make_log('log_b',reverse=True)
        result=core.audit(**self.values())
        self.assertEqual([x['outcome'] for x in result['channel_evidence']],
                         [core.OUTCOMES[6],core.OUTCOMES[6]])
        self.assertEqual(result['required_registry_original_count'],4)
        for log in result['log_evidence']:
            self.assertEqual(len(log['exact_originals_covered']),4)
            self.assertFalse(log['split_view'])
        self.assertTrue(result['parent_actual_signed_originals_replayed'])
        self.assertFalse(result['different_key_bytes_prove_separate_legal_organizations_or_physical_sites'])
        self.assertEqual(result['exit_code'],2)

    def test_02_missing_both_logs_downgraded(self):
        self.baseline()
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_03_one_log_insufficient(self):
        self.baseline();self.make_log()
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_04_missing_signed_root_inclusion_coverage(self):
        self.baseline()
        self.make_log('log_a',add_inclusions=False)
        self.make_log('log_b')
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[4])

    def test_05_bounded_actual_merkle_consistency_and_inclusion_in_prior(self):
        self.baseline()
        for id in ('log_a','log_b'):
            l=self.make_log(id)
            new_leaves=l['leaves']+[f'independent-extra-log-record-{id}'.encode()]
            self.add_checkpoint(id,leaves=new_leaves,issue_minutes=8)
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[6])
        self.assertEqual(res['log_evidence'][0]['checkpoint_count'],2)

    def test_06_consistency_proof_absent_cannot_claim_append_only(self):
        self.baseline()
        l=self.make_log('log_a');self.make_log('log_b')
        self.add_checkpoint('log_a',leaves=l['leaves']+[b'extra'],with_consistency=False)
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        self.assertTrue(res['log_evidence'][0]['append_only_unresolved'])

    def test_07_signed_split_view_two_siblings_no_head_election(self):
        self.baseline()
        l=self.make_log('log_a');self.make_log('log_b')
        self.add_checkpoint('log_a',previous=None,leaves=l['leaves']+[b'split'],issue_minutes=7)
        res=core.audit(**self.values())
        self.assertTrue(res['log_evidence'][0]['split_view'])
        self.assertEqual(len(res['log_evidence'][0]['heads']),2)
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_08_altered_log_checkpoint_true_signature_required(self):
        self.baseline()
        self.make_log('log_a');self.make_log('log_b')
        pin=self.logs['log_a']['bundle']['checkpoints'][0]['checkpoint']
        doc=json.loads(Path(pin['path']).read_bytes());doc['log_signature_ed25519_hex']='a'*128
        Path(pin['path']).write_bytes(canonical.canonical(doc));pin['sha256']=digest(pin['path'])
        self.deny('CHECKPOINT_LOG_SIGNATURE_INVALID')

    def test_09_altered_independent_witness_signature_denied(self):
        self.baseline()
        self.make_log('log_a');self.make_log('log_b')
        pin=self.logs['log_a']['bundle']['checkpoints'][0]['witness_statement']
        doc=json.loads(Path(pin['path']).read_bytes());doc['witness_signature_ed25519_hex']='f'*128
        Path(pin['path']).write_bytes(canonical.canonical(doc));pin['sha256']=digest(pin['path'])
        self.deny('CHECKPOINT_WITNESS_SIGNATURE_INVALID')

    def test_10_altered_witness_hash_stale_pin_denied(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        pin=self.logs['log_a']['bundle']['checkpoints'][0]['witness_statement']
        Path(pin['path']).write_bytes(Path(pin['path']).read_bytes()+b'\n')
        self.deny('WHOLE_ORIGINAL_SHA_MISMATCH_WITNESS_STATEMENT')

    def test_11_merkle_inclusion_invalid_fails_closed(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        pin=self.logs['log_a']['bundle']['inclusions'][0]
        doc=json.loads(Path(pin['path']).read_bytes());doc['leaf_index']=100
        Path(pin['path']).write_bytes(canonical.canonical(doc));pin['sha256']=digest(pin['path'])
        self.deny('INCLUSION_MERKLE_PROOF_INVALID')

    def test_12_reused_log_and_witness_publisher_keys_rejected(self):
        self.baseline()
        a=self.make_log('log_a');self.make_log('log_b',reuse_key=a['private'])
        self.deny('LOG_WITNESS_KEY_ROLE_REUSED')

    def test_13_claimed_same_log_and_witness_org_not_independence(self):
        self.baseline();self.make_log('log_a',claimed_org_match=True);self.make_log('log_b')
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertFalse(res['log_evidence'][0]['claimed_organizations_distinct'])

    def test_14_stale_witness_checkpoint_does_not_become_fresh(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        vals=self.values(publication_evaluation_utc=ut(self.now+timedelta(days=8)))
        res=core.audit(**vals)
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertTrue(res['log_evidence'][0]['claimed_checkpoint_stale'])

    def test_15_prior_ec352_fork_unresolved_not_repaired_by_logs(self):
        self.baseline()
        previous=self.registries['registry_a']['head']
        self.make_event('registry_a',kind='renew',previous=previous,issued_minutes=7)
        self.make_event('registry_a',kind='renew',previous=previous,issued_minutes=6)
        self.make_log('log_a');self.make_log('log_b')
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[0])

    def test_16_absent_actual_ec351_ocsp_not_promoted(self):
        self.make_token(0);self.make_authority(0)
        for id in ('registry_a','registry_b'):
            self.make_root(id);self.make_event(id)
        self.make_log('log_a');self.make_log('log_b')
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[0])

    def test_17_bundle_duplicate_json_key_denied(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        vals=self.values()
        path=Path(vals['publication_bundle_file'])
        path.write_bytes(b'{"logs":[],"logs":[],"schema":"ces.ec353.pinned_publication_evidence_bundle.v1"}')
        vals['expected_publication_bundle_sha256']=digest(path)
        with self.assertRaises(errors.AnchorError) as cm:core.audit(**vals)
        self.assertIn('BUNDLE_JSON_INVALID',cm.exception.code)

    def test_17b_forged_consistency_path_downgrades_to_unresolved(self):
        self.baseline()
        l=self.make_log('log_a');self.make_log('log_b')
        cp=self.add_checkpoint('log_a',leaves=l['leaves']+[b'extra-log-leaf'])
        pin=cp['manifest']['consistency_proof']
        doc=json.loads(Path(pin['path']).read_bytes());doc['audit_path_sha256_hex']=['e'*64]
        Path(pin['path']).write_bytes(canonical.canonical(doc));pin['sha256']=digest(pin['path'])
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        self.assertTrue(res['log_evidence'][0]['append_only_unresolved'])

    def test_17c_cross_log_same_claimed_organization_not_independent(self):
        self.baseline()
        a=self.make_log('log_a');b=self.make_log('log_b')
        refpin=b['bundle']['log_reference'];doc=json.loads(Path(refpin['path']).read_bytes())
        # Re-sign the second log's own claimed entity string, preserving valid
        # cryptography. Cross-channel name collision still downgrades status.
        first=json.loads(Path(a['bundle']['log_reference']['path']).read_bytes())
        body={k:v for k,v in doc.items() if k!='signature_ed25519_hex'}
        body['claimed_log_organization']=first['claimed_log_organization']
        newdoc={**body,'signature_ed25519_hex':b['private'].sign(
            core.LOG_REF_DOMAIN+canonical.canonical(body)).hex()}
        # Replacing a root ref would also require new checkpoint signatures;
        # instead build both logs with a non-overlapping name and call the
        # local claims comparison through a root witness name in one manifest.
        # Deliberately write all linked files as real signed originals.
        oldsha=refpin['sha256'];Path(refpin['path']).write_bytes(canonical.canonical(newdoc))
        refpin['sha256']=digest(refpin['path'])
        checkpoint=b['bundle']['checkpoints'][0]
        cpin=checkpoint['checkpoint'];c=json.loads(Path(cpin['path']).read_bytes())
        cbody={k:v for k,v in c.items() if k!='log_signature_ed25519_hex'}
        cbody['log_reference_original_sha256']=refpin['sha256']
        Path(cpin['path']).write_bytes(canonical.canonical({**cbody,
            'log_signature_ed25519_hex':b['private'].sign(core.CHECKPOINT_DOMAIN+
                                     canonical.canonical(cbody)).hex()}))
        cpin['sha256']=digest(cpin['path'])
        wpin=checkpoint['witness_statement'];w=json.loads(Path(wpin['path']).read_bytes())
        wbody={k:v for k,v in w.items() if k!='witness_signature_ed25519_hex'}
        wbody['checkpoint_original_sha256']=cpin['sha256']
        Path(wpin['path']).write_bytes(canonical.canonical({**wbody,
            'witness_signature_ed25519_hex':b['w_private'].sign(core.WITNESS_DOMAIN+
                                            canonical.canonical(wbody)).hex()}))
        wpin['sha256']=digest(wpin['path'])
        for pin in b['bundle']['inclusions']:
            doc=json.loads(Path(pin['path']).read_bytes())
            doc['checkpoint_original_sha256']=cpin['sha256']
            Path(pin['path']).write_bytes(canonical.canonical(doc));pin['sha256']=digest(pin['path'])
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertFalse(res['log_evidence'][0]['claimed_organizations_distinct'])
        self.assertFalse(res['log_evidence'][1]['claimed_organizations_distinct'])

    def test_17d_checkpoint_missing_not_called_witnessed(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        self.logs['log_a']['bundle']['checkpoints']=[]
        self.logs['log_a']['bundle']['inclusions']=[]
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_17e_signed_rollback_visible_and_not_append_only(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        self.add_checkpoint('log_a',leaves=self.logs['log_a']['leaves'][:-1])
        res=core.audit(**self.values())
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_17f_witness_binding_wrong_checkpoint_is_denied(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        pin=self.logs['log_a']['bundle']['checkpoints'][0]['witness_statement']
        doc=json.loads(Path(pin['path']).read_bytes())
        doc['checkpoint_original_sha256']='a'*64
        Path(pin['path']).write_bytes(canonical.canonical(doc));pin['sha256']=digest(pin['path'])
        self.deny('WITNESS_CHECKPOINT_OR_KEY_BINDING_INVALID')

    def test_17g_log_key_reusing_registry_root_denied(self):
        self.baseline()
        # Even a correctly self-signed log cannot reuse EC352 issuer root.
        key=self.registries['registry_a']['root_private']
        self.make_log('log_a',reuse_key=key);self.make_log('log_b')
        self.deny('LOG_WITNESS_KEY_ROLE_REUSED')

    def test_17h_forged_signed_sibling_in_split_view_denied(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        self.add_checkpoint('log_a',previous=None,
                            leaves=self.logs['log_a']['leaves']+[b'extra'],
                            log_sig_corrupt=True)
        self.deny('CHECKPOINT_LOG_SIGNATURE_INVALID')

    def test_18_standalone_and_unified_real_executions_denied_write_mode(self):
        self.baseline();self.make_log('log_a');self.make_log('log_b')
        vals=self.values()
        from scripts import ces_next
        argv=[]
        for k in ces_next.EC353_KEYS:argv.extend(['--'+k.replace('_','-'),str(vals[k])])
        for k,flag in ces_next.EC353_REPEATS:
            for value in vals[k]:argv.extend([flag,str(value)])
        child=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_transparency_witness.py'),
               'audit-publication-witnesses',*argv]
        run=subprocess.run(child,capture_output=True,text=True,cwd=ROOT,timeout=360)
        self.assertEqual(run.returncode,2,run.stdout+run.stderr)
        self.assertEqual(json.loads(run.stdout)['channel_evidence'][0]['outcome'],
                         core.OUTCOMES[6])
        unified=[sys.executable,'-B',str(ROOT/'scripts'/'ces_next.py'),
                 'audit-registry-transparency','DeliveryAudit',
                 'AuditOfflineRegistryTransparencyWitnesses',*argv]
        outer=subprocess.run(unified,capture_output=True,text=True,cwd=ROOT,timeout=360)
        self.assertEqual(outer.returncode,2,outer.stdout+outer.stderr)
        self.assertEqual(json.loads(outer.stdout)['furnished_log_count'],2)
        unified[4]='IssueNewTransparencySigningKey'
        deny=subprocess.run(unified,capture_output=True,text=True,cwd=ROOT,timeout=360)
        self.assertEqual(deny.returncode,3,deny.stdout+deny.stderr)
        parser=ces_next.build_parser()._subparsers._group_actions[0].choices[
            'audit-registry-transparency']
        flags={x for a in parser._actions for x in a.option_strings}
        for forbidden in ('--private-key-file','--output','--sign','--network','--provider-write'):
            self.assertNotIn(forbidden,flags)

if __name__=='__main__':unittest.main()
