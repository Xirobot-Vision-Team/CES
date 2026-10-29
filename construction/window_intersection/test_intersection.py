#!/usr/bin/env python3
"""EC313 focused LOCAL simulations with true inherited original Ed25519 files.

These tests forge no PASS audit status. They build four successive different
EC307 signed forks, four EC308 issuer signatures and eight genuine EC309
observer readbacks using test-only local keys. Real CAS/organization not tested.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import subprocess
import sys
import unittest

from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from registrar_epochs import epochs
from registrar_epochs.test_epochs import EC306EpochCases as Base
from registrar_forks import forks
from registrar_forks.test_forks import EC307ForkCases as Forks
from cas_receipt import receipt as cas
from cas_receipt.test_receipt import EC308CasReceiptCases as CasFixture
from cas_readback import readback as rb
from cas_readback.test_readback import EC309CasReadbackCases as ObsFixture
from cas_decision_history.test_decisions import EC311SignedDecisionHistoryCases as Prev
from dual_observer_reconciliation.test_reconcile import EC312TwoObserverSignedWindowCases as Old
from . import intersection as r

ROOT = Path(__file__).resolve().parents[2]


class EC313OriginalSignedIntersectionCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Old.setUpClass()
        try:
            cls.w1 = copy.deepcopy(Old.good)
            cls.stage = cls._stage_from_chosen_second_fork()
            cls.fresh = []
            prior = {
                row['observer_id']: {
                    'sequence': 2,
                    'raw_sha256': row['expected_readback_sha256'],
                    'observed_revision': CasFixture.revision+2,
                    'observed_head_raw_sha256': Prev.head2,
                }
                for row in cls.w1['decisions'][1]['readbacks']
            }
            for step in (3, 4):
                original, cls.stage, prior = cls._next_signed_decision(
                    cls.stage, prior, step)
                cls.fresh.append(original)
            cls.w2 = cls._window([cls.w1['decisions'][1], cls.fresh[0]],
                                 previous=cls.w1['decisions'][0])
            cls.w3 = cls._window(cls.fresh,
                                 previous=cls.w1['decisions'][1])
        except BaseException:
            Old.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        Old.tearDownClass()

    @classmethod
    def _stage_from_chosen_second_fork(cls):
        chosen = Prev.case2['candidate_a']
        index = epochs._owner_private_read(
            chosen['chain_file'], chosen['expected_chain_raw_sha256'])
        last = index['epochs'][-1]
        return {
            'chain_file': chosen['chain_file'],
            'external': {
                **Base.s5['external'],
                'chain_raw_sha256': chosen['expected_chain_raw_sha256'],
                'epoch_count': len(index['epochs']),
                'active_registrar_public_hex': last['registrar_public_hex'],
                'active_ledger_raw_sha256': last['ledger_raw_sha256'],
                'active_ledger_sequence': last['ledger_sequence'],
            },
            'ledger_files': chosen['ledger_files'],
            'certificate_files': chosen['certificate_files'],
        }

    @classmethod
    def _next_signed_decision(cls, stage: dict, previous: dict, step: int):
        new_branches = []
        new_stages = []
        for idx, suffix in enumerate(('a', 'b')):
            # Each trial child has a new genuinely Ed25519-signed ACK and
            # registered signed ledger, not a fake CAS head/hash.
            ctx = Forks._signed_ack(
                f'ec313-case-{step}-child-{suffix}', f'{step + 17 + idx:02x}'*32)
            output = str(Prev.home/f'ec313-{step}-{suffix}-ledger.json')
            signed = epochs.register(**stage, **ctx,
                active_private_key_file=Base.third_private, out=output)
            index = str(Prev.home/f'ec313-{step}-{suffix}-index.json')
            result = epochs.commit(**stage, **ctx,
                candidate_ledger_file=output,
                expected_candidate_ledger_sha256=signed['ledger_raw_sha256'],
                expected_candidate_sequence=step, out=index)
            next_stage = {
                'chain_file': index,
                'external': Base._external(result),
                'ledger_files': stage['ledger_files'][:-1] + [output],
                'certificate_files': stage['certificate_files'],
            }
            new_branches.append(Forks._branch(next_stage, ctx))
            new_stages.append(next_stage)
        choice = new_stages[0]
        case = Forks._case(stage, new_branches[0], new_branches[1])
        case_path, case_sha = Prev._private_json(case, f'ec313-fork-{step}')
        fork_path = str(Prev.home/f'ec313-original-fork-{step}.json')
        fork_result = forks.compare(
            parent_chain_file=stage['chain_file'],
            parent_external=stage['external'],
            parent_ledger_files=stage['ledger_files'],
            parent_certificate_files=stage['certificate_files'],
            candidate_a=new_branches[0], candidate_b=new_branches[1],
            out=fork_path)
        fork_sha = fork_result['evidence_report_raw_sha256']
        fork_report = forks._read_report(fork_path, fork_sha)
        handoff = fork_report['external_cas_handoff']
        parent_rev = CasFixture.revision + step - 1
        nonce = f'{step + 49:02x}'*32
        chosen_sha = choice['external']['chain_raw_sha256']
        claim = CasFixture._claim(
            ec307_fork_evidence_raw_sha256=fork_sha,
            ec307_choice_request_raw_sha256=b.digest(b.canonical(handoff)),
            request_nonce_sha256=nonce,
            expected_parent_chain_raw_sha256=stage['external']['chain_raw_sha256'],
            candidate_chain_raw_sha256=handoff['allowed_candidate_chain_raw_sha256'],
            expected_parent_cas_revision=parent_rev,
            expected_parent_cas_head_sha256=stage['external']['chain_raw_sha256'],
            observed_cas_revision=parent_rev+1,
            observed_head_chain_raw_sha256=chosen_sha,
            selected_candidate_chain_raw_sha256=chosen_sha)
        receipt_file, receipt_sha = CasFixture._signed_file(claim=claim)
        original = {
            'fork_case_file': case_path,
            'expected_fork_case_sha256': case_sha,
            'fork_evidence_file': fork_path,
            'expected_fork_evidence_sha256': fork_sha,
            'receipt_file': receipt_file,
            'expected_receipt_sha256': receipt_sha,
            'expected_request_nonce_sha256': nonce,
            'expected_parent_cas_revision': parent_rev,
            'expected_parent_cas_head_sha256': stage['external']['chain_raw_sha256'],
            'readbacks': [],
        }
        signed_issuer = cas.evaluate(
            fork_case_file=case_path, expected_fork_case_sha256=case_sha,
            fork_evidence_file=fork_path, expected_fork_evidence_sha256=fork_sha,
            receipt_file=receipt_file, expected_receipt_sha256=receipt_sha,
            trust={**CasFixture.trust,
                   'expected_request_nonce_sha256': nonce,
                   'expected_parent_cas_revision': parent_rev,
                   'expected_parent_cas_head_sha256': stage['external']['chain_raw_sha256']})
        next_prior = {}
        for index, observer in enumerate(cls.w1['observers']):
            oid = observer['observer_id']
            nonce_obs = f'{step*4 + 60 + index:02x}'*32
            previous_item = previous[oid]
            trust = {
                'cas_store_namespace_id': cls.w1['cas_store_namespace_id'],
                'observer_id': oid,
                'observer_public_hex': observer['observer_public_hex'],
                'expected_readback_request_nonce_sha256': nonce_obs,
                'expected_previous_readback_sequence': previous_item['sequence'],
                'expected_previous_readback_raw_sha256': previous_item['raw_sha256'],
                'expected_previous_readback_observed_revision':
                    previous_item['observed_revision'],
            }
            obs_claim = ObsFixture._claim(cas_report=signed_issuer, observer=trust)
            obs_claim.update({
                'ec307_fork_case_raw_sha256': case_sha,
                'ec307_fork_evidence_raw_sha256': fork_sha,
                'ec308_cas_receipt_raw_sha256': receipt_sha,
                'original_cas_request_nonce_sha256': nonce,
            })
            key = ObsFixture.key if index == 0 else Old.second_key
            signed_path, signed_sha = ObsFixture._signed(key=key, claim=obs_claim)
            original['readbacks'].append({
                'observer_id': oid,
                'readback_file': signed_path,
                'expected_readback_sha256': signed_sha,
                'expected_readback_request_nonce_sha256': nonce_obs,
            })
            next_prior[oid] = {
                'sequence': obs_claim['readback_sequence'],
                'raw_sha256': signed_sha,
                'observed_revision': obs_claim['observed_cas_revision'],
                'observed_head_raw_sha256': obs_claim['observed_head_chain_raw_sha256'],
            }
        return original, choice, next_prior

    @classmethod
    def _window(cls, records: list[dict], *, previous: dict) -> dict:
        doc = copy.deepcopy(cls.w1)
        doc['decisions'] = copy.deepcopy(records)
        for obs in doc['observers']:
            ref = next(x for x in previous['readbacks']
                       if x['observer_id'] == obs['observer_id'])
            prev_claim = rb._parse_readback(ref['readback_file'],
                                            ref['expected_readback_sha256'])[1]
            obs['boundary'] = {
                'sequence': prev_claim['readback_sequence'],
                'raw_sha256': ref['expected_readback_sha256'],
                'observed_revision': prev_claim['observed_cas_revision'],
                'observed_head_raw_sha256': prev_claim['observed_head_chain_raw_sha256'],
            }
        return doc

    @classmethod
    def _outer(cls, wleft: dict, wright: dict) -> tuple[str, str]:
        lf, ls = Prev._private_json(wleft, 'ec313-left')
        rf, rs = Prev._private_json(wright, 'ec313-right')
        doc = {
            'schema': r.MANIFEST_SCHEMA,
            'cas_authority_id': cls.w1['cas_authority_id'],
            'cas_authority_public_hex': cls.w1['cas_authority_public_hex'],
            'cas_store_namespace_id': cls.w1['cas_store_namespace_id'],
            'expected_registry_id': CasFixture.fork_report['registry_id'],
            'windows': [
                {'window_id': 'left', 'manifest_file': lf,
                 'expected_manifest_sha256': ls},
                {'window_id': 'right', 'manifest_file': rf,
                 'expected_manifest_sha256': rs},
            ],
        }
        return Prev._private_json(doc, 'ec313-outer-manifest')

    @classmethod
    def _evaluate(cls, left: dict | None = None, right: dict | None = None) -> dict:
        path, sha = cls._outer(cls.w1 if left is None else left,
                               cls.w2 if right is None else right)
        return r.evaluate(manifest_file=path, expected_manifest_sha256=sha)

    @classmethod
    def _run(cls, script: str, flags: list[str], expected_rc: int):
        done = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'scripts'/script),
                               *flags], capture_output=True, text=True,
                              timeout=850, env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'})
        assert done.returncode == expected_rc, (done.stdout, done.stderr)
        return json.loads(done.stdout.strip())

    @classmethod
    def _fresh_site_window(cls, *, collide_nonce: bool = False,
                           different_issuer_original: bool = False) -> dict:
        """Two MORE locally generated observer keys, authentic EC309 originals.

        Allows two competing actual Ed25519 issuer receipts at exactly the
        same revision, without hiding conflicts under reused observer keys.
        """
        extra_keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        extra_observers = []
        for oid, key in zip(('fresh_alpha_team', 'fresh_zulu_team'), extra_keys):
            pub = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            extra_observers.append({
                'observer_id': oid, 'observer_public_hex': pub,
                'boundary': {'sequence': 0, 'raw_sha256': a.GENESIS,
                             'observed_revision': None,
                             'observed_head_raw_sha256': None},
            })
        issuer = copy.deepcopy(cls.w2['decisions'][0])
        if different_issuer_original:
            receipt = json.loads(Path(issuer['receipt_file']).read_text())
            new_nonce = '7a'*32
            receipt['claim']['request_nonce_sha256'] = new_nonce
            receipt['authority_signature_ed25519'] = CasFixture.key.sign(
                cas.DOMAIN+a.canonical(receipt['claim'])).hex()
            f, sha = Prev._private_json(receipt, 'ec313-double-issued-same-state')
            issuer.update(receipt_file=f, expected_receipt_sha256=sha,
                          expected_request_nonce_sha256=new_nonce)
        documents = [issuer, copy.deepcopy(cls.w2['decisions'][1])]
        prior = {o['observer_id']:
                    {'sequence': 0, 'raw_sha256': a.GENESIS,
                     'observed_revision': None}
                 for o in extra_observers}
        produced = []
        for decision_index, original in enumerate(documents):
            signed = cas.evaluate(
                fork_case_file=original['fork_case_file'],
                expected_fork_case_sha256=original['expected_fork_case_sha256'],
                fork_evidence_file=original['fork_evidence_file'],
                expected_fork_evidence_sha256=original['expected_fork_evidence_sha256'],
                receipt_file=original['receipt_file'],
                expected_receipt_sha256=original['expected_receipt_sha256'],
                trust={**CasFixture.trust,
                       'expected_request_nonce_sha256':original['expected_request_nonce_sha256'],
                       'expected_parent_cas_revision':original['expected_parent_cas_revision'],
                       'expected_parent_cas_head_sha256':original['expected_parent_cas_head_sha256']})
            row = {k: original[k] for k in original if k != 'readbacks'}
            row['readbacks'] = []
            for index, (observer, key) in enumerate(zip(extra_observers, extra_keys)):
                name = observer['observer_id']
                nonce = f'{225+decision_index*2+index:02x}'*32
                if collide_nonce and decision_index == 0 and index == 0:
                    nonce = cls.w1['decisions'][0]['readbacks'][0][
                        'expected_readback_request_nonce_sha256']
                trust = {
                    'cas_store_namespace_id': cls.w1['cas_store_namespace_id'],
                    'observer_id': name,
                    'observer_public_hex': observer['observer_public_hex'],
                    'expected_readback_request_nonce_sha256': nonce,
                    'expected_previous_readback_sequence': prior[name]['sequence'],
                    'expected_previous_readback_raw_sha256': prior[name]['raw_sha256'],
                    'expected_previous_readback_observed_revision':
                        prior[name]['observed_revision'],
                }
                claim = ObsFixture._claim(cas_report=signed, observer=trust)
                claim.update({
                    'ec307_fork_case_raw_sha256':original['expected_fork_case_sha256'],
                    'ec307_fork_evidence_raw_sha256':original['expected_fork_evidence_sha256'],
                    'ec308_cas_receipt_raw_sha256':original['expected_receipt_sha256'],
                    'original_cas_request_nonce_sha256':original['expected_request_nonce_sha256'],
                })
                path, sha = ObsFixture._signed(key=key, claim=claim)
                row['readbacks'].append({
                    'observer_id': name, 'readback_file': path,
                    'expected_readback_sha256': sha,
                    'expected_readback_request_nonce_sha256': nonce,
                })
                prior[name] = {
                    'sequence': claim['readback_sequence'],
                    'raw_sha256': sha,
                    'observed_revision': claim['observed_cas_revision'],
                }
            produced.append(row)
        output = copy.deepcopy(cls.w2)
        output['observers'] = extra_observers
        output['decisions'] = produced
        return output

    def test_01_true_partial_overlap_signed_original_union_and_boundary_replay(self):
        report = self._evaluate()
        self.assertEqual(report['status'], r.SUCCESS)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['shared_signed_issuer_receipt_count'], 1)
        self.assertEqual(report['union_distinct_signed_issuer_receipt_count'], 3)
        self.assertEqual(report['left_only_signed_issuer_receipt_count'], 1)
        self.assertEqual(report['right_only_signed_issuer_receipt_count'], 1)
        self.assertEqual(len(report['non_genesis_boundaries_confirmed_by_other_window_original']), 2)
        self.assertEqual(report['last_replayed_union_signed_revision'], CasFixture.revision+3)
        self.assertTrue(report['all_four_ec312_observer_paths_replay_original_ec309_to_ec294_signatures'])
        self.assertFalse(report['physical_same_store_linearizable_cas_or_global_latest_proven'])
        self.assertNotIn(str(Prev.home), json.dumps(report))

    def test_02_no_common_issuer_even_with_true_compatible_adjacent_claims(self):
        report = self._evaluate(self.w1, self.w3)
        self.assertEqual(report['status'], r.NO_OVERLAP)
        self.assertEqual(report['shared_signed_issuer_receipt_count'], 0)
        self.assertEqual(report['union_distinct_signed_issuer_receipt_count'], 4)
        self.assertEqual(report['exit_code'], 2)
        self.assertIsNone(report['last_candidate_sha256_of_compatible_signed_claims_only'])
        self.assertEqual(len(report['non_genesis_boundaries_confirmed_by_other_window_original']),2)

    def test_03_cross_window_true_signed_same_revision_different_head(self):
        changed = copy.deepcopy(self.w2)
        row = changed['decisions'][0]['readbacks'][1]
        doc = json.loads(Path(row['readback_file']).read_text())
        doc['claim']['observed_head_chain_raw_sha256'] = 'd'*64
        doc['observer_signature_ed25519'] = Old.second_key.sign(
            rb.DOMAIN+a.canonical(doc['claim'])).hex()
        new_path, new_sha = Prev._private_json(doc, 'ec313-actual-head-contradiction')
        row.update(readback_file=new_path, expected_readback_sha256=new_sha)
        # Preserve the independent EC309 B-site predecessor SHA chain so the
        # new true signature is parsed, not denied as malformed input.
        next_row = changed['decisions'][1]['readbacks'][1]
        next_doc = json.loads(Path(next_row['readback_file']).read_text())
        next_doc['claim']['previous_readback_raw_sha256'] = new_sha
        next_doc['observer_signature_ed25519'] = Old.second_key.sign(
            rb.DOMAIN+a.canonical(next_doc['claim'])).hex()
        p, sha = Prev._private_json(next_doc, 'ec313-resigned-next-head')
        next_row.update(readback_file=p, expected_readback_sha256=sha)
        report = self._evaluate(right=changed)
        self.assertEqual(report['status'], r.SIGNED_CONFLICT)
        self.assertEqual(report['exit_code'], 2)
        self.assertTrue(report['cross_window_signed_revision_head_conflicts'])
        self.assertIsNone(report['last_candidate_sha256_of_compatible_signed_claims_only'])

    def test_04_same_observer_sequence_signed_double_origin_cannot_merge(self):
        changed = copy.deepcopy(self.w2)
        row = changed['decisions'][0]['readbacks'][0]
        doc = json.loads(Path(row['readback_file']).read_text())
        doc['claim']['readback_request_nonce_sha256'] = 'bf'*32
        doc['observer_signature_ed25519'] = ObsFixture.key.sign(
            rb.DOMAIN+a.canonical(doc['claim'])).hex()
        p, sha = Prev._private_json(doc, 'ec313-observer-signed-sequence-fork')
        row.update(readback_file=p, expected_readback_sha256=sha,
                   expected_readback_request_nonce_sha256='bf'*32)
        nxt = changed['decisions'][1]['readbacks'][0]
        ndoc = json.loads(Path(nxt['readback_file']).read_text())
        ndoc['claim']['previous_readback_raw_sha256'] = sha
        ndoc['observer_signature_ed25519'] = ObsFixture.key.sign(
            rb.DOMAIN+a.canonical(ndoc['claim'])).hex()
        np, ns = Prev._private_json(ndoc, 'ec313-sequence-fork-followup')
        nxt.update(readback_file=np, expected_readback_sha256=ns)
        report = self._evaluate(right=changed)
        self.assertEqual(report['status'], r.SIGNED_CONFLICT)
        self.assertTrue(report['same_observer_signed_sequence_double_origins'])

    def test_05_sha_pin_signature_identity_and_strict_manifest_denials(self):
        path, sha = self._outer(self.w1, self.w2)
        with self.assertRaises(a.AnchorError):
            r.evaluate(manifest_file=path, expected_manifest_sha256='f'*64)
        outer = json.loads(Path(path).read_text())
        outer['cas_store_namespace_id'] = 'different_trust_namespace'
        new_path, new_sha = Prev._private_json(outer, 'ec313-different-root')
        with self.assertRaisesRegex(a.AnchorError, 'EC313_EC312_WINDOW_TRUST_ROOT_DIFFERS'):
            r.evaluate(manifest_file=new_path, expected_manifest_sha256=new_sha)
        outer['unexpected'] = True
        new_path, new_sha = Prev._private_json(outer, 'ec313-extra-fields')
        with self.assertRaises(a.AnchorError):
            r.evaluate(manifest_file=new_path, expected_manifest_sha256=new_sha)
        forged = copy.deepcopy(self.w2)
        item = forged['decisions'][1]['readbacks'][1]
        obj = json.loads(Path(item['readback_file']).read_text())
        obj['claim']['observed_head_chain_raw_sha256'] = 'd'*64
        fp, fs = Prev._private_json(obj, 'ec313-invalid-original-signature')
        item.update(readback_file=fp, expected_readback_sha256=fs)
        with self.assertRaisesRegex(a.AnchorError, 'EC309_OBSERVER_ED25519_SIGNATURE_INVALID'):
            self._evaluate(right=forged)

    def test_06_private_report_full_original_replay_and_exclusive_write(self):
        path, sha = self._outer(self.w1, self.w2)
        audit = str(Prev.home/'ec313-complete-intersection-audit.json')
        result = r.verify(manifest_file=path, expected_manifest_sha256=sha,
                          out=audit)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(os.stat(audit).st_mode & 0o777, 0o600)
        self.assertEqual(b.digest(Path(audit).read_bytes()),
                         result['audit_report_raw_sha256'])
        repeated = r.verify_report(
            manifest_file=path, expected_manifest_sha256=sha,
            audit_report_file=audit,
            expected_audit_report_sha256=result['audit_report_raw_sha256'])
        self.assertEqual(repeated['exit_code'], 0)
        with self.assertRaises(a.AnchorError):
            r.verify(manifest_file=path, expected_manifest_sha256=sha,
                     out=audit)

    def test_07_cli_and_unified_exact_readonly_entry(self):
        path, sha = self._outer(self.w1, self.w2)
        flags = ['--manifest-file',path,'--expected-manifest-sha256',sha]
        cli = self._run('ces_cas_intersection.py',['verify',*flags],0)
        self.assertEqual(cli['schema'], r.RESULT_SCHEMA)
        self.assertEqual(cli['shared_signed_issuer_receipt_count'],1)
        unified = self._run('ces_next.py',[
            'audit-intersection','DeliveryAudit',
            'ReconcileOverlappingSignedCasWindows',*flags],0)
        self.assertEqual(unified['status'],r.SUCCESS)
        self.assertFalse(unified['external_cas_access_performed'])
        denied = self._run('ces_next.py',[
            'audit-intersection','DeliveryAudit','ApproveCasCommit',*flags],3)
        self.assertEqual(denied['reason_code'],
            'EC313_ONLY_DELIVERYAUDIT_RECONCILE_OVERLAPPING_SIGNED_CAS_WINDOWS')
        out = subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
                             'audit-intersection','DeliveryAudit',
                             'ReconcileOverlappingSignedCasWindows',*flags,
                             '--out','/tmp/not-authorized'],
                             capture_output=True,text=True,timeout=20)
        self.assertNotEqual(out.returncode,0)

    def test_08_four_distinct_observer_keys_share_one_genuine_issuer_anchor(self):
        fresh = self._fresh_site_window()
        report = self._evaluate(self.w1, fresh)
        self.assertEqual(report['status'], r.SUCCESS)
        self.assertEqual(report['shared_signed_issuer_receipt_count'], 1)
        self.assertEqual(len(report['independent_observer_ids_with_unique_validated_public_keys']), 4)
        self.assertFalse(report['actual_key_authority_organization_and_nonce_freshness_proven'])

    def test_09_cross_window_different_signed_source_nonce_reuse_or_issuer_double_issue(self):
        collision = self._fresh_site_window(collide_nonce=True)
        report = self._evaluate(right=collision)
        self.assertEqual(report['status'], r.ISSUER_AMBIGUITY)
        self.assertTrue(report['cross_window_nonce_reuse_for_different_originals'])
        self.assertFalse(report['same_observer_signed_sequence_double_origins'])
        alternate = self._fresh_site_window(different_issuer_original=True)
        report = self._evaluate(right=alternate)
        self.assertEqual(report['status'], r.ISSUER_AMBIGUITY)
        self.assertTrue(report['different_issuer_receipts_at_same_revision'])
        self.assertFalse(report['cross_window_signed_revision_head_conflicts'])

    def test_10_cross_window_verified_predecessor_contradicts_opaque_pin(self):
        modified = copy.deepcopy(self.w3)
        other = 'fa'*32
        modified['observers'][0]['boundary']['raw_sha256'] = other
        first = modified['decisions'][0]['readbacks'][0]
        document = json.loads(Path(first['readback_file']).read_text())
        document['claim']['previous_readback_raw_sha256'] = other
        document['observer_signature_ed25519'] = ObsFixture.key.sign(
            rb.DOMAIN+a.canonical(document['claim'])).hex()
        path, sha = Prev._private_json(document, 'ec313-resigned-opaque-boundary')
        first.update(readback_file=path, expected_readback_sha256=sha)
        second = modified['decisions'][1]['readbacks'][0]
        document = json.loads(Path(second['readback_file']).read_text())
        document['claim']['previous_readback_raw_sha256'] = sha
        document['observer_signature_ed25519'] = ObsFixture.key.sign(
            rb.DOMAIN+a.canonical(document['claim'])).hex()
        path, sha = Prev._private_json(document, 'ec313-boundary-followup')
        second.update(readback_file=path, expected_readback_sha256=sha)
        report = self._evaluate(self.w1, modified)
        self.assertEqual(report['status'], r.BOUNDARY_MISMATCH)
        self.assertEqual(report['exit_code'], 2)
        self.assertEqual(report['non_genesis_boundary_predecessor_mismatches'][0][
            'observer_id'], self.w1['observers'][0]['observer_id'])
        self.assertIsNone(report['last_candidate_sha256_of_compatible_signed_claims_only'])


if __name__ == '__main__':
    unittest.main()
