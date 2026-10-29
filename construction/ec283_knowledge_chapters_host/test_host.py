#!/usr/bin/env python3
"""Focused EC283 real EC206/208/210 stores, POSIX socket and Ed25519.

All signing roles and source consent receipts are synthetic development input,
not certified independent operators or verified organization-source custody.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

CONSTRUCTION = Path(__file__).resolve().parents[1]
ROOT = CONSTRUCTION.parent
sys.path.insert(0, str(CONSTRUCTION))

from ec283_knowledge_chapters_host import protocol as p, daemon, operator
from ec279_finding_query_host import protocol as io
from test_knowledge_lifecycle import LifecycleTests


def private(path: Path, raw: bytes) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return path


def doc(path: Path, obj: dict) -> Path:
    return private(path, p.canonical(obj) + b'\n')


def raw_private(path: Path, key: Ed25519PrivateKey) -> Path:
    return private(path, key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()))


@unittest.skipUnless(hasattr(socket, 'SO_PEERCRED') and hasattr(os, 'getuid'),
                     'Linux kernel AF_UNIX peer credentials required')
class KnowledgeQueryHostTests(unittest.TestCase):
    def setUp(self):
        self.fx = LifecycleTests('test_hashes_only_are_not_text_or_search')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        original = self.fx.fx.api
        store = original.store
        self.base = Path(self.fx.fx.hfx.fx.tmp.name)
        self.signers = {role: Ed25519PrivateKey.generate()
                        for role in ('custodian', 'reader', 'server')}
        self.publics = {role: p.public_hex(k) for role, k in self.signers.items()}
        self.keyfiles = {role: raw_private(self.base / (f'ec283-{role}.ed25519'), key)
                         for role, key in self.signers.items()}
        self.job = {'schema': p.JOB_SCHEMA,
            'repository_root': store.repository_root,
            'knowledge_root': store.knowledge_root,
            'candidate_root': store.root, 'version_root': original.root,
            'candidate_store_id': store.store_id,
            'version_store_id': original.store_id,
            'repository_ref': store.repository_ref,
            'knowledge_space_key': store.knowledge_space_key,
            'period_id': store.period_id,
            'source_policy_revision': store.source_policy_revision,
            'chapter_path': original.chapter_path,
            'trusted_approvers': {
                key: {'role': row['role'], 'public_hex': row['public_key'].hex()}
                for key, row in original.trusted_approvers.items()},
            'revoked_approvers': [],
            'query_request': json.loads(self.fx.request(projection='hashes_only')),
            'query_policy': {},
            'bootstrap_request': None,
            'bootstrap_read_policy': None,
            'version_evidence': None}
        self.configure()
        self.server = None

    def configure(self, *, projection: str = 'hashes_only',
                  view: str = 'source_snapshot', version: dict | None = None,
                  policy_changes: dict | None = None):
        req = self.fx.request(projection=projection, view=view,
            search_terms=['behavior'] if projection == 'match_snippets' else [])
        self.job['query_request'] = json.loads(req)
        policy = json.loads(self.fx.policy(req))
        if policy_changes:
            policy.update(policy_changes)
        self.job['query_policy'] = policy
        self.job['bootstrap_request'] = (
            self.fx.req202 if projection != 'hashes_only' else None)
        self.job['bootstrap_read_policy'] = (
            self.fx.pol202 if projection != 'hashes_only' else None)
        self.job['version_evidence'] = (json.loads(self.fx.version_access(version))
            if version is not None else None)
        return self.job

    def set_files(self):
        self.job_file = doc(self.base / 'ec283-job.json', self.job)
        self.policy = {'schema': p.POLICY_SCHEMA,
            'job_file': str(self.job_file),
            'job_sha256': p.sha(self.job_file.read_bytes()),
            'allowed_uids': [os.getuid()],
            'custodian_issuer_public_hex': self.publics['custodian'],
            'reader_issuer_public_hex': self.publics['reader'],
            'server_public_hex': self.publics['server']}
        self.policy_file = doc(self.base / 'ec283-policy.json', self.policy)
        self.policy_sha = p.sha(self.policy_file.read_bytes())
        self.socket = str(self.base / 'ec283.sock')
        self.subject = p.new_subject(uid=os.getuid(), policy_sha=self.policy_sha,
            job_sha=self.policy['job_sha256'],
            repository_ref=self.job['repository_ref'],
            query_view=self.job['query_request']['view'],
            projection=self.job['query_request']['projection'],
            query_sha=p.sha(p.canonical(self.job['query_request'])), ttl=250)
        self.grant = self.make_grant(self.subject)
        self.grant_file = doc(self.base / 'ec283-grant.json', self.grant)

    def make_grant(self, subject: dict, keys=None):
        keys = keys or self.signers
        return {'schema': p.GRANT_SCHEMA, 'subject': subject,
            'custodian_signature_ed25519': p.sign('custodian', subject,
                                                   keys['custodian']),
            'reader_signature_ed25519': p.sign('reader', subject,
                                               keys['reader'])}

    def start(self):
        self.set_files()
        self.server = daemon.ChaptersServer(
            path=self.socket, policy_path=str(self.policy_file),
            policy_sha=self.policy_sha,
            private_key_file=str(self.keyfiles['server']))
        thread = threading.Thread(target=self.server.serve_forever,
            kwargs={'poll_interval': 0.025}, daemon=True)
        thread.start()
        def close():
            self.server.shutdown()
            thread.join(3)
            self.server.server_close()
        self.addCleanup(close)
        return self.server

    def query(self, grant: dict | None = None, *, pub: str | None = None):
        path = self.grant_file if grant is None else doc(
            self.base / ('grant-' + str(time.time_ns()) + '.json'), grant)
        return operator.query(socket_path=self.socket, grant_file=str(path),
            policy_sha=self.policy_sha,
            server_public_hex=pub or self.publics['server'])

    def test_01_real_original_ec210_sha_projection_and_no_writes(self):
        self.start()
        source_before = self.fx.fx.src.read_bytes()
        rc, docu = self.query()
        self.assertEqual(rc, 2, docu)
        self.assertTrue(docu['verified_server_signature'])
        self.assertEqual(docu['result']['subject']['projection'], 'hashes_only')
        self.assertEqual(docu['result']['subject']['selected_sections'][0]['section_sha256'],
                         self.fx.fx.original_section['sha256'])
        self.assertNotIn('section_content_base64', json.dumps(docu))
        self.assertNotIn('Old API behavior', json.dumps(docu))
        self.assertEqual(self.fx.fx.src.read_bytes(), source_before)
        self.assertEqual(self.fx.fx.api.inspect()['subject']['version_count'], 0)

    def test_02_original_ec202_authorized_full_section_text(self):
        self.configure(projection='full_sections')
        self.start()
        rc, out = self.query()
        self.assertEqual(rc, 2, out)
        data = out['result']['subject']['selected_sections'][0]
        self.assertEqual(base64.b64decode(data['section_content_base64']),
                         self.fx.fx.before[self.fx.fx.original_section['start']:
                                           self.fx.fx.original_section['end']])
        self.assertFalse(out['knowledge_truth_or_publication_verified'])

    def test_03_original_ec210_term_search_stays_in_selected_section(self):
        self.configure(projection='match_snippets')
        self.start()
        rc, out = self.query()
        self.assertEqual(rc, 2, out)
        snippets = out['result']['subject']['selected_sections'][0]['matching_lines']
        self.assertEqual(len(snippets), 1)
        self.assertIn('Old API behavior', snippets[0]['excerpt'])
        self.assertNotIn('Original background', json.dumps(out))

    def test_04_private_version_requires_real_ec206_ec207_replay(self):
        version = self.fx.fx.save()
        self.assertEqual(version['status'], 'partial')
        self.configure(projection='full_sections',
                       view='local_metadata_version', version=version)
        self.start()
        rc, out = self.query()
        self.assertEqual(rc, 2, out)
        section = out['result']['subject']['selected_sections'][0]
        self.assertEqual(base64.b64decode(section['section_content_base64']),
                         self.fx.fx.first_section)
        self.assertEqual(self.fx.fx.src.read_bytes(), self.fx.fx.before)
        self.assertEqual(self.fx.fx.api.inspect()['subject']['version_count'], 1)

    def test_05_missing_private_version_evidence_is_signed_unavailable(self):
        self.fx.fx.save()
        self.configure(projection='full_sections', view='local_metadata_version')
        self.start()
        rc, out = self.query()
        self.assertEqual(rc, 5, out)
        self.assertTrue(out['verified_server_signature'])
        self.assertFalse(out['result']['data_disclosed'])
        self.assertIsNone(out['result'].get('subject'))

    def test_06_two_distinct_offline_signatures_and_kernel_uid(self):
        self.start()
        bad = copy.deepcopy(self.grant)
        bad['custodian_signature_ed25519'] = bad['reader_signature_ed25519']
        rc, out = self.query(bad)
        self.assertEqual(rc, 3, out)
        self.assertFalse(out['result']['handler_invoked'])
        bad = copy.deepcopy(self.grant)
        bad['subject']['uid'] = os.getuid() + 1
        rc, out = self.query(bad)
        self.assertEqual(rc, 3, out)
        bad = copy.deepcopy(self.grant)
        bad['subject']['query_request_sha256'] = '0'*64
        rc, out = self.query(bad)
        self.assertEqual(rc, 3, out)

    def test_07_expiry_and_signature_nonreplay(self):
        self.start()
        old = copy.deepcopy(self.grant)
        old['subject']['issued_at_unix'] -= 500
        old['subject']['expires_at_unix'] -= 500
        old = self.make_grant(old['subject'])
        rc, out = self.query(old)
        self.assertEqual(rc, 3, out)
        other = Ed25519PrivateKey.generate()
        bad = self.make_grant(self.subject, {
            'custodian': other, 'reader': self.signers['reader']})
        self.assertEqual(self.query(bad)[0], 3)

    def test_08_job_mutation_revokes_without_disclosing(self):
        self.start()
        # A signed subject is for raw bytes, not a mutable job descriptor.
        self.job_file.write_bytes(self.job_file.read_bytes() + b' ')
        rc, out = self.query()
        self.assertEqual(rc, 5, out)
        self.assertTrue(out['verified_server_signature'])
        self.assertFalse(out['result']['data_disclosed'])

    def test_09_policy_mutation_revokes_without_disclosing(self):
        self.start()
        self.policy_file.write_bytes(self.policy_file.read_bytes() + b' ')
        rc, out = self.query()
        self.assertEqual(rc, 5, out)
        self.assertFalse(out['result']['data_disclosed'])

    def test_10_host_server_identity_verification(self):
        self.start()
        fake = p.public_hex(Ed25519PrivateKey.generate())
        with self.assertRaises(p.HostError):
            self.query(pub=fake)

    def test_11_undergranted_ec210_read_does_not_leak_text(self):
        self.configure(projection='full_sections',
                       policy_changes={'permit_full_section_return': False})
        self.start()
        rc, out = self.query()
        self.assertEqual(rc, 5, out)
        self.assertNotIn('Old API behavior', json.dumps(out))
        self.assertFalse(out['result']['data_disclosed'])

    def test_12_source_markdown_change_blocks_old_pins(self):
        self.configure(projection='full_sections')
        self.start()
        self.fx.fx.src.write_bytes(self.fx.fx.before + b'changed\n')
        rc, out = self.query()
        self.assertEqual(rc, 5, out)
        self.assertFalse(out['result']['data_disclosed'])

    def test_13_disallow_write_escalation_and_overlapping_roots(self):
        self.job['query_policy']['permit_publish'] = True
        with self.assertRaises(p.HostError):
            p.validate_job(self.job)
        self.job['query_policy']['permit_publish'] = False
        self.job['version_root'] = self.job['candidate_root']
        with self.assertRaises(p.HostError):
            p.validate_job(self.job)

    def test_14_offline_votes_and_grant_assembly_real_files(self):
        self.start()
        sf = doc(self.base / 'ec283-subject.json', self.subject)
        votes = {}
        for role in ('custodian', 'reader'):
            vote_path = self.base / ('ec283-' + role + '.vote.json')
            operator.vote(role, str(sf), str(self.keyfiles[role]), str(vote_path))
            votes[role] = vote_path
        out = self.base / 'ec283-assembled.json'
        operator.assemble(str(sf), str(votes['custodian']),
            str(votes['reader']), self.publics['custodian'],
            self.publics['reader'], str(out))
        self.assertEqual(out.read_bytes().strip(), p.canonical(self.grant))
        self.assertEqual(operator.query(socket_path=self.socket,
            grant_file=str(out), policy_sha=self.policy_sha,
            server_public_hex=self.publics['server'])[0], 2)

    def test_15_original_router_default_denial_and_exact_console(self):
        self.start()
        base = [sys.executable, '-I', str(ROOT/'scripts'/'ces_next.py')]
        args = ['host-chapters', 'KnowledgeQuery', 'Chapters',
                '--socket', self.socket, '--grant-file', str(self.grant_file),
                '--policy-sha256', self.policy_sha,
                '--server-public-hex', self.publics['server']]
        output = subprocess.run(base + args, capture_output=True, text=True,
                                timeout=90, check=False)
        self.assertEqual(output.returncode, 2, output.stdout + output.stderr)
        self.assertTrue(json.loads(output.stdout)['verified_server_signature'])
        other = subprocess.run(base + ['host-chapters', 'KnowledgeImpact', 'Analyze',
                *args[3:]], capture_output=True, text=True, timeout=40)
        self.assertEqual(other.returncode, 3)
        requested = subprocess.run(base + ['run', 'KnowledgeQuery', 'Chapters',
                '--request-file', str(self.grant_file)], capture_output=True,
                text=True, timeout=40)
        self.assertEqual(requested.returncode, 3)
        self.assertFalse(json.loads(requested.stdout)['handler_invoked'])

    def test_16_original_query_is_not_replaced_by_a_mock(self):
        # Presence of EC210's own invalid-input response is not a success.
        self.job['query_request']['expected_chapter_sha256'] = '0' * 64
        # Keep the original policy pin: no valid EC210 preview exists for
        # this falsified expected content SHA.
        self.start()
        rc, out = self.query()
        self.assertEqual(rc, 5, out)
        self.assertFalse(out['result']['data_disclosed'])

    def test_17_private_job_builder_inspector_and_cli_inputs(self):
        inputs = {}
        for name, data in (
            ('trusted_approvers', self.job['trusted_approvers']),
            ('query_request', self.job['query_request']),
            ('query_policy', self.job['query_policy']),
        ):
            inputs[name] = doc(self.base / (name + '.json'), data)
        args = argparse.Namespace(**{
            'repository_root': self.job['repository_root'],
            'knowledge_root': self.job['knowledge_root'],
            'candidate_root': self.job['candidate_root'],
            'version_root': self.job['version_root'],
            'candidate_store_id': self.job['candidate_store_id'],
            'version_store_id': self.job['version_store_id'],
            'repository_ref': self.job['repository_ref'],
            'knowledge_space_key': self.job['knowledge_space_key'],
            'period_id': self.job['period_id'],
            'source_policy_revision': self.job['source_policy_revision'],
            'chapter_path': self.job['chapter_path'],
            'trusted_approvers_file': str(inputs['trusted_approvers']),
            'revoked_approvers_file': None,
            'query_request_file': str(inputs['query_request']),
            'query_policy_file': str(inputs['query_policy']),
            'bootstrap_request_file': None,
            'bootstrap_policy_file': None,
            'version_evidence_file': None,
            'out': str(self.base / 'prepared-ec283.json'),
        })
        receipt = operator.prepare_job(args)
        self.assertEqual(receipt['job_sha256'],
            p.sha(Path(args.out).read_bytes()))
        self.assertEqual(io.parse(Path(args.out).read_bytes()), self.job)
        self.assertEqual(Path(args.out).stat().st_mode & 0o777, 0o600)
        self.assertNotIn('trusted_approvers', receipt)
        with self.assertRaises(p.HostError):
            operator.prepare_job(args)  # refuses even byte-identical overwrite
        proc = subprocess.run([sys.executable, '-I',
            str(ROOT / 'scripts' / 'ces_knowledge_chapters_host.py'),
            'inspect-job', '--job-file', args.out],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['query_request_sha256'],
                         p.sha(p.canonical(self.job['query_request'])))

    def test_18_postread_result_requires_consistent_original_hashes(self):
        self.start()
        _, out = self.query()
        valid = out['result']
        self.assertTrue(p.safe_backend_result(valid, projection='hashes_only',
            view='source_snapshot', section_indices=[1]))
        altered = copy.deepcopy(valid)
        altered['subject']['section_fingerprints'][0]['sha256'] = '0'*64
        self.assertFalse(p.safe_backend_result(altered, projection='hashes_only',
            view='source_snapshot', section_indices=[1]))
        altered = copy.deepcopy(valid)
        altered['subject']['selected_sections'][0]['section_content_base64'] = 'AAA='
        self.assertFalse(p.safe_backend_result(altered, projection='hashes_only',
            view='source_snapshot', section_indices=[1]))



if __name__ == '__main__':
    unittest.main()
