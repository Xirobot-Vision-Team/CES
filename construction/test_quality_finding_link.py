#!/usr/bin/env python3
"""EC189 development-only checks: actual EC179 signed ledger + EC188 code.

All project/provider/reviewer/reproduction inputs are local synthetic fixture
claims. Even a passing case is not proof of a live CI job, source equivalence,
real tests, actual defect, native CLI integration or multi-OS suitability.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import json
from pathlib import Path
import unittest

import jsonschema

import finding_show
import quality_show
import quality_ci_evidence as ci_evidence
import test_finding_show as ftest
import test_quality_show as qtest
from quality_finding_link import QualityFindingLinker, SCHEMA, canonical

SCHEMA_DOC = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                         'quality-finding-link-result.v1.schema.json').read_text())
NOW_KEY = b'EC189-development-note-key-32-bytes-minimum'


def reprove(receipt, state):
    """Synthetic provider-claimed state and producer's REAL checksum algorithm."""
    result = receipt['result']
    result['classification'] = state
    result['test_evidence']['state'] = state
    result['test_evidence']['preview'] = 'SECRET=synthetic_hidden'
    result.pop('evidence_sha256')
    fields = {k: v for k, v in result.items() if k not in
              ('schema', 'status', 'exit_code', 'reason_code', 'trust_boundary')}
    result['evidence_sha256'] = ci_evidence.digest(fields)


class LinkCases(unittest.TestCase):
    def setUp(self):
        self.f = None
        self.begin()

    def begin(self, *, historical=False, signed=('confirm',), with_counter=False):
        # Always allocate a new sealed-stage fixture when switching source or
        # review state; EC172's operation keys intentionally reject reentry
        # with a different immutable source/revision on an existing stage.
        if self.f is not None:
            self.f.doCleanups()
        self.f = ftest.FindingShowCases(
            'test_real_sealed_store_query_has_semantic_boundaries_and_no_plaintext')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.start_finding(signed=signed, historical=historical)
        if with_counter:
            anchor = self.f.outcome['result']['findings'][0]['anchors'][0]
            counter = [{'ordinal': 1, 'anchors': [{
                'segment_index': anchor['segment_index'],
                'item_index': anchor['item_index'],
                'line_number': anchor['line_number_in_segment_or_item'],
                'quote': anchor['quote']}],
                'interpretation': 'This is a synthetic caller counterexample, NOT proof.'}]
            projected = self.f.project(counter_evidence=counter)
            self.assertEqual(projected['status'], 'partial', projected)
            self.f.save_args.update({
                'projection_kwargs': dict(self.f.proj_kw, counter_evidence=counter),
                'expected_projection_sha256': projected['projection_sha256']})
        opts = {'allow_non_reviewed': True, 'acknowledge_non_reviewed': True} if signed != ('confirm',) else {}
        self.assertEqual(self.f.commit(**opts)['status'], 'partial')
        self.f.show = finding_show.FindingShower(
            str(self.f.root), str(self.f.repo), str(self.f.ledger_root), clock=self.f.clock)
        self.mode = 'ProposedPR' if historical else 'WorkingTree'
        self.scope = (copy.deepcopy(qtest.PROPOSAL) if historical
                      else copy.deepcopy(qtest.LOCAL))
        self.evidence = [qtest.sample('ci_evidence', scope=self.scope)] if historical else [
            qtest.sample('config', scope=self.scope)]
        self.qview = quality_show.QualityShow(cursor_key=b'E' * 32, clock=self.f.clock)
        self.linker = QualityFindingLinker(self.qview, self.f.show,
                                           note_reference_key=NOW_KEY, clock=self.f.clock)
        self.calls = {'bridge': [], 'pair': [], 'scope': [], 'item': []}
        def grant(kind):
            def go(facts):
                self.calls[kind].append(facts)
                return True
            return go
        self.args = {
            'source_scope': self.scope, 'evidence': self.evidence,
            'finding_source_binding': dict(self.f.preview['source_binding']),
            'expected_finding_store_pin': self.f.ledger_pin,
            'associations': [self.pair()],
            'allow_link': True, 'allow_quality_query': True,
            'allow_quality_evidence_read': True, 'allow_finding_store_read': True,
            'allow_finding_query': True, 'allow_finding_digest_details': True,
            'authorize_source_bridge': grant('bridge'),
            'authorize_association': grant('pair'),
            'authorize_quality_scope': grant('scope'),
            'authorize_quality_evidence': grant('item'),
            'acknowledge_historical_proposal': historical,
        }

    def pair(self, *, index=0, direction='context', state='NOT_ATTEMPTED', statement=None):
        q = self.evidence[index]
        evidence_id = quality_show.digest(quality_show.DOMAIN_RECORD, q)
        return {'finding_id': self.f.preview['findings'][0]['finding_id'],
                'quality_evidence_id': evidence_id,
                'direction': direction, 'rationale': 'SHARED_HYPOTHESIS_UNVERIFIED',
                'reproduction': {
                    'state': state, 'statement': statement,
                    'reported_at_utc': self.f.clock.value.strftime('%Y-%m-%dT%H:%M:%SZ')
                    if state != 'NOT_ATTEMPTED' else None}}

    def run_link(self, **changes):
        opts = dict(self.args)
        opts.update(changes)
        result = self.linker.link(**opts)
        jsonschema.Draft202012Validator(SCHEMA_DOC).validate(result)
        return result

    def denied(self, response, code=None):
        self.assertIn(response['status'], ('invalid_input', 'unavailable'), response)
        self.assertEqual(response['links'], [], response)
        self.assertIsNone(response['scope'], response)
        self.assertIsNone(response['quality_revision_sha256'], response)
        self.assertIsNone(response['finding_revision_sha256'], response)
        self.assertFalse(response['effects']['finding_created_or_modified'])
        if code:
            self.assertEqual(response['reason_code'], code, response)

    def test_real_local_config_and_stored_review_only_context(self):
        r = self.run_link()
        self.assertEqual((r['status'],r['exit_code']),('partial',2),r)
        self.assertEqual(r['counts']['links'],1)
        item = r['links'][0]
        self.assertEqual(item['finding']['assessment_state'],'REVIEWED')
        self.assertEqual(item['quality']['kind'],'config')
        self.assertEqual(item['relationship']['assessment'],'CONTEXT_ONLY_NO_CAUSAL_FINDING')
        self.assertFalse(item['declared_defect_confirmed'])
        self.assertFalse(r['coverage']['independent_same_source_content_attestation'])
        self.assertGreaterEqual(len(self.calls['scope']),4)
        self.assertGreaterEqual(len(self.calls['item']),2)
        self.assertEqual([c['phase'] for c in self.calls['bridge']],['BEFORE_READ','FINALIZE'])
        self.assertEqual([c['phase'] for c in self.calls['pair']],['BEFORE_READ','FINALIZE'])

    def test_positive_failed_ci_is_only_potential_support(self):
        self.begin(historical=True)
        reprove(self.evidence[0], 'fail')
        r = self.run_link(associations=[self.pair(direction='support')])
        self.assertEqual(r['status'],'partial',r)
        self.assertEqual(r['counts']['possible_support_claim_links'],1)
        self.assertEqual(r['links'][0]['quality']['declared_claim_signal'],'FAILURE_CLAIM')
        self.assertEqual(r['links'][0]['relationship']['assessment'],
                         'POTENTIAL_SUPPORT_NEVER_DEFECT_PROOF')
        self.assertTrue(r['scope']['historical_proposal_only'])
        self.assertTrue(r['links'][0]['finding']['historical_proposal_only'])
        self.assertFalse(r['effects']['defect_confirmed'])

    def test_passing_provider_content_is_counterevidence_not_exoneration(self):
        self.begin(historical=True,with_counter=True)
        r = self.run_link(associations=[self.pair(direction='counter')])
        self.assertEqual(r['status'],'partial',r)
        item = r['links'][0]
        self.assertEqual(item['quality']['declared_claim_signal'],'PASS_CLAIM')
        self.assertEqual(item['relationship']['assessment'],
                         'POTENTIAL_COUNTEREVIDENCE_NEVER_EXONERATION')
        self.assertEqual(item['finding']['counter_evidence_count'],1)
        self.assertEqual(len(item['finding']['counter_evidence_annotation_sha256']),1)
        self.assertFalse(item['relationship']['underlying_causal_link_proven'])

    def test_reproduction_reference_is_keyed_and_never_exposes_sensitive_text(self):
        text = 'secret=/private/project/path; password=TOP_SECRET; steps: foo\nbar'
        pair = self.pair(state='REPRODUCED_REPORTED_UNVERIFIED', statement=text)
        r = self.run_link(associations=[pair])
        self.assertEqual(r['status'],'partial',r)
        note = r['links'][0]['reproduction']
        self.assertRegex(note['private_statement_reference_mac_sha256'],r'^[0-9a-f]{64}$')
        self.assertEqual(note['state'],'REPRODUCED_REPORTED_UNVERIFIED')
        self.assertFalse(note['reproduced_or_disproved_by_ces'])
        raw = json.dumps(r)
        for fragment in ('TOP_SECRET','/private/project/path','foo\\nbar','read-only.py',
                         'synthetic-reviewer','+new'):
            self.assertNotIn(fragment,raw)
        other = QualityFindingLinker(self.qview,self.f.show,
                                     note_reference_key=b'R'*32, clock=self.f.clock)
        self.assertNotEqual(other.link(**self.args | {'associations':[pair]})['links'][0]
                            ['reproduction']['private_statement_reference_mac_sha256'],
                            note['private_statement_reference_mac_sha256'])

    def test_support_direction_requires_failed_claim(self):
        self.denied(self.run_link(associations=[self.pair(direction='support')]),
                    'QUALITYFINDING_DIRECTION_NOT_SUPPORTED_BY_EVIDENCE_CLAIM')

    def test_counter_direction_requires_pass_claim(self):
        self.begin(historical=True)
        reprove(self.evidence[0], 'fail')
        self.denied(self.run_link(associations=[self.pair(direction='counter')]),
                    'QUALITYFINDING_DIRECTION_NOT_SUPPORTED_BY_EVIDENCE_CLAIM')

    def test_rejected_finding_may_be_context_but_not_reconfirmed_by_ci(self):
        self.begin(historical=True,signed=('reject',))
        reprove(self.evidence[0],'fail')
        self.denied(self.run_link(associations=[self.pair(direction='support')]),
                    'QUALITYFINDING_REJECTED_FINDING_CANNOT_GAIN_SUPPORT')
        r = self.run_link(associations=[self.pair()])
        self.assertEqual(r['links'][0]['finding']['assessment_state'],'REJECTED')
        self.assertFalse(r['links'][0]['declared_defect_confirmed'])

    def test_unsigned_review_state_is_preserved(self):
        self.begin(signed=None)
        r = self.run_link()
        self.assertEqual(r['status'],'partial')
        self.assertEqual(r['links'][0]['finding']['assessment_state'],'UNVERIFIED')

    def test_missing_new_opt_ins_are_denied(self):
        for key in ['allow_link','allow_quality_query','allow_quality_evidence_read',
                    'allow_finding_store_read','allow_finding_query','allow_finding_digest_details']:
            self.denied(self.run_link(**{key:False}),
                        'QUALITYFINDING_SIX_SEPARATE_OPT_INS_REQUIRED')

    def test_bridge_and_pair_denial_do_not_return_partial_links(self):
        self.denied(self.run_link(authorize_source_bridge=lambda _facts:False),
                    'QUALITYFINDING_HOST_SOURCE_BRIDGE_NOT_AUTHORIZED')
        self.denied(self.run_link(authorize_association=lambda _facts:False),
                    'QUALITYFINDING_PAIR_NOT_AUTHORIZED')

    def test_bridge_revocation_finalization_is_fatal(self):
        self.denied(self.run_link(authorize_source_bridge=lambda f:
                    f['phase']=='BEFORE_READ'),
                    'QUALITYFINDING_SOURCE_BRIDGE_REVOKED')

    def test_association_revocation_finalization_is_fatal(self):
        self.denied(self.run_link(authorize_association=lambda f:
                    f['phase']=='BEFORE_READ'),
                    'QUALITYFINDING_PAIR_PERMISSION_REVOKED')

    def test_upstream_authorizers_still_enforced_even_with_bridge(self):
        self.denied(self.run_link(authorize_quality_scope=lambda _facts:False),
                    'QUALITYFINDING_QUALITYSHOW_REQUERY_REFUSED')
        self.denied(self.run_link(authorize_quality_evidence=lambda _facts:False),
                    'QUALITYFINDING_QUALITYSHOW_REQUERY_REFUSED')

    def test_wrong_finding_store_pin_or_source_binding_cannot_forge_a_finding(self):
        self.denied(self.run_link(expected_finding_store_pin='1'*64),
                    'QUALITYFINDING_FINDINGSHOW_REQUERY_REFUSED')
        wrong = dict(self.args['finding_source_binding'])
        wrong['source_context_sha256'] = 'f'*64
        self.denied(self.run_link(finding_source_binding=wrong),
                    'QUALITYFINDING_FINDING_MISSING_OR_LEDGER_CHANGED')

    def test_cross_source_mode_refused_before_query_even_with_bridge(self):
        wrong = dict(self.args['finding_source_binding'], source_mode='DeliveredTarget')
        self.denied(self.run_link(finding_source_binding=wrong))
        self.assertEqual(len(self.calls['bridge']),0)

    def test_historical_proposal_requires_new_ack(self):
        self.begin(historical=True)
        self.denied(self.run_link(acknowledge_historical_proposal=False),
                    'QUALITYFINDING_HISTORICAL_PROPOSAL_ACK_REQUIRED')

    def test_expired_finding_refused_instead_of_resurrecting(self):
        self.f.clock.value += timedelta(seconds=360)
        # An existing exact HMAC batch is now expired; no context resurrection.
        self.denied(self.run_link(), 'QUALITYFINDING_FINDING_MISSING_OR_LEDGER_CHANGED')

    def test_duplicate_pair_and_untrusted_reproduction_invalid(self):
        pair = self.pair()
        self.denied(self.run_link(associations=[pair,pair]),
                    'QUALITYFINDING_DUPLICATE_PAIR_FORBIDDEN')
        bad = copy.deepcopy(pair)
        bad['reproduction']['statement']='secret for NOT_ATTEMPTED'
        self.denied(self.run_link(associations=[bad]),
                    'QUALITYFINDING_UNATTEMPTED_REPRODUCTION_MUST_BE_EMPTY')
        bad = self.pair(state='ATTEMPT_REPORTED_UNVERIFIED',statement='A'*2050)
        self.denied(self.run_link(associations=[bad]),
                    'QUALITYFINDING_REPRODUCTION_STATEMENT_INVALID')

    def test_missing_or_cross_scope_quality_receipt_fails_closed(self):
        wrong = self.pair()
        wrong['quality_evidence_id']='e'*64
        self.denied(self.run_link(associations=[wrong]),
                    'QUALITYFINDING_SELECTED_EVIDENCE_NOT_IN_AUTHORIZED_BATCH')
        modified = copy.deepcopy(self.evidence)
        modified[0]['source_scope']['root_pin_sha256']='e'*64
        self.denied(self.run_link(evidence=modified),
                    'QUALITYFINDING_QUALITYSHOW_REQUERY_REFUSED')

    def test_independent_per_evidence_grants_on_every_paginated_quality_page(self):
        # 30 exact source-bound records trigger a second actual EC188 page.
        extra = []
        for i in range(30):
            row = qtest.sample('config',scope=self.scope)
            row['recorded_at_utc'] = (
                self.f.clock.value - timedelta(seconds=i+1)).strftime('%Y-%m-%dT%H:%M:%SZ')
            extra.append(row)
        self.evidence = extra
        self.args['evidence'] = extra
        r = self.run_link(associations=[self.pair(index=29)])
        self.assertEqual(r['status'],'partial',r)
        self.assertEqual(r['counts']['scoped_quality_receipts_read'],30)
        self.assertGreaterEqual(len(self.calls['item']),30*3) # two pages + final first
        self.assertEqual(r['counts']['links'],1)

    def test_insertion_during_query_invalidates_quality_snapshot(self):
        called = [0]
        def mutate(facts):
            called[0]+=1
            if called[0]==1:
                self.evidence.append(copy.deepcopy(self.evidence[0]))
            return True
        self.denied(self.run_link(authorize_quality_scope=mutate),
                    'QUALITYFINDING_QUALITYSHOW_REQUERY_REFUSED')

    def test_inputs_and_reviews_not_mutated_by_linker(self):
        snapshot = canonical({'evidence':self.evidence,'association':self.args['associations'],
                              'source':self.args['finding_source_binding']})
        before = [p.read_bytes() for p in self.f.files()]
        r = self.run_link()
        self.assertEqual(r['status'],'partial')
        self.assertEqual(snapshot,canonical({'evidence':self.evidence,
            'association':self.args['associations'], 'source':self.args['finding_source_binding']}))
        self.assertEqual(before,[p.read_bytes() for p in self.f.files()])
        self.assertFalse(r['effects']['ces_store_written'])


if __name__=='__main__':
    unittest.main(verbosity=2)
