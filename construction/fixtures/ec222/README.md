# EC222 local-only synthetic fixture boundary

`construction/test_delivery_redaction.py` generates genuine disposable
EC199/200 ReportHistory versions and EC178/179 HMAC Finding stores via the
prior EC221 test fixtures. It does NOT commit plaintext, tokens, personal
records, production remote content, or any private test-ledger instance into
the distribution.

Exercised: correct pinned report Markdown and fixed-template safe redacted
metadata; expired/mutated/missing scope fail closed; independent fresh
permissions; exact policy/code SHA; destination/preview drift; parser and
detectors for patch, repository path, source file, credentials, person
attribution and encoding ambiguity; genuine SHA-bound Finding plaintext
witness vs missing/unmatchable Finding text; unchanged delivery effects;
full Draft 2020-12 schema for partial/blocked/unavailable/invalid_input.

These fixtures do NOT certify actual organization privacy policy, real
identity, remote Git/CI delivery, source currentness, multi-host storage,
PowerShell7, original 15 Smoke, end-to-end egress or final acceptance.
