# EC221 synthetic local fixture boundary

The focused tests `../..//test_delivery_preview.py` create **disposable** EC199/EC200
owner-private report stores and EC178/EC179 HMAC Finding stores through the
existing test fixture builders. Their report claims, reviewer IDs, contents,
source anchors, recipient hashes and policy receipts are fictitious. They are
**not proof** of external human consent, account ownership, reliable CI/Git
provenance, released content, or any real delivery.

Tests exercise saved-version SHA bindings, required fresh local preview and
private metadata/content/digest permissions, exact Finding scoped HMAC queries,
recipient identity hash isolation, conservative privacy, redacted fixed-template
output, full failure on stale/unavailable sources, and no send/publish flags.

No real recipient/email address, provider credentials, network calls, remote
work item, ReportPublish, docs-only commit, external AI, or business-code write
is needed or included. The complete R221 ZIP retains every R220 file.
