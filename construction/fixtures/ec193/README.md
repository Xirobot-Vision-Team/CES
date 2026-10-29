# EC193 local fixtures and development scope

The actual feature is `../repository_report_subject.py` (read-only, standard library + EC192 natural period). The compact unittest scenarios live in `../test_repository_report_subject.py`, with Python Draft2020-12 contract checks against `../../references/repository-report-subject-result.v1.schema.json`.

Coverage: three explicit source modes; report key separation; case-sensitive namespaced repository keys distinct from location; POSIX and Windows-drive lexical-only locators; URL credential/query/traversal refusal; purported Git sha1/sha256/receipt fields that never become trusted proof; no source-mode promotion; exact day DST/ISO-week boundaries replayed from EC192; strict UTC `[start,end)` subset and empty/out-of-window refusal; explicit path selectors, exclusions, normalized order, duplicate/nested scope refusal; stable slot vs mutable coverage/binding hash; safe null-on-error; byte-canonical replay/tamper/period drift refusal. This is synthetic contract development, not real host, provider, git, FS or authoritative report testing.

Example: `cd ces/construction && python -m unittest -q test_repository_report_subject`.

**Deferred**: privileged repo locator resolution / symlink and common-dir attestation; real Git OID availability/commit trust; provider PR and delivered release authenticity; persisted receipts/signatures; report content coverage and actor identity; multi-repository federation; Windows/macOS/Linux independent cases; real tzdb policy versions; native PowerShell7/15 Smoke; CI, E63–E66 and final assisted user acceptance. All remain **NOT_RUN**; never promote the unittest result to business PASS.
