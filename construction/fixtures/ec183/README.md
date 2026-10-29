# EC183 development-only synthetic fixtures

`construction/test_quality_sha_bind.py` constructs all GH/GL Provider responses in memory and injects explicit fake transports. It exercises DeliveredTarget branch SHA, same-repository open PR/MR head, immutable project IDs, commit endpoint membership fields, rechecking source after a fresh EC182 re-read, per-endpoint permission decisions, stale/tampered input receipts, changed CI attempts/job metadata, PR forks/merge-SHA mismatches, output refusal privacy and synthetic/live separation. No live Provider, actual Git object, on-disk business repository, runner or external token is accessed by the tests.

Run `python -m unittest construction/test_quality_sha_bind.py` from the `ces/` package only after exposing `construction` in `PYTHONPATH`, or run `cd construction && python -m unittest test_quality_sha_bind -q`.

Schema-only checks use `references/quality-sha-bind-result.v1.schema.json` (Draft 2020-12) against constructed synthetic GH/GL positives, refusal and deliberately falsified execution/association claims. They do **not** authenticate source provenance. Genuine remote/network races and final native/manual acceptance remain deferred.
