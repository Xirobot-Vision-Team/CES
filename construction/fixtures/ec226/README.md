# EC226 — ephemeral synthetic status observation fixtures

`test_delivery_status.py` creates disposable Ed25519 keys and runs the true
EC200 -> EC221 -> EC222 -> EC223 -> EC224 -> EC225 **local** code path on
fake private stores. It makes exactly one in-memory synthetic EC225 Provider
submit, then separately signs simulated provider ACCEPTED/DELIVERED status
statements and, where required, independent test-inbox observer statements.

All accounts, keys, read grants, tokens, route IDs and receipt timestamps are
synthetic test doubles, NOT real organization identities, tokens, inbox access,
external delivery proof or qualified authentication material. No network
request is made; code forces `allow_synthetic_transport_for_development=True`
for both components. Do not import these fixtures into any live Provider or
reuse their signer assumptions with actual customers/recipients.

The synthetic status fake NEVER calls Provider `/submit` or any other write
endpoint and tests require EC225's `03_SUBMIT_ATTEMPTED` protected local
marker. The local folder stores only test-related empty marker files that
are cleaned with the temporary directory. `pytest`, PowerShell, production
provider, OS crash/NFS/multi-host and final acceptance are not implied.
