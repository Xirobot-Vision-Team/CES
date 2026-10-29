# EC-156 synthetic response examples

All six JSON files in this folder are **fabricated test inputs**, not
CES runtime records and not proof of any Git/repository state. The
`coverage=true` values in the Inspect examples are illustrative only;
**no repository was checked**. Every example includes an explicit
synthetic message/warning and no real Git IDs, paths or audit evidence.

Files demonstrate the five wire statuses (success, partial,
not_implemented, invalid_input, unavailable) plus CodeSave's authorization
denial, in which `read_only=false` merely means the action could write
CES-owned metadata if separately authorized. No fixture is an authorization.

Run the consumer without starting CES:

```bash
python construction/response_contract.py inspect --input construction/fixtures/ec156/partial.json --process-exit 2 --json
python construction/response_contract.py inspect --input construction/fixtures/ec156/codesave_denied.json --process-exit 4 --json
```

These synthetic envelopes are not native PowerShell Smoke test results.
