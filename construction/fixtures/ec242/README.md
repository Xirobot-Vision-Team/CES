# EC242 fixtures — synthetic structure only

Each `*-v1.json` is an **invented, locally validated contract-shaped** example,
not a true business producer result. Empty findings, false permission/proof
claims, zero hashes, and synthetic Ed25519-looking text are not attestations.
The Issue `issue-v1.json` deliberately has an invented, unverified signature:
passing a JSON Schema only proves shape. The `issue-unversioned.json` sample
has no top-level version marker by the old EC217 contract's design; EC242
requires explicit `--contract issue-create-content.v1` and responds
`EXPLICIT_CONTRACT_SHAPE_ONLY_NO_VERSION_MIGRATION` rather than claiming
versioned read compatibility. This fixture set must never be accepted as a
real approval, verified source, live provider observation, or trusted Cycle run.

Synthetic CodeInsight is covered by the pre-existing
`construction/fixtures/ec158/ci-example.json` and its genuine *offline*
legacy shape reader, which intentionally does not attest source authenticity.
