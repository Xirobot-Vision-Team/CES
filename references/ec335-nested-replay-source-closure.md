# EC335 — Signed-replay-observed nested source closure / offline receiver protocol

## Contract and reason for this EC

EC334's first-hop private inventory pins direct handoff/manifest/report/ledger/receipt sources, but nested EC317/318 originals may be materialized only while deeper old verifier code replays signed ZIPs. Trying to collect every path token out of all JSON files would generate false provenance, arbitrary-path filesystem reads, and nonexistent temporary sources. **EC335 instead records what the production verifier genuinely reads under the existing guarded source-read observer.** It then separates persistent copyable files from ephemeral unpacked original bytes, and audits embedded `ZIP_STORED` member byte chains inside copyable whole ZIP originals.

### Source authenticity and observer

- `create-closure` takes independently entrusted **EC334 plan SHA**, **EC333 handoff SHA**, **left manifest SHA**, **right manifest SHA**, original absolute paths and an explicit source root. The four caller claims must agree with the original EC334 inventory.
- It calls existing `ec333_replayable_delta_handoff.handoff.verify_handoff` in a scoped EC317 original-read observer, requires its existing true replay and reconstructed-original assertions, and refuses error/denial/missing original source.
- The callback hashes only the actual protected raw bytes (`path`, `bytes`) while discarding old raw content. Repeated reads of the same path must match; bounds on total events/source count/bytes avoid unbounded memory use. The required EC334 first-hop original set must occur as an exact SHA-and-length subset of observed persistent sources.
- Some historic old verifiers unpack a protected ZIP into a private `tempfile` directory and delete it before return. Only a narrow set of known verifier-specific temporary directory prefixes whose files no longer exist may be excluded as independently copyable sources, and their count and read events are disclosed. Any other unaccounted/missing historical path fails closed. Excluding these ephemeral copies is **not** permission to silently omit genuine persistent originals.
- The source-root must contain every persistent source path. The owner must preserve historic signed path-sensitive bytes unchanged; the tool never rewrites the old certificates or signature envelopes.

### Closure v1 exact document fields

Schema `ces.ec335.bounded_signed_replay_observed_original_read_closure.v1` is canonical JSON LF, private `0600` with exclusive creation. Top-level `sources` are unique and absolute-path sorted. Each source entry contains `source_path`, `source_original_raw_sha256`, `byte_length`, `evidence_tier`, `first_hop_roles`, `original_format`.

Evidence tiers:

| Tier | Meaning | Is it an independent external trust anchor? |
|---|---|---|
| `caller_supplied_separate_root_sha_claim_not_custody_proof` | handoff/left/right root digest, separately *claimed* by caller | **Not attested by this CLI** |
| `ec334_checked_inherited_source_digest_not_independent_custody` | an EC334 first-hop digest linked to previously checked inherited signed material | No separate real-world custodian proof |
| `locally_measured_after_signed_replay_no_independent_source_pin` | deeper observed source digest captured at replay | **No** |

`references` contain only declared, observed `parent_source_path -> child_source_path` JSON file-reference edges and whether declared child raw SHA matches. These are descriptive hints. A path to a non-observed source increments `unobserved_declared_path_reference_count`; it is neither read nor automatically trusted. `runtime_only_unlinked_source_count` discloses unlinked deeper observed sources. ZIPs remain canonical whole-file transport originals; `embedded` entries additionally name `owner_source_path`, `member_chain` (ordered nested names), `embedded_raw_sha256`, `byte_length`, `original_format`; `embedded_original_member_count`, `embedded_total_byte_length`, and `opaque_original_zip_count` are explicit. Ephemeral exclusions have source- and read-event counts. The offline outcome is `2` and all seven overclaim flags remain false by contract.

### Nested ZIP byte behavior and bounded limits

Only `ZIP_STORED` regular, non-directory, non-symlink entries with safe relative paths, no duplicate names, empty archive comment, bounded size, and no encrypted/unsupported flag are included. Nested ZIP members recurse at most 6 levels; path traversal, unsupported metadata, compression bombs and oversized inputs are refused. Limits: max 2,048 distinct source files, 100,000 guarded read events, 512 million cumulative original bytes, 8,192 reference edges, 4,096 embedded members, 512 million embedded original bytes, 4,096 entries per ZIP, 3.2MB closure JSON, 750KB mapping JSON, individual original size inherited from EC334. These are design limits, **not proof of semantic completeness** for malformed/unknown historical archive formats.

### Mapping and independent destination audit

The source-side `prepare-map` takes independently entrusted first-hop SHA/closure SHA and two distinct canonical absolute source/destination roots. It creates a private canonical map with exactly one `locations` source→destination row per closure `source`, in closure order, rejecting aliases, duplicates, controls/source files, and traversal. **No data copying occurs.** Source writes and map writes are independent standalone actions, never exposed by the unified entrypoint.

On receiver, only three independently obtained full raw SHA anchors for the **first-hop plan**, **closure** and **mapping** are accepted along with the three original JSON control documents. Receiver calls existing secure original-load/pin helpers for exact schema, SHA, lengths, owner-private file properties, and canonical bytes; checks every mapped destination source byte twice, recursively re-opens copied ZIP whole-byte containers and recalculates embedded member chains, then re-pins all three control documents. It is deliberately independent of old source paths; **it cannot run old path-sensitive signed-history validation** because those original references still name the old absolute paths. A receiver success means `all_observed_nested_original_copy_bytes_match_unresolved`, exit 2, only.

### Trust boundaries, non-goals and honest validation

The operator never manufactures external trusted SHA anchors, signature custody, institution approvals, remote no-submission, signed readback, linearizable global CAS/WORM, global latest/winner, or a transactionally consistent filesystem snapshot. Old signatures are never edited, newly accepted, reissued, or rebound. The local tests cover actual eighth/ninth Ed25519 signature creation and guarded-read topology but **inherit MOCK EC317/318 deep historical signature fixtures**. True production isolated source creation fails closed on those mocks; production unmocked chain and multi-device delivery are **NOT_PROVEN**. A future EC may add explicitly anchored path-independent original-byte bundles and a truly independent replayable receiving-side signature proof, but EC335 must not be described as providing either.

Source code: `construction/ec335_nested_source_closure/closure.py`, `operator.py`, `scripts/ces_cas_relocation_closure.py`; fixed read-only unified route `scripts/ces_next.py`.
