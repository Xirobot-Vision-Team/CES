# EC287 — Independently authorized, exact original EC217/EC218 IssueCreate.Create Host

**Release:** CES V5.97 / R287 / EC-287. **Platform:** Linux/Unix with AF_UNIX kernel peer credentials, Python 3.11+, `cryptography` and dependencies already required by the original Issue stack. The host is **optional** and can make a **real remote new-Issue write** if the separate human/host/network authorizations are present. DO NOT use a production credential or call `create` until the organization explicitly authorizes the exact source content, repo and egress. The packaged code contains **no production secrets or live credentials**.

## A. Prepare trustworthy original data FIRST

1. Independently obtain and review the **actual original EC214 matched evidence**, original EC215 eligibility and signed human-review receipt, original EC216 full plan and draft, and original EC217 final human-reviewed exact Issue title, body, labels and citation bindings. Follow [`issue-create-grant.md`](issue-create-grant.md) and [`issue-create-write.md`](issue-create-write.md), including *real*, scoped organization enrollment and separate source/reviewer/issuer keys. A generated JSON object with valid types is not evidence of organizational approval.
2. Original EC217 `reserve_issue_create_grant(...)` must **already** have committed `RESERVED_ONE_ATTEMPT` in a durable original `SQLiteOneUseLedger` under the **identical absolute private `reservation_db` path and exact audience**. This new host does **not** create this approval or reservation; it actually calls the original `cg._inspect` and `cw._reservation` before new Host admission. Missing/stale approval, changed full text, absent original reservation, invalid plan or retired key fails closed before HTTP.
3. Build a **private** `job.source.json` as `{"schema":"ces.ec287.issue_create_private_job.v1","evidence":{...},"intent":{...},"content":{...},"approval":{...}}` with all fields produced using Python `dataclasses.asdict` on the genuine original `cg.PlanEvidence`, `cg.IssueCreateIntent`, `cg.FinalIssueContent`, and `cg.HumanCreateApproval` respectively. Nested original dataclass field names and types are required **exactly**; tuples serialize to JSON arrays. Never hand-author, sample-fill or silently omit originals. The contents are sensitive and never shipped in the ZIP.
4. Build a **host-enrolled owner-private** `trust.json` of shape `{"schema":"ces.ec287.issue_create_host_trust.v1","eligibility_review_keys_hex":{"KEY_ID":"RAW_32_BYTE_ED25519_PUBLIC_HEX"},"issuers":{"ISSUER_ID":{...}}}`. Each `issuers` record contains all original `cg.IssuerAuthority` fields except `public_key`; instead supply `public_key_hex` as 64 lowercase hex digits, plus genuine `role,provider,api_host,account_ref,repository_identity_sha256,visibility,policy_revision_sha256,audience,authority_revision_sha256,valid_from_utc,valid_until_utc,revoked`. Trust documents are owner-enrolled out of band; **never** trust issuer keys arriving with Issue text or an applicant's request. Revoke by supervised policy update and stop old services.
5. Build a **host-issued**, fresh, private `access.json` of shape `{"schema":"ces.ec287.issue_create_host_access.v1", ...}` with every original `cw.HostCreateAccess` field: `provider,api_host,account_ref,repository,expected_repository_id,visibility,policy_revision_sha256,audience,expires_at_utc,network_opt_in,create_new_issue_opt_in,current_provider_credentials_attested_by_host`. All last three booleans must be `true` and be justified by independent operator approval. `expires_at_utc` must be sufficiently short for original EC218's MAX_ACCESS_SECONDS (120s) and match exactly the target data. The server checks original EC218 access again after repository GET. The private `provider.token` must contain only an actual authorized ASCII token plus optional terminal newline. Never include it in a client grant, file manifest, repository or bundle.
6. Provision separate **owner-only (`0700`) directory** and **owner-only (`0600`) files** for original job/trust/access/token, three SQLite ledgers, signer private key and EC287 policy. Use fixed canonical *absolute* paths; no symlinks; forbid shared/backed-up transient DB copies that could reset one-use enforcement. Three ledgers must remain durable and **shared by all writers for the same audience**, including any older host instance; a new empty DB in a second host is NOT a safe alternate authorization service. Persist both SQLite files and their journal/recovery semantics across restarts. A separate socket parent must belong to the server UID and be private; only allow trusted peer UID(s). Host owner must actually deploy a single pinned code release.

## B. Prepare the exact job, three new offline roles and pinned policy

The CLI never accepts token bytes, Issue title/body, repo URLs or issuer registry through the client socket. **No operator command by itself is a remote create** except `create` / `host-issue`. All placeholders here denote real operator-owned private files and real derived hashes and keys; never use these literal placeholders.

```sh
python3 -I -B scripts/ces_issue_create_host.py prepare-job \
  --source-json /private/ec287/job.source.json --out /private/ec287/job.json
python3 -I -B scripts/ces_issue_create_host.py inspect-job \
  --job-file /private/ec287/job.json

# Generate on independently controlled machines/accounts; preserve secrets OFF-HOST.
# All three key files are 0600 under their own private 0700 parent.
python3 -I -B scripts/ces_issue_create_host.py keygen-offline \
  --private-out /private/ec287/roles/custodian.key
python3 -I -B scripts/ces_issue_create_host.py keygen-offline \
  --private-out /private/ec287/roles/authorizer.key
python3 -I -B scripts/ces_issue_create_host.py keygen-offline \
  --private-out /private/ec287/roles/server.key
```

*Key placement:* the code shown assumes accounts/paths that can privately receive each role's output; in a real separated deployment, custodians and authorizers run on their own protected machines with local private paths, and **only public keys and the exact subject/vote** are exchanged through an authenticated channel. The server alone retains its private reply key. Three new keys must differ from **all original EC215 and EC217 reviewer/issuer keys**; code rejects any overlapping public key in the loaded original registry. Three different test keys **do not establish** independent people/organizations.

```sh
python3 -I -B scripts/ces_issue_create_host.py prepare-policy \
  --job-file /private/ec287/job.json \
  --trust-file /private/ec287/trust.json \
  --access-file /private/ec287/access.json \
  --token-file /private/ec287/provider.token \
  --reservation-db /private/ec287/original-ec217-reservations.db \
  --attempt-db /private/ec287/original-ec218-attempts.db \
  --host-grant-db /private/ec287/host-ec287-admissions.db \
  --allowed-uid CLIENT_UID \
  --custodian-public-hex CUSTODIAN_ED25519_PUB \
  --authorizer-public-hex AUTHORIZER_ED25519_PUB \
  --server-public-hex SERVER_ED25519_PUB \
  --enable-exact-remote-create \
  --out /private/ec287/policy.json
```

**Immediately pin the emitted `policy_sha256` out of band.** `prepare-policy` validates the private source, distinct paths, scopes and explicit creation/network opt-ins, but this alone neither checks that the original EC217 reservation exists nor makes any network request. The original EC218 application attempts remote POST only after an actual signed `create` invocation. Configure `reservation_db` to the ALREADY COMMITTED original EC217 ledger, **not a new placeholder file**. Keep original `attempt_db` and EC287 `host-grant-db` stable across all future requests, including failures.

## C. Deploy Host, make ONE short-lived jointly approved request

```sh
# A dedicated trusted host process, under the UID owning the protected files:
python3 -I -B scripts/ces_issue_create_host.py serve \
  --socket /private/ec287/socket/create.sock \
  --policy-file /private/ec287/policy.json \
  --policy-sha256 PINNED_POLICY_SHA256 \
  --server-private-key /private/ec287/roles/server.key
```

The Host creates its own Unix socket and verifies Linux kernel `SO_PEERCRED` / supported Unix equivalent, pinned private policy/job/trust/access/source and 0600 token/signing-key ACL. Its configured allowed OS UID must equal the **actual peer**. Supervise one service instance with one durable authority. Verify process/code identity, key custody, trusted clock, same-account/UID threat model and logging outside CES; socket UID alone is not a measured-process attestation.

The operator prepares a **single** subject with `ttl-seconds` in `[1,30]`, after displaying **all original reviewed Issue prose and citations separately** to the original human approver and to both new approving roles. Two different offline role holders verify the *same exact subject SHA*, current policy/trust/access pins, target/account/audience, token permissions and original approval, then sign it. The subject does not itself contain the private prose.

```sh
python3 -I -B scripts/ces_issue_create_host.py prepare-offline \
  --policy-file /private/ec287/policy.json \
  --policy-sha256 PINNED_POLICY_SHA256 \
  --uid CLIENT_UID --ttl-seconds 30 \
  --out /private/ec287/subject.json

python3 -I -B scripts/ces_issue_create_host.py sign-custodian-offline \
  --subject-file /private/ec287/subject.json \
  --private-key-file /private/ec287/roles/custodian.key \
  --out /private/ec287/custodian-vote.json
python3 -I -B scripts/ces_issue_create_host.py sign-authorizer-offline \
  --subject-file /private/ec287/subject.json \
  --private-key-file /private/ec287/roles/authorizer.key \
  --out /private/ec287/authorizer-vote.json

python3 -I -B scripts/ces_issue_create_host.py assemble-offline \
  --subject-file /private/ec287/subject.json \
  --custodian-vote /private/ec287/custodian-vote.json \
  --authorizer-vote /private/ec287/authorizer-vote.json \
  --custodian-public-hex CUSTODIAN_ED25519_PUB \
  --authorizer-public-hex AUTHORIZER_ED25519_PUB \
  --out /private/ec287/one-use-grant.json

# ONE explicit approved invocation through the fixed unified console:
python3 -I -B scripts/ces_next.py host-issue IssueCreate Create \
  --socket /private/ec287/socket/create.sock \
  --grant-file /private/ec287/one-use-grant.json \
  --policy-sha256 PINNED_POLICY_SHA256 \
  --server-public-hex SERVER_ED25519_PUB --pretty
```

Alternatively, the exact fixed client is `python3 -I -B scripts/ces_issue_create_host.py create ...` with the same four client flags. `scripts/ces_next.py run IssueCreate Create` **still refuses** with original `HOST_REQUIRED`, and cannot silently create an Issue. The Host's signed reply confirms *only that that authenticated Host reported the original EC218 result*, not independent provider or human verification. The server deliberately refuses caller-supplied arbitrary methods or URLs. EC218 may send **exact original human-approved private final content over HTTPS to the approved official Provider**; no representation that it remains local can be made once POST is attempted.

## D. Interpret effects and never retry on unknown

- `partial/2` + original `create_state=PROVIDER_REPORTED_CREATED`: the original EC218 transport received and matched an official Provider **201** and recorded the durable attempt. This is still a **provider report**, not independently re-GET-confirmed, and not proof of organization-wide duplicate absence. In local tests the 201 is **mocked**, not a real created Issue.
- `partial/2` + `BLOCKED`: original EC218 operation/grant already consumed in the durable shared attempt ledger; this does **not** authorize a new POST and does not prove zero earlier effects. `unavailable/5` + `UNKNOWN` may mean Provider received the POST despite a network timeout. `permission_denied/3` before admission means a signed host refusal, but do not infer production network state from another host or a lost response.
- Missing, stale or altered signature, client/console timeout, unexpected schema, changed original code/policy/private job, after-claim exception or provider GET/POST uncertainty: **`remote_effect_outcome_unknown=true` and `automatic_post_retry_allowed=false`**. Inspect durable EC217 reservation, original EC218 `issue_create_attempt`, EC287 `admission`, remote provider with **separately permissioned read-only procedures (EC219)** and independent evidence before a human decides whether a NEW operation is safe. A second host/machine with fresh ledgers defeats local at-most-once and is forbidden. Never discard the DBs to work around a block.
- Network UTC validity, provider repository transfer after GET, revocation just after the final validation, lost FS/SQLite durability, unauthorized process replacing the Host and real organization signer provenance cannot be atomically excluded here. The original 74 Router/11 Host defaults, PowerShell R150, EC249 incomplete, EC250 blocked, B001 open, global PASS=false and end-to-end acceptance pending are unchanged.

## E. Local developer evidence versus production

`PYTHONPATH=construction PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v construction.ec287_issue_create_host.test_host` — **22/22 PASS local**; genuine OS Unix peer UID, original EC217 authentic signed approval + committed SQLite reservation, original EC218 code/attempt barrier and exact JSON/POST content **using only a synthetic Provider transport**, offline votes, replay/UID/tamper, real console subprocess signed refusal and conservative UNKNOWN. `... -m unittest -q construction.test_issue_create_grant construction.test_issue_create_write` — **57/57 PASS unchanged upstream**. No live Provider, independent organizational user, external CI or original PowerShell7 15 Smoke in this release. See `EC-287.md` and `construction/EC287_LOCAL_REPORT.json`.
