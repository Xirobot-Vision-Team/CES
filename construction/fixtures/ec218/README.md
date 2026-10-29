# EC218 — fabricated provider responses, not real authorization

The `test_issue_create_write.py` development suite uses data constructed by
previous EC214–217 **synthetic** fixture builders, public deterministic test
signer bytes, local POSIX SQLite, an injected test clock, and a fake transport.
It never calls GitHub/GitLab or obtains a user/organization credential.

Fake `HTTP 201` matching means `SIMULATED_RESPONSE_MATCHED`, never a real
Issue created, human review performed, duplicate-absence proven or provider
API behavior validated. No real token or private Issue content belongs in
these fixtures. Do not reuse deterministic test signers for authorization.
