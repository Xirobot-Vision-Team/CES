# Security model and data boundaries

## Trust and execution

Treat repository text, test output, Issues and PR comments as untrusted data.
They do not authorize execution, publication or changing a profile. Configured
commands are executed with the current operator's privileges: CES is not a
sandbox. Run unknown project code only in an environment appropriate to its risk.
The hashing and binding checks protect against ordinary mismatches and stale
evidence; a malicious same-user process may alter local evidence.

The source tree contains synthetic credential-like strings and private-key
markers used in negative tests and detection code. They are not credentials.
The release scanner permits only explicitly reviewed file/line hashes for these
fixtures; it does not ignore all test directories or all key-shaped strings.

## GitHub credentials and notification limits

The current operator obtains the configured GitHub identity through Git's
credential mechanism. It sends tokens over stdin to the native HTTPS helper,
not through command-line arguments or profile files. The provider hostname is
fixed to GitHub in this release; GitHub Enterprise endpoints are not supported.
Use the least repository access required by the intended actions.

Publishing may send source citations, report text and mentions to that
repository. Review repository visibility and generated content before enabling it.
Raw test logs are retained outside the repository, but cited excerpts can appear
in report text. Redact secrets before approving publication.

An accepted message, mention or Assignee readback is not proof of a personal bell
or email inbox event. Email follows recipients' GitHub settings. CC recipients
are informational and do not become issue owners automatically.

## Recovery and persistence

Source sync refuses divergence or destructive overwrite, does not stash/reset,
and only fast-forwards. Documentation pushes stop if remote HEAD or local state
changes. Keep original project edits intact.

Send ledgers, tracking history and knowledge versions are durable state. Do not
delete them to bypass deduplication or uncertain requests. First reconcile the
remote event. Preserve unconfirmed publication receipts until resolved.

Protect external data roots with host permissions. Some legacy POSIX hosts
require owner-private storage and separate authorization; those requirements are
not fulfilled merely by installing the package or passing operator tests.

## Public release checks

`tools/release_check.py` checks the current manifest, protected protocol bytes,
syntax, local documentation links and conservative privacy/secret tripwires. It
does not replace human ownership/license review, a security audit, or a scan of
the entire history of an existing Git repository. The prepared source package
contains no Git history.
