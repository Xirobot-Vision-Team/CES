# Security policy

CES can read repository content, run explicitly configured commands and publish
to GitHub. It is an operator tool, not a security sandbox. Review the
[threat model](docs/SECURITY_MODEL.md) before granting access.

## Reporting a vulnerability

Use this repository's **Security → Report a vulnerability** action once private
vulnerability reporting has been enabled by the maintainer. If it is unavailable,
use an established private maintainer contact. Do not post credentials, private
source, exploit-sensitive details or logs containing them to public Issues.
The source distribution does not invent an email address or promise a response SLA.

For an exposed credential, revoke or rotate it through the issuing service.
Removing it from the current source tree does not remove it from Git history.
For an uncertain GitHub POST, reconcile remotely before retrying; deleting a
ledger is not a recovery procedure.

## Support scope

The current maintained operator release is documented in PRODUCT.json. The
retained 1.0 protocol core has known limits; see docs/KNOWN_ISSUES.md. No claim of
independent security certification or production acceptance is made.

## Publishing checklist

Before a first public push, enable private vulnerability reporting, review
repository access and branch rules, and run the source privacy/release checks.
Run CI on GitHub-hosted disposable runners with no deployment secrets. Never
execute contributions from forks on a privileged self-hosted project runner.
