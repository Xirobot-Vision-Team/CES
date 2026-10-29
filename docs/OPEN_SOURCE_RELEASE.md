# First public release checklist

The prepared source directory is intended for review and a first Git commit. It
contains no project profile, data root, virtual environment, repository history
or GitHub credential. Do not upload the live installation or its sibling data
directory by selecting everything in a file browser.

## Before the first push

- Confirm the publisher has rights to release all original CES material and that
  Apache-2.0 is the intended license. Preserve any discovered third-party notices.
- Review LICENSE, NOTICE and THIRD_PARTY.md. The source inventory found no
  pre-existing copyright/license headers; this does not prove exclusive ownership.
- Run the release check and operator tests from the prepared source directory.
  Inspect test coverage limits and the retained known-failure documentation.
- Review the staged file list. The prepared package has no Git history. If using
  an existing history, separately audit all commits for secrets and private data.
- Choose the GitHub repository owner/name and initial visibility. These are
  publishing decisions, not values embedded in CES.

## Repository settings after creation

- Enable private vulnerability reporting and the security features available for
  the chosen repository. Check the configured default branch.
- Require PR review and successful source/operator CI as appropriate; prevent
  force-pushes to protected branches. Add CODEOWNERS only after real maintainers
  and paths have been selected.
- Use hosted runners without project credentials. The included CI has read-only
  permissions, SHA-pinned actions, no pull_request_target workflow and no live
  publication or hardware execution.
- Describe the actual support boundary: Windows native evidence collection,
  standard-library operator tests, optional POSIX compatibility and opt-in
  project testing. Do not advertise all legacy routes as production-ready.

## Release evidence

Attach the reviewed source checksum and a concise release note only after the
remote CI result is available. Local checks do not establish GitHub CI success.
Do not attach private raw logs or project execution receipts as public artifacts.
Publishing, changing visibility or creating a remote repository is outside the
source-preparation command and requires the operator's chosen target.
