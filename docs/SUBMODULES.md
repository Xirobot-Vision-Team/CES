# Pinned submodule support

Submodule reading and synchronization are opt-in. A project profile must explicitly
allow each superproject-relative mount and its HTTPS GitHub repository identity.
For example, merge this into `repository_sync` in an external profile:

```json
{
  "submodules": {
    "enabled": true,
    "allow_init": true,
    "entries": [
      {"path": "components/core", "repository": "example/core"}
    ]
  }
}
```

Configuration cannot grant authorization. Initialization uses the parent gitlink,
explicit `checkout`, no hooks, no file transport and no `--remote`. HTTPS repository
identity must match both `.gitmodules` and the allowlist. Relative, credential-bearing
and SSH URLs are rejected. Nested mounts require their own full-path allowlist entry;
depth and count are bounded. Dirty or unexpected child HEADs block lifecycle sync/build.
Existing nonempty directories are never deleted to make room for initialization.

Before synchronization, initialized children must match the old parent pins. After
the parent fast-forward, each child is checked out at the new pinned commit. Builds
record and recheck the parent and child commit inventory. A successful build is not
a runtime test. Git history, sources and `.gitmodules` are untrusted data.

## Reading and evidence

Existing profile source paths remain superproject-relative. Source resolution records
the parent commit, every gitlink in the chain, child repository, pinned child commit,
child-relative path and Git blob. Knowledge citations link to the owning repository.
Functional review expands virtual before/after blobs, preserving flat-to-submodule
migration content without inventing mass code deletion. Each source/batch binding is
revalidated before completion. Missing objects or unknown owners block reading rather
than silently substituting a moving remote branch.

Review plans keep integration commits separate from child commit inventories. Child
history records author and committer names, timestamps and repository-specific links.
An initial migration is identified as such, not counted as newly authored historical
child work. Parent-author report routing remains the integration report route; do not
claim separate child-author notifications from that route. Finding attribution resolves
the owning repository's blame and GitHub commit accounts. Native Finding validation
remains independent: use a child repository's own native evidence run when the parent
patch contains only a gitlink. A functional review is not a substitute for that gate.

Manual test discovery can bind sources in children, and existing source-only contracts
must be re-reviewed when their binding changes. Submodule support does not authorize
project runtime tests, new notification targets or child repository publication.

## README and documentation ownership

Parent knowledge can cite child sources. Child project descriptors can contribute to
the parent component inventory, but child READMEs are not parent write targets.
Knowledge planning detaches old parent-owned child README entries into
`detached_submodule_readmes`, preserving their original metadata and recording the
reason. It does not edit the child's README, stage its gitlink, or push the child.
The published result includes explicit `submodule_readme_separate_publication_required`
gaps. To maintain a child's README, use an independently authorized child profile and
its own manifest, repository identity and isolated publication transaction.

Retain pending document receipts and member files when migrating a live checkout.
Old flat directories can contain ignored build/config data; preserve them outside the
checkout before an explicitly reviewed migration, never reset/clean them away.

## Verification

`python -B -m unittest discover -s operator -p "test_submodules.py"` uses disposable local
Git fixtures without credentials/network/project execution. It verifies pin changes,
flat migration, source URLs, resealed binding tampering, dirty/wrong-pin refusal,
allowlist/origin checks, missing paths, nonempty initialization guards, child-source
knowledge/test bindings, and README metadata detachment. Full operator and release
checks remain required; real project builds and remote CI are separate evidence.
