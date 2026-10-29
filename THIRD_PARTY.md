# Third-party dependencies and provenance

The CES source package does not bundle a Python environment, dependency wheels,
Git, PowerShell, Windows SDKs, GitHub Actions code or project-specific drivers.
Those components are distributed and licensed separately. LICENSE applies to
original CES material, not to third-party software.

The current operator uses the Python standard library. Optional retained legacy
features declare these direct dependencies in requirements-local.txt:

| Package | Tested version | License recorded in installed package metadata |
| --- | --- | --- |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| jsonschema | 4.26.0 | MIT |
| asn1crypto | 1.5.1 | MIT |
| lxml | 6.1.1 | BSD-3-Clause |
| pypdf | 6.21.4 | BSD-3-Clause |

The development environment also resolved attrs (MIT), cffi (MIT-0),
jsonschema-specifications (MIT), pycparser (BSD-3-Clause), referencing (MIT),
rpds-py (MIT), typing_extensions (PSF-2.0) and pip (MIT). This is an observed
metadata inventory, not a complete multi-platform dependency lock or a legal
audit. Transitive versions may differ by platform and Python version.

The optional signature/document CI installs the direct pins on Linux Python
3.12 and 3.13 and runs selected local CMS/PDF/XAdES/OCSP regressions. This bounded
coverage does not certify every experimental host. The maintained operator
suite runs before these dependencies are installed and stays standard-library
only. Dependency security advisories must be reviewed against current installed
versions; source pins do not upgrade an existing deployment's environment.

Review the license files included in the actual installed distributions when
redistributing their wheels or binaries. cryptography and lxml binary
distributions may contain additional component notices; consult the specific
wheel's metadata and bundled licenses. CES does not relicense those components.

## Original source provenance

The preparation scan found no pre-existing third-party copyright/license headers
or vendored binary files in the CES source tree. Absence of such headers is not
proof of authorship, ownership or permission. Before the initial public push,
the publisher must confirm rights to the original code and any copied material,
including retained legacy experimental modules. Do not remove an attribution
if one is discovered later; record and comply with its actual license.

The root Apache-2.0 LICENSE was obtained from the Apache Software Foundation's
standard license text. The separate NOTICE names CES contributors without
claiming affiliation with OpenAI, GitHub or the Apache Software Foundation.
