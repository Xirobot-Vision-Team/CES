# Installation and first project

## Runtime scope

| Component | Requirements and verification boundary |
| --- | --- |
| Maintained operator tests | Python 3.12+ standard library; Windows and Linux are exercised separately |
| Native evidence Actions | PowerShell 7 and Git; Windows is the primary deployment |
| GitHub publication | Git credential helper with authorized identity and repository access; outbound HTTPS |
| Project tests | Explicit project command, reviewed result contract and independent authorization |
| Legacy POSIX hosts | Native Linux filesystem, private permissions and the relevant optional runtime/authorization |

macOS is not claimed as verified by the current release. A CLI loading on a
platform does not prove all execution and filesystem safeguards on that platform.

## Install from source

From the source directory:

```powershell
py -3.12 -m venv .venv
& ./.venv/Scripts/python.exe -B operator/ces_product.py --help
& ./.venv/Scripts/python.exe -B -m unittest discover -s operator -p 'test_*.py'
& ./.venv/Scripts/python.exe -B tools/release_check.py
```

On Linux, create the environment with `python3 -m venv .venv`, and use
`.venv/bin/python`. `sh ./ces-product --help` uses that environment, a configured
CES_PYTHON or python3. Install PowerShell separately before invoking native
evidence collection. Do not copy a Windows virtual environment to Linux.

The maintained operator test suite needs no third-party packages. To use
optional legacy modules, install their direct dependencies:

```text
python -m pip install -r requirements-local.txt
python -m pip check
```

Use a virtual environment and review dependency licenses; these direct version
pins are not a complete platform-specific hashed lockfile.

## External profile and credentials

Copy `operator/profile.example.json` into a dedicated external data directory.
Set absolute repository, CES installation and external output/cache/state paths.
Set the exact GitHub repository/account IDs and default branch for the project.
Do not keep profiles or credentials in this public source checkout.

Run `ces-product.cmd doctor --config <profile>` on Windows, or invoke
`python -B operator/ces_product.py doctor --config <profile>`. This inspects local
configuration; it does not authorize enabling any execution or publication flag.

The configured Git credential helper must already provide the intended GitHub
identity. CES does not store tokens in profiles or ask for them in source code.
Use a test repository you control for first live publication acceptance. Test
fixtures and a mock-provider pass do not prove recipient inbox delivery.

## Skill installation

Install the source directory as a CES skill with your host's skill installer, or
copy SKILL.md, agents/ and the required supporting docs/references while preserving
relative links. The full product source must remain available; this is not a
single-file standalone skill. The public SKILL.md is installation-relative.
Existing local deployments may keep their separate installed skill pointing at
the explicit product path.

## Optional WSL compatibility runtime

Use `pwsh -NoProfile -File tools/setup-posix.ps1` to install a fresh owner-private
runtime using the current product manifest. `-Distribution` is optional and uses
the default WSL distribution when omitted. `-Runtime` chooses a dedicated path
under /var/tmp. Existing differing installations are refused rather than overwritten.

Set CES_WSL_DISTRIBUTION when a non-default distribution is required and
CES_POSIX_RUNTIME when a non-default installed runtime is used. The retained
default runtime path is /var/tmp/ces-1.0.0 for compatibility; verify the selected
runtime's PRODUCT.json for the current operator version. /var/tmp retention is
host policy; keep durable project state in separately managed private storage.
