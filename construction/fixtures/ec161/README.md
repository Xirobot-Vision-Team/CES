# EC-161 synthetic fixtures — not a live source

`github.synthetic.json` and `gitlab.synthetic.json` are deliberately fabricated, with `_ces_fixture` markers, invented object IDs and repeated-letter full-length placeholder SHA strings. They are **not** actual Git commits, PRs, GitHub/GitLab API captures or proof of remote availability. The real HTTPS adapter explicitly rejects `_ces_fixture` in a live response; isolated unit-test transports mark every success `synthetic: true`, `origin: synthetic_fixture`.

The fixture title/body/description fields exist only to verify that the adapter **never copies** PR text, actor identity, paths, code patches or source descriptions into CES output. No secrets are bundled.
