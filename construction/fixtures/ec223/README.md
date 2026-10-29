# EC223 local fixture boundary

`construction/test_delivery_identity.py` builds all synthetic identities,
three **ephemeral** Ed25519 key pairs, exact EC221 destination hashes,
fresh signed singleton directory route, independently signed revocation
checkpoint and separate operator identity-check permit **in process**.
No private key, real account, recipient address, enterprise trust root,
credential, provider request or source Markdown is committed here.

The tests use actual disposable EC200 report history and EC221/EC222 exact
versioned private store read functions; they do not establish a real person's
identity, directory legitimacy, organization clearance, production privacy
policy, or sending authorization. Denial cases cover bad signatures,
root substitution, role and project mismatch, changed destination/source,
expired/revoked evidence, missing explicit recipient, external/broadcast,
unknown content review and unsafe recheck. The entire implementation has
no network, AI, provider or native PowerShell call.

Real enterprise directory roots, real status-of-revocation and human
identity assurance require final user-assisted integration acceptance.
