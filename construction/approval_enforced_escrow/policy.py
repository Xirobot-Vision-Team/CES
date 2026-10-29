#!/usr/bin/env python3
"""EC277 pinned, independently installed *server-side* authorization policy.

A site keeps only public approver/witness/peer credentials plus its *own*
TLS/escrow private keys. A full EC276 authorization is checked again by EACH
escrow daemon, independently of whatever the online caller claims to have
checked. A policy file's content hash is an out-of-band deployment pin.
"""
from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any

from source_provenance_host import provenance as prov
from emergency_recovery_host import recovery as rec
from remote_escrow_host import escrow as esc
from dual_escrow_host.quorum import DualEscrow
from dual_approval_host import approval as auth

SCHEMA = 'ces.ec277.approval_enforced_escrow_policy.v1'
POLICY_FIELDS = frozenset({'schema','namespace','recovered_root_public_sha256',
    'closure_sha256','primary','secondary','witnesses','approvers'})
SITE_FIELDS = frozenset({'host','port','tls_ca','tls_ca_sha256',
    'tls_leaf_sha256','escrow_public','escrow_public_sha256'})
KEY_FIELDS = frozenset({'path','sha256'})
MAX_POLICY = 12000


class PolicyError(auth.ApprovalError):
    """Server policy denial, no private paths or untrusted JSON returned."""


def deny(code: str) -> None:
    raise PolicyError(code)


def _pairs(items: Any, role: str) -> list[tuple[str,str]]:
    if type(items) is not list or len(items)!=3 or any(
            type(item) is not dict or set(item)!=KEY_FIELDS or
            type(item['path']) is not str or type(item['sha256']) is not str
            for item in items):
        deny('EC277_INVALID_'+role+'_ROSTER')
    return [(item['path'],esc._sha(item['sha256'])) for item in items]


class TrustPolicy:
    """Enforces a pinned two-site roster, key-role separation and live file pins.

    Constructing a RemoteClient does NOT connect to its site: one daemon can
    validate both identities while the peer is offline. Only the public keys
    and identity hashes are needed for independent admission decisions.
    """

    def __init__(self, path: str, pin: str):
        self.path=prov._path(path)
        self.pin=esc._sha(pin)
        doc=self._pinned_document()
        if (set(doc)!=POLICY_FIELDS or doc.get('schema')!=SCHEMA or
                type(doc.get('primary')) is not dict or
                type(doc.get('secondary')) is not dict):
            deny('EC277_POLICY_SCHEMA_INVALID')
        self.doc=doc
        namespace=esc.validate_namespace(doc['namespace'])
        root=esc._sha(doc['recovered_root_public_sha256'])
        closure=esc._sha(doc['closure_sha256'])
        witness_pairs=_pairs(doc['witnesses'],'WITNESS')
        approver_pairs=_pairs(doc['approvers'],'APPROVER')
        keys=esc.witness_keys(witness_pairs)
        clients=[]
        for role in ('primary','secondary'):
            site=doc[role]
            if set(site)!=SITE_FIELDS or any(type(site[key]) is not str
                    for key in SITE_FIELDS-{'port'}):
                deny('EC277_SITE_SCHEMA_INVALID')
            # A local CA copy and remote signer copy are public *pinned*
            # material; neither site must reach the other's server to boot.
            ca_path=prov._path(site['tls_ca'])
            ca_sha=esc._sha(site['tls_ca_sha256'])
            if esc.sha(prov._bytes(ca_path,65536))!=ca_sha:
                deny('EC277_SITE_CA_CONTENT_PIN_MISMATCH')
            signer_path=prov._path(site['escrow_public'])
            signer_sha=esc._sha(site['escrow_public_sha256'])
            rec._public(signer_path,signer_sha)
            clients.append(esc.RemoteClient(host=site['host'],port=site['port'],
                ca_path=ca_path,ca_pin=ca_sha,leaf_pin=site['tls_leaf_sha256'],
                escrow_public_path=signer_path,escrow_public_pin=signer_sha,
                namespace=namespace,witness_keys_map=keys,root=root,closure=closure))
        self.dual=DualEscrow(*clients)
        self.approvers=auth.approver_keys(approver_pairs,self.dual)
        paths=[self.path,*self.dual.authority_paths(),
               *[prov._path(p) for p,_ in witness_pairs],
               *[prov._path(p) for p,_ in approver_pairs]]
        if len(paths)!=len(set(paths)):
            deny('EC277_POLICY_TRUST_FILE_PATHS_COLLIDE')
        self.trust_paths=paths
        self.witness_pairs=witness_pairs
        self.approver_pairs=approver_pairs
        self.namespace=namespace
        self.root=root
        self.closure=closure
        self.witness_keys=keys

    def _pinned_document(self)->dict:
        raw=prov._bytes(self.path,MAX_POLICY)
        if not hmac.compare_digest(esc.sha(raw),self.pin):
            deny('EC277_POLICY_FILE_SHA256_CHANGED')
        return esc._parse(raw,MAX_POLICY,'EC277_POLICY_NOT_CANONICAL')

    def recheck(self)->None:
        """Use fail-closed public-file checks before every authorized write."""
        if self._pinned_document()!=self.doc:
            deny('EC277_POLICY_CHANGED')
        for client in (self.dual.primary,self.dual.secondary):
            if esc.sha(prov._bytes(client.ca_path,65536))!=client.ca_pin:
                deny('EC277_TRUST_CA_CHANGED')
            rec._public(client.escrow_public_path,client.escrow_pin)
        if esc.witness_keys(self.witness_pairs)!=self.witness_keys:
            deny('EC277_WITNESS_TRUST_CHANGED')
        for path,pin in self.approver_pairs:
            if rec._public(path,pin)!=self.approvers[pin]:
                deny('EC277_APPROVER_TRUST_CHANGED')

    def verify(self, doc: dict, *, now: int)->dict:
        self.recheck()
        return auth.verify_approval(doc,self.dual,self.approvers,now=now)

    def site(self, role: str)->esc.RemoteClient:
        if role=='primary': return self.dual.primary
        if role=='secondary': return self.dual.secondary
        deny('EC277_SERVER_SITE_ROLE_INVALID')

    def validate_server_files(self, role: str, *, port: int, journal: str,
                              escrow_secret: str,tls_cert: str,tls_key: str)->None:
        client=self.site(role)
        if client.port != esc.integer(port,1,65535,'EC277_SERVER_PORT_INVALID'):
            deny('EC277_SERVER_LISTEN_PORT_NOT_APPROVED_SITE_PORT')
        # Cert pin uses actual loaded leaf DER rather than PEM bytes/subject.
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert_bytes=prov._bytes(tls_cert,65536)
        try:
            cert=x509.load_pem_x509_certificate(cert_bytes)
            der=cert.public_bytes(serialization.Encoding.DER)
        except (ValueError,TypeError) as exc:
            raise PolicyError('EC277_SERVER_TLS_LEAF_CERTIFICATE_INVALID') from exc
        if esc.sha(der)!=client.leaf_pin:
            deny('EC277_SERVER_ACTUAL_TLS_LEAF_PIN_MISMATCH')
        # The TLS private key is loaded by SSLContext, but still must be
        # owner-private and distinct from every trust/ledger/secret path.
        prov._bytes(tls_key,65536)
        extra=[prov._path(x) for x in (journal,escrow_secret,tls_cert,tls_key)]
        if len(set(extra+self.trust_paths))!=len(extra)+len(self.trust_paths):
            deny('EC277_SERVER_SECRET_JOURNAL_OR_TRUST_PATH_COLLISION')
