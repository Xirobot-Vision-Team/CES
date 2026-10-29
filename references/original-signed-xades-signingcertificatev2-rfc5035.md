# EC411 original signed XAdES signer-certificate identity — strict receiver contract

This is a **new supplementary signature-identity check, not an official public authority proof**. It deliberately resolves an EC410 XAdES signed-certificate parsing deficiency in the absence of independent public official root and original distribution materials.

## Normative source / safe subset

- ETSI EN 319 132-1 §5.2.2: https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.01.00_30/en_31913201v010100v.pdf . `SigningCertificateV2` is in the **XAdES 1.3.2** namespace, even though its name includes V2; not the XAdES 1.4.1 extension namespace.
- RFC 5035 IssuerSerial: https://www.rfc-editor.org/rfc/rfc5035 . The expected DER is `SEQUENCE { SEQUENCE { [4] EXPLICIT X509 Name }, INTEGER X509 serialNumber }`, and must be **byte-identical** to the base64-decoded `IssuerSerialV2` content. Only a canonical ASN.1 DER positive serial and a true original issuer `Name` are accepted.
- ETSI TS 119 612, Annex B.1.1: https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf .

Required signed properties for *each* real original historical/evaluation LOTL XML:
```
<ds:Object>
  <xades:QualifyingProperties Target="#original-lotl-signature">
    <xades:SignedProperties Id="original-lotl-props">
      <xades:SignedSignatureProperties>
        <xades:SigningTime>...</xades:SigningTime>
        <xades:SigningCertificateV2>
          <xades:Cert>
            <xades:CertDigest>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>BASE64(SHA256(EXACT PINNED SIGNER CERT DER))</ds:DigestValue>
            </xades:CertDigest>
            <xades:IssuerSerialV2>BASE64(DER RFC5035 IssuerSerial)</xades:IssuerSerialV2>
          </xades:Cert>
        </xades:SigningCertificateV2>
      </xades:SignedSignatureProperties>
    </xades:SignedProperties>
  </xades:QualifyingProperties>
</ds:Object>
```
`xades` is `http://uri.etsi.org/01903/v1.3.2#`; `ds` is `http://www.w3.org/2000/09/xmldsig#`. The above is a **structural illustration**, not original evidence. EC410 already requires original XMLDSig exclusive C14N SHA256 references and a genuine RSA2048 or P256 signature over the SignedInfo, plus true X509 DER chain to outside pinned operator root. EC411 requires the referenced SignedProperties and strict additional V2 signature-certificate semantics. It intentionally rejects allowed-by-general-spec variants such as more than one Cert, optional IssuerSerialV2 absent, additional signed properties, or optional Cert URI. This is **not** a claim of complete interoperability with every ETSI profile.

## Threat boundary / data flow

1. Mandatory **real** `lotl_authority.protocol.audit(**inherited)` first (it invokes real EC409→EC408 and all older parents; only the child unit fixture mocks it). Verify exact EC410 report/epoch shapes, input SHA and report status; parent denial terminates.
2. Open the **same EC410 original bundle**, exact outside-pinned operator roster, SHA-pinned original LOTL signer DER and per-epoch original signed XML references via the prior bounded local source readers.
3. For both historical and evaluation windows, securely parse bounded XML offline (no DTD/entity resolution, network or external references), require the direct enveloped XMLDSig and SignedProperties shape already cryptographically checked by EC410; verify `SigningCertificateV2` SHA256 over source X509 signer DER, RFC5035 issuer+serial DER bytes, authenticated SigningTime within certificate validity, and exact signed-order grammar.
4. Produce SHA-hashed per-epoch review/inventory and compare independent outside operator-supplied per-epoch expected hashes/count floors; in audit mode compare the complete retained inventory SHA. Reread all source bytes through prior SHA-pinned readback. Do not upgrade any inherited flags.
5. Return **exit2 unresolved** only for bounded local cryptographic consistency; deny invalid source and unavailable ancestor 3/4/5. The signing-certificate digest does **not** attest the signer is official. Date inside SignedProperties is signer-claimed, **not** a third-party qualified timestamp.

## New flags

`--historical-ec339-xades-cert-v2-epoch-inventory-sha256` repeated 1–3 times; `--minimum-historical-ec339-joint-xades-cert-v2-publisher-count` repeated matching epochs (0–2). Audit additionally requires `--expected-retained-historical-ec339-xades-cert-v2-inventory-sha256`. The first real original SHA pins and signer certificate DER pin **are inherited** from unchanged mandatory EC410; no fake EC411 outside authority bundle is invented.

## Not yet proven

External independently authenticated LOTL root operator provenance, genuine OJEU/Commission supervision claims, real signed public distribution/custody receipts, ETSI full profile interoperability, independent qualified timestamps, actual external unmocked historical ancestor chain, national official issuer provenance, physical WORM, PS7/15 Smoke, Windows/macOS/Git/CI/provider/performance, final user-assisted acceptance.
