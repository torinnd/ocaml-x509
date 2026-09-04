## X.509 - Public Key Infrastructure purely in OCaml

%%VERSION%%
X.509 is a public key infrastructure used mostly on the Internet.  It consists
of certificates which include public keys and identifiers, signed by an
authority.  Authorities must be exchanged over a second channel to establish the
trust relationship.  This library implements most parts of
[RFC5280](https://tools.ietf.org/html/rfc5280) and
[RFC6125](https://tools.ietf.org/html/rfc6125). The
[Public Key Cryptography Standards (PKCS)](https://en.wikipedia.org/wiki/PKCS)
defines encoding and decoding in ASN.1 DER and PEM format, which is also
implemented by this library - namely PKCS 1, PKCS 7, PKCS 8, PKCS 9 and PKCS 10.

Read our [Usenix Security 2015 paper](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/kaloper-mersinjak).

## DRAFT: lossless internal names, unchanged public API

Discussion alternative, not a release-ready change. This branch builds on the
issuer-name fix from PR #184. Certificates, CSRs and CRL
issuers retain a structural Name: ordered RDN attribute lists containing OIDs,
the six already-supported ASN.1 string choices, and their content octets.
`sign_certificate` copies the retained CA subject into the issuer and the retained
CSR subject into the subject. OCSP `issuerNameHash` uses the retained CA subject;
updating an existing CRL also retains its issuer.

Public `CN "x"`, attribute variants, RDN sets, and accessor types are unchanged.
Accessors and `Distinguished_name.decode_der` remain lossy projections: tags and
attributes that collapse in a set cannot be recovered from their results. Fresh
names retain legacy encoding defaults (for example CN uses UTF8String). An
explicit subject override uses those defaults, even if equal to the CSR's public
subject. Low-level `sign` and fresh CRL creation receive a legacy issuer and cannot
recover its provenance; prefer `sign_certificate` when an issuing certificate is
available. Name equality, hostname extraction and validation still use the same
legacy projections, not byte/tag equality.

Tradeoff: this adds a private representation and explicit conversion boundaries
without breaking callers, but does not offer public lossless Name editing. Each
retained name also stores its legacy view, costing memory but preserving fresh
public values such as `Other (known_oid, "x")` without silently changing them. Names
inside GeneralName/extensions and OCSP responder IDs still use the public codec.
This is not Unicode transcoding, support for arbitrary attribute value types, or
preservation of arbitrary BER or every byte of a re-encoded certificate. ASN.1 DER
encoding still controls SET OF canonicalization.

Synthetic Alcotest regressions use literal Name DER for PrintableString issuance,
legacy construction/overrides, all six string choices, multi-valued RDNs, OCSP and
CRL updates. OCaml 5.2 parsing checks pass, along with static call-site review,
a comments-stripped public-interface comparison, independent DER literal
length/hash checks, and `git diff --check`. Full compilation and test execution
are pending: the standalone test dependencies were unavailable. Run the upstream
test suite before relying on this draft.

## Documentation

[API documentation](https://mirleft.github.io/ocaml-x509/doc)

## Installation

`opam install x509` will install this library.
