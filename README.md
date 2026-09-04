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

## Documentation

[API documentation](https://mirleft.github.io/ocaml-x509/doc)

## Installation

`opam install x509` will install this library.

## DRAFT: additive lossless public Name API

Discussion alternative, not a release-ready change. This branch builds on the
issuer-name fix from PR #184. `Distinguished_name.Encoded` adds an abstract name
alongside the unchanged `CN "foo"`/attribute/set API:

```ocaml
let issuer = X509.Certificate.subject_encoded ca in
let subject = X509.Signing_request.subject_encoded csr in
let legacy = X509.Distinguished_name.Encoded.to_legacy_lossy subject in
let fresh = X509.Distinguished_name.Encoded.of_legacy legacy in
(* [fresh] uses the old default encodings; it need not equal [subject]. *)
X509.Signing_request.sign_encoded csr ~valid_from ~valid_until
  ~subject ca_key issuer
```

`Encoded.decode_der` / `encode_der` retain the supported string tags and content
bytes, OIDs, RDN sequence and all RDN members, using a typed ASN.1 grammar, not
byte offsets or a provenance cache. `create_encoded` constructs a CSR with such
a name. `Certificate.subject_encoded` / `issuer_encoded` and
`Signing_request.subject_encoded` retrieve retained names. Use
`sign_certificate_encoded` for the usual CA validity/key/name-constraint checks
and an optional encoded subject override; its issuer always comes from the CA's
retained subject. `sign_encoded`, like `sign`, does not perform those CA checks.

Existing function signatures and `Signing_request.request_info` are unchanged.
Certificate `subject` / `issuer`, CSR `info.subject` and
`Encoded.to_legacy_lossy` expose legacy values: string tags are lost and members
that become equal in the legacy RDN set are merged. `of_legacy`, legacy
`decode_der` followed by `encode_der`, `create`, the issuer argument to `sign`,
and explicit legacy `~subject` overrides use the old defaults: IA5 for DC/Mail,
Printable for C/Serialnumber/DNQ, UTF8 otherwise. Passing an equal legacy subject
explicitly still selects those defaults; there is no equality-based guessing.
Without a subject override, both old signing functions now retain the CSR
subject. `sign_certificate` also automatically retains the CA subject as issuer.
OCSP CertID hashing uses the retained CA subject rather than its lossy view.
Matching, hostname extraction and validation errors still use legacy projections.

Unlike the internal-only alternative, callers can now carry names across API
boundaries and explicitly choose lossless issuance. Unlike replacing the public
DN type, existing constructors and pattern matches need no immediate migration.
The cost is two name APIs and explicit conversions at legacy boundaries. Each
encoded name also retains its legacy view. This preserves caller-supplied values
such as `Other (known_oid, "x")` in fresh objects, rather than silently normalizing
them to a named constructor before DER decoding.

Limits: this is lossless for the supported DER Name syntax, not arbitrary ASN.1
ANY. Supported values remain UTF8String, PrintableString, IA5String,
UniversalString, TeletexString and BMPString. There is no Unicode transcoding or
new string validation. DER encoding sorts SET OF members; this is not a promise
to reproduce noncanonical BER. General-name directory/EDI fields, extension
names, CRL issuer creation/update and OCSP ByName/requestor-name APIs remain on
the legacy codecs in this draft. Raw certificate/CSR/CRL serialization and
signature verification still use their existing original signed bytes; this
change does not make all embedded certificate re-encoding lossless. Existing
name-constraint checks still inspect CSR hostnames rather than subject overrides.

Validation status: synthetic Alcotest cases cover literal PrintableString DER,
all supported string choices, RDN collisions, lossless CSR/certificate access,
issuance/defaults/overrides and OCSP issuer-name hashing. OCaml 5.2 parsing checks,
static source audits, DER fixture checks and `git diff --check` pass. Full
compilation and test execution are pending: the standalone test dependencies
were unavailable. Run the upstream test suite before relying on this draft.
