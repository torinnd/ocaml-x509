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

## Experimental lossless semantic certificate model

This branch is a proof of concept for maintainer discussion, not a proposed
release or a prerequisite for preserving DN string encodings. It is based on
upstream main at `308f80240005ac4cbc481255106ebb4a172d7f37`.

This version makes the semantic certificate record authoritative for encoding,
fingerprints and certificate-signature verification. `Certificate.t` no longer
stores the original whole-certificate bytes. Known extensions are fully typed;
only unsupported extension OIDs retain opaque payload bytes.

The record carries validated public keys with compression/algorithm metadata,
parsed `Ptime.t` values with their ASN.1 time choice, signed arbitrary-precision
serial numbers, exact bit lengths, tagged DN values and ordered typed names and
extensions. Usage/reason flags retain their semantic set and encoded bit width;
fresh values use minimal width, while decoded legacy zero tails survive.
Policy qualifiers retain CPS versus UserNotice, notice references,
DisplayText encoding and notice numbers. Logical matching remains separate from
representation equality.

DN attribute construction now uses encoded values, and RDN storage preserves
multiplicity rather than pretending to be `Set.S`. GeneralNames has an ordered
occurrence representation with a grouped lookup view; empty list bindings normalize
to absence. Extension lookup remains map-like while serialization preserves order.
Known EKU aliases normalize to their named meanings. These are API and construction
semantics changes, not just an encoder optimization.

Decoding checks that the newly parsed semantic value reproduces its input. Field
codecs also reject normalizing noncanonical forms before discarding their spelling,
including inside embedded certificates. The accompanying ASN.1 strict-length fix
rejects the nonminimal long form for a 127-byte length; BER behavior is unchanged.
This is not a general validator for every X.509 profile rule or an implementation of
unsupported algorithms, arbitrary OtherName values or X400 ORAddress.

Signing validates and canonicalizes constructed semantic fields before signing
those exact bytes. The signing convenience API retains its historical whole-second
time normalization; explicit encoded-time constructors reject fractions. Raw caches
for CSR, CRL and OCSP objects are separate and remain in place. Their certificate
consumers have been adapted; the known OCSP issuerKeyHash formula is not changed.

The implementation was tested in a local vendored build: 2,236 X509 tests passed,
including ten new semantic-model cases. All 80 certificates accepted by the
baseline corpus decoder round-tripped byte-for-byte. All 19 signed synthetic
cases retained valid signatures. The OCSP embedding checks accepted 19 controls
and rejected four malformed cases for each container type. Request checks follow
upstream's existing untagged optionalSignature grammar; fixing its missing RFC
[0] wrapper is separate work. These are targeted results, not an exhaustive
compatibility or security claim. The upstream build and CI matrix have not been run.

The audit source is in `semantic-audit/audit.ml`. It prints primitive roundtrips,
signed cases and embedded-certificate results. Optional PEM file arguments add a
corpus scan; `semantic-audit/baseline-accepted-files.txt` records the 80 baseline
fixture paths. With a configured upstream development environment, run:

```sh
dune runtest
dune exec semantic-audit/audit.exe -- $(cat semantic-audit/baseline-accepted-files.txt)
```

The local results also used `semantic-audit/asn1-strict-length.patch`, applied to
asn1-combinators 0.3.2. That one-line DER decoder fix is not part of x509 itself;
apply it to the dependency's source when reproducing the embedded length-127
rejection. The dependency patch and upstream version requirement need to be
resolved before release. No patched dependency version is claimed here.

Remaining work includes API agreement and migration examples, review of the
accepted-input boundary, downstream application migration, property/fuzz tests,
and performance measurements. The public `Roundtrip_audit` module is temporary
instrumentation and should not become a supported API. CSR/CRL/OCSP cache removal
is separate. The public interfaces expose semantic getters and normal signing
APIs; this does not add arbitrary certificate-field mutation or a new trust policy.

## Documentation

[API documentation](https://mirleft.github.io/ocaml-x509/doc)

## Installation

`opam install x509` will install this library.
