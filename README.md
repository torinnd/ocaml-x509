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

## DN attribute value API

This change builds on the issuer-name fix from PR #184. Every
`Distinguished_name.attribute` payload (including `C`, `Serialnumber`, `DNQ`,
`Mail`, `DC`, and `Other`) becomes `Encoded_string.t`. Construction and pattern
matches must migrate; `common_name` now returns `Encoded_string.t option`.

```ocaml
let open X509.Distinguished_name in
(* Previously: CN "example.com", C "GB". *)
let name = [
  Relative_distinguished_name.singleton
    (C (Encoded_string.of_octets ~encoding:`Printable "GB"));
  Relative_distinguished_name.singleton
    (CN (Encoded_string.of_octets "example.com"))
] in
(* Extraction returns raw content bytes, not a Unicode conversion. *)
Option.map Encoded_string.to_octets (common_name name)
```

For direct patterns, replace `CN text -> ...` with
`CN value -> ... Encoded_string.to_octets value ...`; inspect
`Encoded_string.encoding value` when interpreting the bytes. The unchecked
`of_octets` labels existing content octets, without tag/length bytes. Its default
is UTF8String, not encoding inference. For example,
``of_octets ~encoding:`BMP "\000A"`` is BMPString A; `"A"` alone is not.
There is no BMP/Teletex transcoding, repertoire validation, or Unicode library.
Parsed values remain as permissive as the existing ASN.1 decoder.

**Invariant:** each stored attribute retains the accepted string tag and content
bytes through Name decoding/encoding and issuance. All attributes use the same
representation because the parser already accepts six tags for all of them:
keeping fixed-schema values as bare strings would still silently rewrite some
accepted inputs. For fresh names, explicitly choose PrintableString for `C`,
`Serialnumber`, and `DNQ`, and IA5String for `Mail` and `DC`. This draft preserves
unusual parsed tags rather than enforcing those schemas. `Encoded_string` is
intentionally not named DirectoryString: IA5String is among the accepted tags.

**Matching versus storage:** `Distinguished_name.equal` keeps legacy matching by
ordered RDNs and sets of constructor/OID plus raw bytes, ignoring tags (and
collapsing tag-only duplicates). It does not implement Unicode, case-insensitive,
or cross-encoding text equality. Certificate/CRL matching still uses that rule;
CN hostname fallback still uses raw bytes. Its lookup now scans the RDN rather
than depending on tree shape: retaining tag-distinct members exposed the existing
non-monotonic `find_first_opt` predicate. A regression covers direct lookup and
certificate/CSR hostname extraction. RDN set operations and the new
`equal_representation` include tags, so a multi-valued RDN can retain both
PrintableString and UTF8String with identical bytes. Pretty-printing remains a
byte-oriented diagnostic, not a lossless or transcoding text interface.

**Limits:** `Other` still accepts only the six supported string tags, not arbitrary
ASN.1 values; it can alias a known attribute OID. Identical duplicates are still
collapsed, empty RDNs remain possible, and DER SET OF ordering is canonicalized.
Thus this is string-tag/content preservation, not preservation of every original
Name byte sequence. OCSP uses the existing Name encoder to hash retained tags;
the same duplicate/canonicalization limitations apply there.

**Validation:** synthetic DER tests cover all six tags (including actual
BMP/Universal content octets), all attribute variants, UTF8String defaults,
representation versus logical matching, multi-valued RDNs, PrintableString
CSR/CA issuance, mixed-encoding chain verification, and an independent OCSP
issuer-name hash expectation. The local vendored build passed 2,231 tests;
its revocation tests use a fixed clock. A separate issuance reproduction
confirmed that a PrintableString CA subject remains PrintableString in the
issued certificate's issuer. Both signatures and chains validate with OpenSSL.
The upstream build and CI matrix have not been run.
