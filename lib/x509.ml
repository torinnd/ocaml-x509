module Host = Host

module Key_type = Key_type

module Algorithm_identifier = struct
  include Algorithm.Identifier
  let signature_algorithm t = Algorithm.to_signature_algorithm (algorithm t)
end

module Public_key = Public_key

module Private_key = Private_key

module Distinguished_name = Distinguished_name

module General_name = General_name

module Certificate = Certificate

module Validation = Validation

module Extension = Extension

module Signing_request = Signing_request

module CRL = Crl

module Authenticator = Authenticator

module PKCS12 = P12

module OCSP = Ocsp

module Roundtrip_audit = struct
  type kind = [
    | `Certificate | `Tbs | `Algorithm | `Name | `General_name | `General_names
    | `Extensions | `Time | `Serial | `Bits | `Bool | `Octets | `Integer_set
    | `Public_key
  ]
  let roundtrip asn bytes =
    let decode, encode = Asn_grammars.projections_of Asn.der asn in
    Result.map encode (Asn_grammars.err_to_msg (decode bytes))
  let reencode = function
    | `Certificate -> fun bytes -> Result.map Certificate.encode_der (Certificate.decode_der bytes)
    | `Tbs -> roundtrip Certificate.Asn.tBSCertificate
    | `Algorithm -> roundtrip Algorithm.Identifier.asn
    | `Name -> roundtrip Distinguished_name.Asn.name
    | `General_name -> roundtrip General_name.Asn.general_name
    | `General_names -> roundtrip General_name.Asn.gen_names
    | `Extensions -> roundtrip Extension.Asn.extensions_der
    | `Time -> roundtrip Certificate.Time.asn
    | `Serial -> roundtrip Certificate.Serial.asn
    | `Bits -> roundtrip Certificate.Bits.asn
    | `Bool -> roundtrip Asn.S.bool
    | `Octets -> roundtrip Asn.S.octet_string
    | `Integer_set -> roundtrip Asn.S.(set_of integer)
    | `Public_key -> roundtrip Public_key.Info.asn
  let fresh_tbs_of_certificate bytes =
    Result.map (fun certificate ->
        Certificate.Asn.tbs_certificate_to_octets certificate.Certificate.asn.tbs_cert)
      (Certificate.decode_der bytes)
  let certificate_der_of_pem pem =
    Result.map (List.filter_map (fun (tag, bytes) ->
        if String.equal tag "CERTIFICATE" then Some bytes else None)) (Pem.parse pem)
end
