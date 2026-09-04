open X509

let mmap file =
  let ic = open_in file in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln;
  close_in ic;
  Bytes.unsafe_to_string rs

let regression file =
  mmap ("./regression/" ^ file ^ ".pem")

let cert file =
  match Certificate.decode_pem (regression file) with
  | Ok cert -> cert
  | Error (`Msg m) -> Alcotest.failf "certificate %s decoding error %s" file m

let jc = cert "jabber.ccc.de"
let cacert = cert "cacert"

let time () = None

let host str = Some (Domain_name.host_exn (Domain_name.of_string_exn str))

let test_jc_jc () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.ccc.de") ~time ~anchors:[jc] [jc] with
  | Error `InvalidChain -> ()
  | Error e -> Alcotest.failf "something went wrong with jc_jc (expected invalid_chain, got %a"
                 Validation.pp_validation_error e
  | Ok _ -> Alcotest.fail "chain validated when it shouldn't"

let test_jc_ca_fail () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.ccc.de") ~time ~anchors:[cacert] [jc ; cacert] with
  | Error `InvalidChain -> ()
  | _ -> Alcotest.fail "something went wrong with jc_ca"

let test_jc_ca_all_hashes () =
  match Validation.verify_chain_of_trust ~allowed_hashes:[`SHA1] ~host:(host "jabber.ccc.de") ~time ~anchors:[cacert] [jc ; cacert] with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jc_ca"

let telesec = cert "telesec"
let jfd = [ cert "jabber.fu-berlin.de" ; cert "fu-berlin" ; cert "dfn" ]

let test_jfd_ca () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.fu-berlin.de") ~time ~anchors:[telesec] (jfd@[telesec]) with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jfd_ca"

let test_jfd_ca' () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.fu-berlin.de") ~time ~anchors:[telesec] jfd with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jfd_ca'"

let test_izenpe () =
  let crt = cert "izenpe" in
  let _, san = Extension.(get Subject_alt_name (Certificate.extensions crt)) in
  Alcotest.(check int "two SAN (mail + dir)" 2 (General_name.cardinal san));
  Alcotest.(check (list string) "mail in SAN is correct" [ "info@izenpe.com" ]
              General_name.(get Rfc_822 san));
  let dir = General_name.(get Directory san) in
  Alcotest.(check int "directory san len is 1" 1 (List.length dir));
  let data = Fmt.to_to_string Distinguished_name.pp (List.hd dir) in
  let expected = "/O=IZENPE S.A. - CIF A01337260-RMerc.Vitoria-Gasteiz T1055 F62 S8/Street=Avda del Mediterraneo Etorbidea 14 - 01010 Vitoria-Gasteiz" in
  Alcotest.(check string "directory in SAN is correct" expected data)

let test_name_constraints () =
  ignore (cert "name-constraints")

let check_dn =
  (module Distinguished_name: Alcotest.TESTABLE with type t = Distinguished_name.t)

let test_distinguished_name () =
  let open Distinguished_name in
  let crt = cert "PostaCARoot" in
  let expected = [
    Relative_distinguished_name.singleton (DC "rs") ;
    Relative_distinguished_name.singleton (DC "posta") ;
    Relative_distinguished_name.singleton (DC "ca") ;
    Relative_distinguished_name.singleton (CN "Configuration") ;
    Relative_distinguished_name.singleton (CN "Services") ;
    Relative_distinguished_name.singleton (CN "Public Key Services") ;
    Relative_distinguished_name.singleton (CN "AIA") ;
    Relative_distinguished_name.singleton (CN "Posta CA Root")
  ] in
  Alcotest.(check check_dn "complex issuer is good"
              expected (Certificate.issuer crt)) ;
  Alcotest.(check check_dn "complex subject is good"
              expected (Certificate.subject crt))

let test_distinguished_name_pp () =
  let module Dn = struct
    include Distinguished_name
    let cn s = Relative_distinguished_name.singleton (CN s)
    let o s = Relative_distinguished_name.singleton (O s)
    let initials s = Relative_distinguished_name.singleton (Initials s)
    let (+) = Relative_distinguished_name.union
  end in
  let dn1 = "DN1", Dn.[o "Blanc";
                       cn "John Doe" + initials "J.D." + initials "N.N."] in
  let dn2 = "DN2", Dn.[o " Escapist"; cn "# 2"; cn " \"+,;/<>\\  "] in
  let pp1 = "RFC4514", Fmt.hbox (Dn.make_pp ~format:`RFC4514 ()) in
  let pp2 = "RFC4514-spacy",
    Fmt.hbox (Dn.make_pp ~format:`RFC4514 ~spacing:`Loose ()) in
  let pp3 = "OpenSSL", Fmt.hbox (Dn.make_pp ~format:`OpenSSL ()) in
  let pp4 = "OSF", Fmt.hbox (Dn.make_pp ~format:`OSF ()) in
  let pp5 = "RFC4514-vbox", Fmt.vbox (Dn.make_pp ~format:`RFC4514 ()) in
  let check (pp_desc, pp) (dn_desc, dn) expected =
    Alcotest.(check string) (Printf.sprintf "%s %s" pp_desc dn_desc)
      expected (Fmt.to_to_string pp dn)
  in
  check pp1 dn1 {|CN=John Doe+Initials=J.D.+Initials=N.N.,O=Blanc|} ;
  check pp1 dn2 {|CN=\ \"\+\,\;/\<\>\\ \ ,CN=\# 2,O=\ Escapist|} ;
  check pp2 dn1 {|CN = John Doe + Initials = J.D. + Initials = N.N., O = Blanc|} ;
  check pp2 dn2 {|CN = \ \"\+\,\;/\<\>\\ \ , CN = \# 2, O = \ Escapist|} ;
  check pp3 dn1 {|O = Blanc, CN = John Doe + Initials = J.D. + Initials = N.N.|} ;
  check pp3 dn2 {|O = \ Escapist, CN = \# 2, CN = \ \"\+\,\;/\<\>\\ \ |} ;
  check pp4 dn1 {|/O=Blanc/CN=John Doe+Initials=J.D.+Initials=N.N.|} ;
  check pp4 dn2 {|/O=\ Escapist/CN=\# 2/CN=\ \"\+,;\/\<\>\\ \ |} ;
  check pp5 dn1 "CN=John Doe+\nInitials=J.D.+\nInitials=N.N.,\nO=Blanc"

let test_yubico () =
  ignore (cert "yubico")

let test_frac_s () =
  let file = "until_frac_s" in
  match Certificate.decode_pem (regression file) with
  | Ok _ -> Alcotest.failf "certificate %s, expected decoding error" file
  | Error (`Msg _) -> ()

let decode_valid_pem file =
  let data = regression file in
  match Private_key.decode_pem data with
   | Ok _ -> ()
   | Error (`Msg _) ->
     Alcotest.failf "private key %s failed to be verified" file

let test_gcloud_key () =
  (* discussion in https://github.com/mirage/mirage-crypto/issues/62 *)
  let file = "gcloud" in
  decode_valid_pem file

let test_openssl_2048_key () =
  (* this key has a d > lcm (p - 1) (q - 1) *)
  let file = "openssl_2048" in
  decode_valid_pem file

let ed25519_priv =
  Ohex.decode "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842"

let ed25519_priv_key () =
  let data =
    {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----
|}
  in
  match Private_key.decode_pem data with
  | Ok (`ED25519 k as ke) when String.equal ed25519_priv (Mirage_crypto_ec.Ed25519.priv_to_octets k) ->
    let encoded = Private_key.encode_pem ke in
    if not (String.equal encoded data) then
      Alcotest.failf "ED25519 encoding failed"
  | Ok (`ED25519 _) -> Alcotest.failf "wrong ED25519 private key"
  | Ok _ | Error (`Msg _) -> Alcotest.failf "ED25519 private key decode failure"

let ed25519_pub_key () =
  let data =
    {|-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
|}
  and pub =
    match Mirage_crypto_ec.Ed25519.priv_of_octets ed25519_priv with
    | Error _ -> Alcotest.fail "couldn't decode private Ed25519 key"
    | Ok p ->
      match Private_key.public (`ED25519 p) with
      | `ED25519 p -> p
      | _ -> Alcotest.fail "couldn't convert private Ed25519 key to public"
  in
  let to_cs = Mirage_crypto_ec.Ed25519.pub_to_octets in
  match Public_key.decode_pem data with
  | Ok (`ED25519 k) when String.equal (to_cs pub) (to_cs k) ->
    let encoded = Public_key.encode_pem (`ED25519 k) in
    if not (String.equal encoded data) then
      Alcotest.failf "ED25519 public key encoding failure"
  | _ -> Alcotest.failf "bad ED25519 public key"

let p384_key () =
  let priv_data = {|-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDzBTbwp91ON4CNuDE+
pjKsehNV7I3eTpyKpMlSUqHAguO8hK+t28A/730TP2L0rPyhZANiAATZbEoUICtu
yXyN4G6DDHaUHwwe2bfcsTvY9LnlLCPvu24JTuGjf7pT2faiuvjGb49jk8C2KJWt
0DISTEJ945y41DY0cIPl1okaN+E3yJ66kKpJ0XeKoOJ0rTTopazzjzI=
-----END PRIVATE KEY-----
|}
  and pub_data = {|-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2WxKFCArbsl8jeBugwx2lB8MHtm33LE7
2PS55Swj77tuCU7ho3+6U9n2orr4xm+PY5PAtiiVrdAyEkxCfeOcuNQ2NHCD5daJ
GjfhN8ieupCqSdF3iqDidK006KWs848y
-----END PUBLIC KEY-----
|}
  in
  match
    Private_key.decode_pem priv_data,
    Public_key.decode_pem pub_data
  with
  | Ok (`P384 priv), Ok (`P384 pub) ->
    let to_cs = Mirage_crypto_ec.P384.Dsa.pub_to_octets in
    let pub' = Mirage_crypto_ec.P384.Dsa.pub_of_priv priv in
    Alcotest.(check bool __LOC__ true (String.equal (to_cs pub) (to_cs pub')));
    let pub_data' = Public_key.encode_pem (`P384 pub) in
    Alcotest.(check bool __LOC__ true
                (String.equal pub_data pub_data'));
    let priv_data' = Private_key.encode_pem (`P384 priv) in
    begin match Private_key.decode_pem priv_data' with
      | Ok (`P384 priv) ->
        let pub' = Mirage_crypto_ec.P384.Dsa.pub_of_priv priv in
        Alcotest.(check bool __LOC__ true
                    (String.equal (to_cs pub) (to_cs pub')))
      | _ -> Alcotest.failf "cannot decode re-encoded P384 private key"
    end
  | _ -> Alcotest.failf "bad P384 key"

let ed25519_cert () =
  let file = "example-25519" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "ED25519 certificate %s, decoding error %s" file msg
  | Ok cert ->
    match Validation.valid_ca cert with
    | Error e ->
      Alcotest.failf "verifying 25519 ca certificate failed %a"
        Validation.pp_ca_error e
    | Ok () ->
      match Validation.verify_chain ~host:(host "www.example.com") ~time ~anchors:[cert] [cert] with
      | Ok _ -> ()
      | Error e ->
        Alcotest.failf "verifying 25519 certificate failed %a"
          Validation.pp_chain_error e

let le_p384_root () =
  let file = "letsencrypt-root-x2" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "let's encrypt P384 certificate %s, decoding error %s"
      file msg
  | Ok cert ->
    match Validation.valid_ca cert with
    | Error e ->
      Alcotest.failf "verifying P384 ca certificate failed %a"
        Validation.pp_ca_error e
    | Ok () -> ()

let p256_key () =
  let file = "priv_p256" in
  match Private_key.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "private P256 key %s decoding error %s" file msg
  | Ok _ -> ()

let ip_address () =
  let c = cert "1.1.1.1" in
  let ta = cert "digicert" in
  match
    Validation.verify_chain ~ip:(Ipaddr.of_string_exn "1.1.1.1")
      ~host:None ~time:(fun () -> None) ~anchors:[ta] [c]
  with
  | Ok _ -> ()
  | Error ce -> Alcotest.failf "validation of IP address failed: %a"
                  Validation.pp_chain_error ce

let alternate_sha1rsa_oid () =
  let file = "alternate-sha1rsa-oid" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "alternate SHA1RSA OID certificate %s, decoding error %s" file msg
  | Ok _cert -> ()

let p256_sha384 () =
  let file = "p256_sha384" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "P256 certificate with SHA384 %s, decoding error %s"
      file msg
  | Ok cert ->
    match Validation.valid_ca cert with
    | Error e ->
      Alcotest.failf "verifying P256 certificate failed %a"
        Validation.pp_ca_error e
    | Ok () -> ()

let rsa_pub () =
  let file = "rsa_pub" in
  let data = regression file in
  match Public_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "RSA public key %s, decoding error %s" file msg
  | Ok pub ->
    let pem = Public_key.encode_pem pub in
    Alcotest.(check string "PEM encoding of RSA public key is identical"
                data pem)

let rsa_priv () =
  let file = "rsa_priv" in
  let data = regression file in
  match Private_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "RSA private key %s, decoding error %s" file msg
  | Ok priv ->
    let pem = Private_key.encode_pem priv in
    Alcotest.(check string "PEM encoding of RSA private key is identical"
                data pem);
    let pub = regression "rsa_pub" in
    Alcotest.(check string "PEM encoding of RSA public key (derived from private key) is identical"
                pub (Public_key.encode_pem (Private_key.public priv)))

let ec_pub file () =
  let data = regression file in
  match Public_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "EC public key %s, decoding error %s" file msg
  | Ok pub ->
    let pem = Public_key.encode_pem pub in
    Alcotest.(check string "PEM encoding of EC public key is identical"
                data pem)

let ec_priv file pub_file () =
  let data = regression file in
  match Private_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "EC private key %s, decoding error %s" file msg
  | Ok priv ->
    let pem = Private_key.encode_pem priv in
    Alcotest.(check string "PEM encoding of EC private key is identical"
                data pem);
    let pub = regression pub_file in
    Alcotest.(check string "PEM encoding of EC public key (derived from private key) is identical"
                pub (Public_key.encode_pem (Private_key.public priv)))

(* Synthetic DER, independent of the library's Name encoder. Only the outer
   TLV lengths and Ed25519 signatures are constructed here; Name expectations
   are literal octets. Comparing complete certificates also checks that the
   retained names were used in the signed TBS, not just the public accessors. *)
module Lossless_name = struct
  let get = function
    | Ok x -> x
    | Error (`Msg m) -> Alcotest.fail m

  let signed_cert = function
    | Ok x -> x
    | Error e -> Alcotest.failf "%a" Validation.pp_signature_error e

  let tlv tag contents =
    let n = String.length contents in
    let length =
      if n < 128 then String.make 1 (Char.chr n)
      else if n < 256 then "\x81" ^ String.make 1 (Char.chr n)
      else "\x82" ^ String.init 2 (function
          | 0 -> Char.chr (n lsr 8)
          | _ -> Char.chr (n land 255))
    in
    String.make 1 (Char.chr tag) ^ length ^ contents

  let algorithm = Ohex.decode "300506032b6570"
  let ca_name = Ohex.decode "300d310b3009060355040313024341"
  let ca_utf8 = Ohex.decode "300d310b300906035504030c024341"
  let leaf_name = Ohex.decode "300f310d300b060355040313044c656166"
  let leaf_utf8 = Ohex.decode "300f310d300b06035504030c044c656166"
  let root_name = Ohex.decode "300f310d300b06035504030c04526f6f74"
  let validity = Ohex.decode
      "301e170d3235303130313030303030305a170d3330303130313030303030305a"

  let key () =
    match Mirage_crypto_ec.Ed25519.priv_of_octets ed25519_priv with
    | Ok k -> `ED25519 k
    | Error _ -> Alcotest.fail "synthetic Ed25519 key"

  let public_key key = Public_key.encode_der (Private_key.public key)

  let signed key tbs =
    let signature = get (Private_key.sign `SHA512 ~scheme:`ED25519 key (`Message tbs)) in
    tlv 0x30 (tbs ^ algorithm ^ tlv 0x03 ("\x00" ^ signature))

  let certificate_der key issuer subject =
    let tbs = tlv 0x30
        (Ohex.decode "a003020102020101" ^ algorithm ^ issuer ^ validity ^
         subject ^ public_key key)
    in
    signed key tbs

  let csr key subject =
    let info = tlv 0x30
        (Ohex.decode "020100" ^ subject ^ public_key key ^ Ohex.decode "a000")
    in
    get (Signing_request.decode_der (signed key info))

  let ca key = get (Certificate.decode_der (certificate_der key root_name ca_name))

  let issue ?subject key ca csr =
    let valid_from, valid_until = Certificate.validity ca in
    signed_cert (Signing_request.sign_certificate csr ~valid_from ~valid_until
                   ~serial:"\x01" ?subject key ca)

  let check_certificate label key issuer subject cert =
    Alcotest.(check string label
                (certificate_der key issuer subject) (Certificate.encode_der cert))

  let cn s = Distinguished_name.[Relative_distinguished_name.singleton (CN s)]

  let printable () =
    let key = key () in
    let ca = ca key and request = csr key leaf_name in
    let cert = issue key ca request in
    check_certificate "CA subject and CSR subject retain PrintableString"
      key ca_name leaf_name cert;
    Alcotest.check check_dn "legacy subject accessor" (cn "Leaf") (Certificate.subject cert);
    Alcotest.check check_dn "legacy CSR info" (cn "Leaf") (Signing_request.info request).subject;
    (* The projection is intentionally tag-insensitive, including chain name
       matching: introducing retained encodings must not tighten trust rules. *)
    Alcotest.check check_dn "legacy issuer equality"
      (Certificate.subject ca) (Certificate.issuer cert)

  let legacy_and_override () =
    let key = key () in
    let ca = ca key and request = csr key leaf_name in
    let valid_from, valid_until = Certificate.validity ca in
    Alcotest.(check string "CN construction still defaults to UTF8String"
                leaf_utf8 (Distinguished_name.encode_der (cn "Leaf")));
    let fresh = get (Signing_request.create (cn "Leaf") key) in
    let fresh_cert = signed_cert
        (Signing_request.sign fresh ~valid_from ~valid_until ~serial:"\x01" key (cn "CA"))
    in
    check_certificate "legacy construction" key ca_utf8 leaf_utf8 fresh_cert;
    let cert = issue ~subject:(Signing_request.info request).subject key ca request in
    check_certificate "explicit, even equal, subject override uses legacy encoding"
      key ca_name leaf_utf8 cert;
    let cert = signed_cert
        (Signing_request.sign request ~valid_from ~valid_until ~serial:"\x01"
           key (Certificate.subject ca))
    in
    check_certificate "legacy issuer loses provenance, CSR does not"
      key ca_utf8 leaf_name cert;
    let other = Distinguished_name.[Relative_distinguished_name.singleton
        (Other (Asn.OID.(base 2 5 <| 4 <| 3), "Leaf"))]
    in
    let fresh = get (Signing_request.create other key) in
    Alcotest.check check_dn "fresh Other with a known OID is not normalized"
      other (Signing_request.info fresh).subject;
    let cert = issue key ca fresh in
    Alcotest.check check_dn "fresh certificate keeps its supplied public view"
      other (Certificate.subject cert)

  let equality () =
    let key = key () in
    (* V1 trust anchor: issuer UTF8String and subject PrintableString are
       equal under existing name matching, although their DER differs. *)
    let tbs = tlv 0x30
        (Ohex.decode "020101" ^ algorithm ^ ca_utf8 ^ validity ^ ca_name ^ public_key key)
    in
    let cert = get (Certificate.decode_der (signed key tbs)) in
    match Validation.valid_ca cert with
    | Ok () -> ()
    | Error e -> Alcotest.failf "%a" Validation.pp_ca_error e

  let supported_strings () =
    let key = key () in
    let ca = ca key in
    List.iter (fun (label, hex) ->
        let name = Ohex.decode hex in
        let request = csr key name in
        check_certificate label key ca_name name (issue key ca request)) [
      "UTF8String bytes", "300d310b300906035504030c02c3a9";
      "PrintableString", "300c310a30080603550403130141";
      "IA5String", "300c310a30080603550403160141";
      "UniversalString bytes", "300f310d300b06035504031c04000000e9";
      "TeletexString bytes", "300c310a300806035504031401e9";
      "BMPString bytes", "300d310b300906035504031e0200e9";
      (* One RDN with two CNs that collapse to one public attribute, followed
         by an unknown OID in a second RDN. Neither Set deduplication nor public
         constructor order should touch the retained representation. *)
      "RDN grouping and distinct tags",
      "30243114300806035504030c014130080603550403130141310c300a06032a03041303466f6f"
    ]

  let ocsp () =
    let key = key () in
    let ca = ca key in
    let id = OCSP.create_cert_id ca "\x01" in
    let request = get (OCSP.Request.create [id]) in
    (* SHA1 of the literal [ca_name], not of a projected/re-encoded Name. *)
    let hash = Ohex.decode "acb0671fd9f377f8b2a767b82e5de5862dbf6177" in
    let key_hash = Public_key.fingerprint ~hash:`SHA1 (Private_key.public key) in
    let id = tlv 0x30
        (Ohex.decode "300906052b0e03021a0500" ^ tlv 0x04 hash ^
         tlv 0x04 key_hash ^ Ohex.decode "020101")
    in
    let expected = tlv 0x30 (tlv 0x30 (tlv 0x30 (tlv 0x30 id))) in
    Alcotest.(check string "OCSP issuerNameHash hashes literal PrintableString Name"
                expected (OCSP.Request.encode_der request))

  let crl () =
    let key = key () in
    let tbs = tlv 0x30
        (Ohex.decode "020101" ^ algorithm ^ ca_name ^
         Ohex.decode "170d3235303130313030303030305a")
    in
    let crl = get (CRL.decode_der (signed key tbs)) in
    let this_update = CRL.this_update crl in
    let updated = get (CRL.revoke_certificates [] ~this_update crl key) in
    (* With no previous CRLNumber, revoke_certificates starts at zero. *)
    let expected_tbs = tlv 0x30
        (Ohex.decode "020101" ^ algorithm ^ ca_name ^
         Ohex.decode "170d3235303130313030303030305aa00e300c300a0603551d140403020100")
    in
    Alcotest.(check string "updating a CRL retains its issuer"
                (signed key expected_tbs) (CRL.encode_der updated))
end

let regression_tests = [
  "lossless PrintableString issuance", `Quick, Lossless_name.printable ;
  "legacy names and subject override", `Quick, Lossless_name.legacy_and_override ;
  "legacy name equality", `Quick, Lossless_name.equality ;
  "retained string bytes and RDNs", `Quick, Lossless_name.supported_strings ;
  "retained OCSP issuer name hash", `Quick, Lossless_name.ocsp ;
  "retained CRL issuer", `Quick, Lossless_name.crl ;
  "RSA: key too small (jc_jc)", `Quick, test_jc_jc ;
  "jc_ca", `Quick, test_jc_ca_fail ;
  "jc_ca", `Quick, test_jc_ca_all_hashes ;
  "jfd_ca", `Quick, test_jfd_ca ;
  "jfd_ca'", `Quick, test_jfd_ca' ;
  "SAN dir explicit or implicit", `Quick, test_izenpe ;
  "name constraint parsing (DNS: .gr)", `Quick, test_name_constraints ;
  "complex distinguished name", `Quick, test_distinguished_name ;
  "distinguished name pp", `Quick, test_distinguished_name_pp ;
  "algorithm without null", `Quick, test_yubico ;
  "valid until generalized_time with fractional seconds", `Quick, test_frac_s ;
  "parse valid key where 1 <> d * e mod (p - 1) * (q - 1)", `Quick, test_gcloud_key ;
  "parse valid key where d <> e ^ -1 mod lcm ((p - 1) (q - 1))", `Quick, test_openssl_2048_key ;
  "ed25519 private key", `Quick, ed25519_priv_key ;
  "ed25519 public key", `Quick, ed25519_pub_key ;
  "p384 key", `Quick, p384_key ;
  "ed25519 certificate", `Quick, ed25519_cert ;
  "p384 certificate", `Quick, le_p384_root ;
  "p256 key", `Quick, p256_key ;
  "ip_address", `Quick, ip_address ;
  "alternative SHA1RSA OID", `Quick, alternate_sha1rsa_oid;
  "p256 with sha384", `Quick, p256_sha384 ;
  "rsa public key", `Quick, rsa_pub ;
  "rsa private key", `Quick, rsa_priv ;
] @ List.flatten (List.map (fun file ->
    [ "public " ^ file, `Quick, ec_pub ("pub_" ^ file) ;
      "private " ^ file, `Quick, ec_priv ("priv_" ^ file) ("pub_" ^ file)
    ]) [ "p521" ; "p384" ; "p256_2" ])

let host_set_test =
  let module M = struct
    type t = Host.Set.t
    let pp ppf hs =
      let pp_one ppf (typ, name) =
        Fmt.pf ppf "%s%a"
          (match typ with `Strict -> "" | `Wildcard -> "*.")
          Domain_name.pp name
      in
      Fmt.(list ~sep:(any ", ") pp_one) ppf (Host.Set.elements hs)
    let equal = Host.Set.equal
  end in (module M: Alcotest.TESTABLE with type t = M.t)

let cert_hostnames cert names () =
  Alcotest.check host_set_test __LOC__ (Certificate.hostnames cert) names

let csr file =
  let data = mmap ("./csr/" ^ file ^ ".pem") in
  match Signing_request.decode_pem data with
  | Ok csr -> csr
  | Error (`Msg m) ->
    Alcotest.failf "signing request %s decoding error %s" file m

let csr_hostnames cert names () =
  Alcotest.check host_set_test __LOC__ (Signing_request.hostnames cert) names

let host_set xs =
  Host.Set.of_list
    (List.map (fun n -> `Strict, Domain_name.(host_exn (of_string_exn n))) xs)

let hostname_tests = [
  "cacert hostnames", `Quick, cert_hostnames cacert Host.Set.empty;
  "izenpe hostnames", `Quick, cert_hostnames (cert "izenpe") (host_set ["izenpe.com"]);
  "jabber.ccc.de hostnames", `Quick, cert_hostnames jc (host_set [ "jabber.ccc.de" ; "conference.jabber.ccc.de" ; "jabberd.jabber.ccc.de" ; "pubsub.jabber.ccc.de" ; "vjud.jabber.ccc.de" ]);
  "jaber.fu-berlin.de hostnames", `Quick, cert_hostnames (cert "jabber.fu-berlin.de") (host_set [ "jabber.fu-berlin.de" ; "conference.jabber.fu-berlin.de" ; "proxy.jabber.fu-berlin.de" ; "echo.jabber.fu-berlin.de" ; "file.jabber.fu-berlin.de" ; "jitsi-videobridge.jabber.fu-berlin.de" ; "multicast.jabber.fu-berlin.de" ; "pubsub.jabber.fu-berlin.de" ]);
  "pads.ccc.de hostnames", `Quick, cert_hostnames (cert "pads.ccc.de") (Host.Set.add (`Wildcard, Domain_name.(host_exn (of_string_exn "pads.ccc.de"))) (host_set ["pads.ccc.de"]));
  "first hostnames", `Quick, cert_hostnames (cert "../testcertificates/first/first") (host_set ["foo.foobar.com"; "foobar.com"]);
  "CSR your_new_domain hostnames", `Quick, csr_hostnames (csr "your-new-domain") (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]);
  "CSR your_new_domain_raw hostnames", `Quick, csr_hostnames (csr "your-new-domain-raw") (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]);
  "CSR bar.com hostnames", `Quick, csr_hostnames (csr "wild-bar") (Host.Set.add (`Wildcard, Domain_name.(host_exn (of_string_exn "bar.com"))) (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]));
  "CSR foo.com hostnames", `Quick, csr_hostnames (csr "wild-foo-cn") (Host.Set.singleton (`Wildcard, Domain_name.(host_exn (of_string_exn "foo.com"))));
]
