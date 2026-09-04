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

(* Literal DER, independent of the name encoder under test: CN=Test. *)
let printable_name_der = Ohex.decode "300f310d300b0603550403130454657374"
let utf8_name_der = Ohex.decode "300f310d300b06035504030c0454657374"

let name_ok what = function
  | Ok x -> x
  | Error _ -> Alcotest.fail what

let encoded_name der =
  name_ok "decode encoded name" (Distinguished_name.Encoded.decode_der der)

let check_encoded_name what expected name =
  Alcotest.(check string what expected
              (Distinguished_name.Encoded.encode_der name))

let test_encoded_name () =
  let module E = Distinguished_name.Encoded in
  let name = encoded_name printable_name_der in
  check_encoded_name "PrintableString survives" printable_name_der name;
  let legacy = E.to_legacy_lossy name in
  let expected = Distinguished_name.[Relative_distinguished_name.singleton (CN "Test")] in
  Alcotest.check check_dn "legacy constructors unchanged" expected legacy;
  Alcotest.check check_dn "same view as legacy decoder" legacy
    (name_ok "decode legacy name" (Distinguished_name.decode_der printable_name_der));
  Alcotest.(check string "legacy encoding is deliberately lossy" utf8_name_der
              (Distinguished_name.encode_der legacy));
  check_encoded_name "fresh legacy name uses UTF8" utf8_name_der (E.of_legacy legacy);
  List.iter (fun hex ->
      let der = Ohex.decode hex in
      check_encoded_name "string tag and content octets survive" der (encoded_name der))
    [ "300f310d300b06035504030c0454657374" ; (* UTF8 *)
      "300f310d300b0603550403160454657374" ; (* IA5 *)
      "300f310d300b0603550403140454657374" ; (* Teletex *)
      "300c310a300806035504031401e9" ; (* Teletex, not UTF8 *)
      "30133111300f06035504031e080054006500730074" ; (* BMP *)
      "301b3119301706035504031c1000000054000000650000007300000074" ; (* Universal *)
      "300e310c300a06022a03130454657374" ; (* unknown OID, known value type *)
      "3000" ];
  let collision = Ohex.decode
      "301c311a300b06035504030c0454657374300b0603550403130454657374" in
  let both = encoded_name collision in
  check_encoded_name "both members of one RDN survive" collision both;
  Alcotest.check check_dn "legacy set merges a tag-only distinction"
    expected (E.to_legacy_lossy both);
  let two_rdns = Ohex.decode
      "301e310d300b0603550403130454657374310d300b06035504030c0454657374" in
  check_encoded_name "RDN sequence order survives" two_rdns (encoded_name two_rdns);
  let defaults = Distinguished_name.[
      Relative_distinguished_name.singleton (C "GB");
      Relative_distinguished_name.singleton (Serialnumber "123");
      Relative_distinguished_name.singleton (DNQ "q");
      Relative_distinguished_name.singleton (DC "com");
      Relative_distinguished_name.singleton (Mail "a@b")
    ] in
  (* Country/serial/qualifier stay PrintableString; DC/mail stay IA5String. *)
  let default_der = Ohex.decode
      "3050310b3009060355040613024742310c300a06035504051303313233310a3008060355042e13017131133011060a0992268993f22c6401191603636f6d3112301006092a864886f70d0109011603614062" in
  check_encoded_name "fresh legacy defaults" default_der (E.of_legacy defaults);
  let alias = Distinguished_name.[Relative_distinguished_name.singleton
      (Other (Asn.OID.(base 2 5 <| 4 <| 3), "Test"))] in
  Alcotest.check check_dn "fresh legacy Other alias is not normalized"
    alias (E.to_legacy_lossy (E.of_legacy alias));
  List.iter (fun der ->
      match E.decode_der der with
      | Error _ -> ()
      | Ok _ -> Alcotest.fail "unexpectedly accepted unsupported or trailing data")
    [ printable_name_der ^ "\x00";
      Ohex.decode "300c310a30080603550403040178" ]

let test_encoded_name_issuance () =
  let module E = Distinguished_name.Encoded in
  let name = encoded_name printable_name_der in
  let root = encoded_name (Ohex.decode "300f310d300b06035504031304526f6f74") in
  let key = match Mirage_crypto_ec.Ed25519.priv_of_octets ed25519_priv with
    | Ok k -> `ED25519 k
    | Error _ -> Alcotest.fail "decode Ed25519 test key"
  in
  let valid_from, valid_until =
    match Ptime.of_date (2024, 1, 1), Ptime.of_date (2025, 1, 1) with
    | Some a, Some b -> a, b
    | _ -> assert false
  in
  let decode_cert result =
    let cert = name_ok "sign certificate" result in
    name_ok "decode signed certificate"
      (Certificate.decode_der (Certificate.encode_der cert))
  in
  let request = name_ok "create encoded CSR" (Signing_request.create_encoded name key) in
  let request = name_ok "decode encoded CSR"
      (Signing_request.decode_der (Signing_request.encode_der request)) in
  check_encoded_name "CSR accessor retains PrintableString" printable_name_der
    (Signing_request.subject_encoded request);
  Alcotest.check check_dn "CSR info is a lossy view" (E.to_legacy_lossy name)
    (Signing_request.info request).subject;
  let ca_extensions = Extension.(
      add Basic_constraints (true, (true, None))
        (singleton Key_usage (true, [ `Key_cert_sign ]))) in
  let ca = decode_cert (Signing_request.sign_encoded request
      ~valid_from ~valid_until ~serial:"\x01" ~extensions:ca_extensions key root) in
  check_encoded_name "CA subject" printable_name_der (Certificate.subject_encoded ca);
  check_encoded_name "CA issuer differs from CA subject" (E.encode_der root)
    (Certificate.issuer_encoded ca);
  let leaf = decode_cert (Signing_request.sign_certificate request
      ~valid_from ~valid_until ~serial:"\x02" key ca) in
  check_encoded_name "legacy sign_certificate retains issuer" printable_name_der
    (Certificate.issuer_encoded leaf);
  check_encoded_name "legacy sign_certificate retains CSR subject" printable_name_der
    (Certificate.subject_encoded leaf);
  let verify leaf =
    match Validation.verify_chain ~host:None ~time:(fun () -> None) ~anchors:[ca] [leaf] with
    | Ok _ -> ()
    | Error e -> Alcotest.failf "issued signature/chain invalid: %a" Validation.pp_chain_error e
  in
  verify leaf;
  let legacy = Certificate.subject ca in
  Alcotest.check check_dn "certificate accessor is a lossy view"
    (E.to_legacy_lossy name) legacy;
  let legacy_issuer = decode_cert (Signing_request.sign request
      ~valid_from ~valid_until ~serial:"\x03" key legacy) in
  check_encoded_name "legacy issuer argument uses defaults" utf8_name_der
    (Certificate.issuer_encoded legacy_issuer);
  check_encoded_name "legacy sign retains CSR subject by default" printable_name_der
    (Certificate.subject_encoded legacy_issuer);
  (* Tag-insensitive matching has not changed. *)
  verify legacy_issuer;
  let override = decode_cert (Signing_request.sign_certificate request
      ~valid_from ~valid_until ~serial:"\x04" ~subject:legacy key ca) in
  check_encoded_name "explicit equal legacy subject selects defaults" utf8_name_der
    (Certificate.subject_encoded override);
  let override = decode_cert (Signing_request.sign_certificate_encoded request
      ~valid_from ~valid_until ~serial:"\x05" ~subject:root key ca) in
  check_encoded_name "encoded override replaces whole subject" (E.encode_der root)
    (Certificate.subject_encoded override);
  check_encoded_name "encoded override does not replace issuer" printable_name_der
    (Certificate.issuer_encoded override);
  verify override;
  let collision_der = Ohex.decode
      "301c311a300b06035504030c0454657374300b0603550403130454657374" in
  let collision = encoded_name collision_der in
  let multi_request = name_ok "create multi-valued CSR"
      (Signing_request.create_encoded collision key) in
  let multi_request = name_ok "decode multi-valued CSR"
      (Signing_request.decode_der (Signing_request.encode_der multi_request)) in
  let multi = decode_cert (Signing_request.sign_encoded multi_request
      ~valid_from ~valid_until ~serial:"\x06" key name) in
  check_encoded_name "issuance retains members that legacy sets would merge"
    collision_der (Certificate.subject_encoded multi);
  let explicit = decode_cert (Signing_request.sign_encoded request
      ~valid_from ~valid_until ~serial:"\x07" ~subject:collision key name) in
  check_encoded_name "sign_encoded accepts a lossless subject override"
    collision_der (Certificate.subject_encoded explicit);
  let fresh = name_ok "create legacy CSR" (Signing_request.create legacy key) in
  let fresh = name_ok "decode legacy CSR"
      (Signing_request.decode_der (Signing_request.encode_der fresh)) in
  check_encoded_name "legacy create still uses UTF8" utf8_name_der
    (Signing_request.subject_encoded fresh);
  let alias = Distinguished_name.[Relative_distinguished_name.singleton
      (Other (Asn.OID.(base 2 5 <| 4 <| 3), "Test"))] in
  let alias_request = name_ok "create legacy alias CSR"
      (Signing_request.create alias key) in
  Alcotest.check check_dn "fresh CSR preserves the supplied legacy view"
    alias (Signing_request.info alias_request).subject;
  let alias_leaf = name_ok "sign legacy alias CSR"
      (Signing_request.sign_certificate alias_request ~valid_from ~valid_until
         ~serial:"\x08" key ca) in
  Alcotest.check check_dn "fresh certificate preserves the supplied legacy view"
    alias (Certificate.subject alias_leaf);
  (* Decode the minimal unsigned OCSP request structurally, independently of
     X509's private CertID codec. Each single-field SEQUENCE is represented by
     a singleton list here; there are no optional fields in this request. *)
  let cert_id = Asn.S.(sequence4
      (required (sequence2 (required oid) (optional null)))
      (required octet_string) (required octet_string) (required integer)) in
  let request_codec = Asn.(codec der S.(
      sequence_of (sequence_of (sequence_of (sequence_of cert_id))))) in
  let ocsp = name_ok "create OCSP request"
      (OCSP.Request.create [OCSP.create_cert_id ca "\x02"]) in
  match Asn.decode request_codec (OCSP.Request.encode_der ocsp) with
  | Ok ([[[[(_, name_hash, _, _)]]]], "") ->
    let hash s = Digestif.SHA1.(to_raw_string (digest_string s)) in
    Alcotest.(check string "OCSP hashes literal retained issuer Name DER"
                (hash printable_name_der) name_hash);
    Alcotest.(check bool "OCSP does not hash the lossy UTF8 view" false
                (String.equal (hash utf8_name_der) name_hash))
  | _ -> Alcotest.fail "unexpected minimal OCSP request"

let regression_tests = [
  "lossless name codec and legacy view", `Quick, test_encoded_name ;
  "lossless name issuance and OCSP hash", `Quick, test_encoded_name_issuance ;
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
