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
    Relative_distinguished_name.singleton (DC (Encoded_string.of_octets ~encoding:`IA5 "rs")) ;
    Relative_distinguished_name.singleton (DC (Encoded_string.of_octets ~encoding:`IA5 "posta")) ;
    Relative_distinguished_name.singleton (DC (Encoded_string.of_octets ~encoding:`IA5 "ca")) ;
    Relative_distinguished_name.singleton (CN (Encoded_string.of_octets "Configuration")) ;
    Relative_distinguished_name.singleton (CN (Encoded_string.of_octets "Services")) ;
    Relative_distinguished_name.singleton (CN (Encoded_string.of_octets "Public Key Services")) ;
    Relative_distinguished_name.singleton (CN (Encoded_string.of_octets "AIA")) ;
    Relative_distinguished_name.singleton (CN (Encoded_string.of_octets "Posta CA Root"))
  ] in
  Alcotest.(check check_dn "complex issuer is good"
              expected (Certificate.issuer crt)) ;
  Alcotest.(check check_dn "complex subject is good"
              expected (Certificate.subject crt))

let test_distinguished_name_pp () =
  let module Dn = struct
    include Distinguished_name
    let cn s = Relative_distinguished_name.singleton (CN (Encoded_string.of_octets s))
    let o s = Relative_distinguished_name.singleton (O (Encoded_string.of_octets s))
    let initials s =
      Relative_distinguished_name.singleton (Initials (Encoded_string.of_octets s))
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

let decode_name der =
  match Distinguished_name.decode_der der with
  | Ok dn -> dn
  | Error (`Msg msg) -> Alcotest.failf "name decoding error: %s" msg

let test_encoded_name_roundtrip () =
  let open Distinguished_name in
  (* These are content octets, not text passed through a tag-specific encoder.
     In particular, A is two bytes in BMPString and four in UniversalString. *)
  List.iter (fun (encoding, octets, hex) ->
      let der = Ohex.decode hex in
      let dn = decode_name der in
      Alcotest.(check string "name DER" der (encode_der dn)) ;
      match common_name dn with
      | None -> Alcotest.fail "missing CN"
      | Some value ->
        Alcotest.(check string "CN content octets" octets
                    (Encoded_string.to_octets value)) ;
        Alcotest.(check bool "CN tag" true
                    (encoding = Encoded_string.encoding value)))
    [ `UTF8, "A", "300c310a300806035504030c0141" ;
      `UTF8, "\xc3\xa9", "300d310b300906035504030c02c3a9" ;
      `Printable, "A", "300c310a30080603550403130141" ;
      `IA5, "A", "300c310a30080603550403160141" ;
      `Teletex, "A", "300c310a30080603550403140141" ;
      `Universal, "\x00\x00\x00A", "300f310d300b06035504031c0400000041" ;
      `BMP, "\x00A", "300d310b300906035504031e020041" ] ;
  let fresh = [Relative_distinguished_name.singleton
                 (CN (Encoded_string.of_octets "A"))] in
  Alcotest.(check string "fresh CN defaults to UTF8String"
              (Ohex.decode "300c310a300806035504030c0141") (encode_der fresh))

(* A short-form DER fixture builder, independent of the library encoder. *)
let short_tlv tag contents =
  let len = String.length contents in
  assert (len < 128) ;
  String.make 1 (Char.chr tag) ^ String.make 1 (Char.chr len) ^ contents

let test_all_attribute_tags () =
  let open Distinguished_name in
  let other_oid = Asn.OID.(base 1 2 <| 3 <| 4) in
  let attributes = [
    (fun x -> CN x), "550403" ;
    (fun x -> Serialnumber x), "550405" ;
    (fun x -> C x), "550406" ;
    (fun x -> L x), "550407" ;
    (fun x -> ST x), "550408" ;
    (fun x -> O x), "55040a" ;
    (fun x -> OU x), "55040b" ;
    (fun x -> T x), "55040c" ;
    (fun x -> DNQ x), "55042e" ;
    (fun x -> Mail x), "2a864886f70d010901" ;
    (fun x -> DC x), "0992268993f22c640119" ;
    (fun x -> Given_name x), "55042a" ;
    (fun x -> Surname x), "550404" ;
    (fun x -> Initials x), "55042b" ;
    (fun x -> Pseudonym x), "550441" ;
    (fun x -> Generation x), "55042c" ;
    (fun x -> Street x), "550409" ;
    (fun x -> Userid x), "0992268993f22c640101" ;
    (fun x -> Other (other_oid, x)), "2a0304"
  ] in
  (* Deliberately use BMPString even for fixed-schema attributes. The parser
     already accepts this: preservation must not silently repair their tags. *)
  let value = Encoded_string.of_octets ~encoding:`BMP "\x00A" in
  List.iter (fun (attribute, oid) ->
      let der = short_tlv 0x30 (short_tlv 0x31
          (short_tlv 0x30 (short_tlv 0x06 (Ohex.decode oid) ^ "\x1e\x02\x00A"))) in
      let expected = [Relative_distinguished_name.singleton (attribute value)] in
      let decoded = decode_name der in
      Alcotest.(check bool "decoded attribute and tag" true
                  (equal_representation expected decoded)) ;
      Alcotest.(check string "constructed attribute DER" der (encode_der expected)) ;
      Alcotest.(check string "parsed attribute DER" der (encode_der decoded)))
    attributes

let test_name_matching_and_storage () =
  let open Distinguished_name in
  let utf8 = CN (Encoded_string.of_octets "A")
  and printable = CN (Encoded_string.of_octets ~encoding:`Printable "A")
  and bmp = CN (Encoded_string.of_octets ~encoding:`BMP "\x00A") in
  let name attr = [Relative_distinguished_name.singleton attr] in
  Alcotest.(check bool "tag-agnostic matching" true
              (equal (name utf8) (name printable))) ;
  Alcotest.(check bool "representation distinguishes tags" false
              (equal_representation (name utf8) (name printable))) ;
  Alcotest.(check bool "wire encoding distinguishes tags" false
              (String.equal (encode_der (name utf8)) (encode_der (name printable)))) ;
  Alcotest.(check bool "matching does not transcode BMPString" false
              (equal (name utf8) (name bmp))) ;
  Alcotest.(check bool "matching remains case sensitive" false
              (equal (name utf8) (name (CN (Encoded_string.of_octets "a"))))) ;
  Alcotest.(check bool "matching distinguishes attribute types" false
              (equal (name utf8) (name (O (Encoded_string.of_octets "A"))))) ;
  let mixed_der = Ohex.decode "30163114300806035504030c014130080603550403130141" in
  let mixed = decode_name mixed_der in
  let constructed = [Relative_distinguished_name.of_list [printable; utf8; utf8]] in
  Alcotest.(check bool "storage retains tag differences, not exact duplicates" true
              (equal_representation mixed constructed)) ;
  Alcotest.(check string "constructed multi-valued RDN DER"
              mixed_der (encode_der constructed)) ;
  (match mixed with
   | [rdn] ->
     Alcotest.(check int "tag-only duplicates survive in storage" 2
                 (Relative_distinguished_name.cardinal rdn)) ;
     Alcotest.(check bool "set operations distinguish tags" false
                 (Relative_distinguished_name.equal rdn
                    (Relative_distinguished_name.singleton utf8)))
   | _ -> Alcotest.fail "expected one multi-valued RDN") ;
  Alcotest.(check string "multi-valued RDN DER" mixed_der (encode_der mixed)) ;
  Alcotest.(check bool "matching collapses tag-only duplicates" true
              (equal mixed (name printable))) ;
  Alcotest.(check bool "RDN boundaries still matter" false
              (equal mixed (name utf8 @ name printable))) ;
  let organization = name (O (Encoded_string.of_octets "Example")) in
  Alcotest.(check bool "RDN order still matters" false
              (equal (organization @ name utf8) (name utf8 @ organization)))

let test_common_name_with_tag_distinct_attributes () =
  let open Distinguished_name in
  let attrs = [
    CN (Encoded_string.of_octets "a.example");
    O (Encoded_string.of_octets "X");
    O (Encoded_string.of_octets ~encoding:`Printable "X");
    O (Encoded_string.of_octets ~encoding:`Teletex "X")
  ] in
  let get what = function
    | Ok value -> value
    | Error _ -> Alcotest.fail what
  in
  let key = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:1024 ()) in
  let valid_from = Ptime.epoch in
  let valid_until = match Ptime.add_span valid_from (Ptime.Span.of_int_s 3600) with
    | Some time -> time
    | None -> assert false
  in
  let expected = Host.Set.singleton
      (`Strict, Domain_name.host_exn (Domain_name.of_string_exn "a.example")) in
  List.iter (fun attrs ->
      let rdn = List.fold_left (fun rdn attr ->
          Relative_distinguished_name.add attr rdn)
          Relative_distinguished_name.empty attrs in
      let name = [rdn] in
      (match common_name name with
       | Some value -> Alcotest.(check string "CN survives tag-distinct attributes"
                                  "a.example" (Encoded_string.to_octets value))
       | None -> Alcotest.fail "CN disappeared from a multi-valued RDN");
      let request = get "create mixed-RDN CSR" (Signing_request.create name key) in
      Alcotest.(check bool "CSR hostname fallback" true
                  (Host.Set.equal expected (Signing_request.hostnames request)));
      let certificate = get "sign mixed-RDN certificate"
          (Signing_request.sign request ~valid_from ~valid_until key name) in
      Alcotest.(check bool "certificate hostname fallback" true
                  (Host.Set.equal expected (Certificate.hostnames certificate))))
    [attrs; List.rev attrs]

let test_encoded_name_issuance () =
  let open Distinguished_name in
  let key () = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:1024 ())
  and get what = function
    | Ok value -> value
    | Error _ -> Alcotest.fail ("couldn't " ^ what)
  in
  let valid_from = Ptime.epoch
  and valid_until =
    match Ptime.add_span Ptime.epoch (Ptime.Span.of_int_s 3600) with
    | Some time -> time
    | None -> assert false
  in
  let ca_der = Ohex.decode "3015311330110603550403130a4578616d706c65204341"
  and leaf_der = Ohex.decode "301a311830160603550403130f7777772e6578616d706c652e636f6d" in
  let ca_name = decode_name ca_der
  and ca_key = key () in
  let ca_extensions = Extension.(add Key_usage (true, [`Key_cert_sign])
      (singleton Basic_constraints (true, (true, None)))) in
  let ca_request = Signing_request.create ca_name ca_key |> get "create CA CSR" in
  let ca = Signing_request.sign ca_request ~valid_from ~valid_until
      ~extensions:ca_extensions ca_key ca_name |> get "sign CA" in
  let ca = Certificate.decode_der (Certificate.encode_der ca) |> get "decode CA" in
  let leaf_request = Signing_request.create (decode_name leaf_der) (key ())
                     |> get "create leaf CSR" in
  let leaf_request = Signing_request.decode_der (Signing_request.encode_der leaf_request)
                     |> get "decode leaf CSR" in
  let leaf = Signing_request.sign_certificate leaf_request ~valid_from ~valid_until
      ca_key ca |> get "sign leaf" in
  let leaf = Certificate.decode_der (Certificate.encode_der leaf) |> get "decode leaf" in
  (* Literal DER expectations cannot pass merely because both sides lost tags. *)
  Alcotest.(check string "CA subject retains PrintableString"
              ca_der (encode_der (Certificate.subject ca))) ;
  Alcotest.(check string "CSR subject retains PrintableString"
              leaf_der (encode_der (Signing_request.info leaf_request).subject)) ;
  Alcotest.(check string "leaf subject retains PrintableString"
              leaf_der (encode_der (Certificate.subject leaf))) ;
  Alcotest.(check string "leaf issuer retains PrintableString"
              ca_der (encode_der (Certificate.issuer leaf))) ;
  (* Changing storage equality must not tighten issuer matching. *)
  let utf8_issuer = [Relative_distinguished_name.singleton
                      (CN (Encoded_string.of_octets "Example CA"))] in
  let mixed_leaf = Signing_request.sign leaf_request ~valid_from ~valid_until
      ca_key utf8_issuer |> get "sign mixed-encoding leaf" in
  Alcotest.(check bool "mixed issuer differs in representation" false
              (equal_representation (Certificate.subject ca) (Certificate.issuer mixed_leaf))) ;
  (match Validation.verify_chain ~host:None ~time:(fun () -> None)
           ~anchors:[ca] [mixed_leaf] with
   | Ok _ -> ()
   | Error err -> Alcotest.failf "mixed-encoding chain: %a"
                    Validation.pp_chain_error err) ;
  (* SHA1 of the literal PrintableString CA Name, independently computed.
     Only the unrelated key hash varies with the freshly generated key. *)
  let expected_request =
    Ohex.decode ("30423040303e303c303a300906052b0e03021a05000414" ^
                 "ef0085e8bdda047c568dcf61fc7da44493fdf0e6" ^ "0414") ^
    Public_key.fingerprint ~hash:`SHA1 (Certificate.public_key ca) ^ "\x02\x01\x2a"
  in
  let request = OCSP.Request.create [OCSP.create_cert_id ~hash:`SHA1 ca "\x2a"]
                |> get "create OCSP request" in
  Alcotest.(check string "OCSP issuerNameHash covers preserved tag"
              expected_request (OCSP.Request.encode_der request))

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

let regression_tests = [
  "RSA: key too small (jc_jc)", `Quick, test_jc_jc ;
  "jc_ca", `Quick, test_jc_ca_fail ;
  "jc_ca", `Quick, test_jc_ca_all_hashes ;
  "jfd_ca", `Quick, test_jfd_ca ;
  "jfd_ca'", `Quick, test_jfd_ca' ;
  "SAN dir explicit or implicit", `Quick, test_izenpe ;
  "name constraint parsing (DNS: .gr)", `Quick, test_name_constraints ;
  "complex distinguished name", `Quick, test_distinguished_name ;
  "distinguished name pp", `Quick, test_distinguished_name_pp ;
  "encoded name roundtrip", `Quick, test_encoded_name_roundtrip ;
  "all attribute tags", `Quick, test_all_attribute_tags ;
  "name matching and storage", `Quick, test_name_matching_and_storage ;
  "encoded name issuance and OCSP", `Quick, test_encoded_name_issuance ;
  "CN lookup with tag-distinct RDN members", `Quick,
    test_common_name_with_tag_distinct_attributes ;
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
