open X509

let hex = Ohex.decode
let seq s =
  let n = String.length s in
  let length =
    if n < 128 then String.make 1 (Char.chr n)
    else if n < 256 then "\x81" ^ String.make 1 (Char.chr n)
    else "\x82" ^ String.init 2 (fun i ->
        Char.chr (if i = 0 then n lsr 8 else n land 255))
  in
  "\x30" ^ length ^ s

let tlv tag s =
  let encoded = seq s in
  String.make 1 (Char.chr tag) ^ String.sub encoded 1 (String.length encoded - 1)

let extension ?(critical = "") oid contents =
  seq (hex oid ^ critical ^ tlv 4 contents)

let extensions xs = seq (String.concat "" xs)
let dns s = tlv 0x82 s
let uri s = tlv 0x86 s
let name tag s = seq (tlv 0x31 (seq (hex "0603550403" ^ tlv tag s)))
let gn_order = seq (dns "a.example" ^ uri "https://example.com" ^ dns "b.example")
let basic = extension "0603551d13" (hex "30030101ff")
let skid = extension "0603551d0e" (hex "040141")
let ordered_extensions = extensions [basic; skid]
let key_usage = extensions [extension "0603551d0f" (hex "03020780")]
let cps =
  let qualifier = seq (hex "06082b06010505070201" ^ tlv 0x16 "https://example.com/cps") in
  seq (seq (hex "06022a03" ^ seq qualifier))
let notice =
  let reference = seq (tlv 0x0c "Example" ^ seq (hex "020101")) in
  let qualifier = seq (hex "06082b06010505070202" ^ seq reference) in
  seq (seq (hex "06022a03" ^ seq qualifier))
let compressed_spki = hex
    "3039301306072a8648ce3d020106082a8648ce3d030107032200036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"

let show label kind bytes =
  try
    match Roundtrip_audit.reencode kind bytes with
    | Error (`Msg message) -> Printf.printf "%s\tREJECTED\t%s\n" label message
    | Ok after ->
      Printf.printf "%s\t%s\t%s\t%s\n" label
        (if String.equal bytes after then "SAME" else "CHANGED")
        (Ohex.encode bytes) (Ohex.encode after)
  with exn -> Printf.printf "%s\tEXCEPTION\t%s\n" label (Printexc.to_string exn)

let get = function Ok x -> x | Error (`Msg message) -> failwith message

let primitive_cases () =
  List.iter (fun (label, kind, bytes) -> show label kind bytes) [
    "rsa-parameters-absent", `Algorithm, hex "300b06092a864886f70d01010b";
    "rsa-parameters-null", `Algorithm, hex "300d06092a864886f70d01010b0500";
    "sha1-oiw-oid", `Algorithm, hex "300906052b0e03021d0500";
    "p256-compressed-spki", `Public_key, compressed_spki;
    "name-printable", `Name, name 0x13 "A";
    "name-bmp", `Name, name 0x1e "\x00A";
    "name-identical-duplicates", `Name,
      hex "30163114300806035504030c0141300806035504030c0141";
    "name-fixed-country-utf8", `Name, hex "300d310b300906035504060c025553";
    "another-name-unknown-utf8", `General_name, hex "a00906022a03a0030c0141";
    "another-name-empty-utf8", `General_name, hex "a00806022a03a0020c00";
    "another-name-null", `General_name, hex "a00806022a03a0020500";
    "edi-party-printable", `General_name, hex "a505a103130141";
    "general-names-interleaving", `General_names, gn_order;
    "x400-placeholder-duplicates", `General_names, hex "300483008300";
    "extension-order", `Extensions, ordered_extensions;
    "extension-unknown-raw", `Extensions, extensions [extension "06032a0304" (hex "ff000123")];
    "extension-critical-false", `Extensions,
      extensions [extension ~critical:(hex "010100") "06032a0304" (hex "040141")];
    "basic-constraints-default-false", `Extensions,
      extensions [extension "0603551d13" (hex "3003010100")];
    "basic-constraints-pathlen-zero", `Extensions,
      extensions [extension "0603551d13" (hex "30060101ff020100")];
    "key-usage-digital-signature", `Extensions, key_usage;
    "key-usage-unknown-bit9", `Extensions,
      extensions [extension "0603551d0f" (hex "0303060040")];
    "policy-cps-qualifier", `Extensions, extensions [extension "0603551d20" cps];
    "policy-user-notice", `Extensions, extensions [extension "0603551d20" notice];
    "aki-empty-issuer", `Extensions, extensions [extension "0603551d23" (hex "3002a100")];
    "aki-negative-serial", `Extensions, extensions [extension "0603551d23" (hex "30038201ff")];
    "name-constraints-empty-permitted", `Extensions,
      extensions [extension "0603551d1e" (hex "3002a000")];
    "name-constraints-explicit-min-zero", `Extensions,
      extensions [extension "0603551d1e" (seq (tlv 0xa0 (seq (dns "example.com" ^ hex "800100"))))];
    "name-constraints-max-zero", `Extensions,
      extensions [extension "0603551d1e" (seq (tlv 0xa0 (seq (dns "example.com" ^ hex "810100"))))];
    "duplicate-extension", `Extensions, extensions [basic; basic];
    "time-generalized-year2000", `Time, tlv 0x18 "20000101000000Z";
    "time-generalized-year1949", `Time, tlv 0x18 "19490101000000Z";
    "time-utc-no-seconds", `Time, tlv 0x17 "0001010000Z";
    "time-generalized-zero-fraction", `Time, tlv 0x18 "20500101000000.000Z";
    "time-generalized-offset", `Time, tlv 0x18 "20500101010000+0100";
    "time-generalized-missing-zone", `Time, tlv 0x18 "20500101000000";
    "serial-negative", `Serial, hex "0201ff";
    "serial-negative20", `Serial, tlv 2 ("\x80" ^ String.make 19 '\x00');
    "serial-positive128", `Serial, hex "02020080";
    "bit-string-seven-bits", `Bits, hex "03020180";
    "bit-string-nonzero-padding", `Bits, hex "03020181";
    "boolean-noncanonical-true", `Bool, hex "010101";
    "length127-nonminimal", `Octets, "\x04\x81\x7f" ^ String.make 127 'A';
    "set-unsorted", `Integer_set, hex "3106020102020101"
  ]

let check_embedded label certificate =
  (* Decode-path checks only: the enclosing OCSP signature is a dummy value.
     The request uses upstream's legacy untagged optionalSignature grammar;
     fixing its missing RFC [0] wrapper is a separate OCSP issue. *)
  let algorithm = hex "300506032b6570" in
  let signature = tlv 3 ("\x00" ^ String.make 64 '\x00') in
  let certs = tlv 0xa0 (seq certificate) in
  let id = seq (hex "300906052b0e03021a0500" ^ tlv 4 (String.make 20 '\x00') ^
                tlv 4 (String.make 20 '\x00') ^ hex "020101") in
  let request_tbs = seq (seq (seq id)) in
  let request = seq (request_tbs ^ seq (algorithm ^ signature ^ certs)) in
  let now = tlv 0x18 "20300101000000Z" in
  let single_response = seq (id ^ hex "8000" ^ now) in
  let response_data = seq (tlv 0xa2 (tlv 4 (String.make 20 '\x00')) ^ now ^ seq single_response) in
  let basic = seq (response_data ^ algorithm ^ signature ^ certs) in
  let response = seq (hex "0a0100" ^ tlv 0xa0 (seq
      (hex "06092b0601050507300101" ^ tlv 4 basic))) in
  let accepted = function Ok _ -> true | Error _ -> false in
  Printf.printf "%s/embedded-request\taccepted=%b\n" label
    (accepted (OCSP.Request.decode_der request));
  Printf.printf "%s/embedded-response\taccepted=%b\n" label
    (accepted (OCSP.Response.decode_der response))

let report_signed label hash scheme pub (bytes, tbs, signature) =
  check_embedded label bytes;
  show label `Certificate bytes;
  let valid message = Result.is_ok (Public_key.verify hash ~scheme ~signature pub (`Message message)) in
  match Roundtrip_audit.fresh_tbs_of_certificate bytes with
  | Error _ -> ()
  | Ok after ->
    Printf.printf "%s/signature\toriginal=%b\tfresh-tbs=%b\n" label (valid tbs) (valid after)

let signed_certificate_cases () =
  let secret = hex "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" in
  let key = match Mirage_crypto_ec.Ed25519.priv_of_octets secret with
    | Ok key -> `ED25519 key | Error _ -> failwith "Ed25519 test seed"
  in
  let pub = Private_key.public key in
  let algorithm = hex "300506032b6570" in
  let base_validity = seq (tlv 0x17 "260101000000Z" ^ tlv 0x17 "300101000000Z") in
  let make ?(version = hex "a003020102") ?(serial = hex "020101")
      ?(subject = name 0x0c "Leaf") ?(validity = base_validity)
      ?(spki = Public_key.encode_der pub) ?(uid = "") ?(exts = "") () =
    let tbs = seq (version ^ serial ^ algorithm ^ name 0x0c "Root" ^ validity ^
                   subject ^ spki ^ uid ^ exts) in
    let signature = get (Private_key.sign `SHA512 ~scheme:`ED25519 key (`Message tbs)) in
    seq (tbs ^ algorithm ^ tlv 3 ("\x00" ^ signature)), tbs, signature
  in
  List.iter (fun (label, signed) -> report_signed label `SHA512 `ED25519 pub signed) [
    "cert-baseline", make ();
    "cert-printable-subject", make ~subject:(name 0x13 "Leaf") ();
    "cert-negative-serial", make ~serial:(hex "0201ff") ();
    "cert-negative-serial20", make ~serial:(tlv 2 ("\x80" ^ String.make 19 '\x00')) ();
    "cert-explicit-v1", make ~version:(hex "a003020100") ();
    "cert-empty-extensions", make ~exts:(hex "a3023000") ();
    "cert-generalized-time", make
      ~validity:(seq (tlv 0x18 "20260101000000Z" ^ tlv 0x17 "300101000000Z")) ();
    "cert-seven-bit-uid", make ~uid:(hex "81020180") ();
    "cert-compressed-ec-spki", make ~spki:compressed_spki ();
    "cert-extension-order", make ~exts:(tlv 0xa3 ordered_extensions) ();
    "cert-key-usage", make ~exts:(tlv 0xa3 key_usage) ();
    "cert-policy-cps", make ~exts:(tlv 0xa3 (extensions [extension "0603551d20" cps])) ();
    "cert-san-order", make ~exts:(tlv 0xa3 (extensions [extension "0603551d11" gn_order])) ();
    "guard-unsorted-name-set", make ~subject:(hex
      "3016311430080603550403130141300806035504030c0141") ();
    "guard-noncanonical-critical", make ~exts:(tlv 0xa3 (extensions
      [extension ~critical:(hex "010101") "0603551d13" (hex "3000")])) ();
    "guard-nonzero-bit-padding", make ~uid:(hex "81020181") ();
    "guard-nonminimal-length127", make ~subject:(seq (tlv 0x31 (seq
      (hex "0603550403" ^ "\x0c\x81\x7f" ^ String.make 127 'A')))) ()
  ]

let rsa_certificate_cases () =
  let key = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:1024 ()) in
  let pub = Private_key.public key in
  let validity = seq (tlv 0x17 "260101000000Z" ^ tlv 0x17 "300101000000Z") in
  let with_null = hex "300d06092a864886f70d01010b0500"
  and without_null = hex "300b06092a864886f70d01010b"
  and sha1_pkcs = hex "300d06092a864886f70d0101050500"
  and sha1_oiw = hex "300906052b0e03021d0500" in
  List.iter (fun (label, hash, inner, outer) ->
      let tbs = seq (hex "a003020102020101" ^ inner ^ name 0x0c "Root" ^ validity ^
                     name 0x0c "Leaf" ^ Public_key.encode_der pub) in
      let signature = get (Private_key.sign hash ~scheme:`RSA_PKCS1 key (`Message tbs)) in
      let bytes = seq (tbs ^ outer ^ tlv 3 ("\x00" ^ signature)) in
      report_signed label hash `RSA_PKCS1 pub (bytes, tbs, signature)) [
    "rsa-cert-baseline", `SHA256, with_null, with_null;
    "rsa-cert-absent-parameters", `SHA256, without_null, without_null;
    "rsa-cert-inner-absent-parameters", `SHA256, without_null, with_null;
    "rsa-cert-outer-absent-parameters", `SHA256, with_null, without_null;
    "rsa-cert-legacy-oid", `SHA1, sha1_oiw, sha1_oiw;
    "rsa-cert-outer-legacy-oid", `SHA1, sha1_pkcs, sha1_oiw
  ]

let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in channel) (fun () ->
      really_input_string channel (in_channel_length channel))

let corpus paths =
  let parsed = ref 0 and same = ref 0 and changed = ref 0 and exceptions = ref 0 in
  List.iter (fun path ->
      match Roundtrip_audit.certificate_der_of_pem (read_file path) with
      | Error _ -> ()
      | Ok certificates ->
        List.iteri (fun index bytes ->
            incr parsed;
            try
              match Roundtrip_audit.reencode `Certificate bytes with
              | Ok after when String.equal after bytes -> incr same
              | Ok after ->
                incr changed;
                Printf.printf "CORPUS\t%s#%d\tCHANGED\t%d\t%d\n"
                  path index (String.length bytes) (String.length after)
              | Error (`Msg message) ->
                incr exceptions;
                Printf.printf "CORPUS\t%s#%d\tREJECTED\t%s\n" path index message
            with exn ->
              incr exceptions;
              Printf.printf "CORPUS\t%s#%d\tEXCEPTION\t%s\n"
                path index (Printexc.to_string exn)) certificates) paths;
  Printf.printf "CORPUS_SUMMARY\tparsed=%d\tsame=%d\tchanged=%d\terrors=%d\n"
    !parsed !same !changed !exceptions

let () =
  Mirage_crypto_rng_unix.use_default ();
  primitive_cases ();
  (match Roundtrip_audit.reencode `Serial (tlv 2 ("\x80" ^ String.make 19 '\x00')) with
   | Error (`Msg message) -> Printf.printf "negative20-first-pass\t%s\n" message
   | Ok after -> show "negative20-second-pass" `Serial after);
  signed_certificate_cases ();
  rsa_certificate_cases ();
  corpus (List.tl (Array.to_list Sys.argv))
