open X509

let get = function
  | Ok x -> x
  | Error (`Msg message) -> Alcotest.fail message

let signed = function
  | Ok x -> x
  | Error error -> Alcotest.failf "%a" Validation.pp_signature_error error

let present label = function
  | Some x -> x
  | None -> Alcotest.fail (label ^ " is absent")

let check_error label = function
  | Error _ -> ()
  | Ok _ -> Alcotest.fail (label ^ " unexpectedly succeeded")

let check_invalid_argument label f =
  match f () with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail (label ^ " did not raise Invalid_argument")

let bytes = Alcotest.check Alcotest.string
let truth = Alcotest.check Alcotest.bool
let integer = Alcotest.check Alcotest.int
let z = Alcotest.testable (fun ppf n -> Fmt.string ppf (Z.to_string n)) Z.equal
let ptime = Alcotest.testable Ptime.pp Ptime.equal

let hex s =
  let digit c = match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | _ -> invalid_arg "hex fixture"
  in
  if String.length s mod 2 <> 0 then invalid_arg "hex fixture length";
  String.init (String.length s / 2) (fun i ->
      Char.chr ((digit s.[2 * i] lsl 4) lor digit s.[2 * i + 1]))

(* Independent, test-only DER builders. Expected certificates are assembled and
   signed before decoding, never obtained by encoding the certificate under test.
   Only synthetic data and published RFC 8032 test seeds are used. *)
let tlv tag contents =
  let n = String.length contents in
  let length =
    if n < 128 then String.make 1 (Char.chr n)
    else if n < 256 then "\x81" ^ String.make 1 (Char.chr n)
    else if n < 65536 then "\x82" ^ String.init 2 (fun i ->
        Char.chr (if i = 0 then n lsr 8 else n land 255))
    else invalid_arg "oversized DER fixture"
  in
  String.make 1 (Char.chr tag) ^ length ^ contents

let seq s = tlv 0x30 s
let name_der tag value = seq (tlv 0x31 (seq (hex "0603550403" ^ tlv tag value)))
let extension_der ?(critical = false) oid contents =
  seq (hex oid ^ (if critical then hex "0101ff" else "") ^ tlv 4 contents)
let extensions_der xs = tlv 0xa3 (seq (String.concat "" xs))
let dns_der s = tlv 0x82 s
let uri_der s = tlv 0x86 s
let encoded ?(encoding = `UTF8) s = Distinguished_name.Encoded_string.of_octets ~encoding s
let name s = [Distinguished_name.Relative_distinguished_name.singleton
                (Distinguished_name.CN (encoded s))]

let root_key () = get (Private_key.of_octets
    (hex "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60") `ED25519)
let intermediate_key () = get (Private_key.of_octets
    (hex "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb") `ED25519)
let p256_key () = get (Private_key.of_octets (String.make 31 '\x00' ^ "\x01") `P256)
let ed25519_algorithm = hex "300506032b6570"
let compressed_p256_spki = hex
    "3039301306072a8648ce3d020106082a8648ce3d030107032200036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
let date year = present "date" (Ptime.of_date (year, 1, 1))
let valid_from = date 2026
let valid_until = date 2030
let validity_der = seq (tlv 0x17 "260101000000Z" ^ tlv 0x17 "300101000000Z")

type fixture = { der : string; tbs : string; signature : string }

let make_certificate ?(key = root_key ()) ?(serial = "\x01")
    ?(issuer = name_der 0x0c "Root") ?(subject = name_der 0x0c "Leaf")
    ?(validity = validity_der) ?spki ?(ids = "") ?(extensions = "") () =
  let spki = match spki with
    | Some spki -> spki
    | None -> Public_key.encode_der (Private_key.public (root_key ()))
  in
  let tbs = seq (hex "a003020102" ^ tlv 2 serial ^ ed25519_algorithm ^
                 issuer ^ validity ^ subject ^ spki ^ ids ^ extensions) in
  let signature = get (Private_key.sign `SHA512 ~scheme:`ED25519 key (`Message tbs)) in
  { der = seq (tbs ^ ed25519_algorithm ^ tlv 3 ("\x00" ^ signature)); tbs; signature }

let decode_fixture fixture =
  let certificate = get (Certificate.decode_der fixture.der) in
  bytes "independent original DER" fixture.der (Certificate.encode_der certificate);
  certificate

let check_fixture_signature ?(key = root_key ()) fixture certificate =
  bytes "semantic signature" fixture.signature
    (Certificate.Bits.octets (Certificate.signature certificate));
  integer "signature bit length" (8 * String.length fixture.signature)
    (Certificate.Bits.bit_length (Certificate.signature certificate));
  get (Public_key.verify `SHA512 ~scheme:`ED25519
         ~signature:(Certificate.Bits.octets (Certificate.signature certificate))
         (Private_key.public key) (`Message fixture.tbs))

let leaf_request () = get (Signing_request.create (name "Leaf") (root_key ()))
let issue ?(serial = "\x01") ?(extensions = Extension.empty)
    ?(valid_from = valid_from) ?(valid_until = valid_until) request =
  signed (Signing_request.sign request ~serial ~extensions ~valid_from ~valid_until
            (root_key ()) (name "Root"))

let check_rebuilt_extensions extensions raw_extensions =
  let expected = make_certificate ~extensions:(extensions_der raw_extensions) () in
  let certificate = issue ~extensions (leaf_request ()) in
  bytes "constructed extensions determine certificate DER" expected.der
    (Certificate.encode_der certificate);
  check_fixture_signature expected certificate;
  decode_fixture expected

let serial_boundaries () =
  let open Certificate.Serial in
  let limit = Z.shift_left Z.one 159 in
  let cases = [
    Z.of_int (-1), "\xff";
    Z.of_int (-128), "\x80";
    Z.of_int (-256), "\xff\x00";
    Z.of_int (-129), "\xff\x7f";
    Z.of_int (-32768), "\x80\x00";
    Z.zero, "\x00";
    Z.of_int 127, "\x7f";
    Z.of_int 128, "\x00\x80";
    Z.neg limit, "\x80" ^ String.make 19 '\x00';
    Z.pred limit, "\x7f" ^ String.make 19 '\xff';
  ] in
  let request = leaf_request () in
  List.iter (fun (expected, content) ->
      let serial = get (of_z expected) in
      Alcotest.check z "of_z/to_z" expected (to_z serial);
      bytes "minimal signed INTEGER contents" content (to_content serial);
      let parsed = get (of_content content) in
      truth "content semantic equality" true (equal serial parsed);
      truth "negative sign" (Z.sign expected < 0) (is_negative parsed);
      integer "semantic comparison with zero" (Z.sign expected) (compare parsed (of_int 0));
      let fixture = make_certificate ~serial:content () in
      let certificate = decode_fixture fixture in
      Alcotest.check z "certificate signed serial" expected
        (to_z (Certificate.serial_number certificate));
      bytes "legacy serial getter is signed content" content (Certificate.serial certificate);
      let constructed = issue ~serial:content request in
      bytes "signing preserves signed serial" fixture.der (Certificate.encode_der constructed);
      check_fixture_signature fixture certificate) cases;
  List.iter (fun content ->
      check_error "malformed serial content" (of_content content);
      check_error "malformed certificate serial"
        (Certificate.decode_der (make_certificate ~serial:content ()).der);
      check_error "malformed signing serial"
        (Signing_request.sign request ~serial:content ~valid_from ~valid_until
           (root_key ()) (name "Root")))
    [""; "\x00\x01"; "\xff\xff"; "\xff\x80";
     "\x01" ^ String.make 20 '\x00'; "\x80" ^ String.make 20 '\x00'];
  check_error "positive 21-octet serial" (of_z limit);
  check_error "negative 21-octet serial" (of_z (Z.pred (Z.neg limit)))

let certificate_times () =
  let cases = [
    1949, `Generalized, 0x18, "19490101000000Z";
    1950, `UTC, 0x17, "500101000000Z";
    2049, `UTC, 0x17, "490101000000Z";
    2050, `Generalized, 0x18, "20500101000000Z";
  ] in
  List.iter (fun (year, encoding, tag, content) ->
      let expected = date year in
      let time = get (Certificate.Time.of_ptime expected) in
      truth "default Time encoding" true (Certificate.Time.encoding time = encoding);
      Alcotest.check ptime "Time semantic getter" expected (Certificate.Time.time time);
      let fixture = make_certificate ~validity:(seq (tlv tag content ^ tlv tag content)) () in
      let certificate = decode_fixture fixture in
      let before, after = Certificate.validity_times certificate in
      List.iter (fun t ->
          truth "decoded encoding" true (Certificate.Time.encoding t = encoding);
          Alcotest.check ptime "decoded Ptime" expected (Certificate.Time.time t)) [before; after];
      let constructed = issue ~valid_from:expected ~valid_until:expected (leaf_request ()) in
      bytes "signing chooses boundary time tag" fixture.der (Certificate.encode_der constructed)) cases;
  let explicit = get (Certificate.Time.of_ptime ~encoding:`Generalized valid_from) in
  truth "explicit Generalized constructor" true (Certificate.Time.encoding explicit = `Generalized);
  Alcotest.check ptime "explicit Generalized Ptime" valid_from (Certificate.Time.time explicit);
  let fixture = make_certificate
      ~validity:(seq (tlv 0x18 "20260101000000Z" ^ tlv 0x17 "300101000000Z")) () in
  let certificate = decode_fixture fixture in
  let before, after = Certificate.validity_times certificate in
  truth "Generalized within UTC range is retained" true (Certificate.Time.encoding before = `Generalized);
  truth "UTC partner is retained" true (Certificate.Time.encoding after = `UTC);
  Alcotest.check ptime "validity is semantic" valid_from (fst (Certificate.validity certificate));
  List.iter (fun year -> check_error "out-of-range explicit UTC"
      (Certificate.Time.of_ptime ~encoding:`UTC (date year))) [1949; 2050];
  let fraction = present "fraction" (Ptime.Span.of_d_ps (0, 123456789012L)) in
  let fractional t = present "fractional timestamp" (Ptime.add_span t fraction) in
  check_error "strict Time rejects fractions" (Certificate.Time.of_ptime (fractional valid_from));
  (* The convenience signing API truncates once; its in-memory getters must
     agree with the whole seconds actually signed, not retain the input fraction. *)
  let certificate = issue ~valid_from:(fractional valid_from)
      ~valid_until:(fractional valid_until) (leaf_request ()) in
  let before, after = Certificate.validity certificate in
  Alcotest.check ptime "signing normalizes notBefore" valid_from before;
  Alcotest.check ptime "signing normalizes notAfter" valid_until after;
  let expected = make_certificate () in
  bytes "fractional signing produces whole-second DER" expected.der (Certificate.encode_der certificate);
  let decoded = get (Certificate.decode_der (Certificate.encode_der certificate)) in
  Alcotest.check ptime "normalized model survives decoding" before (fst (Certificate.validity decoded))

let bit_string_metadata () =
  let bitstring = get (Certificate.Bits.create ~bit_length:7 "\x80") in
  integer "constructed bit length" 7 (Certificate.Bits.bit_length bitstring);
  bytes "constructed octets" "\x80" (Certificate.Bits.octets bitstring);
  let fixture = make_certificate ~ids:(hex "81020180820100") () in
  let certificate = decode_fixture fixture in
  let issuer = present "issuer ID" (Certificate.issuer_id certificate)
  and subject = present "subject ID" (Certificate.subject_id certificate) in
  integer "issuer ID length, not highest set bit" 7 (Certificate.Bits.bit_length issuer);
  bytes "issuer ID octets" "\x80" (Certificate.Bits.octets issuer);
  integer "present empty subject ID" 0 (Certificate.Bits.bit_length subject);
  bytes "empty subject ID octets" "" (Certificate.Bits.octets subject);
  check_fixture_signature fixture certificate;
  bytes "signature AlgorithmIdentifier" ed25519_algorithm
    (Algorithm_identifier.encode_der (Certificate.signature_identifier certificate));
  check_error "nonzero padding" (Certificate.Bits.create ~bit_length:7 "\x81");
  check_error "wrong length" (Certificate.Bits.create ~bit_length:9 "\x80");
  check_error "negative length" (Certificate.Bits.create ~bit_length:(-1) "");
  check_error "inverse guard rejects nonzero UID padding"
    (Certificate.decode_der (make_certificate ~ids:(hex "81020181") ()).der)

let distinguished_names () =
  let module D = Distinguished_name in
  let module R = D.Relative_distinguished_name in
  let utf8 = D.CN (encoded "A") and printable = D.CN (encoded ~encoding:`Printable "A") in
  let duplicates_der = hex "30163114300806035504030c0141300806035504030c0141" in
  let duplicates = get (D.decode_der duplicates_der) in
  let rdn = match duplicates with [rdn] -> rdn | _ -> Alcotest.fail "one RDN expected" in
  integer "duplicate AVAs retained" 2 (R.cardinal rdn);
  bytes "constructed duplicate DER" duplicates_der (D.encode_der [R.of_list [utf8; utf8]]);
  integer "add adds an occurrence" 3 (R.cardinal (R.add utf8 rdn));
  integer "remove removes one occurrence" 1 (R.cardinal (R.remove utf8 rdn));
  integer "union adds multiplicities" 4 (R.cardinal (R.union rdn rdn));
  let single_printable = [R.singleton printable] in
  truth "logical equality ignores tag and multiplicity" true (D.equal duplicates single_printable);
  truth "representation equality includes multiplicity" false
    (D.equal_representation duplicates [R.singleton utf8]);
  truth "representation equality includes tags" false
    (D.equal_representation [R.singleton utf8] single_printable);
  let mixed_der = hex "30163114300806035504030c014130080603550403130141" in
  bytes "DER SET order is canonical, not insertion order" mixed_der
    (D.encode_der [R.of_list [printable; utf8]]);
  let fixture = make_certificate ~subject:duplicates_der () in
  let certificate = decode_fixture fixture in
  truth "real certificate subject retains duplicate AVAs" true
    (D.equal_representation duplicates (Certificate.subject certificate));
  let tag_cases = [
    `UTF8, 0x0c, "A"; `Printable, 0x13, "A"; `IA5, 0x16, "A";
    `Teletex, 0x14, "A"; `BMP, 0x1e, "\x00A"; `Universal, 0x1c, "\x00\x00\x00A";
  ] in
  List.iter (fun (encoding, tag, octets) ->
      let wire = name_der tag octets in
      let dn = get (D.decode_der wire) in
      let value = present "encoded CN" (D.common_name_encoded dn) in
      truth "CN tag" true (D.Encoded_string.encoding value = encoding);
      bytes "CN content" octets (D.Encoded_string.to_octets value);
      bytes "constructed name tag" wire
        (D.encode_der [R.singleton (D.CN (encoded ~encoding octets))])) tag_cases;
  check_error "inverse guard rejects unsorted AVAs"
    (Certificate.decode_der (make_certificate ~subject:(hex
       "3016311430080603550403130141300806035504030c0141") ()).der)

let compressed_spki_and_csr () =
  let key = p256_key () in
  let public = Private_key.public key in
  let info = get (Public_key.Info.decode_der compressed_p256_spki) in
  bytes "compressed SPKI is retained" compressed_p256_spki (Public_key.Info.encode_der info);
  bytes "validated mathematical public key" (Public_key.encode_der public)
    (Public_key.encode_der (Public_key.Info.key info));
  integer "compressed point length" 33 (String.length (Public_key.Info.subject_public_key info));
  bytes "EC AlgorithmIdentifier" (hex "301306072a8648ce3d020106082a8648ce3d030107")
    (Algorithm_identifier.encode_der (Public_key.Info.algorithm info));
  let message = "synthetic compressed-key proof" in
  let signature = get (Private_key.sign `SHA256 ~scheme:`ECDSA key (`Message message)) in
  get (Public_key.verify `SHA256 ~scheme:`ECDSA ~signature (Public_key.Info.key info) (`Message message));
  (* A CSR with a compressed generator point and a PrintableString subject.
     Its signature must be checked using the parsed mathematical P256 key. *)
  let subject = name_der 0x13 "Leaf" in
  let request_info = seq (hex "020100" ^ subject ^ compressed_p256_spki ^ hex "a000") in
  let signature = get (Private_key.sign `SHA256 ~scheme:`ECDSA key (`Message request_info)) in
  let request_der = seq (request_info ^ hex "300a06082a8648ce3d040302" ^ tlv 3 ("\x00" ^ signature)) in
  let request = get (Signing_request.decode_der request_der) in
  bytes "CSR exposes validated key" (Public_key.encode_der public)
    (Public_key.encode_der (Signing_request.info request).public_key);
  bytes "CSR subject tag" subject (Distinguished_name.encode_der (Signing_request.info request).subject);
  let certificate = issue request in
  let fixture = make_certificate ~subject ~spki:compressed_p256_spki () in
  bytes "issuance retains compressed SPKI and Name tag" fixture.der (Certificate.encode_der certificate);
  let decoded = decode_fixture fixture in
  bytes "certificate Info preserves compressed encoding" compressed_p256_spki
    (Public_key.Info.encode_der (Certificate.public_key_info decoded));
  bytes "certificate exposes validated key" (Public_key.encode_der public)
    (Public_key.encode_der (Certificate.public_key decoded));
  check_fixture_signature fixture decoded;
  let bad_point = seq (hex "301306072a8648ce3d020106082a8648ce3d030107" ^
                      tlv 3 ("\x00\x03" ^ String.make 32 '\xff')) in
  check_error "out-of-field compressed point" (Public_key.Info.decode_der bad_point)

let equal_list f a b = List.length a = List.length b && List.for_all2 f a b
let equal_option f a b = match a, b with
  | None, None -> true
  | Some a, Some b -> f a b
  | _ -> false
let equal_notice_reference (a : Extension.notice_reference) (b : Extension.notice_reference) =
  a.organization = b.organization && equal_list Z.equal a.notice_numbers b.notice_numbers
let equal_user_notice (a : Extension.user_notice) (b : Extension.user_notice) =
  equal_option equal_notice_reference a.notice_ref b.notice_ref && a.explicit_text = b.explicit_text
let equal_qualifier a b = match a, b with
  | `CPS_uri a, `CPS_uri b -> String.equal a b
  | `User_notice a, `User_notice b -> equal_user_notice a b
  | _ -> false
let equal_policy (a : Extension.policy) (b : Extension.policy) =
  Asn.OID.equal a.policy_identifier b.policy_identifier &&
  equal_option (equal_list equal_qualifier) a.policy_qualifiers b.policy_qualifiers
let policies = Alcotest.testable Fmt.(list ~sep:sp Extension.pp_policy) (equal_list equal_policy)

let policy_qualifiers () =
  let open Extension in
  let oid = Asn.OID.(base 1 2 <| 3) in
  let big = Z.shift_left Z.one 80 in
  let numbers = [Z.zero; Z.of_int (-129); big; Z.neg big; Z.one] in
  (* The integer contents below are literal expected encodings, independent of
     Serial or the policy encoder; notice numbers are not bounded serials. *)
  let number_der = seq (hex "0201000202ff7f" ^
      tlv 2 ("\x01" ^ String.make 10 '\x00') ^
      tlv 2 ("\xff" ^ String.make 10 '\x00') ^ hex "020101") in
  let display_cases = [
    `IA5 "IA5 organization", 0x16, "IA5 organization";
    `Visible "Visible organization", 0x1a, "Visible organization";
    `BMP "\x00B\x00M\x00P", 0x1e, "\x00B\x00M\x00P";
    `UTF8 "UTF8 organization", 0x0c, "UTF8 organization";
  ] in
  let notices = List.map (fun (text, tag, octets) ->
      let reference = { organization = text; notice_numbers = numbers } in
      let notice = { notice_ref = Some reference; explicit_text = Some text } in
      let der = seq (seq (tlv tag octets ^ number_der) ^ tlv tag octets) in
      `User_notice notice, der) display_cases in
  let reference = { organization = `UTF8 "Only reference"; notice_numbers = [] } in
  let optional_notices = [
    `User_notice { notice_ref = None; explicit_text = None }, seq "";
    `User_notice { notice_ref = Some reference; explicit_text = None },
      seq (seq (tlv 0x0c "Only reference" ^ seq ""));
    `User_notice { notice_ref = None; explicit_text = Some (`Visible "Only text") },
      seq (tlv 0x1a "Only text");
  ] in
  let all_notices = notices @ optional_notices in
  let cps = "https://example.invalid/cps" in
  let cps_der uri = seq (hex "06082b06010505070201" ^ tlv 0x16 uri) in
  let notice_der notice = seq (hex "06082b06010505070202" ^ notice) in
  let qualifiers = `CPS_uri cps :: List.map fst all_notices @ [`CPS_uri cps] in
  let qualified = policy ~qualifiers oid in
  let expected_policies = [qualified; policy oid; policy ~qualifiers:[] oid; any_policy ()] in
  let wire_policies first_uri notice_values = seq (
      seq (hex "06022a03" ^ seq (cps_der first_uri ^
        String.concat "" (List.map notice_der notice_values) ^ cps_der cps)) ^
      seq (hex "06022a03") ^ seq (hex "06022a03" ^ seq "") ^ seq (hex "0604551d2000")) in
  let raw uri notice_values = extension_der "0603551d20" (wire_policies uri notice_values) in
  let original_notices = List.map snd all_notices in
  let fixture = make_certificate ~extensions:(extensions_der [raw cps original_notices]) () in
  let certificate = decode_fixture fixture in
  let critical, actual = present "Policies" (find Policies (Certificate.extensions certificate)) in
  truth "policy critical flag" false critical;
  Alcotest.check policies "full typed policy values" expected_policies actual;
  truth "anyPolicy semantic identifier" true (is_any_policy (List.nth actual 3));
  truth "ordinary policy is not anyPolicy" false (is_any_policy (List.hd actual));
  let replacement_uri = "https://example.invalid/revised-cps" in
  let edited = match actual with
    | first :: rest ->
      let qualifiers = match first.policy_qualifiers with
        | Some (`CPS_uri _ :: `User_notice notice :: rest) ->
          let reference = present "notice reference" notice.notice_ref in
          let reference = { reference with notice_numbers = [Z.minus_one; big] } in
          let notice = { notice_ref = Some reference; explicit_text = Some (`Visible "Revised") } in
          `CPS_uri replacement_uri :: `User_notice notice :: rest
        | _ -> Alcotest.fail "qualifiers were not exposed as semantic values"
      in
      { first with policy_qualifiers = Some qualifiers } :: rest
    | [] -> Alcotest.fail "Policies is empty"
  in
  let extensions = add Policies (critical, edited) (Certificate.extensions certificate) in
  let newly_signed = issue ~extensions (leaf_request ()) in
  let revised_notice = seq (
      seq (tlv 0x16 "IA5 organization" ^
           seq (hex "0201ff" ^ tlv 2 ("\x01" ^ String.make 10 '\x00'))) ^
      tlv 0x1a "Revised") in
  let expected = make_certificate
      ~extensions:(extensions_der [raw replacement_uri (revised_notice :: List.tl original_notices)]) () in
  bytes "edited CPS, notice numbers and DisplayText determine signed DER"
    expected.der (Certificate.encode_der newly_signed);
  truth "edit changes signed DER" false (String.equal fixture.der expected.der);
  check_fixture_signature expected newly_signed;
  let decoded = decode_fixture expected in
  let _, actual = present "edited Policies" (find Policies (Certificate.extensions decoded)) in
  Alcotest.check policies "edited policy semantic getter" edited actual

let ordered_names_and_extensions () =
  let module G = General_name in
  let module E = Extension in
  let names = G.of_entries [G.B (DNS, ["a.example"]); G.B (URI, ["https://example.invalid"]);
                            G.B (DNS, ["b.example"])] in
  let raw_names = seq (dns_der "a.example" ^ uri_der "https://example.invalid" ^ dns_der "b.example") in
  let san raw = extension_der "0603551d11" raw in
  let basic = extension_der "0603551d13" (hex "30030101ff") in
  let skid s = extension_der "0603551d0e" (tlv 4 s) in
  let usage = extension_der "0603551d0f" (hex "03020780") in
  let extensions = E.(empty |> add Basic_constraints (false, (true, None))
      |> add Subject_alt_name (false, names) |> add Subject_key_id (false, "A")) in
  let certificate = check_rebuilt_extensions extensions [basic; san raw_names; skid "A"] in
  let _, decoded_names = present "SAN" E.(find Subject_alt_name (Certificate.extensions certificate)) in
  truth "decoded interleaving" true (G.equal_representation names decoded_names);
  Alcotest.(check (option (list string))) "grouped DNS getter"
    (Some ["a.example"; "b.example"]) (G.find DNS decoded_names);
  let reordered = G.of_entries [G.B (DNS, ["a.example"]); G.B (DNS, ["b.example"]);
                                G.B (URI, ["https://example.invalid"])] in
  let name_equality : G.eq = { f = (fun _ a b -> a = b) } in
  truth "map equality ignores occurrence order" true (G.equal name_equality names reordered);
  truth "representation equality sees occurrence order" false (G.equal_representation names reordered);
  let replaced = G.add DNS ["x.example"; "y.example"; "z.example"] names in
  let expected_entries = G.of_entries [G.B (DNS, ["x.example"]);
      G.B (URI, ["https://example.invalid"]); G.B (DNS, ["y.example"]); G.B (DNS, ["z.example"])] in
  truth "replacement retains positions and inserts surplus at last occurrence" true
    (G.equal_representation expected_entries replaced);
  let raw_replaced = seq (dns_der "x.example" ^ uri_der "https://example.invalid" ^
                          dns_der "y.example" ^ dns_der "z.example") in
  let replaced_exts = E.add Subject_alt_name (false, replaced) extensions in
  ignore (check_rebuilt_extensions replaced_exts [basic; san raw_replaced; skid "A"]);
  let shortened = G.update DNS (fun _ -> Some ["one.example"]) replaced in
  let removed = G.remove URI shortened in
  let appended = G.add URI ["https://new.example.invalid"] removed in
  truth "remove deletes URI occurrences" false (G.mem URI removed);
  let raw_appended = seq (dns_der "one.example" ^ uri_der "https://new.example.invalid") in
  let changed = E.(replaced_exts |> add Subject_alt_name (false, appended)
      |> add Key_usage (false, Key_usage.of_list [`Digital_signature]) |> add Subject_key_id (false, "B")) in
  ignore (check_rebuilt_extensions changed [basic; san raw_appended; skid "B"; usage]);
  let moved = E.(changed |> remove Basic_constraints |> add Basic_constraints (false, (true, None))) in
  ignore (check_rebuilt_extensions moved [san raw_appended; skid "B"; usage; basic]);
  let equality : E.eq = { f = (fun _ a b -> a = b) } in
  truth "extension lookup equality ignores sequence order" true (E.equal equality changed moved);
  truth "ordered equality distinguishes remove/re-add" false (E.equal_ordered equality changed moved);
  let rebuilt = List.fold_left (fun acc (E.B (key, value)) -> E.add key value acc)
      E.empty (E.ordered_bindings moved) in
  truth "ordered_bindings reconstruct encoding order" true (E.equal_ordered equality moved rebuilt);
  let identity : E.mapper = { f = (fun _ value -> value) } in
  let filtered = E.filter (function E.B (Subject_key_id, _) -> false | _ -> true) (E.map identity moved) in
  ignore (check_rebuilt_extensions filtered [san raw_appended; usage; basic]);
  let left : E.unionee = { f = (fun _ a _ -> Some a) } in
  let joined = E.union left filtered E.(empty |> add Key_usage (false, Key_usage.of_list []) |> add Subject_key_id (false, "C")) in
  ignore (check_rebuilt_extensions joined [san raw_appended; usage; basic; skid "C"]);
  check_invalid_argument "GeneralNames entries must be single occurrences"
    (fun () -> G.of_entries [G.B (DNS, ["a.example"; "b.example"])]);
  check_invalid_argument "known extension OID cannot hide in Unsupported"
    (fun () -> E.singleton (Unsupported Asn.OID.(base 2 5 <| 29 <| 15)) (false, hex "030100"));
  check_error "duplicate extension OIDs"
    (Certificate.decode_der (make_certificate ~extensions:(extensions_der [basic; basic]) ()).der)

let named_bits_and_reasons () =
  let open Extension in
  let cases : (key_usage list * int * string) list = [
    [], 0, "030100";
    [`Digital_signature], 1, "03020780";
    [`Encipher_only], 8, "03020001";
    [`Decipher_only], 9, "0303070080";
    [`Unknown_bit 9], 10, "0303060040";
    [`Unknown_bit 31], 32, "03050000000001";
    [`Unknown_bit 32], 33, "0306070000000080";
    [`Digital_signature; `Decipher_only; `Unknown_bit 9; `Unknown_bit 31], 32, "03050080c00001";
  ] in
  List.iter (fun (flags, bit_length, der) ->
      let usages = Key_usage.of_list (List.rev flags @ flags) in
      truth "KeyUsage constructor sorts and deduplicates" true (Key_usage.to_list usages = flags);
      integer "constructed minimal KeyUsage length" bit_length (Key_usage.bit_length usages);
      let extensions = singleton Key_usage (false, usages) in
      let certificate = check_rebuilt_extensions extensions [extension_der "0603551d0f" (hex der)] in
      let _, actual = present "KeyUsage" (find Key_usage (Certificate.extensions certificate)) in
      truth "all key-usage positions are semantic" true (Key_usage.to_list actual = flags);
      integer "decoded KeyUsage length" bit_length (Key_usage.bit_length actual);
      truth "KeyUsage representation round trip" true (Key_usage.equal_representation usages actual);
      List.iter (fun flag -> truth "KeyUsage member" true (Key_usage.mem flag actual)) flags;
      truth "absent KeyUsage" false (Key_usage.mem `CRL_sign actual)) cases;
  let reason_cases : (reason_flag list * int * string) list = [
    [], 0, "00";
    [`Unused], 1, "0780";
    [`Privilege_withdrawn], 8, "0001";
    [`AA_compromise], 9, "070080";
    [`Unknown_bit 9], 10, "060040";
    [`Unknown_bit 31], 32, "0000000001";
    [`Unknown_bit 32], 33, "070000000080";
    [`Unused; `Privilege_withdrawn; `AA_compromise; `Unknown_bit 31], 32, "0081800001";
  ] in
  List.iter (fun (flags, bit_length, content) ->
      let reasons = Reason_flags.of_list (List.rev flags @ flags) in
      truth "ReasonFlags constructor sorts and deduplicates" true (Reason_flags.to_list reasons = flags);
      integer "constructed minimal ReasonFlags length" bit_length (Reason_flags.bit_length reasons);
      let points = [None, Some reasons, None] in
      let extensions = singleton CRL_distribution_points (false, points) in
      let raw = extension_der "0603551d1f" (seq (seq (tlv 0x81 (hex content)))) in
      let certificate = check_rebuilt_extensions extensions [raw] in
      let _, actual = present "distribution points"
          (find CRL_distribution_points (Certificate.extensions certificate)) in
      let actual = match actual with
        | [None, Some reasons, None] -> reasons
        | _ -> Alcotest.fail "expected reasons-only distribution point"
      in
      truth "ReasonFlags retains all positions" true (Reason_flags.to_list actual = flags);
      integer "decoded ReasonFlags length" bit_length (Reason_flags.bit_length actual);
      truth "ReasonFlags representation round trip" true (Reason_flags.equal_representation reasons actual);
      List.iter (fun flag -> truth "ReasonFlags member" true (Reason_flags.mem flag actual)) flags;
      truth "absent ReasonFlags" false (Reason_flags.mem `CA_compromise actual)) reason_cases;
  let wide = Key_usage.of_list ~bit_length:9 [`Digital_signature] in
  let minimal = Key_usage.of_list [`Digital_signature] in
  let wide_raw = extension_der "0603551d0f" (hex "0303078000") in
  let certificate = check_rebuilt_extensions (singleton Key_usage (false, wide)) [wide_raw] in
  let _, actual = present "wide KeyUsage" (find Key_usage (Certificate.extensions certificate)) in
  truth "wide KeyUsage still means digital signature only" true (Key_usage.to_list actual = [`Digital_signature]);
  integer "original nine-bit KeyUsage width" 9 (Key_usage.bit_length actual);
  integer "fresh KeyUsage is minimal" 1 (Key_usage.bit_length minimal);
  truth "KeyUsage semantic equality ignores zero tail" true (Key_usage.equal minimal actual);
  truth "KeyUsage representation equality retains zero tail" false (Key_usage.equal_representation minimal actual);
  truth "KeyUsage semantic equality distinguishes flags" false (Key_usage.equal minimal (Key_usage.of_list []));
  truth "wide KeyUsage representation round trip" true (Key_usage.equal_representation wide actual);
  ignore (check_rebuilt_extensions (Certificate.extensions certificate) [wide_raw]);
  let normalized = Key_usage.of_list (Key_usage.to_list actual) in
  truth "explicit semantic reconstruction drops zero tail" true (Key_usage.equal_representation minimal normalized);
  ignore (check_rebuilt_extensions (singleton Key_usage (false, normalized))
            [extension_der "0603551d0f" (hex "03020780")]);
  List.iter (fun flags ->
      let wide = Reason_flags.of_list ~bit_length:9 flags in
      let minimal = Reason_flags.of_list flags in
      let content = if flags = [] then hex "070000" else hex "078000" in
      let raw = extension_der "0603551d1c" (seq (tlv 0x83 content)) in
      let value = None, false, false, Some wide, false, false in
      let certificate = check_rebuilt_extensions (singleton Issuing_distribution_point (false, value)) [raw] in
      let _, (_, _, _, reasons, _, _) = present "issuing distribution point"
          (find Issuing_distribution_point (Certificate.extensions certificate)) in
      let actual = present "onlySomeReasons" reasons in
      truth "wide ReasonFlags meaning" true (Reason_flags.to_list actual = flags);
      integer "original nine-bit ReasonFlags width" 9 (Reason_flags.bit_length actual);
      integer "fresh ReasonFlags width" (if flags = [] then 0 else 1) (Reason_flags.bit_length minimal);
      truth "ReasonFlags semantic equality ignores zero tail" true (Reason_flags.equal minimal actual);
      truth "ReasonFlags representation equality retains zero tail" false (Reason_flags.equal_representation minimal actual);
      truth "wide ReasonFlags representation round trip" true (Reason_flags.equal_representation wide actual);
      ignore (check_rebuilt_extensions (Certificate.extensions certificate) [raw]))
    [[]; [`Unused]];
  truth "ReasonFlags semantic equality distinguishes flags" false
    (Reason_flags.equal (Reason_flags.of_list [`Unused]) (Reason_flags.of_list []));
  List.iter (fun (reason, code) ->
      let extensions = singleton Reason (false, reason) in
      let certificate = check_rebuilt_extensions extensions
          [extension_der "0603551d15" (tlv 0x0a (String.make 1 (Char.chr code)))] in
      let _, actual = present "CRLReason" (find Reason (Certificate.extensions certificate)) in
      truth "CRLReason is an enumeration, not a bit position" true (actual = reason))
    [`Remove_from_CRL, 8; `Privilege_withdrawn, 9; `AA_compromise, 10];
  List.iter (fun bit ->
      check_invalid_argument "KeyUsage Unknown_bit cannot alias known or negative positions"
        (fun () -> Key_usage.of_list [`Unknown_bit bit]);
      check_invalid_argument "ReasonFlags Unknown_bit cannot alias known or negative positions"
        (fun () -> Reason_flags.of_list [`Unknown_bit bit]))
    [-1; 0; 8; max_int];
  List.iter (fun (bit_length, flags) ->
      check_invalid_argument "KeyUsage explicit length must contain every set bit"
        (fun () -> Key_usage.of_list ~bit_length flags))
    [-1, []; 0, [`Digital_signature]; 31, [`Unknown_bit 31]; max_int, []];
  List.iter (fun (bit_length, flags) ->
      check_invalid_argument "ReasonFlags explicit length must contain every set bit"
        (fun () -> Reason_flags.of_list ~bit_length flags))
    [-1, []; 0, [`Unused]; 31, [`Unknown_bit 31]; max_int, []];
  List.iter (fun content ->
      let key_usage = extension_der "0603551d0f" (tlv 3 (hex content)) in
      let reasons = extension_der "0603551d1f" (seq (seq (tlv 0x81 (hex content)))) in
      List.iter (fun raw ->
          check_error "named flags reject malformed padding before semantic projection"
            (Certificate.decode_der (make_certificate ~extensions:(extensions_der [raw]) ()).der))
        [key_usage; reasons])
    ["0781"; "078001"; "0880"; ""; "07"]

let chain_construction () =
  let root_private = root_key () and intermediate_private = intermediate_key () in
  let ca_extensions pathlen = Extension.(empty
      |> add Basic_constraints (true, (true, Some pathlen))
      |> add Key_usage (true, Key_usage.of_list [`Key_cert_sign; `CRL_sign])) in
  let ca_der pathlen = extensions_der [
    extension_der ~critical:true "0603551d13" (seq (hex "0101ff" ^ tlv 2 (String.make 1 (Char.chr pathlen))));
    extension_der ~critical:true "0603551d0f" (hex "03020106")
  ] in
  let root_request = get (Signing_request.create (name "Root") root_private) in
  let root = issue ~extensions:(ca_extensions 1) root_request in
  let root_fixture = make_certificate ~subject:(name_der 0x0c "Root") ~extensions:(ca_der 1) () in
  bytes "normal self-signed root DER" root_fixture.der (Certificate.encode_der root);
  let intermediate_request = get (Signing_request.create (name "Intermediate") intermediate_private) in
  let intermediate = signed (Signing_request.sign_certificate intermediate_request
      ~valid_from ~valid_until ~serial:"\x02" ~extensions:(ca_extensions 0) root_private root) in
  let intermediate_fixture = make_certificate ~serial:"\x02" ~subject:(name_der 0x0c "Intermediate")
      ~spki:(Public_key.encode_der (Private_key.public intermediate_private)) ~extensions:(ca_der 0) () in
  bytes "normal intermediate DER" intermediate_fixture.der (Certificate.encode_der intermediate);
  let requested = Extension.singleton Subject_alt_name
      (false, General_name.singleton DNS ["requested.example"]) in
  let request = get (Signing_request.create (name "requested.example")
      ~extensions:(Signing_request.Ext.singleton Extensions requested) root_private) in
  let overrides = Extension.(empty
      |> add Subject_alt_name (false, General_name.singleton DNS ["override.example"])
      |> add Key_usage (true, Key_usage.of_list [`Digital_signature])) in
  let leaf = signed (Signing_request.sign_certificate request ~valid_from ~valid_until
      ~serial:"\x03" ~subject:(name "override.example") ~extensions:overrides
      intermediate_private intermediate) in
  let leaf_fixture = make_certificate ~key:intermediate_private ~serial:"\x03"
      ~issuer:(name_der 0x0c "Intermediate") ~subject:(name_der 0x0c "override.example")
      ~extensions:(extensions_der [
          extension_der "0603551d11" (seq (dns_der "override.example"));
          extension_der ~critical:true "0603551d0f" (hex "03020780")]) () in
  bytes "subject/extensions overrides and intermediate issuer determine DER"
    leaf_fixture.der (Certificate.encode_der leaf);
  truth "issuer is CA subject, not CA issuer" true
    (Distinguished_name.equal_representation (Certificate.subject intermediate) (Certificate.issuer leaf));
  truth "CA issuer differs from leaf issuer" false
    (Distinguished_name.equal (Certificate.issuer intermediate) (Certificate.issuer leaf));
  let _, names = present "overridden SAN" Extension.(find Subject_alt_name (Certificate.extensions leaf)) in
  Alcotest.(check (option (list string))) "explicit extension overrides requested extension"
    (Some ["override.example"]) (General_name.find DNS names);
  List.iter (fun (fixture, certificate) ->
      let digest = Digestif.SHA256.(to_raw_string (digest_string fixture.der)) in
      bytes "fingerprint hashes independent DER" digest (Certificate.fingerprint `SHA256 certificate);
      bytes "fingerprint hashes reconstructed encode_der"
        Digestif.SHA256.(to_raw_string (digest_string (Certificate.encode_der certificate)))
        (Certificate.fingerprint `SHA256 certificate))
    [root_fixture, root; intermediate_fixture, intermediate; leaf_fixture, leaf];
  let root = decode_fixture root_fixture
  and intermediate = decode_fixture intermediate_fixture
  and leaf = decode_fixture leaf_fixture in
  check_fixture_signature ~key:intermediate_private leaf_fixture leaf;
  let host = Domain_name.host_exn (Domain_name.of_string_exn "override.example") in
  let anchor = match Validation.verify_chain ~host:(Some host) ~time:(fun () -> Some (date 2027))
      ~anchors:[root] [leaf; intermediate] with
    | Ok anchor -> anchor
    | Error error -> Alcotest.failf "%a" Validation.pp_chain_error error
  in
  bytes "decoded chain verifies to the root" root_fixture.der (Certificate.encode_der anchor)

let constructor_normalization () =
  let module G = General_name in
  let module E = Extension in
  let names = G.of_entries [G.B (DNS, ["a.example"]); G.B (URI, ["https://example.invalid"])] in
  let no_dns label names =
    truth label false (G.mem G.DNS names);
    truth (label ^ " lookup") true (G.find G.DNS names = None)
  in
  no_dns "empty singleton" (G.singleton G.DNS []);
  integer "empty singleton cardinal" 0 (G.cardinal (G.singleton G.DNS []));
  no_dns "empty add" (G.add G.DNS [] names);
  no_dns "empty update" (G.update G.DNS (fun _ -> Some []) names);
  let clear : G.mapper = { f = (fun (type a) (key : a G.key) (value : a) ->
      (match key with G.DNS -> [] | _ -> value : a)) } in
  no_dns "empty map" (G.map clear names);
  let server_auth = Asn.OID.(base 1 3 <| 6 <| 1 <| 5 <| 5 <| 7 <| 3 <| 1) in
  let alias = false, [`Other server_auth] in
  let check_eku label extensions =
    match E.find E.Ext_key_usage extensions with
    | Some (_, [`Server_auth]) -> ()
    | _ -> Alcotest.fail (label ^ " did not normalize known EKU alias")
  in
  let extensions = E.singleton E.Ext_key_usage alias in
  check_eku "singleton" extensions;
  let alias_mapper : E.mapper = { f = (fun (type a) (key : a E.key) (value : a) ->
      (match key with E.Ext_key_usage -> alias | _ -> value : a)) } in
  check_eku "map" (E.map alias_mapper extensions);
  let alias_union : E.unionee = { f = (fun (type a) (key : a E.key) (a : a) (_ : a) ->
      (match key with E.Ext_key_usage -> Some alias | _ -> Some a : a option)) } in
  check_eku "union" (E.union alias_union extensions extensions);
  let alias_merge : E.merger = { f = (fun (type a) (key : a E.key) (a : a option) (_ : a option) ->
      (match key with E.Ext_key_usage -> Some alias | _ -> a : a option)) } in
  check_eku "merge" (E.merge alias_merge extensions extensions)

let tests = [
  "constructor views normalize empty names and EKU aliases", `Quick, constructor_normalization;
  "signed serial boundaries and malformed contents", `Quick, serial_boundaries;
  "semantic certificate times and fractional signing", `Quick, certificate_times;
  "bit-string lengths and signature metadata", `Quick, bit_string_metadata;
  "Name tags, duplicate AVAs, and equality", `Quick, distinguished_names;
  "validated compressed SPKI through CSR issuance", `Quick, compressed_spki_and_csr;
  "typed policy qualifiers can be edited and re-signed", `Quick, policy_qualifiers;
  "ordered GeneralNames and extension mutations", `Quick, ordered_names_and_extensions;
  "named key-usage bits, ReasonFlags, and CRLReason", `Quick, named_bits_and_reasons;
  "create, sign through intermediate, decode, and verify", `Quick, chain_construction;
]
