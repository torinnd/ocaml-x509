let ( let* ) = Result.bind

type ecdsa = [
  | `P256 of Mirage_crypto_ec.P256.Dsa.pub
  | `P384 of Mirage_crypto_ec.P384.Dsa.pub
  | `P521 of Mirage_crypto_ec.P521.Dsa.pub
]

type t = [
  | ecdsa
  | `RSA of Mirage_crypto_pk.Rsa.pub
  | `ED25519 of Mirage_crypto_ec.Ed25519.pub
]

module Asn_oid = Asn.OID
module Asn_syntax = Asn

module Asn = struct
  open Asn_grammars
  open Asn.S
  open Mirage_crypto_pk

  let rsa_public_key =
    let f (n, e) =
      let n = Z_extra.of_octets_be n
      and e = Z_extra.of_octets_be e in
      match Rsa.pub ~e ~n with
      | Ok p -> p
      | Error (`Msg m) -> parse_error "bad RSA public key %s" m
    and g ({ Rsa.n; e } : Rsa.pub) = (Z_extra.to_octets_be n, Z_extra.to_octets_be e) in
    map f g @@
    sequence2
      (required ~label:"modulus"        unsigned_integer)
      (required ~label:"publicExponent" unsigned_integer)

  let (rsa_public_of_octets, rsa_public_to_octets) =
    projections_of Asn.der rsa_public_key

  let rsa_pub_of_octets, rsa_pub_to_octets = project_exn rsa_public_key

  let to_err = function
    | Ok r -> r
    | Error e ->
      parse_error "failed to decode public EC key %a"
        Mirage_crypto_ec.pp_error e

  let reparse_pk =
    let open Mirage_crypto_ec in
    let open Algorithm in
    function
    | (RSA      , cs) -> `RSA (rsa_pub_of_octets cs)
    | (ED25519  , cs) -> `ED25519 (to_err (Ed25519.pub_of_octets cs))
    | (EC_pub `SECP256R1, cs) -> `P256 (to_err (P256.Dsa.pub_of_octets cs))
    | (EC_pub `SECP384R1, cs) -> `P384 (to_err (P384.Dsa.pub_of_octets cs))
    | (EC_pub `SECP521R1, cs) -> `P521 (to_err (P521.Dsa.pub_of_octets cs))
    | _ -> parse_error "unknown public key algorithm"

  let unparse_pk_with_compression ~compress =
    let open Mirage_crypto_ec in
    let open Algorithm in
    function
    | `RSA pk    -> (RSA, rsa_pub_to_octets pk)
    | `ED25519 pk -> (ED25519, Ed25519.pub_to_octets pk)
    | `P256 pk -> (EC_pub `SECP256R1, P256.Dsa.pub_to_octets ~compress pk)
    | `P384 pk -> (EC_pub `SECP384R1, P384.Dsa.pub_to_octets ~compress pk)
    | `P521 pk -> (EC_pub `SECP521R1, P521.Dsa.pub_to_octets ~compress pk)

  let unparse_pk = unparse_pk_with_compression ~compress:false

  let pk_info_der =
    map reparse_pk unparse_pk @@
    sequence2
      (required ~label:"algorithm" Algorithm.identifier)
      (required ~label:"subjectPK" bit_string_octets)

  let (pub_info_of_octets, pub_info_to_octets) =
    projections_of Asn.der pk_info_der
end

module Info : sig
  type key = t
  type t

  (** Uses an uncompressed EC point and conventional algorithm parameters. *)
  val of_key : key -> t

  val key : t -> key
  val algorithm : t -> Algorithm.Identifier.t

  (** Reconstructs the BIT STRING payload from the validated mathematical key,
      preserving compressed versus uncompressed EC point representation. *)
  val subject_public_key : t -> string

  (** Supported RSA, EC and Ed25519 keys have octet-aligned payloads. Rejects
      non-octet-aligned BIT STRINGs rather than silently padding them. *)
  val asn : t Asn_syntax.t
  val encode_der : t -> string
  val decode_der : string -> (t, [> `Msg of string ]) result
end = struct
  type key = t
  open Asn_syntax.S

  (* All supported key formats contain whole octets, so the bit length is
     determined by the key and compression form. No original payload or SPKI
     bytes are retained. The abstract type keeps the algorithm and key matched. *)
  type t = {
    key : key;
    algorithm : Algorithm.Identifier.t;
    compress : bool;
  }

  let of_key key =
    let algorithm, _ = Asn.unparse_pk key in
    { key; algorithm = Algorithm.Identifier.of_algorithm algorithm; compress = false }

  let key t = t.key
  let algorithm t = t.algorithm
  let subject_public_key t = snd (Asn.unparse_pk_with_compression ~compress:t.compress t.key)

  let octets_of_bits bits =
    let length = Array.length bits in
    if length mod 8 <> 0 then
      parse_error "public key BIT STRING is not octet-aligned";
    String.init (length / 8) (fun i ->
        let octet = ref 0 in
        for bit = 0 to 7 do
          if bits.(8 * i + bit) then octet := !octet lor (1 lsl (7 - bit))
        done;
        Char.chr !octet)

  let bits_of_octets octets =
    Array.init (8 * String.length octets) (fun bit ->
        Char.code octets.[bit / 8] land (1 lsl (7 - bit mod 8)) <> 0)

  let of_components (algorithm, bits) =
    let octets = octets_of_bits bits in
    let key = Asn.reparse_pk (Algorithm.Identifier.algorithm algorithm, octets) in
    let compress = match key with
      | #ecdsa -> octets.[0] = '\002' || octets.[0] = '\003'
      | `RSA _ | `ED25519 _ -> false
    in
    { key; algorithm; compress }

  let to_components t = t.algorithm, bits_of_octets (subject_public_key t)

  let asn =
    map of_components to_components @@
    sequence2
      (required ~label:"algorithm" Algorithm.Identifier.asn)
      (required ~label:"subjectPK" bit_string)

  let of_der, encode_der = Asn_grammars.projections_of Asn_syntax.der asn
  let decode_der der = Asn_grammars.err_to_msg (of_der der)
end

let id k =
  let data = match k with
    | `RSA p -> Asn.rsa_public_to_octets p
    | `ED25519 pk -> Mirage_crypto_ec.Ed25519.pub_to_octets pk
    | `P256 pk -> Mirage_crypto_ec.P256.Dsa.pub_to_octets pk
    | `P384 pk -> Mirage_crypto_ec.P384.Dsa.pub_to_octets pk
    | `P521 pk -> Mirage_crypto_ec.P521.Dsa.pub_to_octets pk
  in
  Digestif.(to_raw_string SHA1 (digest_string SHA1 data))

let fingerprint ?(hash = `SHA256) pub =
  let module Hash = (val (Digestif.module_of_hash' (hash :> Digestif.hash'))) in
  Hash.(to_raw_string (digest_string (Asn.pub_info_to_octets pub)))

let key_type = function
  | `RSA _ -> `RSA
  | `ED25519 _ -> `ED25519
  | `P256 _ -> `P256
  | `P384 _ -> `P384
  | `P521 _ -> `P521

let sig_alg = function
  | #ecdsa -> `ECDSA
  | `RSA _ -> `RSA
  | `ED25519 _ -> `ED25519

let pp ppf k =
  Fmt.string ppf (Key_type.to_string (key_type k));
  Fmt.sp ppf ();
  Ohex.pp ppf (fingerprint k)

let hashed hash data =
  let module Hash = (val (Digestif.module_of_hash' hash)) in
  match data with
  | `Message msg -> Ok Hash.(to_raw_string (digest_string msg))
  | `Digest d ->
    let n = String.length d and m = Hash.digest_size in
    if n = m then Ok d else Error (`Msg "digested data of invalid size")

let trunc len data =
  if String.length data > len then
    String.sub data 0 len
  else
    data

let verify hash ?scheme ~signature key data =
  let open Mirage_crypto_ec in
  let ok_if_true p = if p then Ok () else Error (`Msg "bad signature") in
  let ecdsa_of_str cs =
    Result.map_error (function `Parse s -> `Msg s)
      (Algorithm.ecdsa_sig_of_octets cs)
  in
  let scheme = Key_type.opt_signature_scheme ?scheme (key_type key) in
  match key, scheme with
  | `RSA key, `RSA_PSS ->
    let module H = (val (Digestif.module_of_hash' hash)) in
    let module PSS = Mirage_crypto_pk.Rsa.PSS(H) in
    let* d = hashed hash data in
    ok_if_true (PSS.verify ~key ~signature (`Digest d))
  | `RSA key, `RSA_PKCS1 ->
    let hashp x = x = hash in
    let* d = hashed hash data in
    ok_if_true (Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature (`Digest d))
  | `ED25519 key, `ED25519 ->
    begin match data with
      | `Message msg -> ok_if_true (Ed25519.verify ~key signature ~msg)
      | `Digest _ -> Error (`Msg "Ed25519 only suitable with raw message")
    end
  | #ecdsa as key, `ECDSA ->
    let* d = hashed hash data in
    let* s = ecdsa_of_str signature in
    ok_if_true
      (match key with
       | `P256 key -> P256.Dsa.verify ~key s (trunc P256.Dsa.byte_length d)
       | `P384 key -> P384.Dsa.verify ~key s (trunc P384.Dsa.byte_length d)
       | `P521 key -> P521.Dsa.verify ~key s (trunc P521.Dsa.byte_length d))
  | _ -> Error (`Msg "invalid key and signature scheme combination")

let encode_der = Asn.pub_info_to_octets

let decode_der cs = Asn_grammars.err_to_msg (Asn.pub_info_of_octets cs)

let decode_pem cs =
  let* data = Pem.parse cs in
  let pks = List.filter (fun (t, _) -> String.equal "PUBLIC KEY" t) data in
  let* keys = Pem.foldM (fun (_, k) -> decode_der k) pks in
  Pem.exactly_one ~what:"public key" keys

let encode_pem v =
  Pem.unparse ~tag:"PUBLIC KEY" (encode_der v)
