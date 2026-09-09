module Encoded_string : sig
  type encoding = [ `UTF8 | `Printable | `IA5 | `Universal | `Teletex | `BMP ]
  type t

  val of_octets : ?encoding:encoding -> string -> t
  val to_octets : t -> string
  val encoding : t -> encoding
  val compare_octets : t -> t -> int
  val compare : t -> t -> int
  val equal : t -> t -> bool
  val pp : t Fmt.t
end = struct
  type encoding = [ `UTF8 | `Printable | `IA5 | `Universal | `Teletex | `BMP ]
  type t = { octets : string; encoding : encoding }

  (* These are the contents octets of the selected ASN.1 string type, not
     necessarily UTF-8. No Unicode validation or transcoding is performed. *)
  let of_octets ?(encoding = `UTF8) octets = { octets; encoding }
  let to_octets t = t.octets
  let encoding t = t.encoding
  let compare_octets a b = String.compare a.octets b.octets

  let tag = function
    | `UTF8 -> 12 | `Printable -> 19 | `Teletex -> 20
    | `IA5 -> 22 | `Universal -> 28 | `BMP -> 30

  let compare a b =
    match compare_octets a b with
    | 0 -> Int.compare (tag a.encoding) (tag b.encoding)
    | n -> n

  let equal a b = compare a b = 0
  let pp ppf t = Fmt.string ppf t.octets
end

type attribute =
  | CN of Encoded_string.t
  | Serialnumber of Encoded_string.t
  | C of Encoded_string.t
  | L of Encoded_string.t
  | ST of Encoded_string.t
  | O of Encoded_string.t
  | OU of Encoded_string.t
  | T of Encoded_string.t
  | DNQ of Encoded_string.t
  | Mail of Encoded_string.t
  | DC of Encoded_string.t
  | Given_name of Encoded_string.t
  | Surname of Encoded_string.t
  | Initials of Encoded_string.t
  | Pseudonym of Encoded_string.t
  | Generation of Encoded_string.t
  | Street of Encoded_string.t
  | Userid of Encoded_string.t
  | Other of Asn.oid * Encoded_string.t

let attribute_of_oid =
  let open Registry in
  let f = Asn_grammars.case_of_oid_f [
      (domain_component, fun x -> DC x);
      (X520.common_name, fun x -> CN x);
      (X520.serial_number, fun x -> Serialnumber x);
      (X520.country_name, fun x -> C x);
      (X520.locality_name, fun x -> L x);
      (X520.state_or_province_name, fun x -> ST x);
      (X520.organization_name, fun x -> O x);
      (X520.organizational_unit_name, fun x -> OU x);
      (X520.title, fun x -> T x);
      (X520.dn_qualifier, fun x -> DNQ x);
      (PKCS9.email, fun x -> Mail x);
      (X520.given_name, fun x -> Given_name x);
      (X520.surname, fun x -> Surname x);
      (X520.initials, fun x -> Initials x);
      (X520.pseudonym, fun x -> Pseudonym x);
      (X520.generation_qualifier, fun x -> Generation x);
      (X520.street_address, fun x -> Street x);
      (userid, fun x -> Userid x)
    ] ~default:(fun oid x -> Other (oid, x))
  in
  fun oid value -> f (oid, value)

let canonical_attribute = function
  | Other (oid, value) -> attribute_of_oid oid value
  | attribute -> attribute

let attribute_oid_value =
  let open Registry in
  function
  | DC x -> domain_component, x
  | CN x -> X520.common_name, x
  | Serialnumber x -> X520.serial_number, x
  | C x -> X520.country_name, x
  | L x -> X520.locality_name, x
  | ST x -> X520.state_or_province_name, x
  | O x -> X520.organization_name, x
  | OU x -> X520.organizational_unit_name, x
  | T x -> X520.title, x
  | DNQ x -> X520.dn_qualifier, x
  | Mail x -> PKCS9.email, x
  | Given_name x -> X520.given_name, x
  | Surname x -> X520.surname, x
  | Initials x -> X520.initials, x
  | Pseudonym x -> X520.pseudonym, x
  | Generation x -> X520.generation_qualifier, x
  | Street x -> X520.street_address, x
  | Userid x -> userid, x
  | Other (oid, x) -> oid, x

(* Fresh construction can opt into the conventional encoding defaults. Parsing
   never uses this helper: even C, DC and Mail retain whichever tag was read. *)
let attribute_of_octets constructor octets =
  let attribute = canonical_attribute (constructor (Encoded_string.of_octets octets)) in
  let encoding = match attribute with
    | Serialnumber _ | C _ | DNQ _ -> `Printable
    | Mail _ | DC _ -> `IA5
    | _ -> `UTF8
  in
  let oid, _ = attribute_oid_value attribute in
  attribute_of_oid oid (Encoded_string.of_octets ~encoding octets)

(* Escaping is described in RFC4514. Escaping '=' is optional, otherwise the
 * following is minimal, using the character instead of hex where possible. *)
let pp_attribute_value ?(osf = false) () ppf s =
  let n = String.length s in
  for i = 0 to n - 1 do
    match s.[i] with
    | '#' when i = 0 -> Fmt.string ppf "\\#"
    | ' ' when i = 0 || i = n - 1 -> Fmt.string ppf "\\ "
    | ',' when not osf -> Fmt.string ppf "\\,"
    | ';' when not osf -> Fmt.string ppf "\\;"
    | '/' when osf -> Fmt.string ppf "\\/"
    | '"' | '+' | '<' | '=' | '>' | '\\' as c -> Fmt.pf ppf "\\%c" c
    | '\x00' -> Fmt.string ppf "\\00"
    | c -> Fmt.char ppf c
  done

let pp_string_hex ppf s =
  for i = 0 to String.length s - 1 do
    Fmt.pf ppf "%02x" (Char.code s.[i])
  done

let pp_attribute ?osf ?(ava_equal = Fmt.any "=") () ppf attr =
  let aux a v =
    Fmt.pf ppf "%s%a%a" a ava_equal () (pp_attribute_value ?osf ())
      (Encoded_string.to_octets v) in
  match attr with
  | CN s -> aux "CN" s
  | Serialnumber s -> aux "Serialnumber" s
  | C s -> aux "C" s
  | L s -> aux "L" s
  | ST s -> aux "ST" s
  | O s -> aux "O" s
  | OU s -> aux "OU" s
  | T s -> aux "T" s
  | DNQ s -> aux "DNQ" s
  | Mail s -> aux "Mail" s
  | DC s -> aux "DC" s
  | Given_name s -> aux "Given_name" s
  | Surname s -> aux "Surname" s
  | Initials s -> aux "Initials" s
  | Pseudonym s -> aux "Pseudonym" s
  | Generation s -> aux "Generation" s
  | Street s -> aux "Street" s
  | Userid s -> aux "UID" s
  | Other (oid, s) ->
    Fmt.pf ppf "%a%a#%a" Asn.OID.pp oid ava_equal () pp_string_hex
      (Encoded_string.to_octets s)

let compare_attribute compare_value t t' =
  match t, t' with
  | CN a, CN b -> compare_value a b
  | CN _, _ -> -1 | _, CN _ -> 1
  | Serialnumber a, Serialnumber b -> compare_value a b
  | Serialnumber _, _ -> -1 | _, Serialnumber _ -> 1
  | C a, C b -> compare_value a b
  | C _, _ -> -1 | _, C _ -> 1
  | L a, L b -> compare_value a b
  | L _, _ -> -1 | _, L _ -> 1
  | ST a, ST b -> compare_value a b
  | ST _, _ -> -1 | _, ST _ -> 1
  | O a, O b -> compare_value a b
  | O _, _ -> -1 | _, O _ -> 1
  | OU a, OU b -> compare_value a b
  | OU _, _ -> -1 | _, OU _ -> 1
  | T a, T b -> compare_value a b
  | T _, _ -> -1 | _, T _ -> 1
  | DNQ a, DNQ b -> compare_value a b
  | DNQ _, _ -> -1 | _, DNQ _ -> 1
  | Mail a, Mail b -> compare_value a b
  | Mail _, _ -> -1 | _, Mail _ -> 1
  | DC a, DC b -> compare_value a b
  | DC _, _ -> -1 | _, DC _ -> 1
  | Given_name a, Given_name b -> compare_value a b
  | Given_name _, _ -> -1 | _, Given_name _ -> 1
  | Surname a, Surname b -> compare_value a b
  | Surname _, _ -> -1 | _, Surname _ -> 1
  | Initials a, Initials b -> compare_value a b
  | Initials _, _ -> -1 | _, Initials _ -> 1
  | Pseudonym a, Pseudonym b -> compare_value a b
  | Pseudonym _, _ -> -1 | _, Pseudonym _ -> 1
  | Generation a, Generation b -> compare_value a b
  | Generation _, _ -> -1 | _, Generation _ -> 1
  | Street a, Street b -> compare_value a b
  | Street _, _ -> -1 | _, Street _ -> 1
  | Userid a, Userid b -> compare_value a b
  | Userid _, _ -> -1 | _, Userid _ -> 1
  | Other (oid_a, v_a), Other (oid_b, v_b) ->
    match Asn.OID.compare oid_a oid_b with
    | 0 -> compare_value v_a v_b
    | n -> n

module Relative_distinguished_name : sig
  type elt = attribute
  type t
  val empty : t
  val is_empty : t -> bool
  val singleton : elt -> t
  val of_list : elt list -> t
  val elements : t -> elt list
  val add : elt -> t -> t
  val union : t -> t -> t
  val remove : elt -> t -> t
  val mem : elt -> t -> bool
  val cardinal : t -> int
  val compare : t -> t -> int
  val equal : t -> t -> bool
  val iter : (elt -> unit) -> t -> unit
  val fold : (elt -> 'a -> 'a) -> t -> 'a -> 'a
  val filter : (elt -> bool) -> t -> t
  val for_all : (elt -> bool) -> t -> bool
  val exists : (elt -> bool) -> t -> bool
end = struct
  type elt = attribute
  (* A sorted multiset, not Set.S. Duplicate AVAs (including identical ones)
     are meaningful representation data. DER supplies the SET OF wire order;
     this internal ordering need not be the DER ordering. *)
  type t = attribute list
  let compare_elt = compare_attribute Encoded_string.compare
  let empty = []
  let is_empty = function [] -> true | _ -> false
  let singleton elt = [ canonical_attribute elt ]
  let of_list xs = List.sort compare_elt (List.map canonical_attribute xs)
  let elements t = t
  let add elt t = List.merge compare_elt (singleton elt) t
  let union = List.merge compare_elt
  let remove elt t =
    let elt = canonical_attribute elt in
    let rec go = function
      | [] -> []
      | x :: xs when compare_elt elt x = 0 -> xs
      | x :: xs -> x :: go xs
    in
    go t
  let mem elt t =
    let elt = canonical_attribute elt in
    List.exists (fun x -> compare_elt elt x = 0) t
  let cardinal = List.length
  let rec compare a b = match a, b with
    | [], [] -> 0 | [], _ -> -1 | _, [] -> 1
    | a :: aa, b :: bb ->
      match compare_elt a b with 0 -> compare aa bb | n -> n
  let equal a b = compare a b = 0
  let iter = List.iter
  let fold f t acc = List.fold_left (fun acc elt -> f elt acc) acc t
  let filter = List.filter
  let for_all = List.for_all
  let exists = List.exists
end

(* Logical matching preserves the legacy byte-value, tag-insensitive set
   semantics, separately from the lossless representation multiset. *)
module Matching_rdn = Set.Make(struct
    type t = attribute
    let compare = compare_attribute Encoded_string.compare_octets
  end)

let matching_rdn rdn =
  Relative_distinguished_name.fold Matching_rdn.add rdn Matching_rdn.empty

type t = Relative_distinguished_name.t list

let equal_representation a b =
  List.length a = List.length b &&
  List.for_all2 Relative_distinguished_name.equal a b

let equal a b =
  List.length a = List.length b &&
  List.for_all2 (fun a b -> Matching_rdn.equal (matching_rdn a) (matching_rdn b)) a b

let make_pp_rdn ?osf ?(spacing = `Tight) () =
  let ava_sep, ava_equal =
    match spacing with
    | `Tight -> Fmt.(any "+" ++ cut, any "=")
    | `Medium -> Fmt.(any " +" ++ sp, any "=")
    | `Loose -> Fmt.(any " +" ++ sp, any " = ")
  in
  let pp_ava = pp_attribute ?osf ~ava_equal () in
  Fmt.(using Relative_distinguished_name.elements @@ list ~sep:ava_sep pp_ava)

let make_pp ~format ?spacing () =
  match format, spacing with
  | `RFC4514, (None | Some `Tight) ->
    Fmt.(using List.rev @@ list ~sep:(any "," ++ cut) (make_pp_rdn ()))
  | `RFC4514, Some (`Medium | `Loose as spacing) ->
    Fmt.(using List.rev @@ list ~sep:comma (make_pp_rdn ~spacing ()))
  | `OpenSSL, (None | Some `Loose) ->
    Fmt.(list ~sep:comma (make_pp_rdn ~spacing:`Loose ()))
  | `OpenSSL, Some (`Tight | `Medium as spacing) ->
    Fmt.(list ~sep:(any "," ++ cut) (make_pp_rdn ~spacing ()))
  | `OSF, _ ->
    Fmt.(any "/" ++ list ~sep:(any "/") (make_pp_rdn ~osf:true ()))

let pp = Fmt.hbox (make_pp ~format:`OSF ())

let common_name_encoded t =
  List.fold_left (fun acc dn ->
      (* Unlike Set.find_first_opt, this needs no monotone predicate. *)
      let name = Relative_distinguished_name.fold (fun attr name ->
          match name, attr with
          | None, CN value -> Some value
          | _ -> name) dn None
      in
      match name with Some _ -> name | None -> acc)
    None t

let common_name t = Option.map Encoded_string.to_octets (common_name_encoded t)

module Asn = struct
  open Asn.S

  (* Preserve all six historical alternatives, including IA5String, and even
     the non-default tags accepted for fixed-schema attributes such as C. *)
  let directory_name =
    let f = function
      | `C1 x -> Encoded_string.of_octets ~encoding:`UTF8 x
      | `C2 x -> Encoded_string.of_octets ~encoding:`Printable x
      | `C3 x -> Encoded_string.of_octets ~encoding:`IA5 x
      | `C4 x -> Encoded_string.of_octets ~encoding:`Universal x
      | `C5 x -> Encoded_string.of_octets ~encoding:`Teletex x
      | `C6 x -> Encoded_string.of_octets ~encoding:`BMP x
    and g x =
      let octets = Encoded_string.to_octets x in
      match Encoded_string.encoding x with
      | `UTF8 -> `C1 octets
      | `Printable -> `C2 octets
      | `IA5 -> `C3 octets
      | `Universal -> `C4 octets
      | `Teletex -> `C5 octets
      | `BMP -> `C6 octets
    in
    map f g @@ choice6
      utf8_string printable_string ia5_string universal_string teletex_string bmp_string

  let relative_distinguished_name =
    let attribute_tv =
      map (fun (oid, value) -> attribute_of_oid oid value) attribute_oid_value @@
      sequence2
        (required ~label:"attr type" oid)
        (required ~label:"attr value" directory_name)
    in
    let encode_attribute = Asn.encode (Asn.codec Asn.der attribute_tv) in
    let decode attributes =
      let check_order = function
        | [] -> ()
        | first :: rest ->
          let rec go previous = function
            | [] -> ()
            | attribute :: rest ->
              let encoded = encode_attribute attribute in
              if String.compare previous encoded > 0 then
                parse_error "RDN SET OF attributes is not in DER order";
              go encoded rest
          in
          go (encode_attribute first) rest
      in
      (* Semantic multiset order differs from DER's full-encoding order.
         Equal encodings are valid duplicate AVAs and must not be removed. *)
      check_order attributes;
      Relative_distinguished_name.of_list attributes
    in
    map ~random:(fun () ->
        Relative_distinguished_name.of_list (Asn.random (set_of attribute_tv)))
      decode Relative_distinguished_name.elements (set_of attribute_tv)

  let name = sequence_of relative_distinguished_name

  let name_of_octets, name_to_octets = Asn_grammars.projections_of Asn.der name
end

let decode_der cs = Asn_grammars.err_to_msg (Asn.name_of_octets cs)
let encode_der = Asn.name_to_octets
