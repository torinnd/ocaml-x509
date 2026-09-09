module Encoded_string = struct
  type encoding = [ `UTF8 | `Printable | `IA5 | `Universal | `Teletex | `BMP ]

  type t = {
    octets : string ;
    encoding : encoding ;
  }

  let of_octets ?(encoding = `UTF8) octets = { octets ; encoding }
  let to_octets { octets ; _ } = octets
  let encoding { encoding ; _ } = encoding

  let compare_octets a b = String.compare a.octets b.octets

  let tag = function
    | `UTF8 -> 12
    | `Printable -> 19
    | `Teletex -> 20
    | `IA5 -> 22
    | `Universal -> 28
    | `BMP -> 30

  let compare a b =
    match compare_octets a b with
    | 0 -> Int.compare (tag a.encoding) (tag b.encoding)
    | n -> n
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

(* Escaping is described in RFC4514. Escaing '=' is optional, otherwise the
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
    | x when x < 0 -> -1
    | _ -> 1

module Relative_distinguished_name = Set.Make(struct
    type t = attribute
    let compare = compare_attribute Encoded_string.compare
  end)

(* Matching deliberately forgets the tag, including collapsing attributes that
   differed only in tag. Keep this separate from representation storage. *)
module Matching_rdn = Set.Make(struct
    type t = attribute
    let compare = compare_attribute Encoded_string.compare_octets
  end)

let matching_rdn rdn =
  Relative_distinguished_name.fold Matching_rdn.add rdn Matching_rdn.empty

(* TODO:
   - each RDN should be a non-empty set
   - Other can use an OID that already has a named constructor; these aliases
     are not identified by the set comparison *)
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

let common_name t =
  List.fold_left (fun acc dn ->
      (* CN sorts before other attributes, so is_cn would not satisfy
         find_first_opt's monotonic-predicate requirement. *)
      let name =
        Relative_distinguished_name.fold (fun attr name ->
            match name, attr with
            | None, CN value -> Some value
            | _ -> name)
          dn None
      in
      match name with Some _ -> name | None -> acc)
    None t

module Asn = struct
  open Asn.S
  open Asn_grammars

  (* ASN `Name' fragmet appears all over. *)

  (* rfc5280 section 4.1.2.4 - name components we "must" handle. *)
  (* A list of abbreviations: http://pic.dhe.ibm.com/infocenter/wmqv7/v7r1/index.jsp?topic=%2Fcom.ibm.mq.doc%2Fsy10570_.htm *)
  (* Also rfc4519. *)

  (* Preserve the six string alternatives historically accepted by this parser.
     This is not precisely DirectoryString: it includes IA5String. *)
  let encoded_string =
    choice6
      utf8_string printable_string
      ia5_string universal_string teletex_string bmp_string

  let name =
    let open Registry in
    let of_c = function
      | `C1 x -> Encoded_string.of_octets ~encoding:`UTF8 x
      | `C2 x -> Encoded_string.of_octets ~encoding:`Printable x
      | `C3 x -> Encoded_string.of_octets ~encoding:`IA5 x
      | `C4 x -> Encoded_string.of_octets ~encoding:`Universal x
      | `C5 x -> Encoded_string.of_octets ~encoding:`Teletex x
      | `C6 x -> Encoded_string.of_octets ~encoding:`BMP x
    and to_c x =
      let octets = Encoded_string.to_octets x in
      match Encoded_string.encoding x with
      | `UTF8 -> `C1 octets
      | `Printable -> `C2 octets
      | `IA5 -> `C3 octets
      | `Universal -> `C4 octets
      | `Teletex -> `C5 octets
      | `BMP -> `C6 octets
    in

    let a_f = case_of_oid_f [
      (domain_component              , fun x -> DC (of_c x)) ;
      (X520.common_name              , fun x -> CN (of_c x)) ;
      (X520.serial_number            , fun x -> Serialnumber (of_c x)) ;
      (X520.country_name             , fun x -> C (of_c x)) ;
      (X520.locality_name            , fun x -> L (of_c x)) ;
      (X520.state_or_province_name   , fun x -> ST (of_c x)) ;
      (X520.organization_name        , fun x -> O (of_c x)) ;
      (X520.organizational_unit_name , fun x -> OU (of_c x)) ;
      (X520.title                    , fun x -> T (of_c x)) ;
      (X520.dn_qualifier             , fun x -> DNQ (of_c x)) ;
      (PKCS9.email                   , fun x -> Mail (of_c x)) ;
      (X520.given_name               , fun x -> Given_name (of_c x)) ;
      (X520.surname                  , fun x -> Surname (of_c x)) ;
      (X520.initials                 , fun x -> Initials (of_c x)) ;
      (X520.pseudonym                , fun x -> Pseudonym (of_c x)) ;
      (X520.generation_qualifier     , fun x -> Generation (of_c x)) ;
      (X520.street_address           , fun x -> Street (of_c x)) ;
      (userid                        , fun x -> Userid (of_c x))]
      ~default:(fun oid x -> Other (oid, of_c x))

    and a_g = function
      | DC x -> (domain_component, to_c x)
      | CN x -> (X520.common_name, to_c x)
      | Serialnumber x -> (X520.serial_number, to_c x)
      | C x -> (X520.country_name, to_c x)
      | L x -> (X520.locality_name, to_c x)
      | ST x -> (X520.state_or_province_name, to_c x)
      | O x -> (X520.organization_name, to_c x)
      | OU x -> (X520.organizational_unit_name, to_c x)
      | T x -> (X520.title, to_c x)
      | DNQ x -> (X520.dn_qualifier, to_c x)
      | Mail x -> (PKCS9.email, to_c x)
      | Given_name x -> (X520.given_name, to_c x)
      | Surname x -> (X520.surname, to_c x)
      | Initials x -> (X520.initials, to_c x)
      | Pseudonym x -> (X520.pseudonym, to_c x)
      | Generation x -> (X520.generation_qualifier, to_c x)
      | Street x -> (X520.street_address, to_c x)
      | Userid x -> (userid, to_c x)
      | Other (oid, x) -> (oid, to_c x)
    in

    let attribute_tv =
      map a_f a_g @@
      sequence2
        (required ~label:"attr type"  oid)
        (* This is ANY according to rfc5280. *)
        (required ~label:"attr value" encoded_string)
    in
    let rd_name =
      let f exts =
        List.fold_left
          (fun set attr -> Relative_distinguished_name.add attr set)
          Relative_distinguished_name.empty exts
      and g map = Relative_distinguished_name.elements map
      in
      map f g @@ set_of attribute_tv
    in
    sequence_of rd_name (* A vacuous choice, in the standard. *)

  let (name_of_octets, name_to_octets) =
    projections_of Asn.der name
end

let decode_der cs = Asn_grammars.err_to_msg (Asn.name_of_octets cs)

let encode_der = Asn.name_to_octets
