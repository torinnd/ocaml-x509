
(* Named flags retain their semantic set and BIT STRING width, not encoded
   octets. Fresh values use the minimal width; decoded zero tails are retained. *)
module Make_flags (Flag : sig
    type t
    val known : (int * t) list
    val unknown_bit : t -> int option
    val of_unknown_bit : int -> t
    val pp : t Fmt.t
  end) : sig
  type t
  val of_list : ?bit_length:int -> Flag.t list -> t
  val to_list : t -> Flag.t list
  val bit_length : t -> int
  val mem : Flag.t -> t -> bool
  val equal : t -> t -> bool
  val equal_representation : t -> t -> bool
  val pp : t Fmt.t
  val asn : t Asn.t
end = struct
  type t = { flags : Flag.t list; bit_length : int }

  let position flag =
    match Flag.unknown_bit flag with
    | Some bit ->
      if bit < 0 || List.mem_assoc bit Flag.known then
        invalid_arg "Extension: Unknown_bit must be a nonnegative unknown position";
      bit
    | None ->
      match List.find_opt (fun (_, known) -> known = flag) Flag.known with
      | Some (bit, _) -> bit
      | None -> invalid_arg "Extension: invalid named bit"

  let of_list ?bit_length flags =
    let positioned = List.map (fun flag -> position flag, flag) flags in
    let highest = List.fold_left (fun highest (bit, _) -> max highest bit) (-1) positioned in
    if highest >= Sys.max_array_length then
      invalid_arg "Extension: named bit position exceeds maximum array length";
    let minimum = highest + 1 in
    let bit_length = Option.value ~default:minimum bit_length in
    if bit_length < minimum || bit_length > Sys.max_array_length then
      invalid_arg "Extension: invalid named bit length";
    let flags = List.map snd
        (List.sort_uniq (fun (a, _) (b, _) -> Int.compare a b) positioned) in
    { flags; bit_length }

  let to_list t = t.flags
  let bit_length t = t.bit_length
  let mem flag t = List.mem flag t.flags
  let equal a b = a.flags = b.flags
  let equal_representation a b = equal a b && a.bit_length = b.bit_length
  let pp ppf t =
    Fmt.pf ppf "[%a] (%d bits)" Fmt.(list ~sep:(any ", ") Flag.pp)
      t.flags t.bit_length

  let of_bits bits =
    let flags = ref [] in
    for bit = 0 to Bits.bit_length bits - 1 do
      if String.get_uint8 (Bits.octets bits) (bit / 8) land (1 lsl (7 - bit mod 8)) <> 0 then
        let flag = match List.assoc_opt bit Flag.known with
          | Some flag -> flag
          | None -> Flag.of_unknown_bit bit
        in
        flags := flag :: !flags
    done;
    { flags = List.rev !flags; bit_length = Bits.bit_length bits }

  let to_bits t =
    let octets = Bytes.make ((t.bit_length + 7) / 8) '\000' in
    List.iter (fun flag ->
        let bit = position flag in
        let offset = bit / 8 in
        Bytes.set_uint8 octets offset
          (Bytes.get_uint8 octets offset lor (1 lsl (7 - bit mod 8)))) t.flags;
    match Bits.create ~bit_length:t.bit_length (Bytes.to_string octets) with
    | Ok bits -> bits
    | Error (`Msg msg) -> invalid_arg msg

  (* Bits.asn validates unused-bit counts and nonzero padding before projection.
     A zero tail within the declared width is meaningful representation metadata. *)
  let asn = Asn.S.map ~random:(fun () -> of_bits (Asn.random Bits.asn))
      of_bits to_bits Bits.asn
end

type key_usage = [
  | `Digital_signature
  | `Content_commitment
  | `Key_encipherment
  | `Data_encipherment
  | `Key_agreement
  | `Key_cert_sign
  | `CRL_sign
  | `Encipher_only
  | `Decipher_only
  | `Unknown_bit of int
]

let pp_key_usage ppf ku =
  Fmt.string ppf
    (match ku with
     | `Digital_signature ->  "digital signature"
     | `Content_commitment -> "content commitment"
     | `Key_encipherment -> "key encipherment"
     | `Data_encipherment -> "data encipherment"
     | `Key_agreement -> "key agreement"
     | `Key_cert_sign -> "key cert sign"
     | `CRL_sign -> "CRL sign"
     | `Encipher_only -> "encipher only"
     | `Decipher_only -> "decipher only"
     | `Unknown_bit n -> Printf.sprintf "unknown key-usage bit %d" n)

module Key_usage = Make_flags (struct
    type t = key_usage
    let known = [
      0, `Digital_signature; 1, `Content_commitment; 2, `Key_encipherment;
      3, `Data_encipherment; 4, `Key_agreement; 5, `Key_cert_sign;
      6, `CRL_sign; 7, `Encipher_only; 8, `Decipher_only;
    ]
    let unknown_bit = function `Unknown_bit bit -> Some bit | _ -> None
    let of_unknown_bit bit = `Unknown_bit bit
    let pp = pp_key_usage
  end)

type extended_key_usage = [
  | `Any
  | `Server_auth
  | `Client_auth
  | `Code_signing
  | `Email_protection
  | `Ipsec_end
  | `Ipsec_tunnel
  | `Ipsec_user
  | `Time_stamping
  | `Ocsp_signing
  | `Other of Asn.oid
]

let pp_extended_key_usage ppf = function
  | `Any -> Fmt.string ppf "any"
  | `Server_auth -> Fmt.string ppf "server authentication"
  | `Client_auth -> Fmt.string ppf "client authentication"
  | `Code_signing -> Fmt.string ppf "code signing"
  | `Email_protection -> Fmt.string ppf "email protection"
  | `Ipsec_end -> Fmt.string ppf "ipsec end"
  | `Ipsec_tunnel -> Fmt.string ppf "ipsec tunnel"
  | `Ipsec_user -> Fmt.string ppf "ipsec user"
  | `Time_stamping -> Fmt.string ppf "time stamping"
  | `Ocsp_signing -> Fmt.string ppf "ocsp signing"
  | `Other oid -> Asn.OID.pp ppf oid

type authority_key_id = string option * General_name.t * string option

let pp_authority_key_id ppf (id, issuer, serial) =
  Fmt.pf ppf "identifier %a@ issuer %a@ serial %a@ "
    Fmt.(option ~none:(any "none") Ohex.pp) id
    General_name.pp issuer
    Fmt.(option ~none:(any "none") Ohex.pp) serial

type priv_key_usage_period = [
  | `Interval   of Ptime.t * Ptime.t
  | `Not_after  of Ptime.t
  | `Not_before of Ptime.t
]

let pp_priv_key_usage_period ppf =
  let pp_ptime ppf t =
    let frac_s = if Ptime.Span.equal (Ptime.frac_s t) Ptime.Span.zero then 0 else 12 in
    Ptime.pp_human ~frac_s ~tz_offset_s:0 () ppf t
  in
  function
  | `Interval (start, stop) ->
    Fmt.pf ppf "from %a till %a" pp_ptime start pp_ptime stop
  | `Not_after after -> Fmt.pf ppf "not after %a" pp_ptime after
  | `Not_before before -> Fmt.pf ppf "not before %a" pp_ptime before

type name_constraint = (General_name.b * int * int option) list

let pp_name_constraints ppf (permitted, excluded) =
  let pp_one ppf (General_name.B (k, base), min, max) =
    Fmt.pf ppf "base %a min %u max %a"
      (General_name.pp_k k) base min Fmt.(option ~none:(any "none") int) max
  in
  Fmt.pf ppf "permitted %a@ excluded %a"
    Fmt.(list ~sep:(any ", ") pp_one) permitted
    Fmt.(list ~sep:(any ", ") pp_one) excluded

(* String contents retain the ASN.1 string choice; BMP contents are big-endian
   code units, not UTF-8. These are values, not cached extension DER. *)
type display_text = [
  | `IA5 of string
  | `Visible of string
  | `BMP of string
  | `UTF8 of string
]

type notice_reference = {
  organization : display_text;
  notice_numbers : Z.t list;
}

type user_notice = {
  notice_ref : notice_reference option;
  explicit_text : display_text option;
}

type policy_qualifier = [ `CPS_uri of string | `User_notice of user_notice ]

type policy = {
  policy_identifier : Asn.oid;
  policy_qualifiers : policy_qualifier list option;
}

let policy ?qualifiers policy_identifier =
  { policy_identifier; policy_qualifiers = qualifiers }

let any_policy ?qualifiers () =
  policy ?qualifiers Registry.Cert_extn.Cert_policy.any_policy

let is_any_policy p =
  Asn.OID.equal p.policy_identifier Registry.Cert_extn.Cert_policy.any_policy

let pp_display_text ppf = function
  | `IA5 s -> Fmt.pf ppf "IA5 %S" s
  | `Visible s -> Fmt.pf ppf "Visible %S" s
  | `BMP s -> Fmt.pf ppf "BMP %a" Ohex.pp s
  | `UTF8 s -> Fmt.pf ppf "UTF8 %S" s

let pp_notice_reference ppf { organization; notice_numbers } =
  Fmt.pf ppf "organization %a numbers [%a]" pp_display_text organization
    Fmt.(list ~sep:(any ", ") (using Z.to_string string)) notice_numbers

let pp_user_notice ppf { notice_ref; explicit_text } =
  Fmt.pf ppf "notice reference %a explicit text %a"
    Fmt.(option ~none:(any "none") pp_notice_reference) notice_ref
    Fmt.(option ~none:(any "none") pp_display_text) explicit_text

let pp_policy_qualifier ppf = function
  | `CPS_uri uri -> Fmt.pf ppf "CPS URI %S" uri
  | `User_notice notice -> Fmt.pf ppf "user notice %a" pp_user_notice notice

let pp_policy ppf p =
  Fmt.pf ppf "%a qualifiers %a" Asn.OID.pp p.policy_identifier
    Fmt.(option ~none:(any "none") (list ~sep:(any "; ") pp_policy_qualifier))
    p.policy_qualifiers

type reason = [
  | `Unspecified
  | `Key_compromise
  | `CA_compromise
  | `Affiliation_changed
  | `Superseded
  | `Cessation_of_operation
  | `Certificate_hold
  | `Remove_from_CRL
  | `Privilege_withdrawn
  | `AA_compromise
]

let reason_to_int = function
  | `Unspecified -> 0
  | `Key_compromise -> 1
  | `CA_compromise -> 2
  | `Affiliation_changed -> 3
  | `Superseded -> 4
  | `Cessation_of_operation -> 5
  | `Certificate_hold -> 6
  (* 7 is not used *)
  | `Remove_from_CRL -> 8
  | `Privilege_withdrawn -> 9
  | `AA_compromise -> 10

let reason_of_int = function
  |  0 -> `Unspecified
  |  1 -> `Key_compromise
  |  2 -> `CA_compromise
  |  3 -> `Affiliation_changed
  |  4 -> `Superseded
  |  5 -> `Cessation_of_operation
  |  6 -> `Certificate_hold
  (* 7 is not used *)
  |  8 -> `Remove_from_CRL
  |  9 -> `Privilege_withdrawn
  |  10 -> `AA_compromise
  | x -> Asn.S.parse_error "Unknown reason %d" x

let pp_reason ppf r =
  Fmt.string ppf (match r with
      | `Unspecified -> "unspecified"
      | `Key_compromise -> "key compromise"
      | `CA_compromise -> "CA compromise"
      | `Affiliation_changed -> "affiliation changed"
      | `Superseded -> "superseded"
      | `Cessation_of_operation -> "cessation of operation"
      | `Certificate_hold -> "certificate hold"
      | `Remove_from_CRL -> "remove from CRL"
      | `Privilege_withdrawn -> "privilege withdrawn"
      | `AA_compromise -> "AA compromise")

(* ReasonFlags is a named bit list, NOT CRLReason ENUMERATED. In particular,
   privilegeWithdrawn/aaCompromise occupy bits 7/8 but enum codes 9/10.
   removeFromCRL has no flag, and bit 0 is named unused, not unspecified. *)
type reason_flag = [
  | `Unused
  | `Key_compromise
  | `CA_compromise
  | `Affiliation_changed
  | `Superseded
  | `Cessation_of_operation
  | `Certificate_hold
  | `Privilege_withdrawn
  | `AA_compromise
  | `Unknown_bit of int
]

let pp_reason_flag ppf = function
  | `Unused -> Fmt.string ppf "unused"
  | `Unknown_bit n -> Fmt.pf ppf "unknown reason bit %d" n
  | (`Key_compromise | `CA_compromise | `Affiliation_changed | `Superseded
    | `Cessation_of_operation | `Certificate_hold | `Privilege_withdrawn
    | `AA_compromise) as r -> pp_reason ppf r

module Reason_flags = Make_flags (struct
    type t = reason_flag
    let known = [
      0, `Unused; 1, `Key_compromise; 2, `CA_compromise;
      3, `Affiliation_changed; 4, `Superseded; 5, `Cessation_of_operation;
      6, `Certificate_hold; 7, `Privilege_withdrawn; 8, `AA_compromise;
    ]
    let unknown_bit = function `Unknown_bit bit -> Some bit | _ -> None
    let of_unknown_bit bit = `Unknown_bit bit
    let pp = pp_reason_flag
  end)

type distribution_point_name =
  [ `Full of General_name.t
  | `Relative of Distinguished_name.Relative_distinguished_name.t ]

let pp_distribution_point_name ppf = function
  | `Full name -> Fmt.pf ppf "full %a" General_name.pp name
  | `Relative name -> Fmt.pf ppf "relative %a" Distinguished_name.pp [ name ]

type distribution_point =
  distribution_point_name option *
  Reason_flags.t option *
  General_name.t option

let pp_distribution_point ppf (name, reasons, issuer) =
  Fmt.pf ppf "name %a reason %a issuer %a"
    Fmt.(option ~none:(any "none") pp_distribution_point_name) name
    Fmt.(option ~none:(any "none") Reason_flags.pp) reasons
    Fmt.(option ~none:(any "none") General_name.pp) issuer

let pp_issuing_distribution_point ppf (name, onlyuser, onlyca, onlysome, indirectcrl, onlyattributes) =
  Fmt.pf ppf "name %a only user certs %B only CA certs %B only reasons %a indirectcrl %B only attribute certs %B"
    Fmt.(option ~none:(any "none") pp_distribution_point_name) name
    onlyuser onlyca
    Fmt.(option ~none:(any "no") Reason_flags.pp) onlysome
    indirectcrl onlyattributes

type 'a extension = bool * 'a

type _ k =
  | Unsupported : Asn.oid -> string extension k
  | Subject_alt_name : General_name.t extension k
  | Authority_key_id : authority_key_id extension k
  | Subject_key_id : string extension k
  | Issuer_alt_name : General_name.t extension k
  | Key_usage : Key_usage.t extension k
  | Ext_key_usage : extended_key_usage list extension k
  | Basic_constraints : (bool * int option) extension k
  | CRL_number : int extension k
  | Delta_CRL_indicator : int extension k
  | Priv_key_period : priv_key_usage_period extension k
  | Name_constraints : (name_constraint * name_constraint) extension k
  | CRL_distribution_points : distribution_point list extension k
  | Issuing_distribution_point : (distribution_point_name option * bool * bool * Reason_flags.t option * bool * bool) extension k
  | Freshest_CRL : distribution_point list extension k
  | Reason : reason extension k
  | Invalidity_date : Ptime.t extension k
  | Certificate_issuer : General_name.t extension k
  | Policies : policy list extension k

let pp_one' : type a. (Format.formatter -> Asn.oid * string -> unit) -> a k -> Format.formatter -> a -> unit = fun custom k ppf v ->
  let c_to_str b = if b then "critical " else "" in
  match k, v with
  | Subject_alt_name, (crit, alt) ->
    Fmt.pf ppf "%ssubjectAlternativeName %a" (c_to_str crit)
      General_name.pp alt
  | Authority_key_id, (crit, kid) ->
    Fmt.pf ppf "%sauthorityKeyIdentifier %a" (c_to_str crit)
      pp_authority_key_id kid
  | Subject_key_id, (crit, kid) ->
    Fmt.pf ppf "%ssubjectKeyIdentifier %a" (c_to_str crit)
      Ohex.pp kid
  | Issuer_alt_name, (crit, alt) ->
    Fmt.pf ppf "%sissuerAlternativeNames %a" (c_to_str crit)
      General_name.pp alt
  | Key_usage, (crit, ku) ->
    Fmt.pf ppf "%skeyUsage %a" (c_to_str crit)
      Key_usage.pp ku
  | Ext_key_usage, (crit, eku) ->
    Fmt.pf ppf "%sextendedKeyUsage %a" (c_to_str crit)
      Fmt.(list ~sep:(any ", ") pp_extended_key_usage) eku
  | Basic_constraints, (crit, (ca, depth)) ->
    Fmt.pf ppf "%sbasicConstraints CA %B depth %a" (c_to_str crit) ca
      Fmt.(option ~none:(any "none") int) depth
  | CRL_number, (crit, i) ->
    Fmt.pf ppf "%scRLNumber %u" (c_to_str crit) i
  | Delta_CRL_indicator, (crit, indicator) ->
    Fmt.pf ppf "%sdeltaCRLIndicator %u" (c_to_str crit) indicator
  | Priv_key_period, (crit, period) ->
    Fmt.pf ppf "%sprivateKeyUsagePeriod %a" (c_to_str crit)
      pp_priv_key_usage_period period
  | Name_constraints, (crit, ncs) ->
    Fmt.pf ppf "%snameConstraints %a" (c_to_str crit) pp_name_constraints ncs
  | CRL_distribution_points, (crit, points) ->
    Fmt.pf ppf "%scRLDistributionPoints %a" (c_to_str crit)
      Fmt.(list ~sep:(any "; ") pp_distribution_point) points
  | Issuing_distribution_point, (crit, point) ->
    Fmt.pf ppf "%sissuingDistributionPoint %a" (c_to_str crit)
      pp_issuing_distribution_point point
  | Freshest_CRL, (crit, points) ->
    Fmt.pf ppf "%sfreshestCRL %a" (c_to_str crit)
      Fmt.(list ~sep:(any "; ") pp_distribution_point) points
  | Reason, (crit, reason) ->
    Fmt.pf ppf "%sreason %a" (c_to_str crit) pp_reason reason
  | Invalidity_date, (crit, date) ->
    Fmt.pf ppf "%sinvalidityDate %a" (c_to_str crit)
      (Ptime.pp_human
         ~frac_s:(if Ptime.Span.equal (Ptime.frac_s date) Ptime.Span.zero then 0 else 12)
         ~tz_offset_s:0 ()) date
  | Certificate_issuer, (crit, name) ->
    Fmt.pf ppf "%scertificateIssuer %a" (c_to_str crit) General_name.pp name
  | Policies, (crit, pols) ->
    Fmt.pf ppf "%spolicies %a" (c_to_str crit)
      Fmt.(list ~sep:(any "; ") pp_policy) pols
  | Unsupported oid, (crit, str) ->
    Fmt.pf ppf "%s%a" (c_to_str crit) custom (oid, str)

let default_pp_custom_extension ppf (oid, str) =
  Fmt.pf ppf "unsupported %a: %a" Asn.OID.pp oid Ohex.pp str

let pp_one k fmt =
  pp_one' default_pp_custom_extension k fmt

module ID = Registry.Cert_extn

let to_oid : type a. a k -> Asn.oid = function
  | Unsupported oid -> oid
  | Subject_alt_name -> ID.subject_alternative_name
  | Authority_key_id -> ID.authority_key_identifier
  | Subject_key_id -> ID.subject_key_identifier
  | Issuer_alt_name -> ID.issuer_alternative_name
  | Key_usage -> ID.key_usage
  | Ext_key_usage -> ID.extended_key_usage
  | Basic_constraints -> ID.basic_constraints
  | CRL_number -> ID.crl_number
  | Delta_CRL_indicator -> ID.delta_crl_indicator
  | Priv_key_period -> ID.private_key_usage_period
  | Name_constraints -> ID.name_constraints
  | CRL_distribution_points -> ID.crl_distribution_points
  | Issuing_distribution_point -> ID.issuing_distribution_point
  | Freshest_CRL -> ID.freshest_crl
  | Reason -> ID.reason_code
  | Invalidity_date -> ID.invalidity_date
  | Certificate_issuer -> ID.certificate_issuer
  | Policies -> ID.certificate_policies_2

let critical : type a. a k -> a -> bool = fun k v ->
  match k, v with
  | Unsupported _, (b, _) -> b
  | Subject_alt_name, (b, _) -> b
  | Authority_key_id, (b, _) -> b
  | Subject_key_id, (b, _) -> b
  | Issuer_alt_name, (b, _) -> b
  | Key_usage, (b, _) -> b
  | Ext_key_usage, (b, _) -> b
  | Basic_constraints, (b, _) -> b
  | CRL_number, (b, _) -> b
  | Delta_CRL_indicator, (b, _) -> b
  | Priv_key_period, (b, _) -> b
  | Name_constraints, (b, _) -> b
  | CRL_distribution_points, (b, _) -> b
  | Issuing_distribution_point, (b, _) -> b
  | Freshest_CRL, (b, _) -> b
  | Reason, (b, _) -> b
  | Invalidity_date, (b, _) -> b
  | Certificate_issuer, (b, _) -> b
  | Policies, (b, _) -> b

module K = struct
  type 'a t = 'a k

  let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
    let open Gmap.Order in
    match t, t' with
    | Subject_alt_name, Subject_alt_name -> Eq
    | Authority_key_id, Authority_key_id -> Eq
    | Subject_key_id, Subject_key_id -> Eq
    | Issuer_alt_name, Issuer_alt_name -> Eq
    | Key_usage, Key_usage -> Eq
    | Ext_key_usage, Ext_key_usage -> Eq
    | Basic_constraints, Basic_constraints -> Eq
    | CRL_number, CRL_number -> Eq
    | Delta_CRL_indicator, Delta_CRL_indicator -> Eq
    | Priv_key_period, Priv_key_period -> Eq
    | Name_constraints, Name_constraints -> Eq
    | CRL_distribution_points, CRL_distribution_points -> Eq
    | Issuing_distribution_point, Issuing_distribution_point -> Eq
    | Freshest_CRL, Freshest_CRL -> Eq
    | Reason, Reason -> Eq
    | Invalidity_date, Invalidity_date -> Eq
    | Certificate_issuer, Certificate_issuer -> Eq
    | Policies, Policies -> Eq
    | Unsupported oid, Unsupported oid' when Asn.OID.equal oid oid' -> Eq
    | a, b ->
      let r = Asn.OID.compare (to_oid a) (to_oid b) in
      if r < 0 then Lt else if r > 0 then Gt else
        (* A known constructor and Unsupported can name the same OID but do
           not have equal value types. Insertion rejects this alias below;
           lookup/removal still need a total, type-safe key comparison. *)
        match a, b with
        | Unsupported _, _ -> Gt
        | _, Unsupported _ -> Lt
        | _ -> assert false
end

let supported_oids = [
  ID.subject_alternative_name; ID.authority_key_identifier;
  ID.subject_key_identifier; ID.issuer_alternative_name; ID.key_usage;
  ID.extended_key_usage; ID.basic_constraints; ID.crl_number;
  ID.delta_crl_indicator; ID.private_key_usage_period; ID.name_constraints;
  ID.crl_distribution_points; ID.issuing_distribution_point; ID.freshest_crl;
  ID.reason_code; ID.invalidity_date; ID.certificate_issuer;
  ID.certificate_policies_2;
]

let validate_key : type a. a k -> unit = function
  | Unsupported oid when List.exists (Asn.OID.equal oid) supported_oids ->
    invalid_arg "Extension: a supported OID requires its typed constructor"
  | _ -> ()

let normalize_eku = function
  | `Other oid as original ->
    let open ID.Extended_usage in
    (match List.find_opt (fun (known, _) -> Asn.OID.equal oid known)
       [ any, `Any; server_auth, `Server_auth; client_auth, `Client_auth;
         code_signing, `Code_signing; email_protection, `Email_protection;
         ipsec_end_system, `Ipsec_end; ipsec_tunnel, `Ipsec_tunnel;
         ipsec_user, `Ipsec_user; time_stamping, `Time_stamping;
         ocsp_signing, `Ocsp_signing ] with
     | Some (_, usage) -> usage | None -> original)
  | usage -> usage

let normalize_value : type a. a k -> a -> a = fun key value ->
  match key, value with
  | Ext_key_usage, (critical, usages) -> critical, List.map normalize_eku usages
  | _ -> value

(* The Gmap.S API remains the key-sorted lookup view (including traversal and
   order-insensitive equal). The sequence order is separately authoritative:
   replacement retains its position; insertion appends; removal/filtering
   preserve survivor order; map retains order; merge/union retain surviving
   left keys then append surviving right-only keys in right order. Removing
   and re-adding a key appends it. Unsupported aliases of known OIDs are never
   insertable, even into an empty map. No extension payload DER is retained. *)
module Ordered : sig
  include Gmap.S with type 'a key = 'a k
  val ordered_bindings : t -> b list
  val equal_ordered : eq -> t -> t -> bool
end = struct
  module Lookup = Gmap.Make(K)
  type 'a key = 'a k
  type b = Lookup.b = B : 'a key * 'a -> b
  type packed_key = Key : 'a key -> packed_key
  type t = { index : Lookup.t; order : packed_key list }

  let empty = { index = Lookup.empty; order = [] }
  let is_empty t = Lookup.is_empty t.index
  let cardinal t = Lookup.cardinal t.index
  let mem k t = Lookup.mem k t.index
  let find k t = Lookup.find k t.index
  let get k t = Lookup.get k t.index

  let add k v t =
    validate_key k;
    let order = if mem k t then t.order else t.order @ [ Key k ] in
    { index = Lookup.add k (normalize_value k v) t.index; order }

  let singleton k v = add k v empty
  let add_unless_bound k v t =
    validate_key k;
    if mem k t then None else Some (add k v t)

  let keep_present index order =
    List.filter (fun (Key k) -> Lookup.mem k index) order

  let remove k t =
    let index = Lookup.remove k t.index in
    { index; order = keep_present index t.order }

  let update k f t =
    match f (find k t) with None -> remove k t | Some v -> add k v t

  let min_binding t = Lookup.min_binding t.index
  let max_binding t = Lookup.max_binding t.index
  let any_binding t = Lookup.any_binding t.index
  let bindings t = Lookup.bindings t.index
  let ordered_bindings t =
    List.map (fun (Key k) -> B (k, Lookup.get k t.index)) t.order

  type eq = Lookup.eq = { f : 'a. 'a key -> 'a -> 'a -> bool }
  let equal eq a b = Lookup.equal eq a.index b.index
  let equal_ordered eq a b =
    let same_key (Key a) (Key b) =
      match K.compare a b with Gmap.Order.Eq -> true | _ -> false
    in
    List.length a.order = List.length b.order &&
    List.for_all2 same_key a.order b.order && equal eq a b

  type mapper = Lookup.mapper = { f : 'a. 'a key -> 'a -> 'a }
  let map (f : mapper) t =
    { t with index = Lookup.map
        { f = (fun key value -> normalize_value key (f.f key value)) } t.index }
  let iter f t = Lookup.iter f t.index
  let fold f t acc = Lookup.fold f t.index acc
  let for_all f t = Lookup.for_all f t.index
  let exists f t = Lookup.exists f t.index
  let filter f t =
    let index = Lookup.filter f t.index in
    { index; order = keep_present index t.order }

  let combined_order index a b =
    keep_present index a.order @
    List.filter (fun (Key k) ->
        not (mem k a) && Lookup.mem k index) b.order

  type merger = Lookup.merger = {
    f : 'a. 'a key -> 'a option -> 'a option -> 'a option
  }
  let merge f a b =
    let index = Lookup.map { f = normalize_value } (Lookup.merge f a.index b.index) in
    { index; order = combined_order index a b }

  type unionee = Lookup.unionee = {
    f : 'a. 'a key -> 'a -> 'a -> 'a option
  }
  let union f a b =
    let index = Lookup.map { f = normalize_value } (Lookup.union f a.index b.index) in
    { index; order = combined_order index a b }
end

include Ordered

let pp' custom ppf m =
  iter (fun (B (k, v)) -> pp_one' custom k ppf v ; Fmt.sp ppf ()) m

let pp = pp' default_pp_custom_extension

let hostnames exts =
  match find Subject_alt_name exts with
  | None -> None
  | Some (_, names) ->
    match General_name.find DNS names with
    | None -> None
    | Some xs ->
      let names =
        List.fold_left (fun acc s ->
            match Host.host s with
            | Some (typ, hostname) -> Host.Set.add (typ, hostname) acc
            | None -> acc)
          Host.Set.empty xs
      in
      if Host.Set.is_empty names then None else Some names

let ips exts =
  match find Subject_alt_name exts with
  | None -> None
  | Some (_, names) ->
    match General_name.find IP names with
    | None -> None
    | Some xs ->
      let ips =
        List.fold_left (fun acc ip ->
          match
            match String.length ip with
            | 4 -> Result.map (fun ip -> Ipaddr.V4 ip) (Ipaddr.V4.of_octets ip)
            | 16 -> Result.map (fun ip -> Ipaddr.V6 ip) (Ipaddr.V6.of_octets ip)
            | _ -> Error (`Msg "unknown IP address kind")
          with
          | Ok ip -> Ipaddr.Set.add ip acc
          | Error _ -> acc)
        Ipaddr.Set.empty xs
      in
      if Ipaddr.Set.is_empty ips then None else Some ips

module Asn = struct
  open Asn.S
  open Asn_grammars

  let bool =
    let decode = function
      | "\000" -> false
      | "\255" -> true
      | _ -> parse_error "extension BOOLEAN must be one octet, 00 or ff"
    and encode value = if value then "\255" else "\000" in
    map ~random:Random.bool decode encode (implicit ~cls:`Universal 1 octet_string)

  let default_false label = function
    | None -> false
    | Some true -> true
    | Some false -> parse_error "%s: explicit DEFAULT FALSE" label

  let display_text : display_text Asn.t =
    map
      (function `C1 s -> `IA5 s | `C2 s -> `Visible s
              | `C3 s -> `BMP s | `C4 s -> `UTF8 s)
      (function `IA5 s -> `C1 s | `Visible s -> `C2 s
              | `BMP s -> `C3 s | `UTF8 s -> `C4 s)
    @@ choice4 ia5_string visible_string bmp_string utf8_string

  (* ASN.1 INTEGER contents are two's complement. Notice numbers have no
     machine-word bound; project them to genuine signed arbitrary integers. *)
  let notice_number =
    let decode octets =
      let n = Mirage_crypto_pk.Z_extra.of_octets_be octets in
      if Char.code octets.[0] land 0x80 = 0 then n
      else Z.sub n (Z.shift_left Z.one (8 * String.length octets))
    and encode n =
      let negative = Z.sign n < 0 in
      let bits = 1 + Z.numbits (if negative then Z.lognot n else n) in
      let size = max 1 ((bits + 7) / 8) in
      let n = if negative then Z.add n (Z.shift_left Z.one (8 * size)) else n in
      Mirage_crypto_pk.Z_extra.to_octets_be ~size n
    in
    map decode encode integer

  (* The upstream GeneralizedTime codec only has millisecond precision and
     pads fractions to three digits. Use its fixed universal tag, but model
     the contents as Ptime directly, with canonical DER decimal fractions.
     Sub-picosecond precision and leap seconds are explicitly unsupported;
     constructed Ptime values are never rounded or truncated. *)
  let generalized_time =
    let decode s =
      let n = String.length s in
      let bad () = parse_error "noncanonical extension GeneralizedTime" in
      let digits start len =
        for i = start to start + len - 1 do
          if s.[i] < '0' || s.[i] > '9' then bad ()
        done
      in
      if n < 15 || s.[n - 1] <> 'Z' then bad ();
      digits 0 14;
      let ps =
        if n = 15 then 0L else begin
          if s.[14] <> '.' || n < 17 || s.[n - 2] = '0' then bad ();
          let len = n - 16 in
          digits 15 len;
          if len > 12 then
            parse_error "unsupported sub-picosecond extension GeneralizedTime";
          let fraction = Int64.of_string (String.sub s 15 len) in
          let rec pad n value =
            if n = 0 then value else pad (n - 1) (Int64.mul value 10L)
          in
          pad (12 - len) fraction
        end
      in
      let number start len = int_of_string (String.sub s start len) in
      let date = number 0 4, number 4 2, number 6 2 in
      let hh, mm, ss = number 8 2, number 10 2, number 12 2 in
      if ss = 60 then parse_error "unsupported GeneralizedTime leap second";
      match Ptime.of_date_time (date, ((hh, mm, ss), 0)) with
      | None -> parse_error "invalid extension GeneralizedTime date"
      | Some t ->
        match Ptime.add_span t (Ptime.Span.v (0, ps)) with
        | Some t -> t
        | None -> parse_error "extension GeneralizedTime out of range"
    and encode t =
      let (y, m, d), ((hh, mm, ss), _) = Ptime.to_date_time ~tz_offset_s:0 t in
      let _, ps = Ptime.Span.to_d_ps (Ptime.frac_s t) in
      let fraction = if ps = 0L then "" else
          let digits = Printf.sprintf "%012Ld" ps in
          let rec trim n = if digits.[n - 1] = '0' then trim (n - 1) else n in
          "." ^ String.sub digits 0 (trim 12)
      in
      Printf.sprintf "%04d%02d%02d%02d%02d%02d%sZ" y m d hh mm ss fraction
    in
    map ~random:(fun () -> Asn.random Asn.S.generalized_time)
      decode encode (implicit ~cls:`Universal 24 ia5_string)

  module ID = Registry.Cert_extn

  let key_usage = Key_usage.asn

  let ext_key_usage =
    let open ID.Extended_usage in
    let f = case_of_oid [
      (any              , `Any             ) ;
      (server_auth      , `Server_auth     ) ;
      (client_auth      , `Client_auth     ) ;
      (code_signing     , `Code_signing    ) ;
      (email_protection , `Email_protection) ;
      (ipsec_end_system , `Ipsec_end       ) ;
      (ipsec_tunnel     , `Ipsec_tunnel    ) ;
      (ipsec_user       , `Ipsec_user      ) ;
      (time_stamping    , `Time_stamping   ) ;
      (ocsp_signing     , `Ocsp_signing    ) ]
      ~default:(fun oid -> `Other oid)
    and g = function
      | `Any              -> any
      | `Server_auth      -> server_auth
      | `Client_auth      -> client_auth
      | `Code_signing     -> code_signing
      | `Email_protection -> email_protection
      | `Ipsec_end        -> ipsec_end_system
      | `Ipsec_tunnel     -> ipsec_tunnel
      | `Ipsec_user       -> ipsec_user
      | `Time_stamping    -> time_stamping
      | `Ocsp_signing     -> ocsp_signing
      | `Other oid        -> oid
    in
    map (List.map f) (List.map g) @@ sequence_of oid

  (* cA is DEFAULT FALSE, but pathLen is OPTIONAL, not DEFAULT 0:
     in particular Some 0 must survive both projections. *)
  let basic_constraints =
    map (fun (a, b) -> (default_false "basicConstraints cA" a, b))
        (fun (a, b) -> ((if a = false then None else Some a), b))
    @@
    sequence2
      (optional ~label:"cA"      bool)
      (optional ~label:"pathLen" int)

  (* The issuer lookup view uses empty for absent. Reject present-empty
     GeneralNames before projecting away that invalid presence. Key identifier
     and serial options, including empty key identifiers, stay intact. *)
  let authority_key_id =
    map (fun (a, b, c) ->
        (match b with
         | Some issuer when General_name.is_empty issuer ->
           parse_error "empty authorityCertIssuer"
         | _ -> ());
        (a, Option.value ~default:General_name.empty b, c))
      (fun (a, b, c) ->
         (a, (if General_name.is_empty b then None else Some b), c))
    @@
    sequence3
      (optional ~label:"keyIdentifier"  @@ implicit 0 octet_string)
      (optional ~label:"authCertIssuer" @@ implicit 1 General_name.Asn.gen_names)
      (optional ~label:"authCertSN"     @@ implicit 2 serial)

  let priv_key_usage_period =
    let f = function
      | (Some t1, Some t2) -> `Interval (t1, t2)
      | (Some t1, None   ) -> `Not_before t1
      | (None   , Some t2) -> `Not_after  t2
      | _                  -> parse_error "empty PrivateKeyUsagePeriod"
    and g = function
      | `Interval (t1, t2) -> (Some t1, Some t2)
      | `Not_before t1     -> (Some t1, None   )
      | `Not_after  t2     -> (None   , Some t2) in
    map f g @@
    sequence2
      (optional ~label:"notBefore" @@ implicit 0 generalized_time)
      (optional ~label:"notAfter"  @@ implicit 1 generalized_time)

  (* minimum has DEFAULT 0; maximum is OPTIONAL and Some 0 is distinct from
     None. Reject explicit defaults and present-empty GeneralSubtrees before
     their projection collapses them to absence. *)
  let name_constraints =
    let subtree =
      map
        (fun (base, min, max) ->
           if min = Some 0 then parse_error "GeneralSubtree minimum: explicit DEFAULT 0";
           (base, Option.value ~default:0 min, max))
        (fun (base, min, max) -> (base, (if min = 0 then None else Some min), max))
      @@
      sequence3
        (required ~label:"base"       General_name.Asn.general_name)
        (optional ~label:"minimum" @@ implicit 0 int)
        (optional ~label:"maximum" @@ implicit 1 int)
    in
    map
      (fun (a, b) ->
         if a = Some [] || b = Some [] then parse_error "empty GeneralSubtrees";
         (Option.value ~default:[] a, Option.value ~default:[] b))
      (fun (a, b) -> ((if a = [] then None else Some a),
                      (if b = [] then None else Some b)))
    @@
    sequence2
      (optional ~label:"permittedSubtrees" @@ implicit 0 (sequence_of subtree))
      (optional ~label:"excludedSubtrees"  @@ implicit 1 (sequence_of subtree))

  let cert_policies =
    let open ID.Cert_policy in
    let notice_reference =
      map
        (fun (organization, notice_numbers) -> { organization; notice_numbers })
        (fun { organization; notice_numbers } -> organization, notice_numbers)
      @@ sequence2
        (required ~label:"organization" display_text)
        (required ~label:"numbers" (sequence_of notice_number))
    in
    let user_notice =
      map
        (fun (notice_ref, explicit_text) -> { notice_ref; explicit_text })
        (fun { notice_ref; explicit_text } -> notice_ref, explicit_text)
      @@ sequence2
        (optional ~label:"noticeRef" notice_reference)
        (optional ~label:"explicitText" display_text)
    in
    let qualifier_info =
      map
        (function
          | (oid, `C1 uri) when Asn.OID.equal oid cps -> `CPS_uri uri
          | (oid, `C2 notice) when Asn.OID.equal oid unotice -> `User_notice notice
          | (oid, _) -> parse_error "unsupported or mismatched policy qualifier %a" Asn.OID.pp oid)
        (function
          | `CPS_uri uri -> cps, `C1 uri
          | `User_notice notice -> unotice, `C2 notice)
      @@ sequence2
        (required ~label:"qualifierId" oid)
        (required ~label:"qualifier" (choice2 ia5_string user_notice))
    in
    sequence_of @@
    map
      (fun (policy_identifier, policy_qualifiers) -> { policy_identifier; policy_qualifiers })
      (fun { policy_identifier; policy_qualifiers } -> policy_identifier, policy_qualifiers)
    @@ sequence2
      (required ~label:"policyIdentifier" oid)
      (optional ~label:"policyQualifiers" (sequence_of qualifier_info))

  let reason = Reason_flags.asn

  let reason_enumerated : reason Asn.t =
    enumerated reason_of_int reason_to_int

  (* nameRelativeToCRLIssuer is one RDN (SET OF AVAs), not Name (SEQUENCE OF
     RDNs). Reuse the same typed attributes and string choices as names without
     accepting the old, incorrectly nested wire shape. *)
  let relative_distinguished_name = Distinguished_name.Asn.relative_distinguished_name

  let distribution_point_name =
    map (function | `C1 s -> `Full s | `C2 s -> `Relative s)
      (function | `Full s -> `C1 s | `Relative s -> `C2 s)
    @@
    choice2
      (implicit 0 General_name.Asn.gen_names)
      (implicit 1 relative_distinguished_name)

  let distribution_point =
    sequence3
      (optional ~label:"distributionPoint" @@ explicit 0 distribution_point_name)
      (optional ~label:"reasons"           @@ implicit 1 reason)
      (optional ~label:"cRLIssuer"         @@ implicit 2 General_name.Asn.gen_names)

  let crl_distribution_points = sequence_of distribution_point

  let issuing_distribution_point =
    map
      (fun (a, b, c, d, e, f) ->
        (a,
         default_false "onlyContainsUserCerts" b,
         default_false "onlyContainsCACerts" c,
         d,
         default_false "indirectCRL" e,
         default_false "onlyContainsAttributeCerts" f))
      (fun (a, b, c, d, e, f) ->
         (a,
          (if b = false then None else Some b),
          (if c = false then None else Some c),
          d,
          (if e = false then None else Some e),
          (if f = false then None else Some f)))
    @@
    sequence6
      (optional ~label:"distributionPoint"          @@ explicit 0 distribution_point_name)
      (optional ~label:"onlyContainsUserCerts"      @@ implicit 1 bool)
      (optional ~label:"onlyContainsCACerts"        @@ implicit 2 bool)
      (optional ~label:"onlySomeReasons"            @@ implicit 3 reason)
      (optional ~label:"indirectCRL"                @@ implicit 4 bool)
      (optional ~label:"onlyContainsAttributeCerts" @@ implicit 5 bool)

  let crl_reason = reason_enumerated

  let gen_names_of_str, gen_names_to_str       = project_exn General_name.Asn.gen_names
  and auth_key_id_of_str, auth_key_id_to_str   = project_exn authority_key_id
  and subj_key_id_of_str, subj_key_id_to_str   = project_exn octet_string
  and key_usage_of_str, key_usage_to_str       = project_exn key_usage
  and e_key_usage_of_str, e_key_usage_to_str   = project_exn ext_key_usage
  and basic_constr_of_str, basic_constr_to_str = project_exn basic_constraints
  and pr_key_peri_of_str, pr_key_peri_to_str   = project_exn priv_key_usage_period
  and name_con_of_str, name_con_to_str         = project_exn name_constraints
  and crl_distrib_of_str, crl_distrib_to_str   = project_exn crl_distribution_points
  and cert_pol_of_str, cert_pol_to_str         = project_exn cert_policies
  and int_of_str, int_to_str                   = project_exn int
  and issuing_dp_of_str, issuing_dp_to_str     = project_exn issuing_distribution_point
  and crl_reason_of_str, crl_reason_to_str     = project_exn crl_reason
  and time_of_str, time_to_str                 = project_exn generalized_time

  let reparse_extension_exn crit = case_of_oid_f [
      (ID.subject_alternative_name,
       fun cs -> B (Subject_alt_name, (crit, gen_names_of_str cs))) ;
      (ID.issuer_alternative_name,
       fun cs -> B (Issuer_alt_name, (crit, gen_names_of_str cs))) ;
      (ID.authority_key_identifier,
       fun cs -> B (Authority_key_id, (crit, auth_key_id_of_str cs))) ;
      (ID.subject_key_identifier,
       fun cs -> B (Subject_key_id, (crit, subj_key_id_of_str cs))) ;
      (ID.key_usage,
       fun cs -> B (Key_usage, (crit, key_usage_of_str cs))) ;
      (ID.basic_constraints,
       fun cs -> B (Basic_constraints, (crit, basic_constr_of_str cs))) ;
      (ID.crl_number,
       fun cs -> B (CRL_number, (crit, int_of_str cs))) ;
      (ID.delta_crl_indicator,
       fun cs -> B (Delta_CRL_indicator, (crit, int_of_str cs))) ;
      (ID.extended_key_usage,
       fun cs -> B (Ext_key_usage, (crit, e_key_usage_of_str cs))) ;
      (ID.private_key_usage_period,
       fun cs -> B (Priv_key_period, (crit, pr_key_peri_of_str cs))) ;
      (ID.name_constraints,
       fun cs -> B (Name_constraints, (crit, name_con_of_str cs))) ;
      (ID.crl_distribution_points,
       fun cs -> B (CRL_distribution_points, (crit, crl_distrib_of_str cs))) ;
      (ID.issuing_distribution_point,
       fun cs -> B (Issuing_distribution_point, (crit, issuing_dp_of_str cs))) ;
      (ID.freshest_crl,
       fun cs -> B (Freshest_CRL, (crit, crl_distrib_of_str cs))) ;
      (ID.reason_code,
       fun cs -> B (Reason, (crit, crl_reason_of_str cs))) ;
      (ID.invalidity_date,
       fun cs -> B (Invalidity_date, (crit, time_of_str cs))) ;
      (ID.certificate_issuer,
       fun cs -> B (Certificate_issuer, (crit, gen_names_of_str cs))) ;
      (ID.certificate_policies_2,
       fun cs -> B (Policies, (crit, cert_pol_of_str cs)))
    ]
      ~default:(fun oid -> fun cs -> B (Unsupported oid, (crit, cs)))

  let unparse_extension (B (k, v)) =
    validate_key k;
    let v' = match k, v with
      | Subject_alt_name, (_, x) -> gen_names_to_str x
      | Issuer_alt_name, (_, x) -> gen_names_to_str x
      | Authority_key_id, (_, x) -> auth_key_id_to_str x
      | Subject_key_id, (_, x) -> subj_key_id_to_str  x
      | Key_usage, (_, x) -> key_usage_to_str x
      | Basic_constraints, (_, x) -> basic_constr_to_str x
      | CRL_number, (_, x) -> int_to_str x
      | Delta_CRL_indicator, (_, x) -> int_to_str x
      | Ext_key_usage, (_, x) -> e_key_usage_to_str x
      | Priv_key_period, (_, x) -> pr_key_peri_to_str x
      | Name_constraints, (_, x) -> name_con_to_str x
      | CRL_distribution_points, (_, x) -> crl_distrib_to_str x
      | Issuing_distribution_point, (_, x) -> issuing_dp_to_str x
      | Freshest_CRL, (_, x) -> crl_distrib_to_str x
      | Reason, (_, x) -> crl_reason_to_str x
      | Invalidity_date, (_, x) -> time_to_str x
      | Certificate_issuer, (_, x) -> gen_names_to_str x
      | Policies, (_, x) -> cert_pol_to_str x
      | Unsupported _, (_, x) -> x
    in
    to_oid k, critical k v, v'

  (* Noncanonical defaults and named bit lists are rejected by their component
     decoders, including when certificates are embedded in another grammar.
     Required sequence payloads and OPTIONAL values without defaults keep
     their order and presence. Duplicate OIDs reject, never overwrite. *)
  let extensions_der =
    let extension =
      let f (oid, crit, cs) =
        reparse_extension_exn (default_false "extension critical" crit) (oid, cs)
      and g b =
        let oid, crit, cs = unparse_extension b in
        (oid, (if crit = false then None else Some crit), cs)
      in
      map f g @@
      sequence3
        (required ~label:"id"       oid)
        (optional ~label:"critical" bool) (* default false *)
        (required ~label:"value"    octet_string)
    in
    let f exts =
      List.fold_left (fun map (B (k, v)) ->
          match add_unless_bound k v map with
          | None -> parse_error "%a already bound" (pp_one k) v
          | Some b -> b)
        empty exts
    and g map = ordered_bindings map
    in
    map f g @@ sequence_of extension
end
