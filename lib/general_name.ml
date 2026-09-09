module Other_value = struct
  (* Contents octets, not transcoded text. Empty strings remain distinct from
     NULL, and UTF8String remains distinct from IA5String for every OID. *)
  type t = UTF8 of string | IA5 of string | Null

  let equal a b = match a, b with
    | UTF8 a, UTF8 b | IA5 a, IA5 b -> String.equal a b
    | Null, Null -> true
    | _ -> false

  let pp ppf = function
    | UTF8 s -> Fmt.pf ppf "UTF8 %S" s
    | IA5 s -> Fmt.pf ppf "IA5 %S" s
    | Null -> Fmt.string ppf "NULL"
end

module Encoded_string = Distinguished_name.Encoded_string

type _ k =
  | Other : Asn.oid -> Other_value.t list k
  | Rfc_822 : string list k
  | DNS : string list k
  | X400_address : unit k
  | Directory : Distinguished_name.t list k
  | EDI_party : (Encoded_string.t option * Encoded_string.t) list k
  | URI : string list k
  | IP : string list k
  | Registered_id : Asn.oid list k

module K = struct
  type 'a t = 'a k

  let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
    let open Gmap.Order in
    match t, t' with
    | Rfc_822, Rfc_822 -> Eq | Rfc_822, _ -> Lt | _, Rfc_822 -> Gt
    | DNS, DNS -> Eq | DNS, _ -> Lt | _, DNS -> Gt
    | X400_address, X400_address -> Eq | X400_address, _ -> Lt | _, X400_address -> Gt
    | Directory, Directory -> Eq | Directory, _ -> Lt | _, Directory -> Gt
    | EDI_party, EDI_party -> Eq | EDI_party, _ -> Lt | _, EDI_party -> Gt
    | URI, URI -> Eq | URI, _ -> Lt | _, URI -> Gt
    | IP, IP -> Eq | IP, _ -> Lt | _, IP -> Gt
    | Registered_id, Registered_id -> Eq | Registered_id, _ -> Lt | _, Registered_id -> Gt
    | Other a, Other b -> match Asn.OID.compare a b with
      | 0 -> Eq
      | x when x < 0 -> Lt
      | _ -> Gt
end

module View = Gmap.Make(K)
type 'a key = 'a k
type b = View.b = B : 'a key * 'a -> b

(* [ordered] is authoritative for encoding, one binding per GeneralName. The
   grouped map is only a lookup view. In particular, it cannot express either
   interleaving between keys or the multiplicity of the legacy NULL X400
   placeholder. Empty list values are normalized to absence at every ingress,
   so the lookup view never contains a binding with no encoded occurrence. *)
type t = { ordered : b list; view : View.t }

let merge_values : type a. a k -> a -> a -> a = fun k v v' ->
  match k, v, v' with
  | Other _, a, b -> a @ b
  | Registered_id, a, b -> a @ b
  | IP, a, b -> a @ b
  | URI, a, b -> a @ b
  | EDI_party, a, b -> a @ b
  | Directory, a, b -> a @ b
  | X400_address, (), () -> ()
  | DNS, a, b -> a @ b
  | Rfc_822, a, b -> a @ b

let split : type a. a k -> a -> b list = fun k v ->
  match k, v with
  | Other oid, xs -> List.map (fun x -> B (Other oid, [ x ])) xs
  | Rfc_822, xs -> List.map (fun x -> B (Rfc_822, [ x ])) xs
  | DNS, xs -> List.map (fun x -> B (DNS, [ x ])) xs
  | X400_address, () -> [ B (X400_address, ()) ]
  | Directory, xs -> List.map (fun x -> B (Directory, [ x ])) xs
  | EDI_party, xs -> List.map (fun x -> B (EDI_party, [ x ])) xs
  | URI, xs -> List.map (fun x -> B (URI, [ x ])) xs
  | IP, xs -> List.map (fun x -> B (IP, [ x ])) xs
  | Registered_id, xs -> List.map (fun x -> B (Registered_id, [ x ])) xs

let has_key : type a. a k -> b -> bool = fun k (B (k', _)) -> match K.compare k k' with
  | Gmap.Order.Eq -> true
  | _ -> false

let entries t = t.ordered

let of_entries ordered =
  let view = List.fold_left (fun view (B (k, v)) ->
      (match split k v with
       | [ _ ] -> ()
       | _ -> invalid_arg "General_name.of_entries: expected one name per entry");
      let v = match View.find k view with
        | None -> v
        | Some previous -> merge_values k previous v
      in
      View.add k v view) View.empty ordered
  in
  { ordered; view }

let empty = { ordered = []; view = View.empty }
let singleton k v = of_entries (split k v)
let is_empty t = View.is_empty t.view
let cardinal t = View.cardinal t.view
let mem k t = View.mem k t.view
let find k t = View.find k t.view
let get k t = View.get k t.view
let bindings t = View.bindings t.view
let min_binding t = View.min_binding t.view
let max_binding t = View.max_binding t.view
let any_binding t = View.any_binding t.view

(* Replace values at their existing occurrence positions. If the new list is
   longer, append its surplus at the final occurrence of the key; a new key
   goes at the end. Other keys never move relative to one another. *)
let replace_entries k fresh ordered =
  let count = List.fold_left (fun n b -> if has_key k b then n + 1 else n) 0 ordered in
  let rec go count fresh = function
    | [] -> fresh
    | b :: bs when has_key k b ->
      if count = 1 then fresh @ bs else
        (match fresh with
         | [] -> go (count - 1) [] bs
         | x :: xs -> x :: go (count - 1) xs bs)
    | b :: bs -> b :: go count fresh bs
  in
  go count fresh ordered

let replacement : type a. a k -> a -> t -> b list = fun k v t ->
  match k, v with
  | X400_address, () ->
    (* Replacing an unchanged unit-valued view must not erase occurrences. *)
    (match List.filter (has_key k) t.ordered with
     | [] -> split k v
     | xs -> xs)
  | _ -> split k v

let add k v t =
  let fresh = replacement k v t in
  { ordered = replace_entries k fresh t.ordered;
    view = if fresh = [] then View.remove k t.view else View.add k v t.view }

let remove k t =
  { ordered = List.filter (fun b -> not (has_key k b)) t.ordered;
    view = View.remove k t.view }

let add_unless_bound k v t = if mem k t then None else Some (add k v t)
let update k f t = match f (find k t) with
  | None -> remove k t
  | Some v -> add k v t

let iter f t = View.iter f t.view
let fold f t acc = View.fold f t.view acc
let for_all f t = View.for_all f t.view
let exists f t = View.exists f t.view

type eq = View.eq = { f : 'a. 'a key -> 'a -> 'a -> bool }
let equal eq a b = View.equal eq a.view b.view

(* Reconcile a map transformation with its ordered template, rather than
   flattening sorted map bindings back into a GeneralNames SEQUENCE. *)
let with_view template view =
  let t = View.fold (fun (B (k, _)) t ->
      match View.find k view with
      | None -> remove k t
      | Some v -> add k v t) template.view template
  in
  View.fold (fun (B (k, v)) t ->
      if mem k t then t else add k v t) view t

type mapper = View.mapper = { f : 'a. 'a key -> 'a -> 'a }
let map f t = with_view t (View.map f t.view)
let filter f t = with_view t (View.filter f t.view)

(* Binary map operations take positions from the left input, followed by the
   right input's keys absent on the left. The callback determines grouped
   values; use [of_entries] when exact occurrence placement is required. *)
let merge_template a b =
  let right_only = List.filter (fun (B (k, _)) -> not (mem k a)) b.ordered in
  let view = View.fold (fun (B (k, v)) view ->
      if View.mem k view then view else View.add k v view) b.view a.view
  in
  { ordered = a.ordered @ right_only; view }

type merger = View.merger = { f : 'a. 'a key -> 'a option -> 'a option -> 'a option }
let merge f a b = with_view (merge_template a b) (View.merge f a.view b.view)

type unionee = View.unionee = { f : 'a. 'a key -> 'a -> 'a -> 'a option }
let union f a b = with_view (merge_template a b) (View.union f a.view b.view)

let equal_list f a b = List.length a = List.length b && List.for_all2 f a b

let equal_value : type a. a k -> a -> a -> bool = fun k a b ->
  match k, a, b with
  | Other _, a, b -> equal_list Other_value.equal a b
  | Rfc_822, a, b -> equal_list String.equal a b
  | DNS, a, b -> equal_list String.equal a b
  | X400_address, (), () -> true
  | Directory, a, b -> equal_list Distinguished_name.equal_representation a b
  | EDI_party, a, b ->
    equal_list (fun (assigner, party) (assigner', party') ->
        Option.equal Encoded_string.equal assigner assigner' &&
        Encoded_string.equal party party') a b
  | URI, a, b -> equal_list String.equal a b
  | IP, a, b -> equal_list String.equal a b
  | Registered_id, a, b -> equal_list Asn.OID.equal a b

let equal_entry (B (k, v)) (B (k', v')) = match K.compare k k' with
  | Gmap.Order.Eq -> equal_value k v v'
  | _ -> false

let equal_representation a b = equal_list equal_entry a.ordered b.ordered

let pp_k : type a. a k -> Format.formatter -> a -> unit = fun k ppf v ->
  let pp_strs = Fmt.(list ~sep:(any "; ") string) in
  match k, v with
  | Rfc_822, x -> Fmt.pf ppf "rfc822 %a" pp_strs x
  | DNS, x -> Fmt.pf ppf "dns %a" pp_strs x
  | X400_address, () -> Fmt.string ppf "x400 NULL placeholder (not ORAddress)"
  | Directory, x ->
    Fmt.pf ppf "directory %a"
      Fmt.(list ~sep:(any "; ") Distinguished_name.pp) x
  | EDI_party, xs ->
    Fmt.pf ppf "edi party %a"
      Fmt.(list ~sep:(any "; ")
               (pair ~sep:(any ", ")
                  (option ~none:(any "") Encoded_string.pp) Encoded_string.pp)) xs
  | URI, x -> Fmt.pf ppf "uri %a" pp_strs x
  | IP, x -> Fmt.pf ppf "ip %a" Fmt.(list ~sep:(any ";") (fmt "%S")) x
  | Registered_id, x ->
    Fmt.pf ppf "registered id %a" Fmt.(list ~sep:(any ";") Asn.OID.pp) x
  | Other oid, x ->
    Fmt.pf ppf "other %a: %a" Asn.OID.pp oid
      Fmt.(list ~sep:(any "; ") Other_value.pp) x

let pp ppf m = iter (fun (B (k, v)) -> pp_k k ppf v; Fmt.sp ppf ()) m

module Asn = struct
  open Asn.S

  let another_name =
    let f = function
      | oid, `C1 n -> oid, Other_value.UTF8 n
      | oid, `C2 n -> oid, Other_value.IA5 n
      | oid, `C3 () -> oid, Other_value.Null
    and g = function
      | oid, Other_value.UTF8 n -> oid, `C1 n
      | oid, Other_value.IA5 n -> oid, `C2 n
      | oid, Other_value.Null -> oid, `C3 ()
    in
    map f g @@ sequence2
      (required ~label:"type-id" oid)
      (required ~label:"value" @@ explicit 0 (choice3 utf8_string ia5_string null))

  (* Compatibility with the historical NULL placeholder only. A real
     ORAddress is not supported, and is rejected by this grammar. *)
  let or_address = null

  let edi_party_name =
    let dir_name = Distinguished_name.Asn.directory_name in
    sequence2
      (optional ~label:"nameAssigner" @@ implicit 0 dir_name)
      (required ~label:"partyName" @@ implicit 1 dir_name)

  let general_name =
    let f = function
      | `C1 (`C1 (oid, x)) -> B (Other oid, [ x ])
      | `C1 (`C2 x) -> B (Rfc_822, [ x ])
      | `C1 (`C3 x) -> B (DNS, [ x ])
      | `C1 (`C4 ()) -> B (X400_address, ())
      | `C1 (`C5 x) -> B (Directory, [ x ])
      | `C1 (`C6 x) -> B (EDI_party, [ x ])
      | `C2 (`C1 x) -> B (URI, [ x ])
      | `C2 (`C2 x) -> B (IP, [ x ])
      | `C2 (`C3 x) -> B (Registered_id, [ x ])
    and g (B (k, v)) = match k, v with
      | Other oid, [ x ] -> `C1 (`C1 (oid, x))
      | Rfc_822, [ x ] -> `C1 (`C2 x)
      | DNS, [ x ] -> `C1 (`C3 x)
      | X400_address, () -> `C1 (`C4 ())
      | Directory, [ x ] -> `C1 (`C5 x)
      | EDI_party, [ x ] -> `C1 (`C6 x)
      | URI, [ x ] -> `C2 (`C1 x)
      | IP, [ x ] -> `C2 (`C2 x)
      | Registered_id, [ x ] -> `C2 (`C3 x)
      | _ -> Asn.S.error (`Parse "bad general name")
    in
    map f g @@
    choice2
      (choice6
         (implicit 0 another_name)
         (implicit 1 ia5_string)
         (implicit 2 ia5_string)
         (implicit 3 or_address)
         (explicit 4 Distinguished_name.Asn.name)
         (implicit 5 edi_party_name))
      (choice3
         (implicit 6 ia5_string)
         (implicit 7 octet_string)
         (implicit 8 oid))

  let gen_names = map of_entries entries @@ sequence_of general_name
end
