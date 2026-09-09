(** Signed integers whose canonical ASN.1 INTEGER content occupies at most
    20 octets. Zero and negative serial numbers are supported. *)
type t

val of_z : Z.t -> (t, [> `Msg of string ]) result
val to_z : t -> Z.t

(** Rejects empty, redundant-sign and overlong INTEGER content. *)
val of_content : string -> (t, [> `Msg of string ]) result

(** Canonical signed two's-complement INTEGER content, without tag or length. *)
val to_content : t -> string
val of_int : int -> t
val is_negative : t -> bool
val equal : t -> t -> bool
val compare : t -> t -> int
val asn : t Asn.t
