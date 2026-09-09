(** ASN.1 BIT STRING values, including their exact length in bits. *)
type t

(** Rejects a length inconsistent with the octet count, or nonzero padding. *)
val create : bit_length:int -> string -> (t, [> `Msg of string ]) result
val of_octets : string -> t
val octets : t -> string
val bit_length : t -> int
val asn : t Asn.t
