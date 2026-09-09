(** Whole-second certificate times with their ASN.1 time choice preserved. *)
type encoding = [ `UTC | `Generalized ]
type t

(** Defaults to UTC only for years 1950 through 2049. Rejects fractional seconds
    and UTC values outside that range. Explicit GeneralizedTime is preserved. *)
val of_ptime : ?encoding:encoding -> Ptime.t -> (t, [> `Msg of string ]) result
val time : t -> Ptime.t
val encoding : t -> encoding
val asn : t Asn.t
