type t = Z.t

let is_negative n = Z.sign n < 0

let content_size n =
  let bits = 1 + Z.numbits (if is_negative n then Z.lognot n else n) in
  max 1 ((bits + 7) / 8)

let of_z n =
  if content_size n > 20 then Error (`Msg "serial exceeds 20 octets") else Ok n

let to_z n = n

let valid_content s =
  let n = String.length s in
  if n = 0 then Error (`Msg "empty serial number")
  else if n > 20 then Error (`Msg "serial exceeds 20 octets")
  else if n > 1 &&
          ((String.get_uint8 s 0 = 0 && String.get_uint8 s 1 < 128) ||
           (String.get_uint8 s 0 = 255 && String.get_uint8 s 1 >= 128)) then
    Error (`Msg "serial has redundant sign octets")
  else Ok ()

let of_content s =
  match valid_content s with
  | Error _ as error -> error
  | Ok () ->
    let n = Mirage_crypto_pk.Z_extra.of_octets_be s in
    if String.get_uint8 s 0 < 128 then Ok n
    else Ok (Z.sub n (Z.shift_left Z.one (8 * String.length s)))

let to_content n =
  let size = content_size n in
  let n = if is_negative n then Z.add n (Z.shift_left Z.one (8 * size)) else n in
  Mirage_crypto_pk.Z_extra.to_octets_be ~size n

let equal = Z.equal
let compare = Z.compare
let of_int = Z.of_int

let asn =
  Asn.S.map
    (fun s -> match of_content s with
       | Ok n -> n
       | Error (`Msg msg) -> Asn.S.parse_error "%s" msg)
    to_content Asn.S.integer
