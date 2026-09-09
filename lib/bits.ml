type t = { octets : string; bit_length : int }

let octets t = t.octets
let bit_length t = t.bit_length

let create ~bit_length octets =
  let length = String.length octets in
  if bit_length < 0 || bit_length / 8 + (if bit_length mod 8 = 0 then 0 else 1) <> length then
    Error (`Msg "BIT STRING length does not match its octets")
  else
    let unused = (8 - bit_length mod 8) mod 8 in
    if length > 0 && String.get_uint8 octets (length - 1) land ((1 lsl unused) - 1) <> 0 then
      Error (`Msg "BIT STRING has nonzero padding")
    else
      Ok { octets; bit_length }

let of_octets octets = { octets; bit_length = 8 * String.length octets }

let of_array bits =
  let bit_length = Array.length bits in
  let octets = Bytes.make ((bit_length + 7) / 8) '\000' in
  Array.iteri (fun i bit ->
      if bit then
        Bytes.set_uint8 octets (i / 8)
          (Bytes.get_uint8 octets (i / 8) lor (1 lsl (7 - i mod 8)))) bits;
  { octets = Bytes.to_string octets; bit_length }

let asn =
  let decode contents =
    let length = String.length contents in
    if length = 0 then Asn.S.parse_error "BIT STRING has no unused-bit count";
    let unused = String.get_uint8 contents 0 in
    if unused > 7 then Asn.S.parse_error "BIT STRING has invalid unused-bit count";
    let octets = String.sub contents 1 (length - 1) in
    match create ~bit_length:(8 * (length - 1) - unused) octets with
    | Ok bits -> bits
    | Error (`Msg msg) -> Asn.S.parse_error "%s" msg
  and encode { octets; bit_length } =
    String.make 1 (Char.chr ((8 - bit_length mod 8) mod 8)) ^ octets
  in
  (* The BIT STRING primitive masks padding before projecting to a bool array.
     Validate the contents before that information can be lost. *)
  Asn.S.map ~random:(fun () -> of_array (Asn.random Asn.S.bit_string))
    decode encode Asn.S.(implicit ~cls:`Universal 3 octet_string)
