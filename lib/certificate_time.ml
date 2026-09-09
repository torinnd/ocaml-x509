type encoding = [ `UTC | `Generalized ]
type t = { time : Ptime.t; encoding : encoding }

let time t = t.time
let encoding t = t.encoding

let of_ptime ?encoding time =
  let year, _, _ = Ptime.to_date time in
  let utc_range = year >= 1950 && year < 2050 in
  let encoding = match encoding with
    | Some encoding -> encoding
    | None -> if utc_range then `UTC else `Generalized
  in
  if not Ptime.Span.(equal zero (Ptime.frac_s time)) then
    Error (`Msg "certificate time has fractional seconds")
  else if encoding = `UTC && not utc_range then
    Error (`Msg "certificate UTCTime is outside 1950..2049")
  else
    Ok { time; encoding }

let asn =
  let f choice =
    let contents, encoding, year_digits = match choice with
      | `C1 contents -> contents, `UTC, 2
      | `C2 contents -> contents, `Generalized, 4
    in
    let length = year_digits + 11 in
    if String.length contents <> length || contents.[length - 1] <> 'Z' then
      Asn.S.parse_error "certificate time must be canonical whole-second Z form";
    for i = 0 to length - 2 do
      if contents.[i] < '0' || contents.[i] > '9' then
        Asn.S.parse_error "certificate time contains a nondecimal digit"
    done;
    let number start len = int_of_string (String.sub contents start len) in
    let year = number 0 year_digits in
    let year = match encoding with
      | `UTC -> if year < 50 then 2000 + year else 1900 + year
      | `Generalized -> year
    in
    let month, day = number year_digits 2, number (year_digits + 2) 2 in
    let hh, mm, ss =
      number (year_digits + 4) 2, number (year_digits + 6) 2,
      number (year_digits + 8) 2
    in
    if ss = 60 then Asn.S.parse_error "unsupported certificate time leap second";
    match Ptime.of_date_time ((year, month, day), ((hh, mm, ss), 0)) with
    | None -> Asn.S.parse_error "invalid certificate time date"
    | Some time -> { time; encoding }
  and g { time; encoding } =
    let (year, month, day), ((hh, mm, ss), _) =
      Ptime.to_date_time ~tz_offset_s:0 time
    in
    match encoding with
    | `UTC -> `C1 (Printf.sprintf "%02d%02d%02d%02d%02d%02dZ"
                     (year mod 100) month day hh mm ss)
    | `Generalized -> `C2 (Printf.sprintf "%04d%02d%02d%02d%02d%02dZ"
                            year month day hh mm ss)
  in
  let random () =
    let time, encoding =
      if Random.bool () then Asn.random Asn.S.utc_time, `UTC
      else Asn.random Asn.S.generalized_time, `Generalized
    in
    { time = Ptime.truncate ~frac_s:0 time; encoding }
  in
  (* Time primitives normalize lexical variants. Check contents transiently;
     only the whole-second value and its ASN.1 choice belong in the model. *)
  Asn.S.(map ~random f g (choice2
    (implicit ~cls:`Universal 23 ia5_string)
    (implicit ~cls:`Universal 24 ia5_string)))
