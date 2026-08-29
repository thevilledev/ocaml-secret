(* Leak census: how many copies of a key exist in process memory, by
   scenario. The needle lives only in a Secret.t; the scanner compares from
   that memory directly. Output is a table; a few assertions guard the
   properties the library promises. *)

external scan : Secret.t -> Secret.t array -> int -> int array = "leak_scan"
external supported : unit -> bool = "leak_scan_supported"

let key_len = 32
let record = 1024

let encrypt_traffic ~total key =
  (* drive AES-GCM over [total] bytes in 1 KiB records *)
  let nonce = Bytes.make 12 '\000' in
  let msg = String.make record 'm' in
  for i = 0 to (total / record) - 1 do
    Bytes.set nonce 0 (Char.chr (i land 0xff));
    Bytes.set nonce 1 (Char.chr ((i lsr 8) land 0xff));
    Bytes.set nonce 2 (Char.chr ((i lsr 16) land 0xff));
    let ct =
      Mirage_crypto.AES.GCM.authenticate_encrypt ~key
        ~nonce:(Bytes.to_string nonce) msg
    in
    ignore (Sys.opaque_identity ct)
  done

let total hits = hits.(0) + hits.(1) + hits.(2)

let report name (v, w) =
  Printf.printf
    "  %-44s verbatim: minor=%-2d stack=%-2d other=%-2d | bswap32: minor=%-2d \
     stack=%-2d other=%-2d\n\
     %!"
    name v.(0) v.(1) v.(2) w.(0) w.(1) w.(2)

let scan_now ~reference ~excl name =
  let ex = Array.of_list excl in
  let v = scan reference ex 0 and w = scan reference ex 1 in
  report name (v, w);
  (v, w)

let both (v, w) = total v + total w
let verbatim (v, _) = total v

(* One scenario: make a key from a fresh working secret, run traffic, then
   observe the residue at each step. Returns (live, dropped, scrubbed, destroyed). *)
let scenario ~reference ~title ~traffic ~mk_key =
  Printf.printf "%s (%d MiB of AES-GCM traffic)\n" title
    (traffic / (1024 * 1024));
  let w = Secret.copy reference in
  let excl = [ w ] in
  let live =
    let key = mk_key w in
    encrypt_traffic ~total:traffic key;
    let h = scan_now ~reference ~excl "key live" in
    ignore (Sys.opaque_identity key);
    h
  in
  Gc.full_major ();
  let dropped = scan_now ~reference ~excl "key dropped + Gc.full_major" in
  Secret.Gc.scrub_minor_heap ();
  let scrubbed = scan_now ~reference ~excl "+ Secret.Gc.scrub_minor_heap" in
  Secret.destroy w;
  let destroyed =
    scan_now ~reference ~excl "+ Secret.destroy (working secret)"
  in
  print_newline ();
  (live, dropped, scrubbed, destroyed)

let mib n = n * 1024 * 1024

let () =
  if not (supported ()) then (
    print_endline "leak scan: unsupported platform, skipped";
    exit 0);
  (* The census checks are calibrated against 64-bit OCaml heap layouts and
     key-schedule lifetimes. The scanner itself works on 32-bit Linux, but the
     expected stale-copy counts do not transfer: keep this a regression gate
     only where its baselines are meaningful. *)
  if Sys.word_size <> 64 then (
    print_endline "leak scan: 64-bit calibration unavailable, skipped";
    exit 0);
  let reference = Secret.random key_len in
  print_endline
    "Leak census: copies of a 32-byte AES-256 key (its 24-byte tail) in \
     process memory.";
  print_endline
    "verbatim = as-is; bswap32 = byte-swapped per 32-bit word (how the generic \
     AES key";
  print_endline
    "schedule stores the key). Copies inside Secret.t payloads are excluded.\n";
  let h0 = scan_now ~reference ~excl:[] "0. key held only in Secret.t" in
  print_newline ();
  let a_small =
    scenario ~reference ~traffic:(mib 1)
      ~title:
        "A. view: AES.GCM.of_secret (Secret.Unsafe.string_view k), schedule \
         dies young" ~mk_key:(fun w ->
        Mirage_crypto.AES.GCM.of_secret (Secret.Unsafe.string_view w))
  in
  let a_large =
    scenario ~reference ~traffic:(mib 8)
      ~title:"A'. view: same, schedule promoted to the major heap"
      ~mk_key:(fun w ->
        Mirage_crypto.AES.GCM.of_secret (Secret.Unsafe.string_view w))
  in
  let b =
    scenario ~reference ~traffic:(mib 8)
      ~title:"B. baseline: AES.GCM.of_secret (Secret.unsafe_to_string k)"
      ~mk_key:(fun w ->
        Mirage_crypto.AES.GCM.of_secret (Secret.unsafe_to_string w))
  in
  let ok b = if b then "ok" else "FAIL" in
  let _, _, scrubbed_a, destroyed_a = a_small in
  let live_a', dropped_a', _, _ = a_large in
  let _, dropped_b, _, destroyed_b = b in
  let live_b, _, _, _ = b in
  let c1 = both h0 = 0 in
  (* The AES key schedule itself contains the key: verbatim with AES-NI,
     byte-swapped per word with the generic implementation. So "no copy of the
     raw key" is demonstrated relative to the baseline, which additionally
     holds the of_secret argument string. *)
  let c2 = verbatim live_a' < verbatim live_b in
  let c3 = both scrubbed_a = 0 && both destroyed_a = 0 in
  let c4 = both dropped_a' > 0 in
  let c5 = verbatim dropped_b > 0 && verbatim destroyed_b > 0 in
  Printf.printf "Checks:\n";
  Printf.printf "  key only in Secret.t -> 0 copies: %s\n" (ok c1);
  Printf.printf
    "  view: fewer verbatim copies than the baseline (no of_secret argument \
     string): %s\n"
    (ok c2);
  Printf.printf "  view + scrub: a key schedule that died young is erased: %s\n"
    (ok c3);
  Printf.printf
    "  view: a promoted key schedule survives in the major heap (needs the \
     mirage-crypto change): %s\n"
    (ok c4);
  Printf.printf
    "  baseline: a heap-string key is never erased by the runtime: %s\n" (ok c5);
  if not (c1 && c2 && c3 && c5) then exit 1
