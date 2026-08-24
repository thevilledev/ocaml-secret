(* dudect-style leakage test for Secret.equal (Reparaz, Balasch, Verbauwhede
   2017): two input classes, interleaved at random, Welch's t-test on the
   timing distributions. |t| < 4.5 means no evidence of a timing difference.
   Run on bare metal for meaningful numbers; CI only checks it runs. *)

external ticks : unit -> int64 = "ct_ticks"
external equal_raw : Secret.t -> Secret.t -> int = "ct_equal_raw" [@@noalloc]

let n_samples = try int_of_string Sys.argv.(1) with _ -> 20_000

let reps =
  try int_of_string Sys.argv.(2) with _ -> 200 (* calls per timed sample *)

let len = 64

let welch xs ys =
  let mean a = Array.fold_left ( +. ) 0. a /. float (Array.length a) in
  let var a m =
    Array.fold_left (fun s x -> s +. ((x -. m) ** 2.)) 0. a
    /. float (Array.length a - 1)
  in
  let mx = mean xs and my = mean ys in
  let vx = var xs mx and vy = var ys my in
  let nx = float (Array.length xs) and ny = float (Array.length ys) in
  (mx -. my) /. sqrt ((vx /. nx) +. (vy /. ny))

let () =
  Random.self_init ();
  let fixed = Secret.of_string (String.make len 'F') in
  let same = String.make len 'F' in
  let diff_first = "X" ^ String.make (len - 1) 'F' in
  let diff_last = String.make (len - 1) 'F' ^ "X" in
  (* the class contents are written into ONE working secret before each
     timed sample, so both classes see the same addresses and cache state *)
  let y = Secret.create len in
  let trim l =
    (* drop the top 1% (interrupts, context switches) as dudect does *)
    let a = Array.of_list l in
    Array.sort compare a;
    Array.sub a 0 (Array.length a * 99 / 100)
  in
  let mean a = Array.fold_left ( +. ) 0. a /. float (Array.length a) in
  let run ?(raw = false) name contents_b =
    let name =
      if raw then name ^ " (C primitive)" else name ^ " (Secret.equal)"
    in
    let cls = Array.init n_samples (fun _ -> Random.bool ()) in
    let t0 = ref [] and t1 = ref [] in
    for i = 0 to n_samples - 1 do
      Secret.blit_from_string
        (if cls.(i) then contents_b else same)
        ~src_off:0 y ~dst_off:0 ~len;
      let s = ticks () in
      if raw then
        for _ = 1 to reps do
          ignore (Sys.opaque_identity (equal_raw fixed y))
        done
      else
        for _ = 1 to reps do
          ignore (Sys.opaque_identity (Secret.equal fixed y))
        done;
      let e = ticks () in
      let d = Int64.to_float (Int64.sub e s) in
      if cls.(i) then t1 := d :: !t1 else t0 := d :: !t0
    done;
    let x = trim !t0 and z = trim !t1 in
    let t = welch x z in
    Printf.printf "%-44s equal: %8.1f  differing: %8.1f  |t| = %6.2f  %s\n%!"
      name (mean x) (mean z) (abs_float t)
      (if abs_float t < 4.5 then "no leak evidence" else "TIMING DIFFERENCE")
  in
  run ~raw:true "differs in first byte" diff_first;
  run ~raw:true "differs in last byte" diff_last;
  run "differs in first byte" diff_first;
  run "differs in last byte" diff_last;
  (* control: the non-constant-time comparison, same protocol *)
  let yb = Bytes.make len 'F' in
  let cls = Array.init n_samples (fun _ -> Random.bool ()) in
  let t0 = ref [] and t1 = ref [] in
  for i = 0 to n_samples - 1 do
    Bytes.blit_string (if cls.(i) then diff_first else same) 0 yb 0 len;
    let ys = Bytes.unsafe_to_string yb in
    let s = ticks () in
    for _ = 1 to reps do
      ignore (Sys.opaque_identity (String.equal same ys))
    done;
    let e = ticks () in
    let d = Int64.to_float (Int64.sub e s) in
    if cls.(i) then t1 := d :: !t1 else t0 := d :: !t0
  done;
  let t = welch (trim !t0) (trim !t1) in
  Printf.printf
    "%-44s |t| = %6.2f (control: String.equal, expected to differ)\n"
    "differs in first byte (String.equal)" (abs_float t);
  Printf.printf
    "(%d samples x %d calls; |t| < 4.5 = no evidence of a timing difference)\n"
    n_samples reps
