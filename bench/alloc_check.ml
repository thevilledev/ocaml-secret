(* Deterministic allocation checks for the non-allocating hot path. The
   throughput benchmark deliberately remains informational. *)

let iterations = 100_000

let allocated_bytes f =
  Gc.full_major ();
  let before = Gc.allocated_bytes () in
  f ();
  Gc.allocated_bytes () -. before

let loop f () =
  for _ = 1 to iterations do
    f ()
  done

let () =
  let a = Secret.of_string (String.make 32 'a') in
  let b = Secret.copy a in
  let output = Bytes.create 32 in
  let input = String.make 32 'b' in
  let baseline =
    allocated_bytes (loop (fun () -> ignore (Sys.opaque_identity false)))
  in
  let check name operation =
    let allocated = allocated_bytes (loop operation) -. baseline in
    if allocated > 128. then
      failwith
        (Printf.sprintf "%s allocated %.0f bytes across %d calls" name allocated
           iterations);
    Printf.printf "%s: %.0f bytes across %d calls\n%!" name
      (Float.max 0. allocated) iterations
  in
  check "Secret.equal" (fun () ->
      ignore (Sys.opaque_identity (Secret.equal a b)));
  check "Secret.equal_string" (fun () ->
      ignore (Sys.opaque_identity (Secret.equal_string a input)));
  check "Secret.fill" (fun () -> Secret.fill b 'b');
  check "Secret.zero" (fun () -> Secret.zero b);
  check "Secret.blit" (fun () ->
      Secret.blit ~src:a ~src_off:0 ~dst:b ~dst_off:0 ~len:32);
  check "Secret.blit_from_string" (fun () ->
      Secret.blit_from_string input ~src_off:0 b ~dst_off:0 ~len:32);
  check "Secret.blit_to_bytes" (fun () ->
      Secret.blit_to_bytes a ~src_off:0 output ~dst_off:0 ~len:32);
  Secret.destroy a;
  Secret.destroy b
