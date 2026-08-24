(* Throughput of create/destroy per tier, and equal vs String.equal. *)

let time name iters f =
  let t0 = Unix.gettimeofday () in
  for _ = 1 to iters do
    f ()
  done;
  let dt = Unix.gettimeofday () -. t0 in
  Printf.printf "%-46s %8.0f ns/op  (%d ops)\n%!" name
    (dt *. 1e9 /. float iters)
    iters

let () =
  let n = 200_000 in
  time "Bytes.create 32 (reference)" n (fun () ->
      ignore (Sys.opaque_identity (Bytes.create 32)));
  time "Secret.create 32 + destroy (tier a, pooled)" n (fun () ->
      let t = Secret.create 32 in
      Secret.destroy t);
  time "Secret.create 240 + destroy (AES schedule size)" n (fun () ->
      let t = Secret.create 240 in
      Secret.destroy t);
  time "Secret.create 32, GC-collected (tier a)" n (fun () ->
      ignore (Sys.opaque_identity (Secret.create 32)));
  time "Secret.of_string 32 + destroy" n (fun () ->
      let t = Secret.of_string "0123456789abcdef0123456789abcdef" in
      Secret.destroy t);
  time "Secret.Unsafe.string_view" n
    (let t = Secret.create 32 in
     fun () -> ignore (Sys.opaque_identity (Secret.Unsafe.string_view t)));
  time "Secret.expose 32 (Scratch copy + wipe)" n
    (let t = Secret.create 32 in
     fun () -> Secret.expose t (fun _ -> ()));
  let h = 20_000 in
  time "Secret.create ~hardened 32 + destroy (pooled)" h (fun () ->
      let t = Secret.create ~hardened:true 32 in
      Secret.destroy t);
  time "Secret.create ~hardened 32 (first use: mmap+mlock)" 2_000 (fun () ->
      (* defeat the pool by keeping them alive *)
      ignore (Sys.opaque_identity (Secret.create ~hardened:true 32)));
  let a = Secret.of_string (String.make 32 'a')
  and b = Secret.of_string (String.make 32 'a') in
  let sa = String.make 32 'a' and sb = String.make 32 'a' in
  time "Secret.equal 32 bytes" n (fun () ->
      ignore (Sys.opaque_identity (Secret.equal a b)));
  time "String.equal 32 bytes (not constant time)" n (fun () ->
      ignore (Sys.opaque_identity (String.equal sa sb)));
  let a4 = Secret.create 4096 and b4 = Secret.create 4096 in
  time "Secret.equal 4096 bytes" 20_000 (fun () ->
      ignore (Sys.opaque_identity (Secret.equal a4 b4)));
  time "Secret.Gc.scrub_minor_heap" 200 Secret.Gc.scrub_minor_heap;
  Printf.printf "live=%d pooled=%d\n" (Secret.live_count ())
    (Secret.pool_count ())
