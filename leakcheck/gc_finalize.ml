(* No explicit destroy anywhere: the GC finalizer must wipe and release
   every payload and header. Also exercises wipe_all with handles that
   are finalized only afterwards. *)

let () =
  for _ = 1 to 5000 do
    let t = Secret.create 512 in
    Secret.fill t 'g';
    ignore (Sys.opaque_identity t)
  done;
  Gc.full_major ();
  Gc.full_major ();
  Printf.printf "after GC: live=%d pooled=%d\n" (Secret.live_count ())
    (Secret.pool_count ());
  (* wipe_all with live handles, then let finalizers release them *)
  let held = List.init 16 (fun _ -> Secret.random 64) in
  Secret.wipe_all ();
  List.iter (fun t -> assert (Secret.is_destroyed t)) held;
  ignore (Sys.opaque_identity held);
  print_endline "gc_finalize done"
