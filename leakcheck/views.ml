(* Views: scoped string/bytes/bigstring views, unscoped views retained
   across destroy (storage parked forever by design), Unsafe.init,
   expose/unsafe_to_string copies, scratch buffers, minor-heap scrub.
   Parked storage must count as reachable memory, never as a leak. *)

let () =
  Secret.with_random 32 (fun t ->
      assert (Secret.Unsafe.with_string_view t String.length = 32);
      Secret.Unsafe.with_bytes_view t (fun b -> Bytes.set b 0 'x');
      Secret.Unsafe.with_bigstring t (fun ba ->
          assert (Bigarray.Array1.dim ba = 32)));
  (* unscoped views retained across destroy: blocks are parked forever *)
  let parked_views =
    List.init 32 (fun i ->
        let t = Secret.create (16 + (i mod 4 * 8)) in
        Secret.fill t 's';
        let v = Secret.Unsafe.string_view t in
        Secret.destroy t;
        v)
  in
  List.iter
    (fun v -> assert (String.for_all (Char.equal '\000') v))
    parked_views;
  (* unscoped views dropped before destroy: blocks still parked *)
  for _ = 1 to 32 do
    let t = Secret.create 24 in
    ignore (Sys.opaque_identity (Secret.Unsafe.string_view t));
    Secret.destroy t
  done;
  Gc.full_major ();
  let u = Secret.Unsafe.init 16 (fun b -> Bytes.fill b 0 16 'u') in
  Secret.destroy u;
  let t = Secret.of_string "0123456789abcdef" in
  let sum =
    Secret.expose t (fun b -> Bytes.fold_left (fun a c -> a + Char.code c) 0 b)
  in
  assert (sum > 0);
  ignore (Sys.opaque_identity (Secret.unsafe_to_string t));
  Secret.destroy t;
  Secret.Scratch.with_ 512 (fun b -> Bytes.fill b 0 512 'z');
  Secret.Gc.scrub_minor_heap ();
  Printf.printf "views done: live=%d pooled=%d parked=%d\n"
    (Secret.live_count ()) (Secret.pool_count ()) (Secret.parked_count ())
