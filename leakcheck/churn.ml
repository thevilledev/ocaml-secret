(* Key-server shape: heavy create/copy/sub/destroy churn across size
   classes (pooled, pool-overflow, and larger-than-pool), then a few
   secrets left live so the at_exit wipe runs on a populated registry. *)

let sizes = [ 0; 1; 16; 24; 32; 64; 256; 4096; 65536; 100_000 ]

let () =
  for _round = 1 to 50 do
    let batch =
      List.concat_map
        (fun n ->
          let a = Secret.create n in
          Secret.fill a 'k';
          let b = Secret.copy a in
          let c =
            if n >= 16 then Secret.sub a ~off:8 ~len:8 else Secret.copy a
          in
          [ a; b; c ])
        sizes
    in
    List.iter Secret.destroy batch
  done;
  let r1 = Secret.random 32 and r2 = Secret.random 32 in
  assert (not (Secret.equal r1 r2));
  assert (Secret.equal r1 r1);
  assert (not (Secret.equal_string r1 (String.make 32 '\000')));
  Secret.destroy r1;
  Secret.destroy r2;
  let init_direct =
    Secret.init 40 (fun b -> Bytes.fill b 0 (Bytes.length b) 'i')
  in
  let of_b = Secret.of_bytes ~wipe_source:true (Bytes.make 24 'b') in
  Secret.destroy init_direct;
  Secret.destroy of_b;
  let keep = List.init 8 (fun i -> Secret.random (16 + i)) in
  ignore (Sys.opaque_identity keep);
  Printf.printf "churn done: live=%d pooled=%d\n" (Secret.live_count ())
    (Secret.pool_count ())
