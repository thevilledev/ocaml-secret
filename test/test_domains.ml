(* Multi-domain use: concurrent reads, independent create/destroy traffic,
   cross-domain finalization, and concurrent double destroy. *)

let worker n () =
  for i = 1 to n do
    let a = Secret.of_string (string_of_int i) in
    let b = Secret.copy a in
    assert (Secret.equal a b);
    if i mod 3 = 0 then Secret.destroy a;
    if i mod 5 = 0 then Secret.destroy b
  done

let test_parallel_hardened_creation () =
  let start = Atomic.make false in
  let worker () =
    while not (Atomic.get start) do
      Domain.cpu_relax ()
    done;
    for _ = 1 to 100 do
      let t = Secret.create ~hardened:true 32 in
      Secret.destroy t
    done
  in
  let ds = List.init 4 (fun _ -> Domain.spawn worker) in
  Atomic.set start true;
  List.iter Domain.join ds

let test_parallel_workers () =
  let ds = List.init 4 (fun _ -> Domain.spawn (worker 20_000)) in
  List.iter Domain.join ds;
  Gc.full_major ()

let test_cross_domain_finalization () =
  let d =
    Domain.spawn (fun () ->
        for _ = 1 to 10_000 do
          ignore (Secret.create 64)
        done)
  in
  Domain.join d;
  Gc.full_major ();
  Gc.full_major ();
  Alcotest.(check bool) "collected" true (Secret.live_count () < 1000)

let test_concurrent_double_destroy () =
  let secrets = Array.init 1000 (fun _ -> Secret.create 32) in
  let d1 = Domain.spawn (fun () -> Array.iter Secret.destroy secrets) in
  let d2 = Domain.spawn (fun () -> Array.iter Secret.destroy secrets) in
  Domain.join d1;
  Domain.join d2;
  Array.iter (fun s -> assert (Secret.is_destroyed s)) secrets

let test_concurrent_reads () =
  let secret = Secret.of_string "shared read-only secret" in
  let copy = Secret.copy secret in
  let reader () =
    for _ = 1 to 20_000 do
      assert (Secret.equal secret copy);
      assert (Secret.equal_string secret "shared read-only secret");
      assert (Secret.unsafe_to_string secret = "shared read-only secret")
    done
  in
  let readers = List.init 4 (fun _ -> Domain.spawn reader) in
  List.iter Domain.join readers;
  Secret.destroy secret;
  Secret.destroy copy

let test_concurrent_entropy_source_updates () =
  let setter byte () =
    for _ = 1 to 20_000 do
      Secret.set_entropy_source (fun buffer ->
          Bytes.fill buffer 0 (Bytes.length buffer) byte)
    done
  in
  let setters =
    [ Domain.spawn (setter 'a'); Domain.spawn (setter 'b');
      Domain.spawn (setter 'c'); Domain.spawn (setter 'd') ]
  in
  List.iter Domain.join setters;
  Secret.set_entropy_source (fun buffer -> Bytes.fill buffer 0 (Bytes.length buffer) 'r')

let () =
  Alcotest.run "secret-domains"
    [
      ( "domains",
        [
          Alcotest.test_case "parallel hardened creation" `Quick
            test_parallel_hardened_creation;
          Alcotest.test_case "parallel workers" `Quick test_parallel_workers;
          Alcotest.test_case "cross-domain finalization" `Quick
            test_cross_domain_finalization;
          Alcotest.test_case "concurrent reads" `Quick test_concurrent_reads;
          Alcotest.test_case "concurrent double destroy" `Quick
            test_concurrent_double_destroy;
          Alcotest.test_case "concurrent entropy source updates" `Quick
            test_concurrent_entropy_source_updates;
        ] );
    ]
