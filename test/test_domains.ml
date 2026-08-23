(* Multi-domain use: create/equal/destroy across domains, cross-domain
   finalization, concurrent double destroy, wipe_all under allocation. *)

let worker n () =
  for i = 1 to n do
    let a = Secret.of_string (string_of_int i) in
    let b = Secret.copy a in
    assert (Secret.equal a b);
    if i mod 3 = 0 then Secret.destroy a;
    if i mod 5 = 0 then Secret.destroy b
  done

let test_parallel_workers () =
  let ds = List.init 4 (fun _ -> Domain.spawn (worker 20_000)) in
  List.iter Domain.join ds;
  Gc.full_major ()

let test_cross_domain_finalization () =
  let d = Domain.spawn (fun () -> for _ = 1 to 10_000 do ignore (Secret.create 64) done) in
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

let test_wipe_all_under_allocation () =
  let stop = Atomic.make false in
  let errors = Atomic.make 0 in
  let zeroish s =
    (* a read that overlaps a wipe may observe a prefix of the contents
       followed by zeros; anything else is corruption *)
    let n = String.length s in
    n = 6
    && (let rec ok i = i >= n || (if s.[i] = "racing".[i] then ok (i + 1) else zeros i)
        and zeros i = i >= n || (s.[i] = '\000' && zeros (i + 1)) in
        ok 0)
  in
  let allocator () =
    while not (Atomic.get stop) do
      match
        let t = Secret.of_string "racing" in
        Secret.unsafe_to_string t
      with
      | s when zeroish s -> ()
      | _ -> Atomic.incr errors
      | exception Secret.Destroyed -> ()
    done
  in
  let ds = List.init 3 (fun _ -> Domain.spawn allocator) in
  for _ = 1 to 50 do Secret.wipe_all () done;
  Atomic.set stop true;
  List.iter Domain.join ds;
  Alcotest.(check int) "no corruption" 0 (Atomic.get errors)

let () =
  Alcotest.run "secret-domains"
    [
      ( "domains",
        [
          Alcotest.test_case "parallel workers" `Quick test_parallel_workers;
          Alcotest.test_case "cross-domain finalization" `Quick test_cross_domain_finalization;
          Alcotest.test_case "concurrent double destroy" `Quick test_concurrent_double_destroy;
          Alcotest.test_case "wipe_all under allocation" `Quick test_wipe_all_under_allocation;
        ] );
    ]
