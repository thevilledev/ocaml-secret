(* GC interaction: promotion, compaction, finalization, accounting. *)

let test_survives_minor_gc () =
  let t = Secret.of_string "promote me" in
  let v = Secret.Unsafe.string_view t in
  Gc.minor ();
  Gc.minor ();
  Alcotest.(check string)
    "contents after minor" "promote me"
    (Secret.unsafe_to_string t);
  Alcotest.(check string) "view after minor" "promote me" v;
  Alcotest.(check bool)
    "view is not young" false
    (Secret.Scratch.is_young (Bytes.unsafe_of_string v))

let test_survives_compaction () =
  let secrets =
    List.init 2000 (fun i -> Secret.of_string (Printf.sprintf "secret-%05d" i))
  in
  let views = List.map Secret.Unsafe.string_view secrets in
  (* churn the heap so compaction has work to do *)
  let junk = ref [] in
  for i = 0 to 50_000 do
    junk := Bytes.create ((i mod 100) + 1) :: !junk
  done;
  junk := [];
  Gc.compact ();
  Gc.full_major ();
  List.iteri
    (fun i t ->
      let expected = Printf.sprintf "secret-%05d" i in
      if Secret.unsafe_to_string t <> expected then
        Alcotest.failf "secret %d corrupted after compaction" i;
      if List.nth views i <> expected then
        Alcotest.failf "view %d corrupted after compaction" i)
    secrets;
  List.iter Secret.destroy secrets

let test_finalizer_releases () =
  let base = Secret.live_count () in
  let n = 20_000 in
  for _ = 1 to n do
    ignore (Secret.create 40)
  done;
  Gc.full_major ();
  Gc.full_major ();
  let live = Secret.live_count () in
  (* everything unreachable must have been finalized *)
  if live - base > 10 then
    Alcotest.failf "live_count %d (base %d) after full_major" live base;
  (* pooled blocks are reused, not leaked *)
  let pooled_before = Secret.pool_count () in
  let keep = List.init 100 (fun _ -> Secret.create 40) in
  Alcotest.(check bool)
    "pool shrinks on reuse" true
    (Secret.pool_count () < pooled_before);
  List.iter Secret.destroy keep

let test_finalizer_zeroes () =
  (* A view outlives its owner; after the owner is collected the view must
     read as zeros (the block was zeroized, and is either pooled or reused
     by another secret which is also zero at that point). *)
  let view =
    let t = Secret.of_string "finalize-me-please" in
    Secret.Unsafe.string_view t
  in
  Gc.full_major ();
  Gc.full_major ();
  Alcotest.(check string) "zeroed by finalizer" (String.make 18 '\000') view

let test_gc_pressure_accounting () =
  (* Out-of-heap bytes must pace the major GC: allocate ~400 MiB of secrets
     without destroying them; the GC must reclaim them rather than let RSS
     explode. We only assert that live_count stays bounded. *)
  let base = Secret.live_count () in
  for _ = 1 to 4000 do
    ignore (Secret.create 100_000)
  done;
  let live = Secret.live_count () - base in
  Alcotest.(check bool) "GC paced by custom_mem" true (live < 4000)

let test_scrub_minor_heap () =
  (* a marker that dies young must not survive the scrub *)
  let marker = "MINOR-HEAP-MARKER-0123456789" in
  let make () = Bytes.of_string (marker ^ string_of_int (Random.bits ())) in
  let _ = make () in
  ignore (Sys.opaque_identity (make ()));
  Secret.Gc.scrub_minor_heap ();
  (* We cannot scan the minor heap from OCaml; the scrub is exercised for
     crashes here and measured by the leak scanner. *)
  let t = Secret.of_string marker in
  Alcotest.(check string)
    "secrets unaffected" marker
    (Secret.unsafe_to_string t)

let () =
  Alcotest.run "secret-gc"
    [
      ( "gc",
        [
          Alcotest.test_case "survives minor gc" `Quick test_survives_minor_gc;
          Alcotest.test_case "survives compaction" `Quick
            test_survives_compaction;
          Alcotest.test_case "finalizer releases" `Quick test_finalizer_releases;
          Alcotest.test_case "finalizer zeroes" `Quick test_finalizer_zeroes;
          Alcotest.test_case "gc pressure accounting" `Quick
            test_gc_pressure_accounting;
          Alcotest.test_case "scrub minor heap" `Quick test_scrub_minor_heap;
        ] );
    ]
