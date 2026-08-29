let wait_until_started started =
  while not (Atomic.get started) do
    Domain.cpu_relax ()
  done;
  (* Give the worker time to enter the blocking section. If it has not yet
     done so, the test still checks the destroyed-before-read path. *)
  Unix.sleepf 0.02

let test_blocked_read_is_rewiped () =
  let rd, wr = Unix.pipe () in
  Fun.protect
    ~finally:(fun () ->
      Unix.close rd;
      Unix.close wr)
    (fun () ->
      let t = Secret.create 6 in
      let view = Secret.Unsafe.string_view t in
      let started = Atomic.make false in
      let reader =
        Domain.spawn (fun () ->
            Atomic.set started true;
            match Secret_unix.read rd t ~off:0 ~len:6 with
            | _ -> `Returned
            | exception Secret.Destroyed -> `Destroyed)
      in
      wait_until_started started;
      Secret.wipe_all ();
      Alcotest.(check int)
        "write after wipe" 6 (Unix.write_substring wr "SECRET" 0 6);
      Alcotest.(check bool)
        "reader observes destruction" true
        (Domain.join reader = `Destroyed);
      Alcotest.(check string)
        "retired payload re-wiped" (String.make 6 '\000') view)

let () =
  Alcotest.run "secret-wipe-races"
    [
      ( "wipe_all",
        [
          Alcotest.test_case "blocked read is re-wiped" `Quick
            test_blocked_read_is_rewiped;
        ] );
    ]
