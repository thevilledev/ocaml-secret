let test_partial_read_error_wipes () =
  Gc.full_major ();
  Gc.full_major ();
  Helpers.install_hook false;
  let rd, wr = Unix.pipe () in
  Fun.protect
    ~finally:(fun () ->
      Unix.close rd;
      Unix.close wr)
    (fun () ->
      Unix.set_nonblock rd;
      Alcotest.(check int) "seed pipe" 7 (Unix.write_substring wr "partial" 0 7);
      (match Secret_unix.read_fd rd 16 with
      | _ -> Alcotest.fail "expected EAGAIN"
      | exception Unix.Unix_error (Unix.EAGAIN, "read", _) -> ());
      Alcotest.(check int) "partial secret destroyed" 1 (Helpers.hook_calls ());
      Alcotest.(check int)
        "payload zero before release" 0 (Helpers.hook_nonzero ()))

let () =
  Alcotest.run "secret-unix-wipe"
    [
      ( "unix",
        [
          Alcotest.test_case "partial read error" `Quick
            test_partial_read_error_wipes;
        ] );
    ]
