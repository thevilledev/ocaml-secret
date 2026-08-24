let exe = Sys.getenv "SECRET_CHILD_EXE"

let count_wiped lines =
  List.fold_left
    (fun (zero, nonzero) l ->
      match String.split_on_char ' ' l with
      | [ "wiped"; _; "zero" ] -> (zero + 1, nonzero)
      | [ "wiped"; _; "nonzero" ] -> (zero, nonzero + 1)
      | _ -> (zero, nonzero))
    (0, 0) lines

let expect_wipes mode ~exit_code n () =
  let st, lines = Helpers.run_child exe [ mode ] in
  let zero, nonzero = count_wiped lines in
  Alcotest.(check int) "zeroized wipes" n zero;
  Alcotest.(check int) "no non-zero wipes" 0 nonzero;
  match st with
  | Unix.WEXITED c -> Alcotest.(check int) "exit code" exit_code c
  | _ -> Alcotest.fail "child did not exit normally"

let test_user_handler () =
  let st, lines = Helpers.run_child exe [ "user_handler" ] in
  Alcotest.(check bool)
    "handler ran before wipe" true
    (List.mem "handler-ok" lines);
  let zero, _ = count_wiped lines in
  Alcotest.(check int) "wipes" 5 zero;
  ignore st

let test_wipe_all_then_use () =
  let _, lines = Helpers.run_child exe [ "wipe_all_then_use" ] in
  Alcotest.(check bool)
    "Destroyed after wipe_all" true
    (List.mem "use-after-wipe: Destroyed" lines)

let () =
  Alcotest.run "secret-atexit"
    [
      ( "atexit",
        [
          Alcotest.test_case "normal exit" `Quick
            (expect_wipes "normal" ~exit_code:0 5);
          Alcotest.test_case "exit 3" `Quick
            (expect_wipes "exit3" ~exit_code:3 5);
          Alcotest.test_case "uncaught exception" `Quick
            (expect_wipes "raise" ~exit_code:2 5);
          Alcotest.test_case "exit from domain" `Quick
            (expect_wipes "domain_exit" ~exit_code:0 5);
          Alcotest.test_case "user at_exit handler" `Quick test_user_handler;
          Alcotest.test_case "Unix._exit skips wipe (documented)" `Quick
            (expect_wipes "_exit" ~exit_code:0 0);
          Alcotest.test_case "wipe_all then use" `Quick test_wipe_all_then_use;
        ] );
    ]
