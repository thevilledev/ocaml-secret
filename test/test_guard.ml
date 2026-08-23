let exe = Sys.getenv "SECRET_CHILD_EXE"

let died_by_signal st =
  match st with
  | Unix.WSIGNALED s -> s = Sys.sigsegv || s = Sys.sigbus || s = Sys.sigabrt
  | _ -> false

let run mode ~expect_death () =
  let st, lines = Helpers.run_child exe [ mode ] in
  if List.mem "skip" lines then ()
  else begin
    Alcotest.(check bool) "armed" true (List.mem "armed" lines);
    if expect_death then begin
      Alcotest.(check bool) "did not survive" false (List.mem "survived" lines);
      Alcotest.(check bool) "died by signal" true (died_by_signal st)
    end
    else begin
      Alcotest.(check bool) "survived" true (List.mem "survived" lines);
      match st with
      | Unix.WEXITED 0 -> ()
      | _ -> Alcotest.fail "unexpected exit"
    end
  end

let () =
  Alcotest.run "secret-guard"
    [
      ( "guard",
        [
          Alcotest.test_case "overflow hits guard page" `Quick (run "overflow" ~expect_death:true);
          Alcotest.test_case "underflow hits guard page" `Quick (run "underflow" ~expect_death:true);
          Alcotest.test_case "canary corruption aborts" `Quick (run "canary" ~expect_death:true);
          Alcotest.test_case "in-bounds write survives" `Quick (run "inbounds" ~expect_death:false);
        ] );
    ]
