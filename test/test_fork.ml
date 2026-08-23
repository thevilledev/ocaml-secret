(* fork semantics: Keep (default) and Wipe_in_child. POSIX only. *)

let child_check f =
  match Unix.fork () with
  | 0 ->
      let code = try if f () then 0 else 1 with _ -> 2 in
      Unix._exit code
  | pid -> (
      match Unix.waitpid [] pid with
      | _, Unix.WEXITED 0 -> ()
      | _, Unix.WEXITED 1 -> Alcotest.fail "child check failed"
      | _, Unix.WEXITED 2 -> Alcotest.fail "child raised"
      | _ -> Alcotest.fail "child died")

let test_keep () =
  Secret.set_fork_policy `Keep;
  let plain = Secret.of_string "plain-secret" in
  let hard = Secret.create ~hardened:true 32 in
  Secret.fill hard 'h';
  let hard_st = Secret.status hard in
  child_check (fun () ->
      let ok1 = Secret.unsafe_to_string plain = "plain-secret" in
      let ok2 = Secret.equal_string hard (String.make 32 'h') in
      let st = Secret.status hard in
      let ok3 =
        match (hard_st.Secret.lock, st.Secret.lock) with
        | `Locked, `Lost_on_fork -> true
        | `Locked, _ -> false
        | _, _ -> true (* was not locked in the parent; nothing to lose *)
      in
      Secret.after_fork ();
      let st2 = Secret.status hard in
      let ok4 =
        match (hard_st.Secret.lock, st2.Secret.lock) with
        | `Locked, (`Locked | `Failed _) -> true
        | `Locked, _ -> false
        | _, _ -> true
      in
      ok1 && ok2 && ok3 && ok4);
  (* parent unaffected *)
  Alcotest.(check string) "parent plain" "plain-secret" (Secret.unsafe_to_string plain);
  Alcotest.(check bool) "parent hard" true (Secret.equal_string hard (String.make 32 'h'))

let test_wipe_in_child () =
  Secret.set_fork_policy `Wipe_in_child;
  let plain = Secret.of_string "plain-secret" in
  let hard = Secret.create ~hardened:true 32 in
  Secret.fill hard 'h';
  child_check (fun () ->
      let d1 = Secret.is_destroyed plain and d2 = Secret.is_destroyed hard in
      let raises = match Secret.unsafe_to_string plain with _ -> false | exception Secret.Destroyed -> true in
      d1 && d2 && raises);
  Secret.set_fork_policy `Keep;
  Alcotest.(check string) "parent plain" "plain-secret" (Secret.unsafe_to_string plain);
  Alcotest.(check bool) "parent hard" true (Secret.equal_string hard (String.make 32 'h'))

let test_policy_switch_restores_keep () =
  if (Secret.capabilities ()).Secret.can_wipe_on_fork then begin
    Secret.set_fork_policy `Wipe_in_child;
    let hard = Secret.create ~hardened:true 32 in
    Secret.fill hard 'k';
    let advised = (Secret.status hard).Secret.wipe_on_fork in
    Secret.set_fork_policy `Keep;
    Alcotest.(check bool) "wipe advice was applied" true advised;
    Alcotest.(check bool) "wipe advice revoked" false
      (Secret.status hard).Secret.wipe_on_fork;
    child_check (fun () -> Secret.equal_string hard (String.make 32 'k'));
    Secret.destroy hard
  end

let () =
  if (Secret.capabilities ()).Secret.atfork then
    Alcotest.run "secret-fork"
      [
        ( "fork",
          [
            Alcotest.test_case "Keep" `Quick test_keep;
            Alcotest.test_case "Wipe_in_child" `Quick test_wipe_in_child;
            Alcotest.test_case "Wipe then Keep" `Quick test_policy_switch_restores_keep;
          ] );
      ]
  else print_endline "no atfork support: skipped"
