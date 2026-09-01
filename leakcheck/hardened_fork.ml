(* Hardened tier (mmap + guard pages + mlock + canary), pool reuse of
   page-backed blocks, fork with both policies, after_fork relock.
   LEAKCHECK_NO_FORK skips the forks: macOS `leaks --atExit` cannot
   monitor a process that forks. *)

let () =
  let caps = Secret.capabilities () in
  Printf.printf "hardened_tier=%b zeroize=%s\n%!" caps.Secret.hardened_tier
    caps.Secret.zeroize_primitive;
  if not caps.Secret.hardened_tier then (
    print_endline "hardened_fork done: hardened tier unavailable, skipped";
    exit 0);
  for _ = 1 to 40 do
    let t = Secret.random ~hardened:true 32 in
    let st = Secret.status t in
    assert st.Secret.page_backed;
    assert st.Secret.canary;
    Secret.destroy t
  done;
  (* larger than the pool bound: released to the OS on destroy *)
  let big = Secret.create ~hardened:true 100_000 in
  Secret.fill big 'B';
  Secret.destroy big;
  (* mixed-tier equality *)
  let a = Secret.of_string ~hardened:true "same-content-here" in
  let b = Secret.of_string "same-content-here" in
  assert (Secret.equal a b);
  Secret.destroy a;
  Secret.destroy b;
  if Sys.getenv_opt "LEAKCHECK_NO_FORK" <> None then (
    Printf.printf "hardened_fork done (no fork): live=%d pooled=%d\n"
      (Secret.live_count ()) (Secret.pool_count ());
    exit 0);
  (* fork: wipe-in-child, then keep *)
  Secret.set_fork_policy `Wipe_in_child;
  let t = Secret.random ~hardened:true 64 in
  (match Unix.fork () with
  | 0 -> Stdlib.exit (if Secret.is_destroyed t then 0 else 1)
  | pid ->
      let _, st = Unix.waitpid [] pid in
      assert (st = Unix.WEXITED 0));
  Secret.set_fork_policy `Keep;
  (match Unix.fork () with
  | 0 ->
      Secret.after_fork ();
      Stdlib.exit (if Secret.is_destroyed t then 1 else 0)
  | pid ->
      let _, st = Unix.waitpid [] pid in
      assert (st = Unix.WEXITED 0));
  Secret.destroy t;
  Printf.printf "hardened_fork done: live=%d pooled=%d\n" (Secret.live_count ())
    (Secret.pool_count ())
