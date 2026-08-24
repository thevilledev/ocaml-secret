(* Run under `ulimit -l 0`: hardened secrets must stay usable and report the
   lock failure honestly. *)
let () =
  let t = Secret.create ~hardened:true 64 in
  Secret.fill t 'm';
  assert (Secret.equal_string t (String.make 64 'm'));
  let st = Secret.status t in
  let caps = Secret.capabilities () in
  (match st.Secret.lock with
  | `Failed e -> Printf.printf "lock failed as expected (errno %d)\n" e
  | `Unsupported -> print_endline "lock unsupported on this platform"
  | `Not_requested ->
      if caps.Secret.hardened_tier then
        failwith "lock should have been requested"
  | `Locked -> failwith "mlock succeeded despite ulimit -l 0"
  | `Lost_on_fork -> failwith "unexpected Lost_on_fork");
  Secret.destroy t;
  print_endline "ok"
