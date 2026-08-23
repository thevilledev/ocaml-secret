(* The C-level contract used by consumer stubs. *)
let () =
  let t = Secret.of_string "c-api" in
  assert (Helpers.is_secret t);
  assert (not (Helpers.is_secret "c-api"));
  assert (not (Helpers.is_secret 42));
  assert (Helpers.borrow_len t = 5);
  assert (Helpers.borrow_len "hello!" = 6);
  assert (Helpers.borrow_len 42 = -2);
  Secret.destroy t;
  assert (Helpers.borrow_len t = -1);
  assert (Helpers.peek t 0 = -1);
  print_endline "c api ok"
