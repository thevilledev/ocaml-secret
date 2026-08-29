external borrowed_length : Secret.t -> int = "consumer_borrowed_length"

let () =
  let secret = Secret.of_string "installed consumer" in
  assert (borrowed_length secret = Secret.length secret);
  let read_end, write_end = Unix.pipe () in
  Secret_unix.write_all write_end secret;
  Unix.close write_end;
  let copy = Secret_unix.read_fd read_end (Secret.length secret) in
  Unix.close read_end;
  assert (Secret.equal secret copy);
  Secret.destroy secret;
  Secret.destroy copy;
  print_endline "installed OCaml libraries and secret.h work"
