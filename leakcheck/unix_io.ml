(* Direct fd I/O: secret -> pipe -> secret, secret -> temp file ->
   read_file, plus read_fd sizing on short input. *)

let () =
  let t = Secret.random 48 in
  let r, w = Unix.pipe () in
  Secret_unix.write_all w t;
  let back = Secret.create 48 in
  Secret_unix.read_exactly r back ~off:0 ~len:48;
  assert (Secret.equal t back);
  Unix.close r;
  Unix.close w;
  Secret.destroy back;
  let path = Filename.temp_file "leakcheck" ".key" in
  let fd = Unix.openfile path [ O_WRONLY; O_TRUNC ] 0o600 in
  Secret_unix.write_all fd t;
  Unix.close fd;
  let from_file = Secret_unix.read_file path in
  assert (Secret.equal t from_file);
  Secret.destroy from_file;
  let fd = Unix.openfile path [ O_RDONLY ] 0o600 in
  let short = Secret_unix.read_fd fd 1024 in
  assert (Secret.length short = 48);
  Unix.close fd;
  Sys.remove path;
  Secret.destroy short;
  Secret.destroy t;
  Printf.printf "unix_io done: live=%d pooled=%d\n" (Secret.live_count ())
    (Secret.pool_count ())
