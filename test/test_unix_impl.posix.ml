let with_tmp f =
  let path = Filename.temp_file "secret" ".key" in
  Fun.protect ~finally:(fun () -> try Sys.remove path with _ -> ()) (fun () -> f path)

let test_read_write () =
  with_tmp (fun path ->
      let t = Secret.of_string "the-key-material-0123456789" in
      let fd = Unix.openfile path [ Unix.O_WRONLY; Unix.O_TRUNC ] 0o600 in
      Secret_unix.write_all fd t;
      Unix.close fd;
      let r = Secret_unix.read_file path in
      Alcotest.(check bool) "roundtrip" true (Secret.equal t r);
      let r2 = Secret_unix.read_file ~max:7 path in
      Alcotest.(check string) "max" "the-key" (Secret.unsafe_to_string r2);
      let r3 = Secret_unix.read_file ~max:1000 path in
      Alcotest.(check int) "short file" 27 (Secret.length r3);
      let fd = Unix.openfile path [ Unix.O_RDONLY ] 0 in
      let u = Secret.create 10 in
      Secret_unix.read_exactly fd u ~off:0 ~len:10;
      Alcotest.(check string) "read_exactly" "the-key-ma" (Secret.unsafe_to_string u);
      Alcotest.check_raises "eof" End_of_file (fun () ->
          Secret_unix.read_exactly fd (Secret.create 100) ~off:0 ~len:100);
      Unix.close fd;
      Alcotest.check_raises "bounds" (Invalid_argument "Secret_unix.read: out of bounds")
        (fun () -> ignore (Secret_unix.read Unix.stdin u ~off:5 ~len:10));
      Secret.destroy u;
      Alcotest.check_raises "destroyed" Secret.Destroyed (fun () ->
          ignore (Secret_unix.read Unix.stdin u ~off:0 ~len:1)))

let test_errors () =
  (match Secret_unix.read_file "/nonexistent/secret.key" with
  | _ -> Alcotest.fail "expected Unix_error"
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> ());
  let t = Secret.of_string "x" in
  let rd, wr = Unix.pipe () in
  Unix.close wr;
  Unix.close rd;
  match Secret_unix.write wr t ~off:0 ~len:1 with
  | _ -> Alcotest.fail "expected EBADF"
  | exception Unix.Unix_error (Unix.EBADF, "write", _) -> ()

let run () =
  Alcotest.run "secret-unix"
    [ ("unix", [ Alcotest.test_case "read/write" `Quick test_read_write;
                 Alcotest.test_case "errors" `Quick test_errors ]) ]
