(* Child process for the at-exit wipe test. Prints one "wiped <len> zero"
   line per zeroized secret (via the C release hook) and terminates in the
   way selected by argv.(1). *)

let () =
  Helpers.install_hook true;
  let secrets = List.map (fun n -> Secret.of_string (String.make n 'x')) [ 10; 20; 30; 40; 50 ] in
  let mode = if Array.length Sys.argv > 1 then Sys.argv.(1) else "normal" in
  match mode with
  | "normal" -> ()
  | "exit3" -> exit 3
  | "raise" -> failwith "uncaught"
  | "domain_exit" ->
      let d = Domain.spawn (fun () -> exit 0) in
      Domain.join d
  | "user_handler" ->
      (* a handler registered after Secret's runs before the wipe *)
      at_exit (fun () ->
          let ok = List.for_all (fun s -> not (Secret.is_destroyed s)) secrets in
          print_endline (if ok then "handler-ok" else "handler-destroyed"))
  | "_exit" -> Unix._exit 0
  | "wipe_all_then_use" ->
      Secret.wipe_all ();
      (match Secret.unsafe_to_string (List.hd secrets) with
      | _ -> print_endline "use-after-wipe: no exception"
      | exception Secret.Destroyed -> print_endline "use-after-wipe: Destroyed")
  | _ -> prerr_endline "unknown mode"; exit 99
