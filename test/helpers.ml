external install_hook : bool -> unit = "helper_install_hook"
external hook_calls : unit -> int = "helper_hook_calls"
external hook_nonzero : unit -> int = "helper_hook_nonzero"
external poke : Secret.t -> int -> bool = "helper_poke"
external peek : Secret.t -> int -> int = "helper_peek"
external borrow_len : 'a -> int = "helper_borrow_len"
external is_secret : 'a -> bool = "helper_is_secret"

(* Reuse-pool size-class mapping, as the library computes it. *)
external block_size : int -> int = "helper_block_size"
external pool_slot : int -> int = "helper_pool_slot"

(* Run [exe args] and return (exit status, stdout lines).

   [Unix.create_process] resolves a bare name through PATH, and dune before
   3.24 expands [%{exe:...}] to just the basename, so qualify it here. *)
let run_child exe args =
  let exe =
    if Filename.is_implicit exe then
      Filename.concat Filename.current_dir_name exe
    else exe
  in
  let rd, wr = Unix.pipe () in
  let pid =
    Unix.create_process exe
      (Array.of_list (exe :: args))
      Unix.stdin wr Unix.stderr
  in
  Unix.close wr;
  let ic = Unix.in_channel_of_descr rd in
  let lines = ref [] in
  (try
     while true do
       lines := input_line ic :: !lines
     done
   with End_of_file -> ());
  close_in ic;
  let _, st = Unix.waitpid [] pid in
  (st, List.rev !lines)
