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
   3.24 expands [%{exe:...}] to just the basename, so qualify it here.

   The child's stdout goes to a temporary file rather than a pipe. A pipe
   from [Unix.pipe] is not inherited as the child's stdout on Windows, where
   neither the release hook's write nor the child's own output reached the
   parent, and reading a file after the child exits also cannot deadlock the
   way an unread pipe can once its buffer fills. *)
let run_child exe args =
  let exe =
    if Filename.is_implicit exe then
      Filename.concat Filename.current_dir_name exe
    else exe
  in
  let path = Filename.temp_file "secret-child" ".out" in
  Fun.protect
    ~finally:(fun () -> try Sys.remove path with Sys_error _ -> ())
    (fun () ->
      let out = Unix.openfile path [ Unix.O_WRONLY; Unix.O_TRUNC ] 0o600 in
      let st =
        Fun.protect
          ~finally:(fun () -> try Unix.close out with Unix.Unix_error _ -> ())
          (fun () ->
            let pid =
              Unix.create_process exe
                (Array.of_list (exe :: args))
                Unix.stdin out Unix.stderr
            in
            snd (Unix.waitpid [] pid))
      in
      let ic = open_in path in
      let lines = ref [] in
      (try
         while true do
           lines := input_line ic :: !lines
         done
       with End_of_file -> ());
      close_in ic;
      (st, List.rev !lines))
