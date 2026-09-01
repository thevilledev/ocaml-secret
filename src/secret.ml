(* Secret.t: owner custom block -> C header -> out-of-heap payload. *)

type t

exception Destroyed
exception Entropy_unavailable

(* ---- externals --------------------------------------------------------- *)

external init_c : unit -> unit = "secret_ml_init"
external create_c : int -> int -> t = "secret_ml_create"
external destroy_c : t -> unit = "secret_ml_destroy" [@@noalloc]
external length_c : t -> int = "secret_ml_length" [@@noalloc]
external is_destroyed_c : t -> bool = "secret_ml_is_destroyed" [@@noalloc]
external status_c : t -> int = "secret_ml_status" [@@noalloc]
external lock_errno_c : t -> int = "secret_ml_lock_errno" [@@noalloc]
external fill_c : t -> char -> int = "secret_ml_fill" [@@noalloc]
external zero_c : t -> int = "secret_ml_zero" [@@noalloc]

external blit_c : t -> int -> t -> int -> int -> int = "secret_ml_blit"
[@@noalloc]

external blit_from_string_c : string -> int -> t -> int -> int -> int
  = "secret_ml_blit_from_string"
[@@noalloc]

external blit_to_bytes_c : t -> int -> bytes -> int -> int -> int
  = "secret_ml_blit_to_bytes"
[@@noalloc]

external equal_c : t -> t -> int = "secret_ml_equal" [@@noalloc]

external equal_string_c : t -> string -> int = "secret_ml_equal_string"
[@@noalloc]

external view_c : t -> string = "secret_ml_view" [@@noalloc]
external scoped_view_c : t -> string = "secret_ml_scoped_view" [@@noalloc]
external fill_random_c : t -> int = "secret_ml_fill_random"
external alloc_major_bytes_c : int -> bytes = "secret_ml_alloc_major_bytes"
external wipe_bytes_c : bytes -> unit = "secret_ml_wipe_bytes" [@@noalloc]
external is_young_c : bytes -> bool = "secret_ml_is_young" [@@noalloc]
external wipe_all_c : unit -> unit = "secret_ml_wipe_all" [@@noalloc]
external live_count_c : unit -> int = "secret_ml_live_count" [@@noalloc]
external pool_count_c : unit -> int = "secret_ml_pool_count" [@@noalloc]
external parked_count_c : unit -> int = "secret_ml_parked_count" [@@noalloc]
external capabilities_c : unit -> int = "secret_ml_capabilities" [@@noalloc]
external page_size_c : unit -> int = "secret_ml_page_size" [@@noalloc]
external zeroize_name_c : unit -> string = "secret_ml_zeroize_name"

external set_fork_policy_c : bool -> unit = "secret_ml_set_fork_policy"
[@@noalloc]

external after_fork_c : unit -> unit = "secret_ml_after_fork" [@@noalloc]
external scrub_minor_heap_c : unit -> unit = "secret_ml_scrub_minor_heap"

external process_feature_c : int -> int = "secret_ml_process_feature"
[@@noalloc]

external scrub_env_c : string -> int = "secret_ml_scrub_env" [@@noalloc]

type bigstring =
  (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

external bigstring_view_c : t -> bigstring = "secret_ml_bigstring_view"

external revoke_bigstring_c : bigstring -> unit = "secret_ml_revoke_bigstring"
[@@noalloc]

(* ---- flag bits (must match secret_internal.h) ---------------------------- *)

let sf_hardened_req = 1 lsl 0
let sf_page_backed = 1 lsl 1
let sf_guarded = 1 lsl 2
let sf_canary = 1 lsl 3
let sf_locked = 1 lsl 4
let sf_nodump = 1 lsl 5
let sf_wipeonfork = 1 lsl 6
let sf_destroyed = 1 lsl 7
let _sf_fork_wiped = 1 lsl 8
let sf_viewed = 1 lsl 9
let sf_lock_unsupported = 1 lsl 10
let sf_nodump_unsupported = 1 lsl 11
let sf_lock_lost = 1 lsl 12
let cap_hardened_tier = 1 lsl 0
let cap_can_lock = 1 lsl 1
let cap_can_nodump = 1 lsl 2
let cap_can_wipeonfork = 1 lsl 3
let cap_os_random = 1 lsl 4
let cap_atfork = 1 lsl 5
let has f bit = f land bit <> 0

(* ---- helpers -------------------------------------------------------------- *)

let check_rc name = function
  | 0 -> ()
  | -1 -> raise Destroyed
  | -2 -> invalid_arg name
  | _ -> invalid_arg name

let flags_of_hardened hardened = if hardened then sf_hardened_req else 0

(* ---- construction ----------------------------------------------------------- *)

let create ?(hardened = false) n =
  if n < 0 then invalid_arg "Secret.create: negative length";
  create_c n (flags_of_hardened hardened)

let length t = length_c t
let is_destroyed t = is_destroyed_c t
let destroy t = destroy_c t

(* ---- scratch buffers ---------------------------------------------------------- *)

module Scratch = struct
  let create n =
    if n < 0 then invalid_arg "Secret.Scratch.create: negative length";
    alloc_major_bytes_c n

  let wipe b = wipe_bytes_c b

  let with_ n f =
    let b = create n in
    match f b with
    | r ->
        wipe b;
        r
    | exception e ->
        wipe b;
        raise e

  let is_young b = is_young_c b
end

(* ---- views -------------------------------------------------------------------- *)

module Unsafe = struct
  let keep_alive t = ignore (Sys.opaque_identity t)

  let scoped_string_view t =
    if is_destroyed_c t then raise Destroyed;
    scoped_view_c t

  let string_view t =
    if is_destroyed_c t then raise Destroyed;
    view_c t

  let bytes_view t = Bytes.unsafe_of_string (string_view t)

  let with_string_view t f =
    let view = scoped_string_view t in
    Fun.protect ~finally:(fun () -> keep_alive t) (fun () -> f view)

  let with_bytes_view t f =
    let view = Bytes.unsafe_of_string (scoped_string_view t) in
    Fun.protect ~finally:(fun () -> keep_alive t) (fun () -> f view)

  let init ?hardened n f =
    let t = create ?hardened n in
    (match f (Bytes.unsafe_of_string (scoped_string_view t)) with
    | () -> ()
    | exception e ->
        destroy t;
        raise e);
    t

  type nonrec bigstring = bigstring

  let with_bigstring t f =
    if is_destroyed_c t then raise Destroyed;
    let ba = bigstring_view_c t in
    Fun.protect
      ~finally:(fun () ->
        Fun.protect
          ~finally:(fun () -> keep_alive t)
          (fun () -> revoke_bigstring_c ba))
      (fun () -> f ba)
end

(* ---- construction (continued) ---------------------------------------------------- *)

let init ?hardened n f =
  Scratch.with_ n (fun b ->
      f b;
      let t = create ?hardened n in
      match
        check_rc "Secret.init"
          (blit_from_string_c (Bytes.unsafe_to_string b) 0 t 0 n)
      with
      | () -> t
      | exception e ->
          destroy t;
          raise e)

let entropy_source : (bytes -> unit) option Atomic.t = Atomic.make None
let set_entropy_source f = Atomic.set entropy_source (Some f)

let random ?hardened n =
  let t = create ?hardened n in
  (match fill_random_c t with
  | 0 -> ()
  | -1 -> (
      match Atomic.get entropy_source with
      | None ->
          destroy t;
          raise Entropy_unavailable
      | Some gen -> (
          let b = Scratch.create n in
          match
            gen b;
            check_rc "Secret.random"
              (blit_from_string_c (Bytes.unsafe_to_string b) 0 t 0 n)
          with
          | () -> Scratch.wipe b
          | exception e ->
              Scratch.wipe b;
              destroy t;
              raise e))
  | -2 ->
      destroy t;
      raise Destroyed
  | errno ->
      destroy t;
      raise
        (Sys_error
           (Printf.sprintf "Secret.random: OS entropy failed (errno %d)" errno)));
  t

let of_string ?hardened s =
  let n = String.length s in
  let t = create ?hardened n in
  check_rc "Secret.of_string" (blit_from_string_c s 0 t 0 n);
  t

let of_bytes ?hardened ~wipe_source b =
  let copy () =
    let n = Bytes.length b in
    let t = create ?hardened n in
    check_rc "Secret.of_bytes"
      (blit_from_string_c (Bytes.unsafe_to_string b) 0 t 0 n);
    t
  in
  if wipe_source then Fun.protect ~finally:(fun () -> wipe_bytes_c b) copy
  else copy ()

let with_secret ?hardened n f =
  let t = create ?hardened n in
  match f t with
  | r ->
      destroy t;
      r
  | exception e ->
      destroy t;
      raise e

let with_random ?hardened n f =
  let t = random ?hardened n in
  match f t with
  | r ->
      destroy t;
      r
  | exception e ->
      destroy t;
      raise e

(* ---- inspection ------------------------------------------------------------------- *)

(* Branch-free on the result: [r = 1] compiles to a compare + conditional
   set, so the wrapper adds no result-dependent timing of its own (the
   never-taken [Destroyed] check is predicted identically for both outcomes). *)
let equal a b =
  let r = equal_c a b in
  if r > 1 then raise Destroyed;
  r = 1

let equal_string a s =
  let r = equal_string_c a s in
  if r > 1 then raise Destroyed;
  r = 1

let pp ppf t =
  if is_destroyed_c t then Format.pp_print_string ppf "<secret:destroyed>"
  else Format.fprintf ppf "<secret:%dB>" (length_c t)

type lock =
  [ `Locked | `Failed of int | `Lost_on_fork | `Unsupported | `Not_requested ]

type status = {
  page_backed : bool;
  guard_pages : bool;
  canary : bool;
  lock : lock;
  no_core_dump : [ `Yes | `Unsupported | `Not_requested ];
  wipe_on_fork : bool;
  viewed : bool;
  destroyed : bool;
}

type hardening_requirement =
  [ `Page_backed
  | `Guard_pages
  | `Canary
  | `Locked
  | `No_core_dump
  | `Wipe_on_fork ]

exception Hardening_unavailable of hardening_requirement

let status t =
  let f = status_c t in
  let requested = has f sf_hardened_req in
  let page_backed = has f sf_page_backed in
  let lock : lock =
    if not requested then `Not_requested
    else if not page_backed then
      if has f sf_lock_unsupported then `Unsupported
      else `Failed (lock_errno_c t)
    else if has f sf_lock_unsupported then `Unsupported
    else if has f sf_lock_lost then `Lost_on_fork
    else if has f sf_locked then `Locked
    else `Failed (lock_errno_c t)
  in
  let no_core_dump =
    if not requested then `Not_requested
    else if has f sf_nodump then `Yes
    else if has f sf_nodump_unsupported || not page_backed then `Unsupported
    else `Unsupported
  in
  {
    page_backed;
    guard_pages = has f sf_guarded;
    canary = has f sf_canary;
    lock;
    no_core_dump;
    wipe_on_fork = has f sf_wipeonfork;
    viewed = has f sf_viewed;
    destroyed = has f sf_destroyed;
  }

let require_hardening requirements t =
  let st = status t in
  if st.destroyed then raise Destroyed;
  let met = function
    | `Page_backed -> st.page_backed
    | `Guard_pages -> st.guard_pages
    | `Canary -> st.canary
    | `Locked -> st.lock = `Locked
    | `No_core_dump -> st.no_core_dump = `Yes
    | `Wipe_on_fork -> st.wipe_on_fork
  in
  match
    List.find_opt (fun requirement -> not (met requirement)) requirements
  with
  | None -> t
  | Some requirement ->
      destroy t;
      raise (Hardening_unavailable requirement)

type capabilities = {
  hardened_tier : bool;
  can_lock : bool;
  can_exclude_from_dumps : bool;
  can_wipe_on_fork : bool;
  os_random : bool;
  atfork : bool;
  zeroize_primitive : string;
  page_size : int;
}

let capabilities () =
  let c = capabilities_c () in
  {
    hardened_tier = has c cap_hardened_tier;
    can_lock = has c cap_can_lock;
    can_exclude_from_dumps = has c cap_can_nodump;
    can_wipe_on_fork = has c cap_can_wipeonfork;
    os_random = has c cap_os_random;
    atfork = has c cap_atfork;
    zeroize_primitive = zeroize_name_c ();
    page_size = page_size_c ();
  }

(* ---- mutation ------------------------------------------------------------------------ *)

let fill t c = check_rc "Secret.fill" (fill_c t c)
let zero t = check_rc "Secret.zero" (zero_c t)

let blit ~src ~src_off ~dst ~dst_off ~len =
  check_rc "Secret.blit" (blit_c src src_off dst dst_off len)

let blit_from_string s ~src_off t ~dst_off ~len =
  check_rc "Secret.blit_from_string"
    (blit_from_string_c s src_off t dst_off len)

let blit_from_bytes b ~src_off t ~dst_off ~len =
  blit_from_string (Bytes.unsafe_to_string b) ~src_off t ~dst_off ~len

let blit_to_bytes t ~src_off b ~dst_off ~len =
  check_rc "Secret.blit_to_bytes" (blit_to_bytes_c t src_off b dst_off len)

let hardened_of t =
  let f = status_c t in
  has f sf_hardened_req

let sub ?hardened t ~off ~len =
  if is_destroyed_c t then raise Destroyed;
  if off < 0 || len < 0 || off > length_c t - len then invalid_arg "Secret.sub";
  let hardened = match hardened with Some h -> h | None -> hardened_of t in
  let r = create ~hardened len in
  match check_rc "Secret.sub" (blit_c t off r 0 len) with
  | () -> r
  | exception e ->
      destroy r;
      raise e

let copy ?hardened t = sub ?hardened t ~off:0 ~len:(length_c t)

(* ---- exposure ------------------------------------------------------------------------- *)

let expose t f =
  let n = length_c t in
  let b = Scratch.create n in
  match
    check_rc "Secret.expose" (blit_to_bytes_c t 0 b 0 n);
    f b
  with
  | r ->
      Scratch.wipe b;
      r
  | exception e ->
      Scratch.wipe b;
      raise e

let unsafe_to_string t =
  let n = length_c t in
  let b = Scratch.create n in
  check_rc "Secret.unsafe_to_string" (blit_to_bytes_c t 0 b 0 n);
  Bytes.unsafe_to_string b

(* ---- gc / process ----------------------------------------------------------------------- *)

module Gc = struct
  let scrub_minor_heap () = scrub_minor_heap_c ()
end

module Process = struct
  type feature = [ `No_core_dump | `Not_dumpable | `Lock_all | `Deny_attach ]
  type outcome = (unit, [ `Unsupported | `Failed of int ]) result

  let code = function
    | `No_core_dump -> 0
    | `Not_dumpable -> 1
    | `Lock_all -> 2
    | `Deny_attach -> 3

  let apply feat : outcome =
    match process_feature_c (code feat) with
    | 0 -> Ok ()
    | -1 -> Error `Unsupported
    | errno -> Error (`Failed errno)

  let harden ?(features = [ `No_core_dump; `Not_dumpable; `Deny_attach ]) () =
    List.map (fun f -> (f, apply f)) features

  let scrub_env name = scrub_env_c name = 1
end

let wipe_all () = wipe_all_c ()
let live_count () = live_count_c ()
let pool_count () = pool_count_c ()
let parked_count () = parked_count_c ()

let set_fork_policy p =
  set_fork_policy_c (match p with `Keep -> false | `Wipe_in_child -> true)

let after_fork () = after_fork_c ()

let () =
  init_c ();
  at_exit wipe_all
