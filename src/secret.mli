(** Secret key material kept outside the OCaml heap.

    A {!t} owns a fixed-length byte buffer allocated in C memory. The bytes
    never reside in the OCaml heap, so the garbage collector cannot copy them
    (minor-to-major promotion and compaction copy heap blocks and leave the
    old copy behind, unzeroed). The buffer is zeroized when {!destroy} is
    called, when the handle is garbage-collected, and at normal program exit
    ({!wipe_all} is registered with [Stdlib.at_exit]).

    {2 What this module guarantees}

    - The payload is never copied by the GC and is not reachable through
      polymorphic [compare], [Hashtbl.hash] or [Marshal] ([compare] and
      [Marshal] raise [Invalid_argument]; [Hashtbl.hash] ignores the contents).
    - The payload is overwritten with zeros, using a primitive the C compiler
      cannot elide, on {!destroy}, on garbage collection of the handle and on
      normal exit, {i before} its memory is ever reused.
    - {!equal} runs in time that depends only on the lengths.
    - Secret bytes reach OCaml values only through the functions of this
      module whose names contain [expose], [unsafe] or [view]; grep for them.

    {2 What this module does not (and cannot) guarantee}

    - Copies spilled to the C stack or registers inside cryptographic
      primitives, or made by the kernel (page cache, socket buffers,
      hibernation images), or made by callers through [expose]/[unsafe_*].
    - Key-equivalent data kept by libraries that take [string] keys and build
      their own key schedules in the OCaml heap.
    - Zeroization when the process dies by a signal, [Unix._exit] or a runtime
      fatal error: no handler runs.
    - [mlock]/core-dump exclusion are best effort: they depend on resource
      limits and on the platform (no core-dump exclusion on macOS) and their
      outcome is reported by {!val-status}, never assumed.
    - Protection against a root user, [ptrace], cold-boot attacks, or a
      compromised kernel or hypervisor. *)

type t
(** A secret. Values of this type cannot be compared, hashed or marshalled.
    A [t] may be used from any domain. Calling {!destroy} concurrently with
    another operation on the same [t] from another domain is a programming
    error (as it is for [Bytes]); calling {!destroy} twice is always safe. *)

exception Destroyed
(** Raised by every operation that reads or writes a secret after
    {!destroy} (or after {!wipe_all}). Never a crash. *)

exception Entropy_unavailable
(** Raised by {!random} when the OS has no entropy source (for example on
    MirageOS) and no fallback was installed with {!set_entropy_source}. *)

(** {1 Construction} *)

val create : ?hardened:bool -> int -> t
(** [create ?hardened n] is a zero-filled secret of [n] bytes ([n >= 0]).

    [hardened] (default [false]) requests the page-backed tier: guard pages,
    a canary, [mlock], and exclusion from core dumps where the OS supports
    it. Each feature is {e best effort}; check {!val-status}. Cost: at least three
    OS pages of address space per secret. The default tier uses [calloc]
    memory with zero-on-release and is meant for many small or short-lived
    keys.

    @raise Invalid_argument if [n < 0].
    @raise Out_of_memory if the C allocation fails. *)

val random : ?hardened:bool -> int -> t
(** [random ?hardened n] is a secret of [n] bytes of OS entropy
    ([getrandom]/[getentropy]/[BCryptGenRandom]) written directly into the
    secret memory; no copy is made in the OCaml heap. When the platform has
    no OS source, the generator installed with {!set_entropy_source} is used
    (it writes into a {!Scratch} buffer that is wiped afterwards).

    @raise Entropy_unavailable when no source is available. *)

val of_string : ?hardened:bool -> string -> t
(** [of_string s] copies [s] into a new secret. The source string is
    immutable and {b cannot be wiped}: it stays in the OCaml heap until
    collected. Prefer {!random}, {!init}, {!of_bytes} or [Secret_unix.read_fd]
    when the secret can originate in controlled memory. *)

val of_bytes : ?hardened:bool -> wipe_source:bool -> bytes -> t
(** [of_bytes ~wipe_source b] copies [b]. With [~wipe_source:true] the source
    is zeroized afterwards with the same primitive as {!destroy}. This cannot
    reach copies the GC may already have made of [b] (a [bytes] allocated in
    the minor heap is copied when promoted); use {!Scratch} buffers to avoid
    that. *)

val init : ?hardened:bool -> int -> (bytes -> unit) -> t
(** [init n f] creates a secret of [n] bytes and calls [f] with a zero-copy
    mutable view of its memory so that a producer (a PRNG, a KDF, a decoder)
    can fill it in place. [f] must not retain the view. *)

val with_secret : ?hardened:bool -> int -> (t -> 'a) -> 'a
(** [with_secret n f] is [f (create n)]; the secret is destroyed when [f]
    returns or raises. *)

(** {1 Inspection} *)

val length : t -> int
(** Length in bytes. The length is not considered secret. Usable after
    {!destroy}. *)

val is_destroyed : t -> bool

val equal : t -> t -> bool
(** Constant-time equality of the contents (implemented in C). Lengths are
    compared first with an ordinary branch; the contents comparison takes
    time proportional to the length and independent of the values. There is
    deliberately no [compare] and no [hash].
    @raise Destroyed if either argument is destroyed. *)

val equal_string : t -> string -> bool
(** Same as {!equal} against an OCaml string (e.g. a received MAC tag). *)

val pp : Format.formatter -> t -> unit
(** Prints [<secret:32B>] or [<secret:destroyed>], never the contents. *)

type lock =
  [ `Locked  (** pages are locked in RAM *)
  | `Failed of int  (** [mlock] failed with this errno ([ENOMEM]: [RLIMIT_MEMLOCK]; [EPERM]: no [IPC_LOCK]) *)
  | `Lost_on_fork  (** locked before a [fork]; locks are not inherited, see {!after_fork} *)
  | `Unsupported  (** this platform cannot lock pages *)
  | `Not_requested  (** the secret is not hardened *) ]

type status = {
  page_backed : bool;  (** the hardened tier was actually obtained *)
  guard_pages : bool;
  canary : bool;
  lock : lock;
  no_core_dump : [ `Yes | `Unsupported | `Not_requested ];
  wipe_on_fork : bool;
  viewed : bool;  (** an unscoped view was handed out *)
  destroyed : bool;
}

val status : t -> status
(** Never raises; usable after {!destroy}. *)

type capabilities = {
  hardened_tier : bool;
  can_lock : bool;
  can_exclude_from_dumps : bool;
  can_wipe_on_fork : bool;
  os_random : bool;
  atfork : bool;
  zeroize_primitive : string;  (** e.g. ["explicit_bzero"] *)
  page_size : int;
}

val capabilities : unit -> capabilities
(** What this build and platform can provide. The per-value truth is
    {!val-status}. *)

(** {1 Mutation} *)

val fill : t -> char -> unit
val zero : t -> unit
(** [zero t] zeroizes the contents; [t] stays alive. *)

val blit : src:t -> src_off:int -> dst:t -> dst_off:int -> len:int -> unit
(** [memmove] between secrets.
    @raise Invalid_argument on bounds errors.
    @raise Destroyed *)

val blit_from_string : string -> src_off:int -> t -> dst_off:int -> len:int -> unit
val blit_from_bytes : bytes -> src_off:int -> t -> dst_off:int -> len:int -> unit

val sub : ?hardened:bool -> t -> off:int -> len:int -> t
(** A {e copy} of a range (never an alias). Tier defaults to that of the
    source. *)

val copy : ?hardened:bool -> t -> t

val destroy : t -> unit
(** Zeroizes the contents now and releases the memory (the memory is pooled
    for other secrets in a bounded reuse cache, never handed back to the C
    allocator while an unscoped view could exist). Idempotent. After this
    every accessor raises {!Destroyed}.
    Destroy secrets as soon as they are no longer needed: relying on the GC
    delays the wipe until the handle is collected. *)

(** {1 Controlled exposure}

    These are the only ways to get secret bytes into OCaml values. *)

val expose : t -> (bytes -> 'a) -> 'a
(** [expose t f] calls [f] with a temporary copy of the contents in a
    {!Scratch} buffer (allocated directly in the major heap, so the minor
    collector never duplicates it) and zeroizes the buffer when [f] returns
    or raises. [f] must not retain the buffer. Anything [f] does with the
    bytes ([Bytes.to_string], [Buffer.add_bytes], passing them to a
    [string]-keyed API) creates copies this module cannot wipe.
    @raise Destroyed *)

val blit_to_bytes : t -> src_off:int -> bytes -> dst_off:int -> len:int -> unit
(** Copies into a caller-owned buffer (ideally a {!Scratch} buffer). *)

val unsafe_to_string : t -> string
(** A fresh immutable copy that lives in the OCaml heap until collected and
    {b cannot be wiped}. Only for legacy APIs that retain their key argument.
    Allocated in the major heap to avoid promotion copies. *)

(** Zero-copy views of the secret memory.

    A view is an ordinary OCaml [string]/[bytes]/bigarray whose bytes are the
    secret memory itself (the block carries a valid OCaml header outside the
    heap, a representation the runtime supports and uses for static data).
    Any existing API that takes a [string] or [bytes] — including C stubs
    using [String_val] — can therefore work on secret memory without a copy.

    Rules: a view is valid only while its owner [t] is alive; after
    {!destroy} it reads as zeros. Store an unscoped view only next to its
    owner so the owner stays reachable. The bytes of a view that escapes its
    owner's lifetime are never unmapped or given to the C allocator (they may
    be reused for another secret), so a stale view cannot crash the program,
    but it could observe another secret: that is a bug in the caller. Views
    are exempt from none of the copy hazards of ordinary strings
    ([String.sub], [^], [compare], [Marshal] all copy).

    OCaml 4.14: the 4.x runtime classifies out-of-heap blocks by page table,
    so polymorphic [compare]/[=], [Hashtbl.hash] and [Marshal] treat a view
    as a foreign pointer (address comparison, [Marshal] fails). [String.equal],
    every [String]/[Bytes] function and C stubs using [String_val] work the
    same on both 4.14 and 5.x. *)
module Unsafe : sig
  val string_view : t -> string
  (** Zero-copy [string] view. Marks [t] as viewed (see {!val-status}).
      @raise Destroyed *)

  val bytes_view : t -> bytes
  (** Zero-copy mutable view; writes go to the secret memory.
      @raise Destroyed *)

  val with_string_view : t -> (string -> 'a) -> 'a
  (** Scoped variant; the view must not escape [f]. *)

  val with_bytes_view : t -> (bytes -> 'a) -> 'a

  type bigstring =
    (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

  val with_bigstring : t -> (bigstring -> 'a) -> 'a
  (** Borrowed bigarray view for the duration of [f] (for [Eqaf_bigstring],
      [Digestif.*.digest_bigstring], ...). After [f] the view is revoked
      (length 0; accesses raise [Invalid_argument]). Sub-views created with
      [Bigarray.Array1.sub] inside [f] cannot be revoked and must not escape.
      The secret must not be destroyed during [f]. *)
end

(** Scratch buffers allocated directly in the major heap. *)
module Scratch : sig
  val create : int -> bytes
  (** A zero-filled [bytes] allocated directly in the major heap regardless
      of its size, so it is never copied by a minor collection (only an
      explicit [Gc.compact] can move it). Wipe it with {!wipe} before
      dropping it. *)

  val wipe : bytes -> unit
  (** Zeroizes any [bytes] with the platform's explicit zeroization primitive.
      It cannot reach copies the GC already made of an ordinary minor-heap
      [bytes]. *)

  val with_ : int -> (bytes -> 'a) -> 'a
  (** [with_ n f] calls [f] with a fresh scratch buffer and wipes it when [f]
      returns or raises. *)

  val is_young : bytes -> bool
  (** Whether the block currently lives in the minor heap (diagnostics). *)
end

(** Best-effort GC hygiene. *)
module Gc : sig
  val scrub_minor_heap : unit -> unit
  (** Runs a minor collection and then zeroes the free part of the calling
      domain's minor heap, erasing the residue of every object that died
      young (handshake transients, KDF intermediates, scratch buffers) in
      this domain. Cost: one minor collection plus a [memset] of the minor
      heap (256k words by default). Other domains' minor heaps are not
      touched. Relies on documented runtime invariants of the domain state;
      it is hygiene, not a guarantee. *)
end

(** Process-wide hardening. Every feature reports its outcome; nothing is
    silent. *)
module Process : sig
  type feature =
    [ `No_core_dump  (** [setrlimit(RLIMIT_CORE, 0)] *)
    | `Not_dumpable  (** Linux [prctl(PR_SET_DUMPABLE, 0)]: no core dumps, no [ptrace] by non-root, [/proc/pid/mem] hidden *)
    | `Lock_all  (** [mlockall(MCL_CURRENT|MCL_FUTURE)]: no swapping of any page; subject to [RLIMIT_MEMLOCK] *)
    | `Deny_attach  (** macOS [ptrace(PT_DENY_ATTACH)] *) ]

  type outcome = (unit, [ `Unsupported | `Failed of int ]) result

  val harden : ?features:feature list -> unit -> (feature * outcome) list
  (** Applies the requested features (default: [`No_core_dump],
      [`Not_dumpable], [`Deny_attach]; [`Lock_all] is opt-in because it can
      fail or pin the whole heap) and returns what happened for each. *)

  val scrub_env : string -> bool
  (** [scrub_env name] zeroizes the value of the environment variable [name]
      in the process's [environ] block and removes the variable. Returns
      whether it was found. Copies already made by [Sys.getenv] are ordinary
      OCaml strings and are not affected. *)
end

(** {1 Process-level controls} *)

val wipe_all : unit -> unit
(** Destroys every live secret in the process. Registered with
    [Stdlib.at_exit] at module initialisation, so it runs after all handlers
    registered later (i.e. after every handler of code that uses this
    module). Does not run on [Unix._exit], signals or runtime fatal errors;
    call it from your own signal handler if needed. Other domains using a
    secret at the same time observe either {!Destroyed} or zeroed contents.
    To keep those in-flight accesses memory-safe, wiped storage is released
    when its owning handle is finalized. *)

val live_count : unit -> int
(** Number of secrets whose memory has not been released (diagnostics). *)

val pool_count : unit -> int
(** Number of released payload blocks held in the reuse pool (diagnostics). *)

val set_entropy_source : (bytes -> unit) -> unit
(** Fallback generator used by {!random} when [(capabilities ()).os_random]
    is [false] (MirageOS). The callback must fill the whole buffer, which is
    a {!Scratch} buffer wiped afterwards, e.g.
    [set_entropy_source (fun b -> Mirage_crypto_rng.generate_into b (Bytes.length b))]. *)

val set_fork_policy : [ `Keep | `Wipe_in_child ] -> unit
(** POSIX only (no-op elsewhere). [`Keep] (default): the child inherits
    copies of all secrets; memory locks are lost (see {!after_fork}).
    [`Wipe_in_child]: an [atfork] child handler zeroizes every secret in the
    child; on Linux, live and subsequently created hardened secrets also get
    [MADV_WIPEONFORK]. Switching back to [`Keep] revokes that advice. *)

val after_fork : unit -> unit
(** Call in a forked child to re-establish [mlock] on hardened secrets. *)
