(** Secrets and file descriptors.

    [Unix.read] copies through a 64 KiB buffer on the C stack and [In_channel]
    through a 64 KiB heap-allocated channel buffer; neither copy is ever
    zeroized. The functions here call [read(2)]/[write(2)] directly on the
    secret memory. The kernel page cache keeps its own copy of any file that was
    read; that is outside this library's reach. *)

val read : Unix.file_descr -> Secret.t -> off:int -> len:int -> int
(** [read fd t ~off ~len] reads at most [len] bytes into [t] at [off] with a
    single [read(2)] (retried on [EINTR]) and returns the number of bytes read
    (0 at end of file). Raises [Unix.Unix_error] on I/O errors and
    [Invalid_argument] on bounds errors. The caller must not mutate or destroy
    [t], or call {!Secret.wipe_all}, while the read is in flight.
    @raise Secret.Destroyed *)

val read_exactly : Unix.file_descr -> Secret.t -> off:int -> len:int -> unit
(** Loops until [len] bytes were read. Raises [End_of_file] if the descriptor is
    exhausted first. *)

val read_fd : ?hardened:bool -> Unix.file_descr -> int -> Secret.t
(** [read_fd fd n] reads up to [n] bytes into a new secret (looping on short
    reads until [n] bytes or end of file). The result has the number of bytes
    actually read as its length. A partially filled secret is destroyed if
    reading or sizing the result raises. *)

val read_file : ?hardened:bool -> ?max:int -> string -> Secret.t
(** [read_file path] opens [path] read-only ([O_CLOEXEC]), reads at most [max]
    bytes (default: the file size from [fstat], or 1 MiB for non-regular files)
    into a new secret and closes the descriptor. If closing the descriptor
    raises, the result is destroyed before the error escapes. Raises
    [Unix.Unix_error] on I/O errors. *)

val write : Unix.file_descr -> Secret.t -> off:int -> len:int -> int
(** A single [write(2)] from the secret memory; returns the bytes written. The
    caller must not mutate or destroy the secret, or call {!Secret.wipe_all},
    while the write is in flight. *)

val write_all : Unix.file_descr -> Secret.t -> unit
(** Writes the whole secret, looping on short writes. *)
