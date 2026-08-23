external read_c : Unix.file_descr -> Secret.t -> int -> int -> int = "secret_unix_read"
external write_c : Unix.file_descr -> Secret.t -> int -> int -> int = "secret_unix_write"

let decode = function -1 -> raise Secret.Destroyed | r -> r
let read fd t ~off ~len = decode (read_c fd t off len)
let write fd t ~off ~len = decode (write_c fd t off len)

let read_exactly fd t ~off ~len =
  let rec go off len =
    if len > 0 then begin
      let n = read fd t ~off ~len in
      if n = 0 then raise End_of_file;
      go (off + n) (len - n)
    end
  in
  go off len

let read_fd ?hardened fd n =
  if n < 0 then invalid_arg "Secret_unix.read_fd";
  let t = Secret.create ?hardened n in
  let rec go off =
    if off < n then
      let r = read fd t ~off ~len:(n - off) in
      if r = 0 then off else go (off + r)
    else off
  in
  let got = go 0 in
  if got = n then t
  else begin
    let r = Secret.sub t ~off:0 ~len:got in
    Secret.destroy t;
    r
  end

let read_file ?hardened ?max path =
  let fd = Unix.openfile path [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 in
  Fun.protect
    ~finally:(fun () -> Unix.close fd)
    (fun () ->
      let n =
        match max with
        | Some m -> m
        | None -> (
            let st = Unix.fstat fd in
            match st.Unix.st_kind with
            | Unix.S_REG -> st.Unix.st_size
            | _ -> 1 lsl 20)
      in
      read_fd ?hardened fd n)

let write_all fd t =
  let n = Secret.length t in
  let rec go off =
    if off < n then
      let w = write fd t ~off ~len:(n - off) in
      go (off + w)
  in
  go 0
