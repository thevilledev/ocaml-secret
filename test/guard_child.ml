(* Child process that corrupts memory on purpose. Expected to die. *)

let round_up n m = (n + m - 1) / m * m

let () =
  let mode = Sys.argv.(1) in
  let len = 48 in
  let t = Secret.create ~hardened:true len in
  let st = Secret.status t in
  if not st.Secret.page_backed then begin
    print_endline "skip";
    exit 0
  end;
  Secret.fill t 'g';
  let page = (Secret.capabilities ()).Secret.page_size in
  let bsz = (len + 8) / 8 * 8 in
  let inner = round_up (16 + bsz) page in
  print_endline "armed";
  (match mode with
  | "overflow" -> ignore (Helpers.poke t bsz)           (* first byte of trailing guard *)
  | "underflow" -> ignore (Helpers.poke t (-(inner - bsz) - 1)) (* last byte of leading guard *)
  | "canary" ->
      ignore (Helpers.poke t (-16));
      Secret.destroy t
  | "inbounds" ->
      ignore (Helpers.poke t (bsz - 1));               (* padding byte: harmless *)
      Secret.destroy t
  | _ -> exit 99);
  print_endline "survived"
