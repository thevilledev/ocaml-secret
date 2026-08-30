(* A downstream compatibility proof for mirage-crypto 2.4.0.

   AES.GCM.of_secret expands the raw key, so the Secret view only has to live
   for key setup. Mirage_crypto.Chacha20.of_secret retains its string argument,
   so the entire operation has to stay inside the scoped view. *)

let fail name = failwith ("mirage-crypto proof: " ^ name)
let check name condition = if not condition then fail name

let hex_value = function
  | '0' .. '9' as c -> Char.code c - Char.code '0'
  | 'a' .. 'f' as c -> Char.code c - Char.code 'a' + 10
  | 'A' .. 'F' as c -> Char.code c - Char.code 'A' + 10
  | _ -> invalid_arg "hex_value"

let hex s =
  let len = String.length s in
  if len mod 2 <> 0 then invalid_arg "hex";
  String.init (len / 2) (fun i ->
      Char.chr ((hex_value s.[2 * i] lsl 4) lor hex_value s.[(2 * i) + 1]))

module Migrated = struct
  let aes_gcm_key secret =
    Secret.Unsafe.with_string_view secret Mirage_crypto.AES.GCM.of_secret

  let chacha20_encrypt ~key ~nonce ?adata plaintext =
    Secret.Unsafe.with_string_view key (fun raw ->
        let key = Mirage_crypto.Chacha20.of_secret raw in
        Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ?adata plaintext)
end

let prove_aes_gcm () =
  (* NIST SP 800-38D, AES-256-GCM: zero key, IV, and one-block plaintext. *)
  let nonce = String.make 12 '\000' in
  let plaintext = String.make 16 '\000' in
  let expected =
    hex "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
  in
  let baseline_key = Mirage_crypto.AES.GCM.of_secret (String.make 32 '\000') in
  let baseline =
    Mirage_crypto.AES.GCM.authenticate_encrypt ~key:baseline_key ~nonce
      plaintext
  in
  let raw_key = Secret.create 32 in
  let migrated_key = Migrated.aes_gcm_key raw_key in
  check "AES setup used an unscoped view" (not (Secret.status raw_key).viewed);
  let migrated =
    Mirage_crypto.AES.GCM.authenticate_encrypt ~key:migrated_key ~nonce
      plaintext
  in
  check "AES baseline does not match the NIST vector" (baseline = expected);
  check "AES migrated output differs from the baseline" (migrated = baseline);
  Secret.destroy raw_key;
  check "AES raw key owner was not destroyed" (Secret.is_destroyed raw_key);
  print_endline "  AES-256-GCM: NIST vector and legacy equivalence: ok"

let prove_aes_schedule_lifetime () =
  let raw_key =
    Secret.Unsafe.init 32 (fun bytes ->
        for i = 0 to Bytes.length bytes - 1 do
          Bytes.set bytes i (Char.chr (i + 1))
        done)
  in
  let nonce = String.init 12 (fun i -> Char.chr (0xa0 + i)) in
  let plaintext = "the AES schedule must own its derived state" in
  let migrated_key = Migrated.aes_gcm_key raw_key in
  let before_destroy =
    Mirage_crypto.AES.GCM.authenticate_encrypt ~key:migrated_key ~nonce
      plaintext
  in
  let baseline_key =
    Mirage_crypto.AES.GCM.of_secret (String.init 32 (fun i -> Char.chr (i + 1)))
  in
  let baseline =
    Mirage_crypto.AES.GCM.authenticate_encrypt ~key:baseline_key ~nonce
      plaintext
  in
  check "AES nonzero-key migrated output differs from the baseline"
    (before_destroy = baseline);
  Secret.destroy raw_key;
  let after_destroy =
    Mirage_crypto.AES.GCM.authenticate_encrypt ~key:migrated_key ~nonce
      plaintext
  in
  check "AES schedule retained the destroyed raw-key view"
    (after_destroy = before_destroy);
  print_endline "  AES nonzero raw-key owner destroyed after key setup: ok"

let prove_invalid_aes_key () =
  let raw_key = Secret.create 31 in
  let rejected =
    match Migrated.aes_gcm_key raw_key with
    | _ -> false
    | exception Invalid_argument _ -> true
  in
  check "AES accepted a 31-byte key" rejected;
  check "failed AES setup destroyed its caller-owned secret"
    (not (Secret.is_destroyed raw_key));
  check "failed AES setup retained an unscoped view"
    (not (Secret.status raw_key).viewed);
  Secret.destroy raw_key;
  print_endline "  AES invalid-key cleanup and ownership: ok"

let prove_chacha20 () =
  let nonce = String.make 12 '\000' in
  let plaintext = "the operation owns the borrow" in
  let baseline_key = Mirage_crypto.Chacha20.of_secret (String.make 32 '\000') in
  let baseline =
    Mirage_crypto.Chacha20.authenticate_encrypt ~key:baseline_key ~nonce
      plaintext
  in
  let raw_key = Secret.create 32 in
  let migrated = Migrated.chacha20_encrypt ~key:raw_key ~nonce plaintext in
  check "ChaCha20 migrated output differs from the baseline"
    (migrated = baseline);
  check "ChaCha20 operation used an unscoped view"
    (not (Secret.status raw_key).viewed);
  Secret.destroy raw_key;
  check "ChaCha20 raw key owner was not destroyed" (Secret.is_destroyed raw_key);
  print_endline "  ChaCha20-Poly1305: operation-scoped equivalence: ok"

let () =
  print_endline "Mirage Crypto downstream compatibility:";
  prove_aes_gcm ();
  prove_aes_schedule_lifetime ();
  prove_invalid_aes_key ();
  prove_chacha20 ()
