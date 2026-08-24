(* Semantics of the Secret API. *)

let check_raises_destroyed name f =
  Alcotest.check_raises name Secret.Destroyed (fun () -> ignore (f ()))

let s_of s = Secret.of_string s

let test_create_length () =
  let t = Secret.create 32 in
  Alcotest.(check int) "length" 32 (Secret.length t);
  Alcotest.(check bool)
    "zero-filled" true
    (Secret.equal_string t (String.make 32 '\000'));
  Alcotest.(check bool) "not destroyed" false (Secret.is_destroyed t);
  let z = Secret.create 0 in
  Alcotest.(check int) "empty" 0 (Secret.length z);
  Alcotest.check_raises "negative"
    (Invalid_argument "Secret.create: negative length") (fun () ->
      ignore (Secret.create (-1)))

let test_of_string_roundtrip () =
  let t = s_of "hello, secret" in
  Alcotest.(check string)
    "unsafe_to_string" "hello, secret"
    (Secret.unsafe_to_string t);
  Alcotest.(check bool)
    "equal_string" true
    (Secret.equal_string t "hello, secret");
  Alcotest.(check bool)
    "equal_string differs" false
    (Secret.equal_string t "hello, Secret");
  Alcotest.(check bool)
    "equal_string length" false
    (Secret.equal_string t "hello")

let test_equal () =
  let a = s_of "0123456789abcdef" and b = s_of "0123456789abcdef" in
  let c = s_of "0123456789abcdeF" and d = s_of "0123456789abcde" in
  Alcotest.(check bool) "equal" true (Secret.equal a b);
  Alcotest.(check bool) "different" false (Secret.equal a c);
  Alcotest.(check bool) "length" false (Secret.equal a d);
  Alcotest.(check bool) "reflexive" true (Secret.equal a a);
  let e1 = Secret.create 0 and e2 = Secret.create 0 in
  Alcotest.(check bool) "empty equal" true (Secret.equal e1 e2)

let test_destroy () =
  let t = s_of "abc" in
  Secret.destroy t;
  Alcotest.(check bool) "is_destroyed" true (Secret.is_destroyed t);
  Alcotest.(check int) "length still valid" 3 (Secret.length t);
  Secret.destroy t;
  check_raises_destroyed "equal" (fun () -> Secret.equal t t);
  check_raises_destroyed "equal_string" (fun () -> Secret.equal_string t "abc");
  check_raises_destroyed "fill" (fun () -> Secret.fill t 'x');
  check_raises_destroyed "zero" (fun () -> Secret.zero t);
  check_raises_destroyed "expose" (fun () -> Secret.expose t (fun _ -> ()));
  check_raises_destroyed "unsafe_to_string" (fun () ->
      Secret.unsafe_to_string t);
  check_raises_destroyed "string_view" (fun () -> Secret.Unsafe.string_view t);
  check_raises_destroyed "with_bigstring" (fun () ->
      Secret.Unsafe.with_bigstring t (fun _ -> ()));
  let live_before_sub = Secret.live_count () in
  check_raises_destroyed "sub" (fun () -> Secret.sub t ~off:0 ~len:1);
  Alcotest.(check int)
    "destroyed sub does not allocate" live_before_sub (Secret.live_count ());
  check_raises_destroyed "blit_to_bytes" (fun () ->
      Secret.blit_to_bytes t ~src_off:0 (Bytes.create 3) ~dst_off:0 ~len:3);
  Alcotest.(check bool)
    "status.destroyed" true (Secret.status t).Secret.destroyed;
  Alcotest.(check string)
    "pp" "<secret:destroyed>"
    (Format.asprintf "%a" Secret.pp t)

let test_pp () =
  let t = s_of "top secret" in
  Alcotest.(check string)
    "pp redacted" "<secret:10B>"
    (Format.asprintf "%a" Secret.pp t)

let test_compare_hash_marshal () =
  let a = s_of "a" and b = s_of "b" in
  (match compare a b with
  | _ -> Alcotest.fail "compare must raise"
  | exception Invalid_argument _ -> ());
  (match a = b with
  | _ -> Alcotest.fail "= must raise"
  | exception Invalid_argument _ -> ());
  (match Marshal.to_string a [] with
  | _ -> Alcotest.fail "Marshal must raise"
  | exception Invalid_argument _ -> ());
  (* Hashtbl.hash ignores custom blocks without a hash function *)
  Alcotest.(check int) "hash ignores contents" (Hashtbl.hash a) (Hashtbl.hash b)

let test_blit_fill_sub () =
  let t = Secret.create 8 in
  Secret.fill t 'x';
  Alcotest.(check string) "fill" "xxxxxxxx" (Secret.unsafe_to_string t);
  Secret.blit_from_string "ABCD" ~src_off:1 t ~dst_off:2 ~len:3;
  Alcotest.(check string)
    "blit_from_string" "xxBCDxxx"
    (Secret.unsafe_to_string t);
  let u = Secret.create 4 in
  Secret.blit ~src:t ~src_off:2 ~dst:u ~dst_off:0 ~len:4;
  Alcotest.(check string) "blit" "BCDx" (Secret.unsafe_to_string u);
  let v = Secret.sub t ~off:2 ~len:3 in
  Alcotest.(check string) "sub" "BCD" (Secret.unsafe_to_string v);
  Secret.fill v 'q';
  Alcotest.(check string) "sub is a copy" "xxBCDxxx" (Secret.unsafe_to_string t);
  let w = Secret.copy t in
  Alcotest.(check bool) "copy equal" true (Secret.equal t w);
  Secret.zero t;
  Alcotest.(check bool)
    "zero" true
    (Secret.equal_string t (String.make 8 '\000'));
  Alcotest.check_raises "sub bounds" (Invalid_argument "Secret.sub") (fun () ->
      ignore (Secret.sub t ~off:6 ~len:3));
  Alcotest.check_raises "blit bounds" (Invalid_argument "Secret.blit")
    (fun () -> Secret.blit ~src:t ~src_off:0 ~dst:u ~dst_off:2 ~len:4);
  let b = Bytes.create 8 in
  Secret.blit_to_bytes w ~src_off:0 b ~dst_off:0 ~len:8;
  Alcotest.(check string) "blit_to_bytes" "xxBCDxxx" (Bytes.to_string b);
  let b2 = Bytes.of_string "zz" in
  Secret.blit_from_bytes b2 ~src_off:0 w ~dst_off:6 ~len:2;
  Alcotest.(check string)
    "blit_from_bytes" "xxBCDxzz"
    (Secret.unsafe_to_string w)

let test_of_bytes_wipe () =
  let b = Bytes.of_string "wipe me please" in
  let t = Secret.of_bytes ~wipe_source:true b in
  Alcotest.(check string) "copied" "wipe me please" (Secret.unsafe_to_string t);
  Alcotest.(check string)
    "source wiped" (String.make 14 '\000') (Bytes.to_string b);
  let b2 = Bytes.of_string "keep" in
  let _ = Secret.of_bytes ~wipe_source:false b2 in
  Alcotest.(check string) "source kept" "keep" (Bytes.to_string b2)

let test_expose () =
  let t = s_of "exposed" in
  let captured = ref (Bytes.create 0) in
  let r =
    Secret.expose t (fun b ->
        captured := b;
        Alcotest.(check bool)
          "scratch not young" false
          (Secret.Scratch.is_young b);
        Bytes.to_string b)
  in
  Alcotest.(check string) "result" "exposed" r;
  Alcotest.(check string)
    "wiped after" (String.make 7 '\000')
    (Bytes.to_string !captured);
  (match Secret.expose t (fun _ -> failwith "boom") with
  | _ -> Alcotest.fail "expected exception"
  | exception Failure _ -> ());
  Alcotest.(check string)
    "wiped after raise" (String.make 7 '\000')
    (Bytes.to_string !captured)

let test_views () =
  let t = s_of "view me" in
  let v = Secret.Unsafe.string_view t in
  Alcotest.(check int) "view length" 7 (String.length v);
  Alcotest.(check string) "view content" "view me" v;
  Alcotest.(check bool) "viewed flag" true (Secret.status t).Secret.viewed;
  (* a mutable view writes through *)
  let bv = Secret.Unsafe.bytes_view t in
  Bytes.set bv 0 'V';
  Alcotest.(check string) "write through" "View me" (Secret.unsafe_to_string t);
  Alcotest.(check string) "string view sees it" "View me" v;
  (* standard string functions work on the view (they copy, as documented) *)
  Alcotest.(check string) "String.sub" "iew" (String.sub v 1 3);
  Alcotest.(check string) "concat" "View me!" (v ^ "!");
  Alcotest.(check bool) "String.equal" true (String.equal v "View me");
  (* OCaml 4.x classifies out-of-heap blocks by page table and hashes /
     compares them as foreign pointers; 5.x hashes the contents. *)
  if Sys.ocaml_version.[0] >= '5' then
    Alcotest.(check int)
      "Hashtbl.hash works" (Hashtbl.hash "View me") (Hashtbl.hash v);
  (* destroy -> view reads zeros, keeps its length, never crashes *)
  Secret.destroy t;
  Alcotest.(check int) "stale view length" 7 (String.length v);
  Alcotest.(check string) "stale view zero" (String.make 7 '\000') v;
  (* scoped views *)
  let u = s_of "scoped" in
  let r =
    Secret.Unsafe.with_string_view u (fun s -> String.uppercase_ascii s)
  in
  Alcotest.(check string) "with_string_view" "SCOPED" r;
  Secret.Unsafe.with_bytes_view u (fun b -> Bytes.set b 0 'S');
  Alcotest.(check string) "with_bytes_view" "Scoped" (Secret.unsafe_to_string u);
  Alcotest.(check bool)
    "scoped views are not retained" false (Secret.status u).Secret.viewed

let test_bigstring_view () =
  let t = s_of "bigstring" in
  let escaped = ref None in
  Secret.Unsafe.with_bigstring t (fun ba ->
      Alcotest.(check int) "dim" 9 (Bigarray.Array1.dim ba);
      Alcotest.(check char) "content" 'b' (Bigarray.Array1.get ba 0);
      Bigarray.Array1.set ba 0 'B';
      escaped := Some ba);
  Alcotest.(check string)
    "write through" "Bigstring"
    (Secret.unsafe_to_string t);
  match !escaped with
  | None -> Alcotest.fail "no view"
  | Some ba ->
      Alcotest.(check int) "revoked dim" 0 (Bigarray.Array1.dim ba);
      Alcotest.check_raises "revoked access"
        (Invalid_argument "index out of bounds") (fun () ->
          ignore (Bigarray.Array1.get ba 0))

let test_init_random () =
  let t = Secret.init 16 (fun b -> Bytes.fill b 0 16 'i') in
  Alcotest.(check string)
    "init" (String.make 16 'i')
    (Secret.unsafe_to_string t);
  Alcotest.(check bool)
    "init view is scoped" false (Secret.status t).Secret.viewed;
  (match Secret.init 4 (fun _ -> failwith "fill failed") with
  | _ -> Alcotest.fail "expected failure"
  | exception Failure _ -> ());
  let caps = Secret.capabilities () in
  if caps.Secret.os_random then begin
    let r1 = Secret.random 32 and r2 = Secret.random 32 in
    Alcotest.(check int) "len" 32 (Secret.length r1);
    Alcotest.(check bool) "random differs" false (Secret.equal r1 r2);
    Alcotest.(check bool)
      "random not zero" false
      (Secret.equal_string r1 (String.make 32 '\000'))
  end;
  (* fallback generator path *)
  let hit = ref false in
  Secret.set_entropy_source (fun b ->
      hit := true;
      Bytes.fill b 0 (Bytes.length b) 'r');
  ignore (Secret.random 8);
  Alcotest.(check bool)
    "fallback used only without OS entropy"
    (not caps.Secret.os_random)
    !hit

let test_with_secret () =
  let leaked = ref None in
  let r =
    Secret.with_secret 4 (fun t ->
        Secret.fill t 'w';
        leaked := Some t;
        Secret.unsafe_to_string t)
  in
  Alcotest.(check string) "result" "wwww" r;
  (match !leaked with
  | Some t ->
      Alcotest.(check bool) "destroyed after" true (Secret.is_destroyed t)
  | None -> Alcotest.fail "no secret");
  (match
     Secret.with_secret 4 (fun t ->
         leaked := Some t;
         failwith "x")
   with
  | _ -> Alcotest.fail "expected exception"
  | exception Failure _ -> ());
  match !leaked with
  | Some t ->
      Alcotest.(check bool) "destroyed after raise" true (Secret.is_destroyed t)
  | None -> Alcotest.fail "no secret"

let test_status_default_tier () =
  let t = s_of "x" in
  let st = Secret.status t in
  Alcotest.(check bool) "not page backed" false st.Secret.page_backed;
  Alcotest.(check bool) "no guards" false st.Secret.guard_pages;
  (match st.Secret.lock with
  | `Not_requested -> ()
  | _ -> Alcotest.fail "lock should be Not_requested");
  (match st.Secret.no_core_dump with
  | `Not_requested -> ()
  | _ -> Alcotest.fail "no_core_dump should be Not_requested");
  Alcotest.(check bool) "not viewed" false st.Secret.viewed

let test_hardened () =
  let caps = Secret.capabilities () in
  let t = Secret.create ~hardened:true 48 in
  Secret.fill t 'h';
  Alcotest.(check string)
    "usable" (String.make 48 'h')
    (Secret.unsafe_to_string t);
  let st = Secret.status t in
  Alcotest.(check bool)
    "page_backed iff supported" caps.Secret.hardened_tier st.Secret.page_backed;
  if st.Secret.page_backed then begin
    Alcotest.(check bool) "guard pages" true st.Secret.guard_pages;
    Alcotest.(check bool) "canary" true st.Secret.canary;
    (match st.Secret.lock with
    | `Locked | `Failed _ -> ()
    | `Unsupported ->
        Alcotest.(check bool)
          "lock unsupported consistent" false caps.Secret.can_lock
    | `Lost_on_fork | `Not_requested -> Alcotest.fail "unexpected lock status");
    match st.Secret.no_core_dump with
    | `Yes ->
        Alcotest.(check bool)
          "nodump cap" true caps.Secret.can_exclude_from_dumps
    | `Unsupported -> ()
    | `Not_requested -> Alcotest.fail "nodump should be reported"
  end;
  (* views of hardened secrets *)
  let v = Secret.Unsafe.string_view t in
  Alcotest.(check string) "hardened view" (String.make 48 'h') v;
  (* sub inherits tier *)
  let u = Secret.sub t ~off:0 ~len:8 in
  Alcotest.(check bool)
    "sub inherits hardened" st.Secret.page_backed
    (Secret.status u).Secret.page_backed;
  Secret.destroy t;
  Alcotest.(check string) "stale hardened view zero" (String.make 48 '\000') v;
  (* pooled reuse of hardened block *)
  let t2 = Secret.create ~hardened:true 48 in
  Alcotest.(check bool)
    "reuse usable" true
    (Secret.equal_string t2 (String.make 48 '\000'));
  Secret.destroy t2;
  Secret.destroy u

let test_pool_size_classes () =
  (* On 32-bit, block sizes are multiples of 4. Indexing the reuse pool by
     bsz/8 aliases 4-byte and 12-byte blocks; filling the larger secret would
     then overflow the smaller allocation. *)
  let t4 = Secret.create 4 in
  Secret.fill t4 'A';
  Secret.destroy t4;
  let t8 = Secret.create 8 in
  Secret.fill t8 'B';
  Alcotest.(check string) "8-byte" "BBBBBBBB" (Secret.unsafe_to_string t8);
  let t9 = Secret.create 9 in
  Secret.fill t9 'C';
  Alcotest.(check string)
    "9-byte" (String.make 9 'C')
    (Secret.unsafe_to_string t9);
  Secret.destroy t8;
  Secret.destroy t9

let test_pool_reuse () =
  let before = Secret.pool_count () in
  let t = Secret.create 100 in
  Secret.fill t 'p';
  Secret.destroy t;
  Alcotest.(check int) "pooled" (before + 1) (Secret.pool_count ());
  let t2 = Secret.create 100 in
  Alcotest.(check int) "reused" before (Secret.pool_count ());
  Alcotest.(check bool)
    "reused block is zero" true
    (Secret.equal_string t2 (String.make 100 '\000'));
  (* a different length in the same size class keeps a valid view length *)
  Secret.destroy t2;
  let t3 = Secret.create 97 in
  Alcotest.(check int)
    "view length follows new owner" 97
    (String.length (Secret.Unsafe.string_view t3));
  Secret.destroy t3

let test_scratch () =
  let b = Secret.Scratch.create 10 in
  Alcotest.(check int) "len" 10 (Bytes.length b);
  Alcotest.(check bool) "major" false (Secret.Scratch.is_young b);
  Alcotest.(check string) "zero" (String.make 10 '\000') (Bytes.to_string b);
  Bytes.fill b 0 10 's';
  Secret.Scratch.wipe b;
  Alcotest.(check string) "wiped" (String.make 10 '\000') (Bytes.to_string b);
  let kept = ref (Bytes.create 0) in
  let r =
    Secret.Scratch.with_ 5 (fun b ->
        kept := b;
        Bytes.fill b 0 5 'k';
        42)
  in
  Alcotest.(check int) "with_ result" 42 r;
  Alcotest.(check string)
    "with_ wiped" (String.make 5 '\000') (Bytes.to_string !kept);
  let big = Secret.Scratch.create 1_000_000 in
  Alcotest.(check int) "big" 1_000_000 (Bytes.length big);
  let tiny = Secret.Scratch.create 0 in
  Alcotest.(check int) "empty" 0 (Bytes.length tiny);
  (* an ordinary small bytes is young by contrast *)
  Alcotest.(check bool)
    "Bytes.create is young" true
    (Secret.Scratch.is_young (Bytes.create 10))

let test_capabilities () =
  let c = Secret.capabilities () in
  Alcotest.(check bool)
    "zeroize primitive named" true
    (String.length c.Secret.zeroize_primitive > 0);
  Alcotest.(check bool) "page size" true (c.Secret.page_size >= 0);
  if Sys.os_type = "Unix" then
    Alcotest.(check bool) "os random on unix" true c.Secret.os_random

let test_process () =
  (* scrub_env: the value is wiped in environ and the variable removed *)
  if Sys.os_type = "Unix" then begin
    Unix.putenv "SECRET_TEST_VAR" "hunter2";
    Alcotest.(check string) "set" "hunter2" (Sys.getenv "SECRET_TEST_VAR");
    Alcotest.(check bool)
      "found" true
      (Secret.Process.scrub_env "SECRET_TEST_VAR");
    Alcotest.(check bool)
      "removed" true
      (Sys.getenv_opt "SECRET_TEST_VAR" = None);
    Alcotest.(check bool)
      "not found twice" false
      (Secret.Process.scrub_env "SECRET_TEST_VAR");
    Alcotest.(check bool)
      "long name is absent" false
      (Secret.Process.scrub_env (String.make 4096 'X'))
  end;
  (* harden reports every feature; No_core_dump is safe to apply in a test *)
  let r = Secret.Process.harden ~features:[ `No_core_dump ] () in
  match r with
  | [ (`No_core_dump, (Ok () | Error `Unsupported)) ] -> ()
  | [ (`No_core_dump, Error (`Failed e)) ] ->
      Alcotest.failf "setrlimit failed: %d" e
  | _ -> Alcotest.fail "unexpected report shape"

let test_wipe_all () =
  Gc.full_major ();
  Gc.full_major ();
  let a = s_of "a" and b = s_of "bb" in
  Secret.wipe_all ();
  Alcotest.(check bool) "a destroyed" true (Secret.is_destroyed a);
  Alcotest.(check bool) "b destroyed" true (Secret.is_destroyed b);
  (* secrets created afterwards work normally *)
  let c = s_of "c" in
  Alcotest.(check string) "new secret" "c" (Secret.unsafe_to_string c);
  (* Storage deferred for concurrency safety must still be released when the
     destroyed handle is finalized. A pool-sized payload makes that release
     observable without inspecting freed memory. *)
  let before = Secret.pool_count () in
  let weak = Weak.create 1 in
  let allocate_and_wipe () =
    let t = Secret.create 60_001 in
    Weak.set weak 0 (Some t);
    Secret.wipe_all ()
  in
  allocate_and_wipe ();
  Gc.full_major ();
  Gc.full_major ();
  Alcotest.(check bool) "wiped handle finalized" true (Weak.get weak 0 = None);
  Alcotest.(check bool)
    "wiped storage released" true
    (Secret.pool_count () > before)

let test_pool_bounded () =
  let secrets = Array.init 256 (fun _ -> Secret.create 4096) in
  Array.iter Secret.destroy secrets;
  Alcotest.(check bool) "bounded reuse pool" true (Secret.pool_count () <= 128)

let () =
  Alcotest.run "secret"
    [
      ( "api",
        [
          Alcotest.test_case "create/length" `Quick test_create_length;
          Alcotest.test_case "of_string roundtrip" `Quick
            test_of_string_roundtrip;
          Alcotest.test_case "equal" `Quick test_equal;
          Alcotest.test_case "destroy" `Quick test_destroy;
          Alcotest.test_case "pp" `Quick test_pp;
          Alcotest.test_case "compare/hash/marshal" `Quick
            test_compare_hash_marshal;
          Alcotest.test_case "blit/fill/sub" `Quick test_blit_fill_sub;
          Alcotest.test_case "of_bytes wipe" `Quick test_of_bytes_wipe;
          Alcotest.test_case "expose" `Quick test_expose;
          Alcotest.test_case "views" `Quick test_views;
          Alcotest.test_case "bigstring view" `Quick test_bigstring_view;
          Alcotest.test_case "init/random" `Quick test_init_random;
          Alcotest.test_case "with_secret" `Quick test_with_secret;
          Alcotest.test_case "status default tier" `Quick
            test_status_default_tier;
          Alcotest.test_case "hardened" `Quick test_hardened;
          Alcotest.test_case "pool reuse" `Quick test_pool_reuse;
          Alcotest.test_case "pool size classes" `Quick test_pool_size_classes;
          Alcotest.test_case "scratch" `Quick test_scratch;
          Alcotest.test_case "capabilities" `Quick test_capabilities;
          Alcotest.test_case "process" `Quick test_process;
          Alcotest.test_case "wipe_all" `Quick test_wipe_all;
          Alcotest.test_case "bounded pool" `Quick test_pool_bounded;
        ] );
    ]
