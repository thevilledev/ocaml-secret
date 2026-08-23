(* Feature discovery for the secret library.

   Generates:
   - secret_config.h : SECRET_HAVE_* switches used by the C stubs
   - cflags.sexp     : extra C flags
   - clibs.sexp      : extra link flags

   Every probe is a compile+link test of a tiny C program. When a probe cannot
   run (cross compilation to a freestanding target such as solo5, or a broken
   toolchain), the feature is reported as unavailable and the C code falls
   back to portable code paths. *)

module C = Configurator.V1

let probe c ~name ~includes ~body =
  let includes = "stddef.h" :: "stdlib.h" :: includes in
  let includes = String.concat "\n" (List.map (Printf.sprintf "#include <%s>") includes) in
  let src = Printf.sprintf "%s\nint main(void) { %s return 0; }\n" includes body in
  let ok = try C.c_test c src with _ -> false in
  (name, ok)

let () =
  C.main ~name:"secret" (fun c ->
      let is_freestanding =
        let defs =
          try
            C.C_define.import c ~includes:[]
              [ ("__ocaml_solo5__", C.C_define.Type.Switch);
                ("__ocaml_freestanding__", C.C_define.Type.Switch);
                ("_WIN32", C.C_define.Type.Switch) ]
          with _ -> []
        in
        let sw n = List.assoc_opt n defs = Some (C.C_define.Value.Switch true) in
        (sw "__ocaml_solo5__" || sw "__ocaml_freestanding__", sw "_WIN32")
      in
      let freestanding, win32 = is_freestanding in
      let probes =
        if freestanding then []
        else if win32 then
          [ probe c ~name:"SECRET_HAVE_SECUREZEROMEMORY"
              ~includes:[ "windows.h" ]
              ~body:"char b[8]; SecureZeroMemory(b, sizeof b);";
            probe c ~name:"SECRET_HAVE_BCRYPTGENRANDOM"
              ~includes:[ "windows.h"; "bcrypt.h" ]
              ~body:"unsigned char b[8]; (void)BCryptGenRandom(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG);" ]
        else
          [ probe c ~name:"SECRET_HAVE_MEMSET_EXPLICIT"
              ~includes:[ "string.h" ]
              ~body:"char b[8]; memset_explicit(b, 0, sizeof b);";
            probe c ~name:"SECRET_HAVE_EXPLICIT_BZERO"
              ~includes:[ "string.h"; "strings.h" ]
              ~body:"char b[8]; explicit_bzero(b, sizeof b);";
            probe c ~name:"SECRET_HAVE_EXPLICIT_MEMSET"
              ~includes:[ "string.h" ]
              ~body:"char b[8]; explicit_memset(b, 0, sizeof b);";
            probe c ~name:"SECRET_HAVE_MEMSET_S"
              ~includes:[ "string.h" ]
              ~body:"char b[8]; (void)memset_s(b, sizeof b, 0, sizeof b);";
            probe c ~name:"SECRET_HAVE_GETRANDOM"
              ~includes:[ "sys/random.h" ]
              ~body:"unsigned char b[8]; (void)getrandom(b, sizeof b, 0);";
            probe c ~name:"SECRET_HAVE_GETENTROPY"
              ~includes:[ "unistd.h"; "sys/random.h" ]
              ~body:"unsigned char b[8]; (void)getentropy(b, sizeof b);";
            probe c ~name:"SECRET_HAVE_ARC4RANDOM_BUF"
              ~includes:[ "stdlib.h" ]
              ~body:"unsigned char b[8]; arc4random_buf(b, sizeof b);";
            probe c ~name:"SECRET_HAVE_MMAP"
              ~includes:[ "sys/mman.h" ]
              ~body:"void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); (void)munmap(p, 4096);";
            probe c ~name:"SECRET_HAVE_MLOCK"
              ~includes:[ "sys/mman.h" ]
              ~body:"char b[8]; (void)mlock(b, sizeof b); (void)munlock(b, sizeof b);";
            probe c ~name:"SECRET_HAVE_MLOCKALL"
              ~includes:[ "sys/mman.h" ]
              ~body:"(void)mlockall(MCL_CURRENT | MCL_FUTURE);";
            probe c ~name:"SECRET_HAVE_MADV_DONTDUMP"
              ~includes:[ "sys/mman.h" ]
              ~body:"int f = MADV_DONTDUMP; (void)f;";
            probe c ~name:"SECRET_HAVE_MADV_NOCORE"
              ~includes:[ "sys/mman.h" ]
              ~body:"int f = MADV_NOCORE; (void)f;";
            probe c ~name:"SECRET_HAVE_MADV_WIPEONFORK"
              ~includes:[ "sys/mman.h" ]
              ~body:"int f = MADV_WIPEONFORK; (void)f;";
            probe c ~name:"SECRET_HAVE_MAP_CONCEAL"
              ~includes:[ "sys/mman.h" ]
              ~body:"int f = MAP_CONCEAL; (void)f;";
            probe c ~name:"SECRET_HAVE_PTHREAD_ATFORK"
              ~includes:[ "pthread.h" ]
              ~body:"(void)pthread_atfork(NULL, NULL, NULL);";
            probe c ~name:"SECRET_HAVE_PRCTL_DUMPABLE"
              ~includes:[ "sys/prctl.h" ]
              ~body:"(void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);";
            probe c ~name:"SECRET_HAVE_PT_DENY_ATTACH"
              ~includes:[ "sys/types.h"; "sys/ptrace.h" ]
              ~body:"int f = PT_DENY_ATTACH; (void)f;";
            probe c ~name:"SECRET_HAVE_SETRLIMIT_CORE"
              ~includes:[ "sys/resource.h" ]
              ~body:"struct rlimit r = {0, 0}; (void)setrlimit(RLIMIT_CORE, &r);" ]
      in
      let defines =
        List.map
          (fun (name, ok) -> (name, C.C_define.Value.Switch ok))
          probes
        @ [ ("SECRET_CONFIG_FREESTANDING", C.C_define.Value.Switch freestanding) ]
      in
      C.C_define.gen_header_file c ~fname:"secret_config.h" defines;
      let cflags =
        if win32 then [ "/W3" ]
        else [ "-std=c11"; "-Wall"; "-Wextra"; "-Wno-unused-parameter"; "-O2"; "-fno-strict-aliasing" ]
      in
      (* pthread_atfork resolves through the OCaml runtime's own pthread
         dependency; no extra -lpthread needed. *)
      let clibs = if win32 then [ "-lbcrypt" ] else [] in
      C.Flags.write_sexp "cflags.sexp" cflags;
      C.Flags.write_sexp "clibs.sexp" clibs)
