(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (import "mvm" "egress" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 3)
  (data (i32.const 0) "{\"method\":\"POST\",\"url\":\"https://api.openai.com/v1/chat/completions\",\"headers\":[[\"Authorization\",\"Bearer mvm-secret-deadbeef\"]],\"body_b64\":\"\"}")
  (data (i32.const 20000) "{\"result\":\"refused\"")
  (func $_start
    (local $len i32)
    (local $i i32)
    (local.set $len
      (call $mvm_egress
        (i32.const 0) (i32.const 141)
        (i32.const 8192) (i32.const 8192)))
    (if (i32.lt_s (local.get $len) (i32.const 0))
      (then (call $proc_exit (i32.const 3))))
    (if (i32.lt_s (local.get $len) (i32.const 19))
      (then (call $proc_exit (i32.const 1))))
    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (i32.const 19)))
        (if (i32.ne
              (i32.load8_u (i32.add (i32.const 8192) (local.get $i)))
              (i32.load8_u (i32.add (i32.const 20000) (local.get $i))))
          (then (call $proc_exit (i32.const 2))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (call $proc_exit (i32.const 0)))
  (export "_start" (func $_start)))
