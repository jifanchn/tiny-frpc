{
  "targets": [
    {
      "target_name": "frpc_native",
      "sources": [ "frpc_native.c" ],
      "include_dirs": [
        "<(module_root_dir)/../../tiny-frpc/include"
      ],
      "cflags": [ "-std=c11" ],
      "libraries": [
        "-Wl,-rpath,@loader_path/..",
        "<(module_root_dir)/../../build/libfrpc-bindings.so"
      ]
    }
  ]
}


