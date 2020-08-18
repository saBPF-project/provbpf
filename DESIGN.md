# eBPF Maps

* A `task_struct`'s unique identifier (perhaps `pid`) should be mapped to a `task_prov_struct` (`BPF_MAP_TYPE_HASH`)
* A `cred`'s unique identifier should be mapped to a `proc_prov_struct` (`BPF_MAP_TYPE_HASH`)
* A `inode`'s unique identifier should be mapped to a `inode_prov_struct` (this map should include `dentry`,`file`, and `socket`).
`inode`'s uniqueness depends on `super_block`, so maybe we should use `BPF_MAP_TYPE_HASH_OF_MAPS`.
* A `msg_msg`'s unique identifider should be mapped to a `msg_msg_struct` (consider rename `msg_msg_struct` to `msg_msg_prov_struct`?) (`BPF_MAP_TYPE_HASH`)
* A `kern_ipc_perm`'s unique identifier should be mapped to a `shm_struct` (consider rename `shm_struct` to `shm_prov_struct`?) (`BPF_MAP_TYPE_HASH`)
* A `super_block`'s unique identifier should be mapped to a `sb_struct` (consider rename `sb_struct` to `sb_prov_struct`?) (`BPF_MAP_TYPE_HASH`)

No need to have maps for transitive objects like `iattr` or `pck`.

