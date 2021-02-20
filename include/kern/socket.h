static union prov_elt* get_or_create_inode_prov_from_socket(struct socket *sock) {
    uint64_t key;
    umode_t imode;
    int map_id = INODE_PERCPU_TMP;
    struct inode *inode = SOCK_INODE(sock);
    union prov_elt *prov_on_map, *prov_tmp;
    struct local_storage *storage;

    if (!inode)
      return NULL;

    key = get_key(inode);
    prov_on_map = bpf_map_lookup_elem(&inode_map, &key);
//    bpf_inode_storage_delete(&inode_storage_map, (struct inode *)inode);
//    storage = bpf_inode_storage_get(&inode_storage_map, SOCK_INODE(sock), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    storage = bpf_sk_storage_get(&sk_storage_map, sock->sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);

    // inode provenance already being tracked
    if (prov_on_map) {
        // update the inode provenance in case it changed
        prov_update_inode(inode, prov_on_map);
    } else {
        prov_tmp = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);
        if (!prov_tmp)
            return NULL;
        __builtin_memset(prov_tmp, 0, sizeof(union prov_elt));
        bpf_probe_read(&imode, sizeof(imode), &inode->i_mode);
        if (S_ISREG(imode)) {
            // inode mode is regular file
            prov_init_node(prov_tmp, ENT_INODE_FILE);
        } else if (S_ISDIR(imode)) {
            // inode mode is directory
            prov_init_node(prov_tmp, ENT_INODE_DIRECTORY);
        } else if (S_ISCHR(imode)) {
            // inode mode is character device
            prov_init_node(prov_tmp, ENT_INODE_CHAR);
        } else if (S_ISBLK(imode)) {
            // inode mode is block device
            prov_init_node(prov_tmp, ENT_INODE_BLOCK);
        } else if (S_ISFIFO(imode)) {
            // inode mode is FIFO (named pipe)
            prov_init_node(prov_tmp, ENT_INODE_PIPE);
        } else if (S_ISLNK(imode)) {
            // inode mode is symbolic link
            prov_init_node(prov_tmp, ENT_INODE_LINK);
        } else if (S_ISSOCK(imode)) {
            // inode mode is socket
            prov_init_node(prov_tmp, ENT_INODE_SOCKET);
        } else {
            // inode mode is unknown
            prov_init_node(prov_tmp, ENT_INODE_UNKNOWN);
        }

        prov_init_inode(inode, prov_tmp);
        bpf_map_update_elem(&inode_map, &key, prov_tmp, BPF_NOEXIST);
//        bpf_inode_storage_get(&inode_map, inode, prov_tmp, BPF_NOEXIST | BPF_LOCAL_STORAGE_GET_F_CREATE);
        prov_on_map = bpf_map_lookup_elem(&inode_map, &key);
//        prov_on_map = bpf_inode_storage_get(&inode_map, inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    }
    return prov_on_map;
}
