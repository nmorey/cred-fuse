#ifndef CRED_FUSE_OPTS_H
#define CRED_FUSE_OPTS_H

#include <stddef.h>
#include <stdint.h>

#define MAX_ALLOWED_FILE_SIZE 65536

struct cred_fuse_opts {
    char *source_dir;
    size_t source_dir_len;
    int source_dir_fd;
    char *mountpoint;
    char *tpm_handle_str;
    uint32_t tpm_handle;
    char *tpm_pubkey;
    char *tcti;
    int max_open_files;
    int max_file_size;
    int max_threads;
};

extern struct cred_fuse_opts global_opts;

#endif /* CRED_FUSE_OPTS_H */
