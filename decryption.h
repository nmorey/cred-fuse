#ifndef DECRYPTION_H
#define DECRYPTION_H

#include <stddef.h>
#include <stdint.h>

struct cred_fuse_opts {
    char *source_dir;
    char *tpm_handle;
    char *tcti;
    int max_open_files;
    int max_file_size;
};

extern struct cred_fuse_opts global_opts;

/* Initializes decryption module, caching host-specific paths.
 * Returns 0 on success, < 0 on error.
 */
int init_decryption(const char *source_dir);

/*
 * Returns 0 on success, < 0 on error.
 * On success, *out_buf contains the allocated decrypted buffer,
 * and *out_len contains its length.
 * The caller must free *out_buf.
 */
int decrypt_credential(const char *file_path,
                       uint8_t **out_buf,
                       size_t *out_len,
                       size_t *out_allocated);

#endif /* DECRYPTION_H */