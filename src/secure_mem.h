#ifndef CRED_FUSE_SECURE_MEM_H
#define CRED_FUSE_SECURE_MEM_H

#include <stddef.h>
#include <stdint.h>

struct decrypted_node {
    uint8_t *buf;
    size_t len;
    size_t allocated_size;
    uint16_t uid_slot;
};

extern int mlockall_active;

void init_secure_mem(void);
void *malloc_mlock(size_t size);
void free_munlock(void *ptr, size_t size);
void clean_decrypted_node(struct decrypted_node *node);

#endif /* CRED_FUSE_SECURE_MEM_H */
