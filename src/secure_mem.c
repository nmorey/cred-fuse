#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "secure_mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/crypto.h>

static long system_page_size = 4096;

void init_secure_mem(void) {
    long p_sz = sysconf(_SC_PAGESIZE);
    if (p_sz > 0) {
        system_page_size = p_sz;
    }
}

static inline size_t get_aligned_size(size_t size) {
    if (mlockall_active) {
        return size;
    }
    size_t page_size = (size_t)system_page_size;
    if (size > SIZE_MAX - page_size + 1) {
        return SIZE_MAX;
    }
    return ((size + page_size - 1) / page_size) * page_size;
}

void *malloc_mlock(size_t size) {
    void *ptr = NULL;
    if (!mlockall_active) {
        size_t aligned_size = get_aligned_size(size);
        size_t page_size = (size_t)system_page_size;
        int ret = posix_memalign(&ptr, page_size, aligned_size);
        if (ret != 0) {
            errno = ret;
            return NULL;
        }
        if (mlock(ptr, aligned_size) != 0) {
            int saved_errno = errno;
            free(ptr);
            errno = saved_errno;
            return NULL;
        }
        memset(ptr, 0, aligned_size);
    } else {
        ptr = malloc(size);
        if (ptr) {
            memset(ptr, 0, size);
        }
    }
    return ptr;
}

void free_munlock(void *ptr, size_t size) {
    if (!ptr) {
        return;
    }

    size_t aligned_size = get_aligned_size(size);
    OPENSSL_cleanse(ptr, aligned_size);
    if (!mlockall_active) {
        munlock(ptr, aligned_size);
    }
    free(ptr);
}

void clean_decrypted_node(struct decrypted_node *node) {
    if (!node || !node->buf) {
        return;
    }

    free_munlock(node->buf, node->allocated_size);
    memset(node, 0, sizeof(*node));
}
