#include "inode.h"
#include "decryption.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

#define MAX_INODE_LOG2 13
#define MAX_INODE (1U << MAX_INODE_LOG2)
#define BITMASK_WORDS (MAX_INODE / 64)

/* Thread-safe Path-to-Inode lookup table */
struct inode_entry {
    char *path;
    uint64_t refcount;
};

static struct inode_entry inodes[MAX_INODE];
static uint64_t inode_bitmask[BITMASK_WORDS] = {3}; // Pre-mark inode 0 and 1 as active/reserved
static fuse_ino_t last_allocated_ino = 2; // Inode 1 is root
static pthread_mutex_t inode_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void set_inode_bit(fuse_ino_t ino) {
    inode_bitmask[ino / 64] |= (1ULL << (ino % 64));
}

static inline void clear_inode_bit(fuse_ino_t ino) {
    inode_bitmask[ino / 64] &= ~(1ULL << (ino % 64));
}

static inline int is_inode_active(fuse_ino_t ino) {
    if (ino >= MAX_INODE) {
        return 0;
    }
    return (inode_bitmask[ino / 64] & (1ULL << (ino % 64))) != 0;
}

static fuse_ino_t allocate_inode_num(void) {
    fuse_ino_t start_ino = last_allocated_ino + 1;
    if (start_ino >= MAX_INODE || start_ino < 2) {
        start_ino = 2;
    }
    size_t word_idx = start_ino / 64;
    size_t bit_idx = start_ino % 64;

    for (size_t i = 0; i <= BITMASK_WORDS; i++) {
        size_t idx = (word_idx + i) % BITMASK_WORDS;
        uint64_t val = inode_bitmask[idx];

        // If it's the start word and first pass, mask out bits below bit_idx
        if (i == 0) {
            uint64_t mask = (1ULL << bit_idx) - 1;
            val |= mask;
        }

        uint64_t free_bits = ~val;
        if (free_bits) {
            int pos = __builtin_ctzll(free_bits);
            fuse_ino_t ino = idx * 64 + pos;
            if (ino < MAX_INODE) {
                set_inode_bit(ino);
                last_allocated_ino = ino;
                return ino;
            }
        }
    }
    return 0; // No free inodes
}

/* Thread-safe Path-to-Inode lookup table operations */
fuse_ino_t add_inode(const char *rel_path) {
    pthread_mutex_lock(&inode_lock);

    // Check if rel_path already has an inode
    for (fuse_ino_t ino = 2; ino < MAX_INODE; ino++) {
        if (is_inode_active(ino) && strcmp(inodes[ino].path, rel_path) == 0) {
            pthread_mutex_unlock(&inode_lock);
            return ino;
        }
    }

    // Allocate next free inode ID
    fuse_ino_t new_ino = allocate_inode_num();
    if (!new_ino) {
        pthread_mutex_unlock(&inode_lock);
        return 0; // Cache full
    }

    char *path_copy = strdup(rel_path);
    if (!path_copy) {
        clear_inode_bit(new_ino);
        pthread_mutex_unlock(&inode_lock);
        return 0;
    }

    inodes[new_ino].path = path_copy;
    inodes[new_ino].refcount = 0;

    pthread_mutex_unlock(&inode_lock);
    return new_ino;
}

fuse_ino_t find_inode(const char *rel_path) {
    pthread_mutex_lock(&inode_lock);
    for (fuse_ino_t ino = 2; ino < MAX_INODE; ino++) {
        if (is_inode_active(ino) && strcmp(inodes[ino].path, rel_path) == 0) {
            pthread_mutex_unlock(&inode_lock);
            return ino;
        }
    }
    pthread_mutex_unlock(&inode_lock);
    return 0;
}

void inode_lookup_inc(fuse_ino_t ino) {
    if (ino < 2 || ino >= MAX_INODE) return;
    pthread_mutex_lock(&inode_lock);
    if (is_inode_active(ino)) {
        inodes[ino].refcount++;
    }
    pthread_mutex_unlock(&inode_lock);
}

void inode_forget(fuse_ino_t ino, uint64_t nlookup) {
    if (ino < 2 || ino >= MAX_INODE) {
        return;
    }
    pthread_mutex_lock(&inode_lock);
    if (is_inode_active(ino)) {
        if (inodes[ino].refcount > nlookup) {
            inodes[ino].refcount -= nlookup;
        } else {
            inodes[ino].refcount = 0;
        }

        if (inodes[ino].refcount == 0) {
            free(inodes[ino].path);
            inodes[ino].path = NULL;
            clear_inode_bit(ino);
        }
    }
    pthread_mutex_unlock(&inode_lock);
}

char *get_inode_path(fuse_ino_t ino) {
    errno = 0;
    if (ino == 1) {
        return strdup("/");
    }
    if (ino < 2 || ino >= MAX_INODE) {
        errno = ENOENT;
        return NULL;
    }
    pthread_mutex_lock(&inode_lock);
    if (is_inode_active(ino)) {
        char *path = strdup(inodes[ino].path);
        pthread_mutex_unlock(&inode_lock);
        return path;
    }
    pthread_mutex_unlock(&inode_lock);
    errno = ENOENT;
    return NULL;
}

void cleanup_inodes(void) {
    pthread_mutex_lock(&inode_lock);
    for (fuse_ino_t ino = 2; ino < MAX_INODE; ino++) {
        if (is_inode_active(ino)) {
            free(inodes[ino].path);
            inodes[ino].path = NULL;
            inodes[ino].refcount = 0;
        }
    }
    // Re-mark bitmask to original state (only 0 and 1 active/reserved)
    memset(inode_bitmask, 0, sizeof(inode_bitmask));
    inode_bitmask[0] = 3;
    last_allocated_ino = 2;
    pthread_mutex_unlock(&inode_lock);
}
