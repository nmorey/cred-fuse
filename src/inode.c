#include "inode.h"
#include "decryption.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <stdio.h>

#define MAX_INODE_LOG2 13
#define MAX_INODE (1U << MAX_INODE_LOG2)
#define BITMASK_WORDS (MAX_INODE / 64)

_Static_assert((64 - MAX_INODE_LOG2) >= 32, "Generation prefix bit width is too small for safety");
_Static_assert(MAX_INODE <= INT16_MAX, "hash table type too narrow for MAX_INODE");

/* Thread-safe Path-to-Inode lookup table */
struct inode_entry {
    char *path;
    int64_t refcount;
    fuse_ino_t full_ino;
};

#define HASH_SIZE (MAX_INODE * 2)

_Static_assert(MAX_INODE < HASH_SIZE, "hash table must be larger than inode pool");

static struct inode_entry inodes[MAX_INODE];
static uint64_t inode_bitmask[BITMASK_WORDS] = {3}; // Pre-mark inode 0 and 1 as active/reserved
static int16_t path_hash_table[HASH_SIZE]; // Automatically zero-initialized (0 = empty slot)
static fuse_ino_t last_allocated_ino = 2; // Inode 1 is root
static fuse_ino_t current_generation = 0;
static fuse_ino_t last_allocated_slot = 2;
static pthread_rwlock_t inode_lock = PTHREAD_RWLOCK_INITIALIZER;

static inline fuse_ino_t ino_to_slot(fuse_ino_t ino) {
    return ino & (MAX_INODE - 1);
}

static inline fuse_ino_t slot_to_full_ino(fuse_ino_t slot, fuse_ino_t generation) {
    return (generation << MAX_INODE_LOG2) | slot;
}

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

static uint32_t hash_path(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash % HASH_SIZE;
}

static void remove_hash(fuse_ino_t ino) {
    uint32_t bucket;

    if (ino >= MAX_INODE)
	return;

    if (!inodes[ino].path)
	return;

    bucket = hash_path(inodes[ino].path);
    while (path_hash_table[bucket] != 0) {
        if (path_hash_table[bucket] == (int16_t)ino) {
            break;
        }
        bucket = (bucket + 1) % HASH_SIZE;
    }

    if (path_hash_table[bucket] == 0) {
        return; // Not found
    }

    path_hash_table[bucket] = 0;

    // Re-hash the cluster to close the gap and prevent broken chains
    uint32_t empty_slot = bucket;
    uint32_t next_slot = (bucket + 1) % HASH_SIZE;

    while (path_hash_table[next_slot] != 0) {
        fuse_ino_t next_ino = path_hash_table[next_slot];
        uint32_t natural_bucket = hash_path(inodes[next_ino].path);

        int can_move = 0;
        if (empty_slot < next_slot) {
            can_move = (natural_bucket <= empty_slot || natural_bucket > next_slot);
        } else {
            can_move = (natural_bucket <= empty_slot && natural_bucket > next_slot);
        }

        if (can_move) {
            path_hash_table[empty_slot] = (int16_t)next_ino;
            path_hash_table[next_slot] = 0;
            empty_slot = next_slot;
        }
        next_slot = (next_slot + 1) % HASH_SIZE;
    }
}

static void free_inode(fuse_ino_t ino)
{
    remove_hash(ino);
    if (inodes[ino].path)
	free(inodes[ino].path);
    inodes[ino].path = NULL;
    inodes[ino].refcount = 0;
    inodes[ino].full_ino = 0;
    clear_inode_bit(ino);
}

/* Thread-unsafe to evict all inodes with no refcount */
static void evict_inode()
{
    for(unsigned ino = 2; ino < MAX_INODE; ++ino){
	if (!is_inode_active(ino))
	    continue;
	if(__atomic_load_n(&inodes[ino].refcount, __ATOMIC_SEQ_CST) <= 0)
	    free_inode(ino);
    }
}

static fuse_ino_t _allocate_inode_num(void) {
    fuse_ino_t start_ino = last_allocated_ino + 1;
    if (start_ino >= MAX_INODE || start_ino < 2) {
        start_ino = 2;
    }
    size_t word_idx = start_ino / 64;
    size_t bit_idx = start_ino % 64;

    /* We intentionally loop BITMASK_WORDS + 1 time as on the first
     * iter, we only check the bitmask starting at work_idx. while the
     * last iter will check the whole thing in case we missed a free spot
     * in the first part of that word */
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

static fuse_ino_t allocate_inode_num(void) {
    fuse_ino_t slot = _allocate_inode_num();
    if(!slot) {
	evict_inode();
	slot = _allocate_inode_num();
    }
    if (!slot) {
        return 0;
    }
    if (slot <= last_allocated_slot) {
        current_generation++;
    }
    last_allocated_slot = slot;
    fuse_ino_t full_ino = slot_to_full_ino(slot, current_generation);
    inodes[slot].full_ino = full_ino;
    return full_ino;
}

static void insert_hash(fuse_ino_t ino) {
    uint32_t bucket = hash_path(inodes[ino].path);
    while (path_hash_table[bucket] != 0) {
        bucket = (bucket + 1) % HASH_SIZE;
    }
    path_hash_table[bucket] = (int16_t)ino;
}

static fuse_ino_t find_inode_unlocked(const char *rel_path) {
    uint32_t bucket = hash_path(rel_path);
    uint32_t start_bucket = bucket;
    while (path_hash_table[bucket] != 0) {
        fuse_ino_t ino = path_hash_table[bucket];
        if (is_inode_active(ino) && strcmp(inodes[ino].path, rel_path) == 0) {
            return ino;
        }
        bucket = (bucket + 1) % HASH_SIZE;
        if (bucket == start_bucket) {
            break;
        }
    }
    return 0;
}

static inline void inode_lookup_inc(fuse_ino_t ino) {
    __atomic_add_fetch(&inodes[ino].refcount, 1, __ATOMIC_SEQ_CST);
}

static fuse_ino_t inode_lookup_unlocked(const char *rel_path, int take_ref) {
    fuse_ino_t slot;
    slot = find_inode_unlocked(rel_path);
    if (slot) {
        if (take_ref)
            inode_lookup_inc(slot);
        fuse_ino_t full_ino = inodes[slot].full_ino;
        return full_ino;
    }
    return 0;
}

/* Thread-safe Path-to-Inode lookup table operations */
fuse_ino_t add_inode(const char *rel_path, int take_ref) {
    fuse_ino_t full_ino;

    // Fast path: Check under shared read lock
    pthread_rwlock_rdlock(&inode_lock);
    full_ino = inode_lookup_unlocked(rel_path, take_ref);
    pthread_rwlock_unlock(&inode_lock);
    if (full_ino)
	return full_ino;

    // Slow path: Mutate under exclusive write lock
    pthread_rwlock_wrlock(&inode_lock);
    full_ino = inode_lookup_unlocked(rel_path, take_ref);
    if (full_ino) {
        pthread_rwlock_unlock(&inode_lock);
        return full_ino;
    }

    // Allocate next free inode ID (returns full_ino)
    full_ino = allocate_inode_num();
    if (!full_ino) {
        pthread_rwlock_unlock(&inode_lock);
        errno = ENOSPC;
        return 0; // Cache full
    }

    fuse_ino_t new_slot = ino_to_slot(full_ino);

    char *path_copy = strdup(rel_path);
    if (!path_copy) {
        clear_inode_bit(new_slot);
        inodes[new_slot].full_ino = 0;
        pthread_rwlock_unlock(&inode_lock);
        errno = ENOMEM;
        return 0;
    }

    inodes[new_slot].path = path_copy;
    inodes[new_slot].refcount = 0;
    if (take_ref)
	inode_lookup_inc(new_slot);
    insert_hash(new_slot);

    pthread_rwlock_unlock(&inode_lock);
    return full_ino;
}

fuse_ino_t find_inode(const char *rel_path) {
    fuse_ino_t slot;
    pthread_rwlock_rdlock(&inode_lock);
    slot = find_inode_unlocked(rel_path);
    if (slot) {
        fuse_ino_t full_ino = inodes[slot].full_ino;
        pthread_rwlock_unlock(&inode_lock);
        return full_ino;
    }
    pthread_rwlock_unlock(&inode_lock);
    errno = ENOENT;
    return 0;
}

void inode_forget(fuse_ino_t ino, uint64_t nlookup) {
    if (nlookup > INT64_MAX) {
        fprintf(stderr, "inode_forget: nlookup %llu exceeds INT64_MAX, ignoring\n", (unsigned long long)nlookup);
        return;
    }
    fuse_ino_t slot = ino_to_slot(ino);
    if (slot < 2) {
        return;
    }
    pthread_rwlock_wrlock(&inode_lock);
    if (is_inode_active(slot) && inodes[slot].full_ino == ino) {
        int64_t new_val = __atomic_sub_fetch(&inodes[slot].refcount, (int64_t)nlookup, __ATOMIC_SEQ_CST);
        if (new_val < 0) {
            fprintf(stderr, "inode_forget: refcount dropped below 0 (new_val: %lld) for slot %llu (path: %s)\n",
                   (long long)new_val, (unsigned long long)slot, inodes[slot].path ? inodes[slot].path : "NULL");
        }
        if (new_val <= 0)
	    free_inode(slot);
    }
    pthread_rwlock_unlock(&inode_lock);
}

char *get_inode_path(fuse_ino_t ino) {
    errno = 0;
    if (ino == 1) {
        return strdup("/");
    }
    fuse_ino_t slot = ino_to_slot(ino);
    if (slot < 2) {
        errno = ENOENT;
        return NULL;
    }
    pthread_rwlock_rdlock(&inode_lock);
    if (is_inode_active(slot) && inodes[slot].full_ino == ino) {
        char *path = strdup(inodes[slot].path);
        pthread_rwlock_unlock(&inode_lock);
        return path;
    }
    pthread_rwlock_unlock(&inode_lock);
    errno = ENOENT;
    return NULL;
}

void cleanup_inodes(void) {
    pthread_rwlock_wrlock(&inode_lock);
    for (fuse_ino_t ino = 2; ino < MAX_INODE; ino++) {
        if (is_inode_active(ino))
	    free_inode(ino);
    }
    // Re-mark bitmask to original state (only 0 and 1 active/reserved)
    memset(inode_bitmask, 0, sizeof(inode_bitmask));
    inode_bitmask[0] = 3;
    // Clear hash table completely
    memset(path_hash_table, 0, sizeof(path_hash_table));
    last_allocated_ino = 2;
    current_generation = 0;
    last_allocated_slot = 2;
    pthread_rwlock_unlock(&inode_lock);
}
