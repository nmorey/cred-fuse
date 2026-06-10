#define FUSE_USE_VERSION 312

#include "inode.h"
#include "decryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/xattr.h>

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

/* Safely join a parent path and a component name, avoiding duplicate slashes */
int join_paths(char *dest, size_t size, const char *parent, const char *child) {
    int ret;
    size_t len = strlen(parent);
    if (len > 0 && parent[len - 1] == '/') {
        ret = snprintf(dest, size, "%s%s", parent, child);
    } else {
        ret = snprintf(dest, size, "%s/%s", parent, child);
    }

    if (ret < 0 || (size_t)ret >= size) {
        return -ENAMETOOLONG;
    }
    return 0;
}

/* Convert relative fuse path to absolute path in source_dir */
int build_path(char *dest, size_t size, const char *rel_path) {
    int ret;

    const char *p = rel_path;
    while (*p) {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        const char *end = p;
        while (*end && *end != '/') {
            end++;
        }
        if (end - p == 2 && p[0] == '.' && p[1] == '.') {
            return -EACCES;
        }
        p = end;
    }

    if (strcmp(rel_path, "/") == 0) {
        ret = snprintf(dest, size, "%s", global_opts.source_dir);
    } else {
        ret = snprintf(dest, size, "%s%s", global_opts.source_dir, rel_path);
    }

    if (ret < 0 || (size_t)ret >= size) {
        return -ENAMETOOLONG;
    }

    return 0;
}

/* Safely open, query, and validate file metadata using a secure file descriptor */
int open_and_validate_path(const char *full_path, struct stat *st_out) {
    int fd = open(full_path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }

    // Resolve fd's path to prevent intermediate symlink sandbox escapes
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    char resolved_path[PATH_MAX];
    if (!realpath(fd_path, resolved_path)) {
        close(fd);
        return -errno;
    }

    size_t sd_len = global_opts.source_dir_len;
    if (strncmp(resolved_path, global_opts.source_dir, sd_len) != 0 ||
        (resolved_path[sd_len] != '\0' && resolved_path[sd_len] != '/')) {
        close(fd);
        return -EACCES;
    }

    if (fstat(fd, st_out) != 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    if (!S_ISREG(st_out->st_mode) && !S_ISDIR(st_out->st_mode)) {
        close(fd);
        return -EACCES;
    }

    // Reset O_NONBLOCK flag so that subsequent I/O behaves normally
    int flags = fcntl(fd, F_GETFL);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    if (S_ISREG(st_out->st_mode)) {
        char xattr_buf[64] = {0};
        ssize_t s = fgetxattr(fd, "user.size", xattr_buf, sizeof(xattr_buf));
        if (s <= 0 || s >= (ssize_t)sizeof(xattr_buf)) {
            close(fd);
            return -ENOENT;
        }

        char *endptr;
        long parsed_size;
        xattr_buf[s] = '\0';
        errno = 0;
        parsed_size = strtol(xattr_buf, &endptr, 16);
        if (errno || endptr == xattr_buf || *endptr != '\0' || parsed_size < 0 || parsed_size > global_opts.max_file_size) {
            close(fd);
            return -ENOENT;
        }
        st_out->st_size = parsed_size;
    }

    return fd;
}

/* Resolve an inode to its path, open it safely, and validate metadata */
int open_and_validate_ino(fuse_ino_t ino, struct stat *st_out) {
    char *rel_path = get_inode_path(ino);
    if (!rel_path) {
        return -errno;
    }

    char full_path[PATH_MAX];
    int path_ret = build_path(full_path, sizeof(full_path), rel_path);
    free(rel_path);
    if (path_ret < 0) {
        return path_ret;
    }

    return open_and_validate_path(full_path, st_out);
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
