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

/* Thread-safe Path-to-Inode lookup table */
struct inode_entry {
    fuse_ino_t ino;
    char *path;
    uint64_t refcount;
};

static struct inode_entry *inodes = NULL;
static size_t inodes_count = 0;
static size_t inodes_max = 0;
static pthread_mutex_t inode_lock = PTHREAD_MUTEX_INITIALIZER;

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
    int fd = open(full_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
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

    if (S_ISLNK(st_out->st_mode)) {
        close(fd);
        return -ELOOP;
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
        if (errno || endptr == xattr_buf || *endptr != '\0' || parsed_size < 0) {
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
    for (size_t i = 0; i < inodes_count; i++) {
        if (strcmp(inodes[i].path, rel_path) == 0) {
            pthread_mutex_unlock(&inode_lock);
            return inodes[i].ino;
        }
    }

    // Allocate more space if needed
    if (inodes_count >= inodes_max) {
        size_t new_max = inodes_max == 0 ? 1024 : inodes_max * 2;
        struct inode_entry *temp = realloc(inodes, new_max * sizeof(struct inode_entry));
        if (!temp) {
            pthread_mutex_unlock(&inode_lock);
            return 0;
        }
        inodes = temp;
        inodes_max = new_max;
    }

    char *path_copy = strdup(rel_path);
    if (!path_copy) {
        pthread_mutex_unlock(&inode_lock);
        return 0;
    }

    static fuse_ino_t next_ino = 2; // 1 is root
    fuse_ino_t new_ino = next_ino++;
    inodes[inodes_count].ino = new_ino;
    inodes[inodes_count].path = path_copy;
    inodes[inodes_count].refcount = 0;
    inodes_count++;

    pthread_mutex_unlock(&inode_lock);
    return new_ino;
}

void inode_lookup_inc(fuse_ino_t ino) {
    if (ino == 1) return;
    pthread_mutex_lock(&inode_lock);
    for (size_t i = 0; i < inodes_count; i++) {
        if (inodes[i].ino == ino) {
            inodes[i].refcount++;
            break;
        }
    }
    pthread_mutex_unlock(&inode_lock);
}

void inode_forget(fuse_ino_t ino, uint64_t nlookup) {
    if (ino == 1) {
        return;
    }
    pthread_mutex_lock(&inode_lock);
    for (size_t i = 0; i < inodes_count; i++) {
        if (inodes[i].ino == ino) {
            if (inodes[i].refcount > nlookup) {
                inodes[i].refcount -= nlookup;
            } else {
                inodes[i].refcount = 0;
            }

            if (inodes[i].refcount == 0) {
                free(inodes[i].path);
                if (i < inodes_count - 1) {
                    inodes[i] = inodes[inodes_count - 1];
                }
                inodes_count--;
            }
            break;
        }
    }
    pthread_mutex_unlock(&inode_lock);
}

char *get_inode_path(fuse_ino_t ino) {
    errno = 0;
    if (ino == 1) {
        return strdup("/");
    }
    pthread_mutex_lock(&inode_lock);
    for (size_t i = 0; i < inodes_count; i++) {
        if (inodes[i].ino == ino) {
            char *path = strdup(inodes[i].path);
            pthread_mutex_unlock(&inode_lock);
            return path;
        }
    }
    pthread_mutex_unlock(&inode_lock);
    errno = ENOENT;
    return NULL;
}

void cleanup_inodes(void) {
    pthread_mutex_lock(&inode_lock);
    for (size_t i = 0; i < inodes_count; i++) {
        free(inodes[i].path);
    }
    free(inodes);
    inodes = NULL;
    inodes_count = 0;
    inodes_max = 0;
    pthread_mutex_unlock(&inode_lock);
}
