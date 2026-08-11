#include "path.h"
#include "inode.h"
#include "decryption.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/xattr.h>

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
        if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
	    close(fd);
	    return -errno;
	}
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
