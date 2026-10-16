#include "path.h"
#include "inode.h"
#include "decryption.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>

/* Safely join a parent path and a component name, avoiding duplicate slashes */
int join_paths(char *dest, size_t size, const char *parent, const char *child) {
    int ret;

    if (!dest || !parent || !child) {
        return -EINVAL;
    }

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
    int r = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (r < 0 || (size_t)r >= sizeof(fd_path)) {
        close(fd);
        return -ENAMETOOLONG;
    }
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
    if (flags < 0) {
        close(fd);
        return -errno;
    }
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        close(fd);
        return -errno;
    }

    if (S_ISREG(st_out->st_mode)) {
        uint8_t hdr[18];
        ssize_t n = pread(fd, hdr, sizeof(hdr), 0);
        if (n != (ssize_t)sizeof(hdr)) {
            close(fd);
            return -ENOENT;
        }

        if (memcmp(hdr, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN) != 0) {
            close(fd);
            return -ENOENT;
        }

        uint64_t version_be = 0;
        memcpy(&version_be, hdr + 8, sizeof(version_be));
        if (be64toh(version_be) != CRED_ENV_VERSION_1) {
            close(fd);
            return -ENOENT;
        }

        uint16_t rsa_ct_len_be = 0;
        memcpy(&rsa_ct_len_be, hdr + 16, sizeof(rsa_ct_len_be));
        uint16_t rsa_ct_len = be16toh(rsa_ct_len_be);
        if (rsa_ct_len != TPM2_RSA2048_KEY_BYTES && rsa_ct_len != TPM2_RSA4096_KEY_BYTES) {
            close(fd);
            return -ENOENT;
        }

        off_t overhead = (off_t)(CRED_ENV_FIXED_OVERHEAD + rsa_ct_len);
        if (st_out->st_size <= overhead) {
            close(fd);
            return -ENOENT;
        }

        off_t plaintext_size = st_out->st_size - overhead;
        if (plaintext_size > (off_t)global_opts.max_file_size) {
            close(fd);
            return -ENOENT;
        }

        st_out->st_size = plaintext_size;
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
