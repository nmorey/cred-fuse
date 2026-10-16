#define _DEFAULT_SOURCE
#include "path.h"
#include "inode.h"
#include "decryption.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <linux/openat2.h>
#include <sys/syscall.h>

/* Safely join a parent path and a component name, avoiding duplicate slashes */
int join_paths(char *dest, size_t size, const char *parent, const char *child) {
    int ret;

    if (!dest || !parent || !child || *child == '\0') {
        return -EINVAL;
    }
    if (strcmp(child, ".") == 0 || strcmp(child, "..") == 0 || strchr(child, '/') != NULL) {
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

/* Safely open, query, and validate file metadata relative to source_dir_fd */
int open_and_validate_path(const char *rel_path, struct stat *st_out) {
    if (!rel_path || !st_out || global_opts.source_dir_fd < 0) {
        return -EINVAL;
    }

    while (*rel_path == '/') {
        rel_path++;
    }
    const char *target = (*rel_path == '\0') ? "." : rel_path;

    struct open_how how = {
        .flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS,
    };

    int fd = (int)syscall(SYS_openat2, global_opts.source_dir_fd, target, &how, sizeof(how));
    if (fd < 0) {
        return (errno == EXDEV) ? -EACCES : -errno;
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

    if (S_ISDIR(st_out->st_mode)) {
#ifdef CRED_FUSE_ENABLE_SWTPM
        if (st_out->st_uid != 0 && st_out->st_uid != geteuid()) {
            close(fd);
            return -EACCES;
        }
#else
        if (st_out->st_uid != 0) {
            close(fd);
            return -EACCES;
        }
#endif
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
        if (st_out->st_nlink > 1) {
            close(fd);
            return -EACCES;
        }

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

    int fd = open_and_validate_path(rel_path, st_out);
    free(rel_path);
    return fd;
}
