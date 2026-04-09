/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <openssl/crypto.h>
#include <sys/prctl.h>
#include <sys/mman.h>

#include "decryption.h"

struct cred_fuse_opts global_opts;

enum {
    KEY_RO,
};

static int is_ro = 0;

#define CRED_OPT(t, p) { t, offsetof(struct cred_fuse_opts, p), 1 }
static const struct fuse_opt cred_opts[] = {
    CRED_OPT("tpm_handle=%s", tpm_handle_str),
    CRED_OPT("tcti=%s", tcti),
    { "max_open_files=%d", offsetof(struct cred_fuse_opts, max_open_files), 0 },
    { "max_file_size=%d", offsetof(struct cred_fuse_opts, max_file_size), 0 },
    FUSE_OPT_KEY("ro", KEY_RO),
    FUSE_OPT_END
};

static int opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    (void)data;
    (void)outargs;

    if (key == KEY_RO) {
        is_ro = 1;
        return 1; /* Keep 'ro' for FUSE mount logic */
    }

    if (key == FUSE_OPT_KEY_NONOPT && global_opts.source_dir == NULL) {
        global_opts.source_dir = strdup(arg);
        return 0; /* Consume the first non-option argument as source_dir */
    }
    return 1; /* Keep other arguments (like the mountpoint) */
}

static int current_open_files = 0;

/* Convert relative fuse path to absolute path in source_dir */
static int build_path(char *dest, size_t size, const char *rel_path) {
    int ret;
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

static int cred_getattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi __attribute__((unused))) {
    char full_path[PATH_MAX];
    int res;

    if (build_path(full_path, sizeof(full_path), path) < 0)
        return -ENAMETOOLONG;

    res = stat(full_path, stbuf);
    if (res == -1)
	return -errno;

    // For regular files, check user.size xattr
    if (S_ISREG(stbuf->st_mode)) {
        char xattr_buf[64] = {0};
        ssize_t s;

        s = getxattr(full_path, "user.size", xattr_buf, sizeof(xattr_buf));
        if (s > 0 && s < (ssize_t)sizeof(xattr_buf)) {
            long parsed_size;

            xattr_buf[s] = '\0';
            parsed_size = strtol(xattr_buf, NULL, 16);
            if (parsed_size >= 0) {
                stbuf->st_size = parsed_size;
            } else {
                return -ENOENT;
            }
        } else {
            return -ENOENT;
        }
    }

    return 0;
}

static int cred_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset,
			struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
    char full_path[PATH_MAX];
    DIR *dp;
    struct dirent *de;

    (void)fi;
    (void)flags;

    if (build_path(full_path, sizeof(full_path), path) < 0)
        return -ENAMETOOLONG;

    dp = opendir(full_path);
    if (!dp)
	return -errno;

    if (offset > 0)
        seekdir(dp, offset);

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        off_t next_off;

        next_off = telldir(dp);

        if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN) {
            char subpath[PATH_MAX];
            struct stat tmp_st;
            int sn_ret;

            sn_ret = snprintf(subpath, sizeof(subpath), "%s/%s", full_path, de->d_name);
            if (sn_ret < 0 || (size_t)sn_ret >= sizeof(subpath))
                continue; // Skip if path creation failed or was truncated

            if (stat(subpath, &tmp_st) == 0 && S_ISREG(tmp_st.st_mode)) {
                char xattr_buf[64];
                ssize_t s;

                s = getxattr(subpath, "user.size", xattr_buf, sizeof(xattr_buf));
                if (s <= 0 || s >= (ssize_t)sizeof(xattr_buf))
		    continue; // Skip unmanaged files entirely
            }
        }

        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, next_off, 0))
	    break;
    }

    closedir(dp);
    return 0;
}

static int cred_open(const char *path, struct fuse_file_info *fi) {
    char full_path[PATH_MAX];
    char xattr_buf[64];
    int r;
    ssize_t s;
    struct decrypted_node *node;
    int ret;

    if (build_path(full_path, sizeof(full_path), path) < 0)
        return -ENAMETOOLONG;

    // Only allow read access
    if ((fi->flags & O_ACCMODE) != O_RDONLY)
	return -EACCES;

    fi->direct_io = 1;

    int current = __atomic_add_fetch(&current_open_files, 1, __ATOMIC_SEQ_CST);
    if (current > global_opts.max_open_files) {
        ret = -ENFILE;
        goto err_open_files;
    }

    s = getxattr(full_path, "user.size", xattr_buf, sizeof(xattr_buf));
    if (s <= 0 || s >= (ssize_t)sizeof(xattr_buf)) {
        ret = -ENOENT;
        goto err_open_files;
    }

    long parsed_size;
    xattr_buf[s] = '\0';
    parsed_size = strtol(xattr_buf, NULL, 16);
    if (parsed_size < 0) {
        ret = -ENOENT;
        goto err_open_files;
    }

    node = malloc(sizeof(struct decrypted_node));
    if (!node) {
        ret = -ENOMEM;
        goto err_open_files;
    }
    memset(node, 0, sizeof(*node));

    r = decrypt_credential(full_path, node);
    if (r < 0) {
        ret = r;
        goto err_decrypt;
    }

    if (node->len > (size_t)parsed_size) {
        node->len = (size_t)parsed_size;
    }

    fi->fh = (uint64_t)node;
    return 0;

 err_decrypt:
    free(node);
 err_open_files:
    __atomic_sub_fetch(&current_open_files, 1, __ATOMIC_SEQ_CST);
    return ret;
}

static int cred_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    struct decrypted_node *node = (struct decrypted_node *)fi->fh;
    size_t avail;

    (void)path;

    if (!node || !node->buf)
	return -EIO;

    if ((size_t)offset >= node->len) {
        return 0;
    }

    avail = node->len - offset;
    if (size > avail)
	size = avail;

    memcpy(buf, node->buf + offset, size);
    return size;
}

static int cred_release(const char *path, struct fuse_file_info *fi) {
    struct decrypted_node *node = (struct decrypted_node *)fi->fh;

    (void)path;

    if (node) {
        clean_decrypted_node(node);
        free(node);
    }

    __atomic_sub_fetch(&current_open_files, 1, __ATOMIC_SEQ_CST);

    return 0;
}

static const struct fuse_operations cred_oper = {
    .getattr = cred_getattr,
    .readdir = cred_readdir,
    .open    = cred_open,
    .read    = cred_read,
    .release = cred_release,
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int ret;

    // Disable core dumps
    prctl(PR_SET_DUMPABLE, 0);

    memset(&global_opts, 0, sizeof(global_opts));
    global_opts.max_open_files = 1024;
    global_opts.max_file_size = 65536;

    if (fuse_opt_parse(&args, &global_opts, cred_opts, opt_proc) == -1) {
        return 1;
    }

    if (!global_opts.source_dir || !global_opts.tpm_handle_str) {
        fprintf(stderr, "Usage: %s <source_dir> <mountpoint> -o tpm_handle=<hex> [options]\n", argv[0]);
        fprintf(stderr, "Missing required arguments:\n"
                        "  <source_dir>\n  -o tpm_handle=<hex>\n");
        return 1;
    }

    if (!is_ro) {
        fprintf(stderr, "Error: Must be mounted with the 'ro' (read-only) option.\n");
        return 1;
    }

    char *endptr;
    errno = 0;
    unsigned long handle = strtoul(global_opts.tpm_handle_str, &endptr, 0);
    if (errno != 0 || *endptr != '\0' || handle > 0xFFFFFFFF || (handle & 0xFF000000) != 0x81000000) {
        fprintf(stderr, "Invalid tpm_handle. Must be a valid persistent TPM handle (e.g., 0x81xxxxxx).\n");
        return 1;
    }
    global_opts.tpm_handle = (uint32_t)handle;

    if (global_opts.max_file_size <= 0 || global_opts.max_file_size > 1024 * 1024 * 1024) {
        fprintf(stderr, "Invalid max_file_size\n");
        return 1;
    }

    if (global_opts.max_open_files <= 0) {
        fprintf(stderr, "Invalid max_open_files\n");
        return 1;
    }

    if (init_decryption(global_opts.source_dir) != 0) {
        fprintf(stderr, "Failed to initialize decryption\n");
        return 1;
    }

    ret = fuse_main(args.argc, args.argv, &cred_oper, NULL);
    fuse_opt_free_args(&args);
    return ret;
}
