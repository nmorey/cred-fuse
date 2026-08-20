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

#define FUSE_USE_VERSION 312

#include <fuse3/fuse_lowlevel.h>
#include <fuse3/fuse_common.h>
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
#include <sys/resource.h>
#include <pthread.h>
#include <libaudit.h>
#include <limits.h>
#include <syslog.h>

#include "decryption.h"
#include "inode.h"
#include "path.h"

#define MAX_ALLOWED_FILE_SIZE 65536

struct cred_fuse_opts global_opts;

enum {
    KEY_RO,
    KEY_DEFAULT_PERMISSIONS,
};

static int is_ro = 0;
static int has_default_permissions = 0;
int mlockall_active = 0;

#define CRED_OPT(t, p) { t, offsetof(struct cred_fuse_opts, p), 1 }
static const struct fuse_opt cred_opts[] = {
    CRED_OPT("tpm_handle=%s", tpm_handle_str),
    CRED_OPT("tcti=%s", tcti),
    { "max_open_files=%d", offsetof(struct cred_fuse_opts, max_open_files), 0 },
    { "max_file_size=%d", offsetof(struct cred_fuse_opts, max_file_size), 0 },
    FUSE_OPT_KEY("ro", KEY_RO),
    FUSE_OPT_KEY("default_permissions", KEY_DEFAULT_PERMISSIONS),
    FUSE_OPT_END
};

static int opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    (void)data;
    (void)outargs;

    if (key == KEY_RO) {
        is_ro = 1;
        return 1; /* Keep 'ro' for FUSE mount logic */
    }

    if (key == KEY_DEFAULT_PERMISSIONS) {
        has_default_permissions = 1;
        return 1; /* Keep 'default_permissions' for FUSE mount logic */
    }

    if (key == FUSE_OPT_KEY_NONOPT && global_opts.source_dir == NULL) {
        global_opts.source_dir = strdup(arg);
        return 0; /* Consume the first non-option argument as source_dir */
    }
    return 1; /* Keep other arguments (like the mountpoint) */
}

static int current_open_files = 0;

static int audit_fd = -1;

static void init_audit_system(void) {
    audit_fd = audit_open();
    if (audit_fd < 0) {
        fprintf(stderr, "Warning: Failed to open kernel audit netlink socket (errno: %d)\n", errno);
    }
}

static void shutdown_audit_system(void) {
    if (audit_fd >= 0) {
        audit_close(audit_fd);
        audit_fd = -1;
    }
}

static struct audit_rule_data *build_base_rule(const char *source_dir) {
    struct audit_rule_data *rule = audit_rule_create_data();
    if (!rule) {
        return NULL;
    }

    if (audit_rule_syscallbyname_data(rule, "all") < 0) {
        audit_rule_free_data(rule);
        return NULL;
    }

    char arch_filter[32];
    snprintf(arch_filter, sizeof(arch_filter), "arch=b64");
    if (audit_rule_fieldpair_data(&rule, arch_filter, AUDIT_FILTER_EXIT) < 0) {
        audit_rule_free_data(rule);
        return NULL;
    }

    char dir_filter[PATH_MAX + 8];
    snprintf(dir_filter, sizeof(dir_filter), "dir=%s", source_dir);
    if (audit_rule_fieldpair_data(&rule, dir_filter, AUDIT_FILTER_EXIT) < 0) {
        audit_rule_free_data(rule);
        return NULL;
    }

    char perm_filter[32];
    snprintf(perm_filter, sizeof(perm_filter), "perm=rwa");
    if (audit_rule_fieldpair_data(&rule, perm_filter, AUDIT_FILTER_EXIT) < 0) {
        audit_rule_free_data(rule);
        return NULL;
    }

    return rule;
}

static int manage_audit_rules(const char *source_dir, pid_t daemon_pid, int add) {
    if (audit_fd < 0) {
        return -1;
    }

    int rc_exclude = 0;
    int rc_watch = 0;

    struct audit_rule_data *rule_exclude = build_base_rule(source_dir);
    if (rule_exclude) {
        char pid_filter[64];
        snprintf(pid_filter, sizeof(pid_filter), "pid=%d", daemon_pid);
        
        if (audit_rule_fieldpair_data(&rule_exclude, pid_filter, AUDIT_FILTER_EXIT) == 0) {
            if (add) {
                rc_exclude = audit_add_rule_data(audit_fd, rule_exclude, AUDIT_FILTER_EXIT, AUDIT_NEVER);
            } else {
                rc_exclude = audit_delete_rule_data(audit_fd, rule_exclude, AUDIT_FILTER_EXIT, AUDIT_NEVER);
            }
        }
        audit_rule_free_data(rule_exclude);
    }

    struct audit_rule_data *rule_watch = build_base_rule(source_dir);
    if (rule_watch) {
        char key_filter[64];
        snprintf(key_filter, sizeof(key_filter), "key=cred-fuse-bypass");
        if (audit_rule_fieldpair_data(&rule_watch, key_filter, AUDIT_FILTER_EXIT) == 0) {
            if (add) {
                rc_watch = audit_add_rule_data(audit_fd, rule_watch, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
            } else {
                rc_watch = audit_delete_rule_data(audit_fd, rule_watch, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
            }
        }
        audit_rule_free_data(rule_watch);
    }

    return (rc_exclude > 0 && rc_watch > 0) ? 0 : -1;
}

static void reply_err_and_audit(fuse_req_t req, int err, const char *op, fuse_ino_t ino, const char *filename) {
    if (err > 0 && audit_fd >= 0) {
        const struct fuse_ctx *ctx = fuse_req_ctx(req);
        char *path = NULL;

        if (ino > 1) {
            path = get_inode_path(ino);
        }

        const char *mount_prefix = global_opts.mountpoint ? global_opts.mountpoint : "";
        if (strcmp(mount_prefix, "/") == 0) {
            mount_prefix = "";
        }

        char msg[1024];
	char errno_str[256];

	strerror_r(err, errno_str, sizeof(errno_str));
        int ret = snprintf(msg, sizeof(msg),
                 "op=%s path=\"%s%s%s%s\" uid=%u gid=%u pid=%d res=failed error=\"%s\"",
                 op,
                 mount_prefix,
                 path ? path : "",
                 (path && filename) ? "/" : "",
                 filename ? filename : "",
                 ctx->uid, ctx->gid, ctx->pid,
                 errno_str);
        if (ret >= (int)sizeof(msg)) {
            syslog(LOG_WARNING, "reply_err_and_audit: audit message truncated");
        }

        int rc = audit_log_user_message(audit_fd, AUDIT_TRUSTED_APP, msg, NULL, NULL, NULL, 0);
        if (rc < 0) {
            syslog(LOG_WARNING, "reply_err_and_audit: audit_log_user_message failed: %s", strerror(errno));
        }

        if (path) {
            free(path);
        }
    }

    fuse_reply_err(req, err);
}

static void cred_ll_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    (void)req;
    if (ino != 1) {
        inode_forget(ino, nlookup);
    }
    fuse_reply_none(req);
}

static int is_valid_name(const char *name) {
    if (!name || *name == '\0') {
        return 0;
    }
    for (int i = 0; name[i] != '\0'; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

/* 1. LOOKUP: Translate a path component to an inode */
static void cred_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    if (!is_valid_name(name)) {
        reply_err_and_audit(req, ENOENT, "lookup", parent, "invalid_name");
        return;
    }
    struct fuse_entry_param e;
    char *parent_path = get_inode_path(parent);
    if (!parent_path) {
        reply_err_and_audit(req, errno, "lookup", parent, name);
        return;
    }

    char rel_path[PATH_MAX];
    int path_err = join_paths(rel_path, sizeof(rel_path), parent_path, name);
    free(parent_path);
    if (path_err < 0) {
        reply_err_and_audit(req, -path_err, "lookup", parent, name);
        return;
    }

    char full_path[PATH_MAX];
    int path_ret = build_path(full_path, sizeof(full_path), rel_path);
    if (path_ret < 0) {
        reply_err_and_audit(req, -path_ret, "lookup", parent, name);
        return;
    }

    struct stat st;
    int fd = open_and_validate_path(full_path, &st);
    if (fd < 0) {
        reply_err_and_audit(req, -fd, "lookup", parent, name);
        return;
    }
    close(fd);

    fuse_ino_t new_ino = add_inode(rel_path, 1);
    if (new_ino == 0) {
        reply_err_and_audit(req, errno, "lookup", parent, name);
        return;
    }

    memset(&e, 0, sizeof(e));
    e.ino = new_ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;
    e.attr = st;
    e.attr.st_ino = e.ino;
    e.attr.st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);

    fuse_reply_entry(req, &e);
}

/* 2. GETATTR: Retrieve file or directory attributes */
static void cred_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void)fi;
    struct stat st;
    int fd = open_and_validate_ino(ino, &st);
    if (fd < 0) {
        reply_err_and_audit(req, -fd, "getattr", ino, NULL);
        return;
    }
    close(fd);

    st.st_ino = ino;
    st.st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
    fuse_reply_attr(req, &st, 1.0);
}

/* 3. OPEN: Open a file safely */
static void cred_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    int fd = -1;
    struct decrypted_node *node = NULL;
    int err_code = 0;

    // Only allow read-only access and reject write/creation/truncation/append flags
    if ((fi->flags & O_ACCMODE) != O_RDONLY || 
        (fi->flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0) {
        reply_err_and_audit(req, EACCES, "open", ino, NULL);
        return;
    }

    int current = __atomic_add_fetch(&current_open_files, 1, __ATOMIC_SEQ_CST);
    if (current > global_opts.max_open_files) {
        err_code = ENFILE;
        goto err_decrement;
    }

    struct stat st;
    fd = open_and_validate_ino(ino, &st);
    if (fd < 0) {
        err_code = -fd;
        goto err_decrement;
    }

    fi->direct_io = 1;

    node = malloc(sizeof(struct decrypted_node));
    if (!node) {
        err_code = ENOMEM;
        goto err_close;
    }
    memset(node, 0, sizeof(*node));

    int r = decrypt_credential(fd, node);
    if (r < 0) {
        err_code = -r;
        goto err_free_node;
    }

    if (node->len != (size_t)st.st_size) {
        err_code = EBADMSG;
        goto err_free_node;
    }

    _Static_assert(sizeof(node) <= sizeof(fi->fh), "pointer must fit in fuse fh");
    fi->fh = (typeof(fi->fh))node;
    close(fd);

    if (audit_fd >= 0) {
        const struct fuse_ctx *ctx = fuse_req_ctx(req);
        char *path = get_inode_path(ino);

        const char *mount_prefix = global_opts.mountpoint ? global_opts.mountpoint : "";
        if (strcmp(mount_prefix, "/") == 0) {
            mount_prefix = "";
        }

        char msg[1024];
        int ret = snprintf(msg, sizeof(msg),
                 "op=open path=\"%s%s\" uid=%u gid=%u pid=%d res=success",
                 mount_prefix, path ? path : "unknown", ctx->uid, ctx->gid, ctx->pid);
        if (ret >= (int)sizeof(msg)) {
            syslog(LOG_WARNING, "cred_ll_open: audit message truncated");
        }
        int rc = audit_log_user_message(audit_fd, AUDIT_TRUSTED_APP, msg, NULL, NULL, NULL, 1);
        if (rc < 0) {
            syslog(LOG_WARNING, "cred_ll_open: audit_log_user_message failed: %s", strerror(errno));
        }
        if (path) {
            free(path);
        }
    }

    fuse_reply_open(req, fi);
    return;

err_free_node:
    clean_decrypted_node(node);
    free(node);
err_close:
    close(fd);
err_decrement:
    __atomic_sub_fetch(&current_open_files, 1, __ATOMIC_SEQ_CST);
    reply_err_and_audit(req, err_code, "open", ino, NULL);
}

/* 4. READ: Secure low-level zero-copy data reply directly from our mlocked buffer */
static void cred_ll_read(fuse_req_t req, fuse_ino_t ino __attribute__((unused)),
			 size_t size, off_t off, struct fuse_file_info *fi) {
    struct decrypted_node *node = (struct decrypted_node *)fi->fh;
    if (!node || !node->buf) {
        reply_err_and_audit(req, EIO, "read", ino, NULL);
        return;
    }

    if (off < 0) {
        reply_err_and_audit(req, EINVAL, "read", ino, NULL);
        return;
    }

    if ((size_t)off >= node->len) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    size_t avail = node->len - off;
    if (size > avail) {
        size = avail;
    }

    fuse_reply_buf(req, (const char *)node->buf + off, size);
}

/* 5. RELEASE: Secure cleanup and resource recycling */
static void cred_ll_release(fuse_req_t req, fuse_ino_t ino __attribute__((unused)),
			    struct fuse_file_info *fi) {
    struct decrypted_node *node = (struct decrypted_node *)fi->fh;
    if (node) {
        clean_decrypted_node(node);
        free(node);
        __atomic_sub_fetch(&current_open_files, 1, __ATOMIC_SEQ_CST);
    }
    fuse_reply_err(req, 0);
}

/* 6. READDIR: Formats directory entries directly */
#define DIR_BUF_CHUNK_SIZE 16384

struct dir_buf {
    char *p;
    size_t size;
    size_t capacity;
};

static int dir_buf_add(fuse_req_t req, struct dir_buf *b, const char *name, fuse_ino_t ino) {
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino = ino;

    size_t oldsize = b->size;
    size_t entry_size = fuse_add_direntry(req, NULL, 0, name, NULL, 0);
    size_t needed = oldsize + entry_size;

    if (needed > b->capacity) {
        if (needed > (size_t)-1 - DIR_BUF_CHUNK_SIZE) {
            return -1; /* Overflow protection */
        }
        size_t chunks = (needed + DIR_BUF_CHUNK_SIZE - 1) / DIR_BUF_CHUNK_SIZE;
        size_t new_capacity = chunks * DIR_BUF_CHUNK_SIZE;

        char *temp = realloc(b->p, new_capacity);
        if (!temp) {
            return -1;
        }
        b->p = temp;
        b->capacity = new_capacity;
    }

    b->size = needed;
    fuse_add_direntry(req, b->p + oldsize, entry_size, name, &st, b->size);
    return 0;
}

static void cred_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)fi;
    if (off < 0) {
        reply_err_and_audit(req, EINVAL, "readdir", ino, NULL);
        return;
    }

    char *rel_path = get_inode_path(ino);
    if (!rel_path) {
        reply_err_and_audit(req, errno, "readdir", ino, NULL);
        return;
    }

    char full_path[PATH_MAX];
    int path_ret = build_path(full_path, sizeof(full_path), rel_path);
    if (path_ret < 0) {
        free(rel_path);
        reply_err_and_audit(req, -path_ret, "readdir", ino, NULL);
        return;
    }

    struct stat st;
    int dir_fd = open_and_validate_path(full_path, &st);
    if (dir_fd < 0) {
        free(rel_path);
        reply_err_and_audit(req, -dir_fd, "readdir", ino, NULL);
        return;
    }

    DIR *dp = fdopendir(dir_fd);
    if (!dp) {
        close(dir_fd);
        free(rel_path);
        reply_err_and_audit(req, errno, "readdir", ino, NULL);
        return;
    }

    struct dir_buf b;
    memset(&b, 0, sizeof(b));

    // Add standard directory directory markers
    if (dir_buf_add(req, &b, ".", ino) != 0 ||
        dir_buf_add(req, &b, "..", 1) != 0) {
        free(b.p);
        closedir(dp);
        free(rel_path);
        reply_err_and_audit(req, ENOMEM, "readdir", ino, NULL);
        return;
    }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        if (!is_valid_name(de->d_name)) {
            continue; // Skip any entries with invalid/unsafe names
        }

        if (de->d_type == DT_LNK) {
            continue; // Skip symbolic links entirely
        }

        if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN) {
            char subpath[PATH_MAX];
            if (join_paths(subpath, sizeof(subpath), full_path, de->d_name) < 0) {
                continue;
            }
            struct stat tmp_st;
            int fd = open_and_validate_path(subpath, &tmp_st);
            if (fd < 0) {
                continue; // Skip invalid, unmanaged, or symlinked files cleanly
            }
            close(fd);
        }

        // Construct the relative path of this entry to register or find its inode
        char entry_rel_path[PATH_MAX];
        if (join_paths(entry_rel_path, sizeof(entry_rel_path), rel_path, de->d_name) < 0) {
            continue;
        }

	fuse_ino_t entry_ino;
	switch(de->d_type){
	case DT_REG:
	case DT_UNKNOWN:
	case DT_DIR:
	    entry_ino = add_inode(entry_rel_path, 0);
	    break;
	default:
	    entry_ino = find_inode(entry_rel_path);
            break;
        }
	if (entry_ino)
	    if (dir_buf_add(req, &b, de->d_name, entry_ino) != 0)
		break;
    }
    closedir(dp);

    if (off < (off_t)b.size) {
        size_t chunk = b.size - off;
        if (chunk > size) {
            chunk = size;
        }
        fuse_reply_buf(req, b.p + off, chunk);
    } else {
        fuse_reply_buf(req, NULL, 0);
    }

    free(b.p);
    free(rel_path);
}

static int validate_tcti(const char *tcti) {
    if (!tcti) {
        return 1;
    }

    const char *allowed_schemes[] = { "device", "swtpm", "tabrmd" };
    size_t allowed_count = sizeof(allowed_schemes) / sizeof(allowed_schemes[0]);

    const char *colon = strchr(tcti, ':');
    size_t scheme_len = colon ? (size_t)(colon - tcti) : strlen(tcti);

    // 1. Validate Scheme
    int scheme_found = 0;
    const char *scheme = NULL;
    for (size_t i = 0; i < allowed_count; i++) {
        if (scheme_len == strlen(allowed_schemes[i]) && strncmp(tcti, allowed_schemes[i], scheme_len) == 0) {
            scheme_found = 1;
            scheme = allowed_schemes[i];
            break;
        }
    }
    if (!scheme_found) {
        return 0; // Unknown or forbidden scheme (e.g., mssim, none)
    }

    // If there are no options, the scheme prefix alone is valid
    if (!colon) {
        return 1;
    }

    const char *options = colon + 1;
    if (*options == '\0') {
        return 0; // Empty options trailing a colon is invalid
    }

    // 2. Validate Options based on Scheme
    if (strcmp(scheme, "device") == 0) {
        // Must be a safe device path: e.g. /dev/tpm0 or /dev/tpmrm0
        if (strncmp(options, "/dev/tpm", 8) != 0) {
            return 0;
        }
        for (size_t i = 8; options[i] != '\0'; i++) {
            char c = options[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
                return 0; // Block path traversal, directories, or special chars
            }
        }
    } else if (strcmp(scheme, "swtpm") == 0) {
        // Swtpm requires path=/absolute/path/to/socket
        if (strncmp(options, "path=", 5) != 0) {
            return 0;
        }
        const char *path = options + 5;
        if (*path != '/') {
            return 0; // Must be absolute path
        }
        for (size_t i = 0; path[i] != '\0'; i++) {
            char c = path[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || 
                  c == '/' || c == '.' || c == '-' || c == '_')) {
                return 0; // Block commands, wildcard shells, etc.
            }
        }
    } else if (strcmp(scheme, "tabrmd") == 0) {
        // Tabrmd allows bus_name and bus_type (alphanumeric, =, ,, -, _, .)
        for (size_t i = 0; options[i] != '\0'; i++) {
            char c = options[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || 
                  c == '=' || c == ',' || c == '-' || c == '_' || c == '.')) {
                return 0;
            }
        }
    }

    return 1;
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se = NULL;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config *config = NULL;
    int ret = -1;

    memset(&opts, 0, sizeof(opts));

    // Disable core dumps
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        perror("Failed to disable core dumps (prctl)");
        return 1;
    }

    struct rlimit rlim = {0, 0};
    if (setrlimit(RLIMIT_CORE, &rlim) != 0) {
        perror("Failed to set core limit (setrlimit)");
        return 1;
    }

    memset(&global_opts, 0, sizeof(global_opts));
    global_opts.max_open_files = 1024;
    global_opts.max_file_size = MAX_ALLOWED_FILE_SIZE;

    if (fuse_opt_parse(&args, &global_opts, cred_opts, opt_proc) == -1) {
        return 1;
    }

    if (!global_opts.source_dir || !global_opts.tpm_handle_str) {
        fprintf(stderr, "Usage: %s <source_dir> <mountpoint> -o tpm_handle=<hex> [options]\n", argv[0]);
        fprintf(stderr, "Missing required arguments:\n"
                        "  <source_dir>\n  -o tpm_handle=<hex>\n");
        ret = 1;
        goto err_early;
    }

    char *abs_source_dir = realpath(global_opts.source_dir, NULL);
    if (!abs_source_dir) {
        perror("Failed to resolve absolute path of source_dir");
        ret = 1;
        goto err_early;
    }
    if (strcmp(abs_source_dir, "/") == 0) {
        fprintf(stderr, "Error: Root directory '/' is not allowed as source_dir.\n");
        free(abs_source_dir);
        ret = 1;
        goto err_early;
    }
    free(global_opts.source_dir);
    global_opts.source_dir = abs_source_dir;
    global_opts.source_dir_len = strlen(abs_source_dir);

    if (!is_ro) {
        fprintf(stderr, "Error: Must be mounted with the 'ro' (read-only) option.\n");
        ret = 1;
        goto err_early;
    }

    if (!has_default_permissions) {
        fprintf(stderr, "Error: Must be mounted with the 'default_permissions' option.\n");
        ret = 1;
        goto err_early;
    }

    char *endptr;
    errno = 0;
    unsigned long handle = strtoul(global_opts.tpm_handle_str, &endptr, 16);
    if (errno != 0 || *endptr != '\0' || handle > 0xFFFFFFFF || (handle & 0xFF000000) != 0x81000000) {
        fprintf(stderr, "Invalid tpm_handle. Must be a valid persistent TPM handle (e.g., 0x81xxxxxx).\n");
        ret = 1;
        goto err_early;
    }
    global_opts.tpm_handle = (uint32_t)handle;

    if (global_opts.max_file_size <= 0 || global_opts.max_file_size > MAX_ALLOWED_FILE_SIZE) {
        fprintf(stderr, "Invalid max_file_size. Must be between 1 byte and %d bytes.\n", MAX_ALLOWED_FILE_SIZE);
        ret = 1;
        goto err_early;
    }

    if (global_opts.max_open_files <= 0) {
        fprintf(stderr, "Invalid max_open_files\n");
        ret = 1;
        goto err_early;
    }

    if (!validate_tcti(global_opts.tcti)) {
        fprintf(stderr, "Invalid tcti option. Must be device, swtpm, tabrmd, or NULL.\n");
        ret = 1;
        goto err_early;
    }

    if (init_decryption(global_opts.source_dir) != 0) {
        fprintf(stderr, "Failed to initialize decryption\n");
        ret = 1;
        goto err_early;
    }

    if (check_tpm_lockout() != 0) {
        ret = 1;
        goto err_early;
    }

    /* Parse mounting options and extract mountpoint */
    if (fuse_parse_cmdline(&args, &opts) != 0) {
        ret = 1;
        goto err_early;
    }

    if (opts.mountpoint == NULL) {
        fprintf(stderr, "Error: No mountpoint specified.\n");
        ret = 1;
        goto err_opts;
    }

    global_opts.mountpoint = realpath(opts.mountpoint, NULL);
    if (!global_opts.mountpoint) {
        perror("Failed to resolve absolute path of mountpoint");
        ret = 1;
        goto err_opts;
    }

    static const struct fuse_lowlevel_ops cred_ll_oper = {
        .lookup  = cred_ll_lookup,
        .getattr = cred_ll_getattr,
        .open    = cred_ll_open,
        .read    = cred_ll_read,
        .readdir = cred_ll_readdir,
        .release = cred_ll_release,
        .forget  = cred_ll_forget,
    };

    se = fuse_session_new(&args, &cred_ll_oper, sizeof(cred_ll_oper), NULL);
    if (se == NULL) {
        ret = 1;
        goto err_opts;
    }

    if (fuse_set_signal_handlers(se) != 0) {
        ret = 1;
        goto err_session;
    }

    if (fuse_session_mount(se, opts.mountpoint) != 0) {
        ret = 1;
        goto err_signal;
    }

    /* Handle standard daemonization background fork */
    fuse_daemonize(opts.foreground);

    init_audit_system();
    if (audit_fd >= 0) {
        manage_audit_rules(global_opts.source_dir, getpid(), 1);
    }

    // Lock all current and future memory to prevent swapping secrets (post-fork daemon context)
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        mlockall_active = 1;
    } else {
        mlockall_active = 0;
        fprintf(stderr, "Warning: Failed to lock memory in daemon (mlockall: %s). Falling back to individual mlock calls.\n", strerror(errno));
    }

    atexit(cleanup_inodes);

    /* Run standard event loop */
    if (opts.singlethread) {
        ret = fuse_session_loop(se);
    } else {
        config = fuse_loop_cfg_create();
        if (config == NULL) {
            ret = 1;
            goto err_unmount;
        }
        fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
        fuse_loop_cfg_set_max_threads(config, opts.max_threads);
        ret = fuse_session_loop_mt(se, config);
        fuse_loop_cfg_destroy(config);
    }

err_unmount:
    if (audit_fd >= 0) {
        manage_audit_rules(global_opts.source_dir, getpid(), 0);
        shutdown_audit_system();
    }
    fuse_session_unmount(se);
err_signal:
    fuse_remove_signal_handlers(se);
err_session:
    fuse_session_destroy(se);
err_opts:
    free(opts.mountpoint);
err_early:
    free(global_opts.mountpoint);
    free(global_opts.source_dir);
    free(global_opts.tpm_handle_str);
    free(global_opts.tcti);
    fuse_opt_free_args(&args);

    return ret;
}
