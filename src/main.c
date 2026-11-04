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

#define _DEFAULT_SOURCE
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
#include <linux/capability.h>
#include <sys/syscall.h>
#include <grp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <pthread.h>
#include <poll.h>
#include <libaudit.h>
#include <limits.h>
#include <syslog.h>

#include "decryption.h"
#include "inode.h"
#include "path.h"

#define MAX_ALLOWED_FILE_SIZE 65536
#define TPM_SAFE_DEFAULT_MAX_THREADS 5
#define TPM_WARN_MAX_THREADS 10

struct cred_fuse_opts global_opts;

enum {
    KEY_RO,
    KEY_DEFAULT_PERMISSIONS,
    KEY_FORBIDDEN_MOUNT_OPT,
};

static int is_ro = 0;
static int has_default_permissions = 0;
int mlockall_active = 0;

#define CRED_OPT(t, p) { t, offsetof(struct cred_fuse_opts, p), 1 }
static const struct fuse_opt cred_opts[] = {
    CRED_OPT("tpm_handle=%s", tpm_handle_str),
    CRED_OPT("tpm_pubkey=%s", tpm_pubkey),
    CRED_OPT("tcti=%s", tcti),
    { "max_open_files=%d", offsetof(struct cred_fuse_opts, max_open_files), 0 },
    { "max_file_size=%d", offsetof(struct cred_fuse_opts, max_file_size), 0 },
    { "max_threads=%d", offsetof(struct cred_fuse_opts, max_threads), 0 },
    FUSE_OPT_KEY("ro", KEY_RO),
    FUSE_OPT_KEY("default_permissions", KEY_DEFAULT_PERMISSIONS),
    FUSE_OPT_KEY("rw", KEY_FORBIDDEN_MOUNT_OPT),
    FUSE_OPT_KEY("suid", KEY_FORBIDDEN_MOUNT_OPT),
    FUSE_OPT_KEY("dev", KEY_FORBIDDEN_MOUNT_OPT),
    FUSE_OPT_KEY("exec", KEY_FORBIDDEN_MOUNT_OPT),
    FUSE_OPT_END
};

static int opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    (void)data;
    (void)outargs;

    if (key == KEY_FORBIDDEN_MOUNT_OPT) {
        fprintf(stderr, "Error: Mount option '%s' is forbidden.\n", arg);
        return -1;
    }

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

/*
 * Design note on per-UID open file limits:
 * System daemons (UID < MAX_SYSTEM_UID) receive dedicated slots 0..999 to
 * ensure autostart services have guaranteed access to HW-encrypted credentials.
 * Non-system users (UID >= MAX_SYSTEM_UID) intentionally share a single slot
 * (MAX_SYSTEM_UID) as interactive users are expected to utilize dedicated
 * credential stores (e.g., password managers) rather than this filesystem.
 */
#define MAX_SYSTEM_UID 1000
#define UID_COUNTER_SLOTS (MAX_SYSTEM_UID + 1)
static int open_files_per_uid[UID_COUNTER_SLOTS];

static inline uint16_t uid_to_slot(uid_t uid) {
    return (uid < MAX_SYSTEM_UID) ? (uint16_t)uid : (uint16_t)MAX_SYSTEM_UID;
}

static int audit_fd = -1;
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;

static void init_audit_system(void) {
    audit_fd = audit_open();
    if (audit_fd < 0) {
        syslog(LOG_WARNING, "Warning: Failed to open kernel audit netlink socket: %s (errno: %d)",
               strerror(errno), errno);
    }
}

static void shutdown_audit_system(void) {
    if (audit_fd >= 0) {
        audit_close(audit_fd);
        audit_fd = -1;
    }
}

#define CRED_FUSE_AUDIT_KEY "cred-fuse-bypass"

static struct audit_rule_data *build_base_rule(const char *source_dir) {
    struct audit_rule_data *rule = audit_rule_create_data();
    if (!rule) {
        return NULL;
    }

    if (audit_rule_syscallbyname_data(rule, "all") < 0) {
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

    char key_filter[64];
    snprintf(key_filter, sizeof(key_filter), "key=%s", CRED_FUSE_AUDIT_KEY);
    if (audit_rule_fieldpair_data(&rule, key_filter, AUDIT_FILTER_EXIT) < 0) {
        audit_rule_free_data(rule);
        return NULL;
    }

    return rule;
}

static void purge_stale_audit_rules(const char *source_dir) {
    if (audit_fd < 0 || !source_dir) {
        return;
    }

    if (audit_request_rules_list_data(audit_fd) <= 0) {
        return;
    }

    struct audit_rule_data *to_delete[64];
    size_t del_count = 0;
    size_t dir_len = strlen(source_dir);
    size_t key_len = strlen(CRED_FUSE_AUDIT_KEY);

    for (int iter = 0; iter < 4096; iter++) {
        struct pollfd pfd = { .fd = audit_fd, .events = POLLIN };
        if (poll(&pfd, 1, 200) <= 0) {
            break;
        }

        struct audit_reply rep;
        int rc = audit_get_reply(audit_fd, &rep, GET_REPLY_NONBLOCKING, 0);
        if (rc <= 0) {
            break;
        }

        if (rep.type == NLMSG_DONE || rep.type == NLMSG_ERROR) {
            break;
        }

        if (rep.type != AUDIT_LIST_RULES || !rep.ruledata) {
            continue;
        }

        const struct audit_rule_data *r = rep.ruledata;
        if ((r->flags & AUDIT_FILTER_MASK) != AUDIT_FILTER_EXIT) {
            continue;
        }

        int dir_matches = 0;
        int key_matches = 0;
        int has_pid = 0;
        uint32_t buf_off = 0;

        for (uint32_t i = 0; i < r->field_count && i < AUDIT_MAX_FIELDS; i++) {
            uint32_t ftype = r->fields[i] & ~AUDIT_OPERATORS;
            uint32_t fval = r->values[i];

            int is_str = (ftype == AUDIT_DIR || ftype == AUDIT_WATCH ||
                          ftype == AUDIT_FILTERKEY || ftype == AUDIT_EXE ||
                          (ftype >= AUDIT_SUBJ_USER && ftype <= AUDIT_SUBJ_CLR) ||
                          (ftype >= AUDIT_OBJ_USER && ftype <= AUDIT_OBJ_LEV_HIGH));
            if (is_str) {
                if (fval > r->buflen || buf_off > r->buflen - fval) {
                    break;
                }
                if (ftype == AUDIT_DIR && fval == dir_len &&
                    memcmp(r->buf + buf_off, source_dir, dir_len) == 0) {
                    dir_matches = 1;
                } else if (ftype == AUDIT_FILTERKEY && fval == key_len &&
                           memcmp(r->buf + buf_off, CRED_FUSE_AUDIT_KEY, key_len) == 0) {
                    key_matches = 1;
                }
                buf_off += fval;
            } else if (ftype == AUDIT_PID) {
                has_pid = 1;
            }
        }

        if (dir_matches && (key_matches || (r->action == AUDIT_NEVER && has_pid)) &&
            del_count < (sizeof(to_delete) / sizeof(to_delete[0]))) {
            size_t rule_sz = sizeof(*r) + r->buflen;
            struct audit_rule_data *copy = malloc(rule_sz);
            if (copy) {
                memcpy(copy, r, rule_sz);
                to_delete[del_count++] = copy;
            }
        }
    }

    for (size_t i = 0; i < del_count; i++) {
        (void)audit_delete_rule_data(audit_fd, to_delete[i],
                                     to_delete[i]->flags & AUDIT_FILTER_MASK,
                                     to_delete[i]->action);
        free(to_delete[i]);
    }
}

static int manage_audit_rules(const char *source_dir, pid_t daemon_pid, int add) {
    if (audit_fd < 0) {
        return -1;
    }

    if (add) {
        purge_stale_audit_rules(source_dir);
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
        if (add) {
            rc_watch = audit_add_rule_data(audit_fd, rule_watch, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
        } else {
            rc_watch = audit_delete_rule_data(audit_fd, rule_watch, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
        }
        audit_rule_free_data(rule_watch);
    }

    return (rc_exclude > 0 && rc_watch > 0) ? 0 : -1;
}

static void reply_err_and_audit(fuse_req_t req, int err, const char *op, fuse_ino_t ino, const char *filename) {
    int skip_audit = (err == ENOENT && op != NULL &&
                      (strcmp(op, "lookup") == 0 || strcmp(op, "getattr") == 0));

    if (err > 0 && audit_fd >= 0 && !skip_audit) {
        const struct fuse_ctx *ctx = fuse_req_ctx(req);
        char *path = NULL;

        if (ino > 1) {
            path = get_inode_path(ino);
        }

        const char *mount_prefix = global_opts.mountpoint ? global_opts.mountpoint : "";
        if (strcmp(mount_prefix, "/") == 0) {
            mount_prefix = "";
        }

        char full_audit_path[PATH_MAX];
        snprintf(full_audit_path, sizeof(full_audit_path), "%s%s%s%s",
                 mount_prefix,
                 path ? path : "",
                 (path && filename) ? "/" : "",
                 filename ? filename : "");

        char *encoded_path = audit_encode_nv_string("path", full_audit_path, 0);

        char msg[1024];
        char errno_str[256];

        strerror_r(err, errno_str, sizeof(errno_str));
        int ret = snprintf(msg, sizeof(msg),
                 "op=%s %s uid=%u gid=%u pid=%d res=failed error=\"%s\"",
                 op,
                 encoded_path ? encoded_path : "path=?",
                 ctx->uid, ctx->gid, ctx->pid,
                 errno_str);
        free(encoded_path);
        if (ret >= (int)sizeof(msg)) {
            syslog(LOG_WARNING, "reply_err_and_audit: audit message truncated");
        }

        pthread_mutex_lock(&audit_lock);
        int rc = audit_log_user_message(audit_fd, AUDIT_TRUSTED_APP, msg, NULL, NULL, NULL, 0);
        int saved_errno = errno;
        pthread_mutex_unlock(&audit_lock);
        if (rc < 0) {
            syslog(LOG_WARNING, "reply_err_and_audit: audit_log_user_message failed: %s", strerror(saved_errno));
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
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
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

static void sanitize_stat_mode(struct stat *st) {
    if (S_ISREG(st->st_mode)) {
        st->st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH | S_ISUID | S_ISGID | S_ISVTX);
    } else {
        st->st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH | S_ISUID | S_ISGID);
    }
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

    struct stat st;
    int fd = open_and_validate_path(rel_path, &st);
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
    sanitize_stat_mode(&e.attr);

    if (fuse_reply_entry(req, &e) < 0) {
        inode_forget(new_ino, 1);
    }
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
    sanitize_stat_mode(&st);
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

    uint16_t uid_slot = uid_to_slot(fuse_req_ctx(req)->uid);
    int current = __atomic_add_fetch(&open_files_per_uid[uid_slot], 1, __ATOMIC_SEQ_CST);
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

    char *path = get_inode_path(ino);
    if (!path) {
        err_code = errno ? errno : ENOENT;
        goto err_close;
    }

    node = malloc(sizeof(struct decrypted_node));
    if (!node) {
        err_code = ENOMEM;
        goto err_free_path;
    }
    memset(node, 0, sizeof(*node));
    node->uid_slot = uid_slot;

    int r = decrypt_credential(fd, path, node);
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

        const char *mount_prefix = global_opts.mountpoint ? global_opts.mountpoint : "";
        if (strcmp(mount_prefix, "/") == 0) {
            mount_prefix = "";
        }

        char full_audit_path[PATH_MAX];
        snprintf(full_audit_path, sizeof(full_audit_path), "%s%s", mount_prefix, path);
        char *encoded_path = audit_encode_nv_string("path", full_audit_path, 0);

        char msg[1024];
        int ret = snprintf(msg, sizeof(msg),
                 "op=open %s uid=%u gid=%u pid=%d res=success",
                 encoded_path ? encoded_path : "path=?",
                 ctx->uid, ctx->gid, ctx->pid);
        free(encoded_path);
        if (ret >= (int)sizeof(msg)) {
            syslog(LOG_WARNING, "cred_ll_open: audit message truncated");
        }
        pthread_mutex_lock(&audit_lock);
        int rc = audit_log_user_message(audit_fd, AUDIT_TRUSTED_APP, msg, NULL, NULL, NULL, 1);
        int saved_errno = errno;
        pthread_mutex_unlock(&audit_lock);
        if (rc < 0) {
            syslog(LOG_WARNING, "cred_ll_open: audit_log_user_message failed: %s", strerror(saved_errno));
        }
    }

    free(path);
    if (fuse_reply_open(req, fi) < 0) {
        clean_decrypted_node(node);
        free(node);
        __atomic_sub_fetch(&open_files_per_uid[uid_slot], 1, __ATOMIC_SEQ_CST);
    }
    return;

err_free_node:
    clean_decrypted_node(node);
    free(node);
err_free_path:
    free(path);
err_close:
    close(fd);
err_decrement:
    __atomic_sub_fetch(&open_files_per_uid[uid_slot], 1, __ATOMIC_SEQ_CST);
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

    if ((uint64_t)off >= (uint64_t)node->len) {
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
        uint16_t uid_slot = node->uid_slot;
        clean_decrypted_node(node);
        free(node);
        __atomic_sub_fetch(&open_files_per_uid[uid_slot], 1, __ATOMIC_SEQ_CST);
    }
    fuse_reply_err(req, 0);
}

/* 6. READDIR: Formats directory entries directly */
#define MAX_READDIR_BUF_SIZE 65536

static void cred_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)fi;
    if (off < 0) {
        reply_err_and_audit(req, EINVAL, "readdir", ino, NULL);
        return;
    }

    if (size == 0) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }
    if (size > MAX_READDIR_BUF_SIZE) {
        size = MAX_READDIR_BUF_SIZE;
    }

    char *rel_path = get_inode_path(ino);
    if (!rel_path) {
        reply_err_and_audit(req, errno, "readdir", ino, NULL);
        return;
    }

    struct stat st;
    int dir_fd = open_and_validate_path(rel_path, &st);
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

    char *buf = malloc(size);
    if (!buf) {
        closedir(dp);
        free(rel_path);
        reply_err_and_audit(req, ENOMEM, "readdir", ino, NULL);
        return;
    }

    size_t used = 0;

    if (off <= 0) {
        size_t entry_size = fuse_add_direntry(req, NULL, 0, ".", NULL, 0);
        if (used + entry_size <= size) {
            struct stat dot_st;
            memset(&dot_st, 0, sizeof(dot_st));
            dot_st.st_ino = ino;
            dot_st.st_mode = S_IFDIR;
            fuse_add_direntry(req, buf + used, size - used, ".", &dot_st, 1);
            used += entry_size;
        } else {
            goto done;
        }
    }

    if (off <= 1) {
        size_t entry_size = fuse_add_direntry(req, NULL, 0, "..", NULL, 0);
        if (used + entry_size <= size) {
            fuse_ino_t parent_ino = 1;
            const char *last_slash = strrchr(rel_path, '/');
            if (last_slash && last_slash > rel_path) {
                size_t parent_len = (size_t)(last_slash - rel_path);
                if (parent_len < PATH_MAX) {
                    char parent_rel_path[PATH_MAX];
                    memcpy(parent_rel_path, rel_path, parent_len);
                    parent_rel_path[parent_len] = '\0';
                    fuse_ino_t resolved = add_inode(parent_rel_path, 0);
                    if (resolved != 0) {
                        parent_ino = resolved;
                    }
                }
            }
            struct stat dotdot_st;
            memset(&dotdot_st, 0, sizeof(dotdot_st));
            dotdot_st.st_ino = parent_ino;
            dotdot_st.st_mode = S_IFDIR;
            fuse_add_direntry(req, buf + used, size - used, "..", &dotdot_st, 2);
            used += entry_size;
        } else {
            goto done;
        }
    }

    off_t cur_idx = 2;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        off_t this_idx = cur_idx++;
        if (this_idx < off) {
            continue;
        }

        if (!is_valid_name(de->d_name)) {
            continue; // Skip any entries with invalid/unsafe names
        }

        if (de->d_type == DT_LNK) {
            continue; // Skip symbolic links entirely
        }

        size_t entry_size = fuse_add_direntry(req, NULL, 0, de->d_name, NULL, 0);
        if (used + entry_size > size) {
            break;
        }

        // Construct the relative path of this entry to validate and register/find its inode
        char entry_rel_path[PATH_MAX];
        if (join_paths(entry_rel_path, sizeof(entry_rel_path), rel_path, de->d_name) < 0) {
            continue;
        }

        if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN) {
            struct stat tmp_st;
            int fd = open_and_validate_path(entry_rel_path, &tmp_st);
            if (fd < 0) {
                continue; // Skip invalid, unmanaged, or symlinked files cleanly
            }
            close(fd);
        }

        fuse_ino_t entry_ino;
        switch (de->d_type) {
        case DT_REG:
        case DT_UNKNOWN:
        case DT_DIR:
            entry_ino = add_inode(entry_rel_path, 0);
            break;
        default:
            entry_ino = find_inode(entry_rel_path);
            break;
        }
        if (!entry_ino) {
            continue;
        }

        struct stat entry_st;
        memset(&entry_st, 0, sizeof(entry_st));
        entry_st.st_ino = entry_ino;
        fuse_add_direntry(req, buf + used, size - used, de->d_name, &entry_st, this_idx + 1);
        used += entry_size;
    }

done:
    closedir(dp);
    fuse_reply_buf(req, used > 0 ? buf : NULL, used);
    free(buf);
    free(rel_path);
}

/* 8. GETXATTR: Forward POSIX ACL and LSM/SELinux extended attributes */
static void cred_ll_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size) {
    if (!name ||
        (strcmp(name, "system.posix_acl_access") != 0 &&
         strcmp(name, "system.posix_acl_default") != 0 &&
         strncmp(name, "security.", 9) != 0)) {
        fuse_reply_err(req, ENODATA);
        return;
    }

    struct stat st;
    int fd = open_and_validate_ino(ino, &st);
    if (fd < 0) {
        reply_err_and_audit(req, -fd, "getxattr", ino, name);
        return;
    }

    if (size == 0) {
        ssize_t res = fgetxattr(fd, name, NULL, 0);
        int saved_errno = errno;
        close(fd);
        if (res < 0) {
            fuse_reply_err(req, saved_errno);
        } else {
            fuse_reply_xattr(req, (size_t)res);
        }
        return;
    }

    if (size > 65536) {
        close(fd);
        fuse_reply_err(req, ERANGE);
        return;
    }

    char *buf = malloc(size);
    if (!buf) {
        close(fd);
        fuse_reply_err(req, ENOMEM);
        return;
    }

    ssize_t res = fgetxattr(fd, name, buf, size);
    int saved_errno = errno;
    close(fd);

    if (res < 0) {
        free(buf);
        fuse_reply_err(req, saved_errno);
    } else {
        fuse_reply_buf(req, buf, (size_t)res);
        free(buf);
    }
}

static int set_process_caps(uint64_t eff_mask, uint64_t perm_mask) {
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));

    data[0].effective = (uint32_t)(eff_mask & 0xFFFFFFFFULL);
    data[1].effective = (uint32_t)(eff_mask >> 32);
    data[0].permitted = (uint32_t)(perm_mask & 0xFFFFFFFFULL);
    data[1].permitted = (uint32_t)(perm_mask >> 32);
    data[0].inheritable = 0;
    data[1].inheritable = 0;

    return (int)syscall(SYS_capset, &hdr, data);
}

static int drop_privileges(void) {
#ifdef CRED_FUSE_ENABLE_SWTPM
    if (geteuid() != 0) {
        return 0;
    }
#endif
    /* Ensure the daemon belongs to the 'tss' group if present so /dev/tpmrm*
     * (commonly 0660 root:tss or tss:tss) remains accessible without CAP_DAC_OVERRIDE. */
    struct group *tss_grp = getgrnam("tss");
    if (tss_grp != NULL) {
        gid_t gids[1] = { tss_grp->gr_gid };
        (void)setgroups(1, gids);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        syslog(LOG_ERR, "Failed to set PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
        return -1;
    }

    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    uint64_t eff_mask = (1ULL << CAP_DAC_READ_SEARCH) |
                        (1ULL << CAP_IPC_LOCK) |
                        (1ULL << CAP_AUDIT_WRITE);
    uint64_t perm_mask = eff_mask |
                         (1ULL << CAP_AUDIT_CONTROL) |
                         (1ULL << CAP_SYS_ADMIN);

    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (cap < 64 && (perm_mask & (1ULL << cap))) {
            continue;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) {
            syslog(LOG_ERR, "Failed to drop capability %d from bounding set: %s", cap, strerror(errno));
            return -1;
        }
    }

    if (set_process_caps(eff_mask, perm_mask) != 0) {
        syslog(LOG_ERR, "Failed to drop process capabilities: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se = NULL;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config *config = NULL;
    int ret = -1;

    memset(&opts, 0, sizeof(opts));

#ifndef CRED_FUSE_ENABLE_SWTPM
    if (geteuid() != 0) {
        fprintf(stderr, "Error: mount.cred-fuse must be run as root.\n");
        return 1;
    }
#endif

    // Scrub TCTI environment variables so libtss2-tctildr cannot be hijacked when -o tcti is omitted
    unsetenv("TSS2_TCTI");
    unsetenv("TPM2TOOLS_TCTI");
    unsetenv("TCTI");

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
    global_opts.source_dir_fd = -1;
    global_opts.max_open_files = 1024;
    global_opts.max_file_size = MAX_ALLOWED_FILE_SIZE;
    global_opts.max_threads = -1;

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

    global_opts.source_dir_fd = open(global_opts.source_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (global_opts.source_dir_fd < 0) {
        perror("Failed to open source_dir");
        ret = 1;
        goto err_early;
    }
    struct stat sd_st;
    if (fstat(global_opts.source_dir_fd, &sd_st) != 0) {
        perror("Failed to stat source_dir");
        ret = 1;
        goto err_early;
    }
#ifdef CRED_FUSE_ENABLE_SWTPM
    if (sd_st.st_uid != 0 && sd_st.st_uid != geteuid()) {
#else
    if (sd_st.st_uid != 0) {
#endif
        fprintf(stderr, "Error: source_dir must be owned by root.\n");
        ret = 1;
        goto err_early;
    }

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

    if (init_decryption() != 0) {
        fprintf(stderr, "Failed to initialize decryption\n");
        ret = 1;
        goto err_early;
    }

    /*
     * We perform an early TPM lockout check in the foreground to catch errors
     * before mounting. However, if the tabrmd TCTI backend is used, querying
     * the TPM initializes GLib/GDBus worker threads and D-Bus connections.
     * These background threads and socket states do not survive fuse_daemonize()
     * (fork), leading to stale connections and 25s D-Bus timeouts in the daemon.
     *
     * To prevent D-Bus state corruption across fork(), we re-exec the binary
     * with _CREDFUSE_LOCKOUT_CHECKED set upon a successful check. The execv()
     * completely flushes the process memory space and GLib/D-Bus state, ensuring
     * a clean slate before fuse_daemonize() forks.
     */
    if (!getenv("_CREDFUSE_LOCKOUT_CHECKED")) {
        if (check_tpm_lockout() != 0) {
            ret = 1;
            goto err_early;
        }

        if (setenv("_CREDFUSE_LOCKOUT_CHECKED", "1", 1) != 0) {
            perror("setenv failed");
            ret = 1;
            goto err_early;
        }

        execv("/proc/self/exe", argv);
        perror("execv failed");
        ret = 1;
        goto err_early;
    } else {
        unsetenv("_CREDFUSE_LOCKOUT_CHECKED");
    }

    /* Parse mounting options and extract mountpoint */
    if (fuse_parse_cmdline(&args, &opts) != 0) {
        ret = 1;
        goto err_early;
    }

    /*
     * Bound default worker threads to prevent overwhelming the TPM resource
     * manager (/dev/tpmrm0) with concurrent cryptographic sessions during
     * parallel I/O bursts. Warn if explicitly configured above 10.
     */
    if (global_opts.max_threads > 0) {
        opts.max_threads = (unsigned int)global_opts.max_threads;
    } else {
        opts.max_threads = TPM_SAFE_DEFAULT_MAX_THREADS;
    }
    if (opts.max_threads > TPM_WARN_MAX_THREADS) {
        syslog(LOG_WARNING,
               "Warning: max_threads (%u) exceeds %d; concurrent requests may exhaust TPM hardware sessions or overload /dev/tpmrm0",
               opts.max_threads, TPM_WARN_MAX_THREADS);
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

    if (fuse_opt_add_arg(&args, "-oro,default_permissions,nosuid,nodev,noexec") != 0) {
        fprintf(stderr, "Error: Failed to enforce mount hardening flags.\n");
        ret = 1;
        goto err_opts;
    }

    static const struct fuse_lowlevel_ops cred_ll_oper = {
        .lookup   = cred_ll_lookup,
        .getattr  = cred_ll_getattr,
        .getxattr = cred_ll_getxattr,
        .open     = cred_ll_open,
        .read     = cred_ll_read,
        .readdir  = cred_ll_readdir,
        .release  = cred_ll_release,
        .forget   = cred_ll_forget,
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
    openlog("mount.cred-fuse", LOG_PID | (opts.foreground ? LOG_PERROR : 0), LOG_DAEMON);

    init_audit_system();
    if (audit_fd >= 0) {
        if (manage_audit_rules(global_opts.source_dir, getpid(), 1) != 0) {
            syslog(LOG_WARNING, "Warning: Failed to install kernel audit rules for %s", global_opts.source_dir);
        }
    }

    struct rlimit memlock_rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &memlock_rlim) != 0) {
        if (getrlimit(RLIMIT_MEMLOCK, &memlock_rlim) == 0 &&
            memlock_rlim.rlim_cur < memlock_rlim.rlim_max) {
            memlock_rlim.rlim_cur = memlock_rlim.rlim_max;
            (void)setrlimit(RLIMIT_MEMLOCK, &memlock_rlim);
        }
    }

    /* Lock all current and future memory to prevent swapping secrets (post-fork daemon context).
     * NOTE: It is structurally safe that mlockall_active is initialized post-daemonize:
     * No secure allocations via malloc_mlock/free_munlock are active prior to the event loop.
     * Non-secret allocations like inode paths are freed via standard free(), never free_munlock. */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        mlockall_active = 1;
    } else {
        mlockall_active = 0;
        syslog(LOG_WARNING, "Warning: Failed to lock memory in daemon (mlockall: %s). Falling back to individual mlock calls.",
               strerror(errno));
    }

    if (drop_privileges() != 0) {
        ret = 1;
        goto err_unmount;
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
#ifdef CRED_FUSE_ENABLE_SWTPM
    if (geteuid() == 0)
#endif
    {
        uint64_t shutdown_mask = (1ULL << CAP_DAC_READ_SEARCH) |
                                 (1ULL << CAP_IPC_LOCK) |
                                 (1ULL << CAP_AUDIT_WRITE) |
                                 (1ULL << CAP_AUDIT_CONTROL) |
                                 (1ULL << CAP_SYS_ADMIN);
        (void)set_process_caps(shutdown_mask, shutdown_mask);
    }
    if (audit_fd >= 0) {
        manage_audit_rules(global_opts.source_dir, getpid(), 0);
        shutdown_audit_system();
    }
    closelog();
    fuse_session_unmount(se);
err_signal:
    fuse_remove_signal_handlers(se);
err_session:
    fuse_session_destroy(se);
err_opts:
    free(opts.mountpoint);
err_early:
    if (global_opts.source_dir_fd >= 0) {
        close(global_opts.source_dir_fd);
    }
    free(global_opts.mountpoint);
    free(global_opts.source_dir);
    free(global_opts.tpm_handle_str);
    free(global_opts.tpm_pubkey);
    free(global_opts.tcti);
    fuse_opt_free_args(&args);

    return ret;
}
