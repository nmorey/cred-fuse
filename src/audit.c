#define _GNU_SOURCE
#include "audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <libaudit.h>

#define CRED_FUSE_AUDIT_KEY "cred-fuse-bypass"

static int audit_fd = -1;
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;

int init_audit_system(void) {
    pthread_mutex_lock(&audit_lock);
    if (audit_fd >= 0) {
        pthread_mutex_unlock(&audit_lock);
        return 0;
    }

    audit_fd = audit_open();
    if (audit_fd < 0) {
        syslog(LOG_WARNING, "Warning: Failed to open kernel audit netlink socket: %s (errno: %d)",
               strerror(errno), errno);
        pthread_mutex_unlock(&audit_lock);
        return -1;
    }

    /*
     * 10 ms send timeout to prevent blocking worker threads on Netlink queue congestion (SEC-04).
     */
    struct timeval tv = {
        .tv_sec = 0,
        .tv_usec = 10000
    };
    if (setsockopt(audit_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        syslog(LOG_WARNING, "Warning: Failed to set SO_SNDTIMEO on audit socket: %s",
               strerror(errno));
    }

    pthread_mutex_unlock(&audit_lock);
    return 0;
}

void shutdown_audit_system(void) {
    pthread_mutex_lock(&audit_lock);
    if (audit_fd >= 0) {
        audit_close(audit_fd);
        audit_fd = -1;
    }
    pthread_mutex_unlock(&audit_lock);
}

int audit_is_active(void) {
    return audit_fd >= 0;
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

    char dir_filter[PATH_MAX + 16];
    snprintf(dir_filter, sizeof(dir_filter), "dir=%s", source_dir);
    if (audit_rule_fieldpair_data(&rule, dir_filter, AUDIT_FILTER_EXIT) < 0) {
        audit_rule_free_data(rule);
        return NULL;
    }

    char perm_filter[] = "perm=rwa";
    if (audit_rule_fieldpair_data(&rule, perm_filter, AUDIT_FILTER_EXIT) < 0) {
        audit_rule_free_data(rule);
        return NULL;
    }

    char key_filter[128];
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

int manage_audit_rules(const char *source_dir, pid_t daemon_pid, int add) {
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

/*
 * Token bucket rate-limited netlink logger (SEC-04).
 * Limits events to 20 tokens/sec with a burst allowance of 50.
 */
static int safe_audit_log(const char *msg, int res) {
    if (!msg) {
        return -1;
    }

    pthread_mutex_lock(&audit_lock);
    if (audit_fd < 0) {
        pthread_mutex_unlock(&audit_lock);
        return -1;
    }

    static double tokens = 50.0;
    static struct timespec last_time = {0, 0};
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (last_time.tv_sec == 0 && last_time.tv_nsec == 0) {
        last_time = now;
    } else {
        double elapsed = (now.tv_sec - last_time.tv_sec) +
                         (now.tv_nsec - last_time.tv_nsec) / 1e9;
        if (elapsed > 0.0) {
            tokens += elapsed * 20.0; /* 20 tokens per second */
            if (tokens > 50.0) {
                tokens = 50.0;
            }
            last_time = now;
        }
    }

    if (tokens < 1.0) {
        pthread_mutex_unlock(&audit_lock);
        return -1; /* Rate limited: drop message to prevent netlink queue exhaustion */
    }
    tokens -= 1.0;

    int rc = audit_log_user_message(audit_fd, AUDIT_TRUSTED_APP, msg, NULL, NULL, NULL, res);
    int saved_errno = errno;
    pthread_mutex_unlock(&audit_lock);

    if (rc < 0 && saved_errno != EAGAIN && saved_errno != EWOULDBLOCK) {
        syslog(LOG_WARNING, "safe_audit_log: audit_log_user_message failed: %s", strerror(saved_errno));
    }
    return rc;
}

static void format_full_path(char *dst, size_t dst_sz,
                             const char *mountpoint, const char *path, const char *filename) {
    if (!dst || dst_sz == 0) {
        return;
    }

    size_t mlen = 0;
    if (mountpoint && strcmp(mountpoint, "/") != 0) {
        mlen = strlen(mountpoint);
        while (mlen > 0 && mountpoint[mlen - 1] == '/') {
            mlen--;
        }
    }

    const char *p = path ? path : "";
    while (*p == '/') {
        p++;
    }
    size_t plen = strlen(p);
    while (plen > 0 && p[plen - 1] == '/') {
        plen--;
    }

    const char *fn = filename ? filename : "";
    while (*fn == '/') {
        fn++;
    }
    size_t fnlen = strlen(fn);
    while (fnlen > 0 && fn[fnlen - 1] == '/') {
        fnlen--;
    }

    if (plen > 0 && fnlen > 0) {
        snprintf(dst, dst_sz, "%.*s/%.*s/%.*s", (int)mlen, mountpoint ? mountpoint : "", (int)plen, p, (int)fnlen, fn);
    } else if (plen > 0) {
        snprintf(dst, dst_sz, "%.*s/%.*s", (int)mlen, mountpoint ? mountpoint : "", (int)plen, p);
    } else if (fnlen > 0) {
        snprintf(dst, dst_sz, "%.*s/%.*s", (int)mlen, mountpoint ? mountpoint : "", (int)fnlen, fn);
    } else {
        if (mlen > 0) {
            snprintf(dst, dst_sz, "%.*s", (int)mlen, mountpoint);
        } else {
            snprintf(dst, dst_sz, "/");
        }
    }
}

void audit_log_open_success(const char *mountpoint, const char *path,
                            uint32_t uid, uint32_t gid, pid_t pid) {
    if (audit_fd < 0) {
        return;
    }

    char full_audit_path[PATH_MAX];
    format_full_path(full_audit_path, sizeof(full_audit_path), mountpoint, path, NULL);

    char *encoded_path = audit_encode_nv_string("path", full_audit_path, 0);

    char msg[1024];
    int ret = snprintf(msg, sizeof(msg),
                       "op=open %s uid=%u gid=%u pid=%d res=success",
                       encoded_path ? encoded_path : "path=?",
                       uid, gid, pid);
    free(encoded_path);
    if (ret >= (int)sizeof(msg)) {
        syslog(LOG_WARNING, "audit_log_open_success: audit message truncated");
    }

    safe_audit_log(msg, 1);
}

void audit_log_auth_failure(const char *mountpoint, const char *path, const char *filename,
                            uint32_t uid, uint32_t gid, pid_t pid,
                            const char *op, int err) {
    /* Only audit authorization failures (EACCES / EPERM) to prevent backlog saturation (SEC-04) */
    if ((err != EACCES && err != EPERM) || audit_fd < 0) {
        return;
    }

    char full_audit_path[PATH_MAX];
    format_full_path(full_audit_path, sizeof(full_audit_path), mountpoint, path, filename);

    char *encoded_path = audit_encode_nv_string("path", full_audit_path, 0);

    char errno_str[256];
    char *err_msg = strerror_r(err, errno_str, sizeof(errno_str));

    char msg[1024];
    int ret = snprintf(msg, sizeof(msg),
                       "op=%s %s uid=%u gid=%u pid=%d res=failed error=\"%s\"",
                       op ? op : "unknown",
                       encoded_path ? encoded_path : "path=?",
                       uid, gid, pid,
                       err_msg ? err_msg : "unknown error");
    free(encoded_path);
    if (ret >= (int)sizeof(msg)) {
        syslog(LOG_WARNING, "audit_log_auth_failure: audit message truncated");
    }

    safe_audit_log(msg, 0);
}
