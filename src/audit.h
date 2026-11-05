#ifndef CRED_FUSE_AUDIT_H
#define CRED_FUSE_AUDIT_H

#include <sys/types.h>
#include <stdint.h>

/*
 * Lifecycle management for kernel audit netlink connection
 */
int init_audit_system(void);
void shutdown_audit_system(void);
int audit_is_active(void);

/*
 * Kernel audit rule management for the encrypted source directory
 */
int manage_audit_rules(const char *source_dir, pid_t daemon_pid, int add);

/*
 * Rate-limited audit event dispatchers
 */
void audit_log_open_success(const char *mountpoint, const char *path,
                            uint32_t uid, uint32_t gid, pid_t pid);

void audit_log_auth_failure(const char *mountpoint, const char *path, const char *filename,
                            uint32_t uid, uint32_t gid, pid_t pid,
                            const char *op, int err);

#endif /* CRED_FUSE_AUDIT_H */
