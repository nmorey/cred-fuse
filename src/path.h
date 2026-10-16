#ifndef PATH_H
#define PATH_H

#define FUSE_USE_VERSION 312
#include <fuse3/fuse_lowlevel.h>
#include <sys/stat.h>
#include <limits.h>

/* Safely join a parent path and a component name, avoiding duplicate slashes */
int join_paths(char *dest, size_t size, const char *parent, const char *child);

/* Safely open, query, and validate file metadata relative to source_dir_fd */
int open_and_validate_path(const char *rel_path, struct stat *st_out);

/* Resolve an inode to its path, open it safely, and validate metadata */
int open_and_validate_ino(fuse_ino_t ino, struct stat *st_out);

#endif /* PATH_H */
