#ifndef INODE_H
#define INODE_H

#define FUSE_USE_VERSION 312
#include <fuse3/fuse_lowlevel.h>
#include <sys/stat.h>
#include <limits.h>

/* Safely join a parent path and a component name, avoiding duplicate slashes */
int join_paths(char *dest, size_t size, const char *parent, const char *child);

/* Convert relative fuse path to absolute path in source_dir */
int build_path(char *dest, size_t size, const char *rel_path);

/* Safely open, query, and validate file metadata using a secure file descriptor */
int open_and_validate_path(const char *full_path, struct stat *st_out);

/* Resolve an inode to its path, open it safely, and validate metadata */
int open_and_validate_ino(fuse_ino_t ino, struct stat *st_out);

/* Thread-safe Path-to-Inode lookup table operations */
fuse_ino_t add_inode(const char *rel_path);
fuse_ino_t find_inode(const char *rel_path);
void inode_lookup_inc(fuse_ino_t ino);
void inode_forget(fuse_ino_t ino, uint64_t nlookup);
char *get_inode_path(fuse_ino_t ino);
void cleanup_inodes(void);

#endif /* INODE_H */
