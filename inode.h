#ifndef INODE_H
#define INODE_H

#define FUSE_USE_VERSION 312
#include <fuse3/fuse_lowlevel.h>
#include <sys/stat.h>
#include <limits.h>

/* Thread-safe Path-to-Inode lookup table operations */
fuse_ino_t add_inode(const char *rel_path);
fuse_ino_t find_inode(const char *rel_path);
void inode_forget(fuse_ino_t ino, uint64_t nlookup);
char *get_inode_path(fuse_ino_t ino);
void cleanup_inodes(void);

#endif /* INODE_H */
