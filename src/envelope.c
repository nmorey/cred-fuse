#define _DEFAULT_SOURCE
#include "envelope.h"
#include "decryption.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <limits.h>

const inspect_envelope_fn envelope_inspectors[_CRED_ENV_VERSION_MAX] = {
    [CRED_ENV_VERSION_1] = inspect_envelope_v1,
    [CRED_ENV_VERSION_2] = inspect_envelope_v2,
};

ssize_t envelope_inspect_header_version(const struct cred_env_hdr *hdr, size_t hdr_len,
                                        off_t raw_size, size_t max_size,
                                        uint64_t min_version,
                                        struct env_data *out) {
    if (!hdr || hdr_len < sizeof(struct cred_env_commonhdr) || raw_size < 0) {
        return -EINVAL;
    }

    if (memcmp(hdr->common.magic, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN) != 0) {
        return -EBADMSG;
    }

    uint64_t file_ver = be64toh(hdr->common.version);
    if (min_version == 0) {
        min_version = CRED_ENV_VERSION_1;
    }

    if (file_ver < min_version || file_ver > CRED_ENV_CUR_VERSION ||
        file_ver <= CRED_ENV_VERSION_INVALID || file_ver >= _CRED_ENV_VERSION_MAX) {
        return -EPROTONOSUPPORT;
    }

    inspect_envelope_fn fn = envelope_inspectors[file_ver];
    if (!fn) {
        return -EPROTONOSUPPORT;
    }

    return fn(hdr, hdr_len, raw_size, max_size, out);
}

ssize_t envelope_inspect_header(const struct cred_env_hdr *hdr, size_t hdr_len,
                                off_t raw_size, size_t max_size) {
    return envelope_inspect_header_version(hdr, hdr_len, raw_size, max_size,
                                          CRED_ENV_CUR_VERSION, NULL);
}

ssize_t envelope_inspect_file_version(int fd, off_t raw_size, size_t max_size,
                                      uint64_t min_version,
                                      struct env_data *out) {
    if (fd < 0 || raw_size < 0) {
        return -EINVAL;
    }

    struct cred_env_hdr hdr;
    ssize_t n = pread(fd, &hdr, sizeof(hdr), 0);
    if (n < (ssize_t)sizeof(struct cred_env_commonhdr)) {
        return -ENOENT;
    }

    return envelope_inspect_header_version(&hdr, (size_t)n, raw_size, max_size,
                                          min_version, out);
}

ssize_t envelope_inspect_file(int fd, off_t raw_size, size_t max_size) {
    return envelope_inspect_file_version(fd, raw_size, max_size,
                                        CRED_ENV_CUR_VERSION, NULL);
}
