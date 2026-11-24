#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "envelope.h"
#include "secure_mem.h"
#include "cred_opts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <limits.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* Weak stub for targets that do not link a TPM adapter (e.g. offline encryptor, inspect tests) */
__attribute__((weak)) int tpm_unwrap(const uint8_t *in_data, size_t in_len,
                                     const uint8_t oaep_label[33],
                                     struct decrypted_node *out) {
    (void)in_data;
    (void)in_len;
    (void)oaep_label;
    (void)out;
    return -ENOSYS;
}

const inspect_envelope_fn envelope_inspectors[_CRED_ENV_VERSION_MAX] = {
    [CRED_ENV_VERSION_1] = inspect_envelope_v1,
    [CRED_ENV_VERSION_2] = inspect_envelope_v2,
};

const decrypt_envelope_fn envelope_decryptors[_CRED_ENV_VERSION_MAX] = {
    [CRED_ENV_VERSION_1] = decrypt_envelope_v1,
    [CRED_ENV_VERSION_2] = decrypt_envelope_v2,
};

const encrypt_envelope_fn envelope_encryptors[_CRED_ENV_VERSION_MAX] = {
#ifdef CRED_FUSE_TESTING
    [CRED_ENV_VERSION_1] = encrypt_envelope_v1,
#endif
    [CRED_ENV_VERSION_2] = encrypt_envelope_v2,
};

int parse_octal_mode(const char *mode_str, mode_t *mode_out) {
    if (!mode_str || *mode_str == '\0' || !mode_out) {
        return -EINVAL;
    }
    size_t len = strlen(mode_str);
    if (len > 6) {
        return -EINVAL;
    }
    for (size_t i = 0; i < len; i++) {
        if (mode_str[i] < '0' || mode_str[i] > '7') {
            return -EINVAL;
        }
    }
    char *endptr = NULL;
    errno = 0;
    unsigned long val = strtoul(mode_str, &endptr, 8);
    if (errno != 0 || !endptr || *endptr != '\0' || val > 07777UL) {
        return -EINVAL;
    }
    *mode_out = (mode_t)val;
    return 0;
}

int do_aes_decrypt(const uint8_t *iv,
                   const uint8_t *tag,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   const struct decrypted_node *eph_key,
                   struct decrypted_node *out) {
    uint8_t tag_buf[16];
    EVP_CIPHER_CTX *ctx;
    uint8_t *plain;
    size_t alloc_sz;
    int aad_out_len = 0, len1 = 0, len2 = 0;
    int ret_err = -EIO;

    if (!iv || !tag || (!ciphertext && ciphertext_len > 0)) {
        return -EINVAL;
    }

    if (!eph_key || !eph_key->buf || eph_key->len != 32) {
        return -EINVAL;
    }

    if (!aad || aad_len == 0 || aad_len > INT_MAX) {
        return -EINVAL;
    }

    memcpy(tag_buf, tag, sizeof(tag_buf));

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -ENOMEM;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        ret_err = -EIO;
        goto decrypt_init_err;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) {
        ret_err = -EIO;
        goto decrypt_init_err;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, eph_key->buf, iv) != 1) {
        ret_err = -EIO;
        goto decrypt_init_err;
    }

    if (ciphertext_len > INT_MAX) {
        ret_err = -E2BIG;
        goto decrypt_init_err;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &aad_out_len, (const uint8_t *)aad, (int)aad_len) != 1) {
        ret_err = -EACCES;
        goto decrypt_init_err;
    }

    alloc_sz = ciphertext_len > 0 ? ciphertext_len : 1;
    plain = malloc_mlock(alloc_sz);
    if (!plain) {
        ret_err = -errno;
        goto decrypt_init_err;
    }

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plain, &len1, ciphertext, (int)ciphertext_len) != 1) {
            ret_err = -EACCES;
            goto decrypt_update_err;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag_buf) != 1) {
        ret_err = -EIO;
        goto decrypt_update_err;
    }

    if (EVP_DecryptFinal_ex(ctx, plain + len1, &len2) != 1) {
        ret_err = -EACCES;
        goto decrypt_final_err;
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(tag_buf, sizeof(tag_buf));

    out->len = (size_t)len1 + (size_t)len2;
    out->allocated_size = alloc_sz;
    out->buf = plain;

    return 0;

 decrypt_final_err:
 decrypt_update_err:
    free_munlock(plain, alloc_sz);
 decrypt_init_err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(tag_buf, sizeof(tag_buf));
    ERR_clear_error();
    return ret_err;
}

int decrypt_envelope_version(const uint8_t *enc_data, size_t enc_len,
                             const char *rel_path, mode_t mode,
                             struct decrypted_node *out,
                             uint64_t *version_out) {
    if (!enc_data || !rel_path || !out) {
        return -EINVAL;
    }

    if (enc_len < sizeof(struct cred_env_commonhdr)) {
        return -EBADMSG;
    }

    const struct cred_env_hdr *hdr = (const struct cred_env_hdr *)enc_data;
    if (memcmp(hdr->common.magic, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN) != 0) {
        return -EBADMSG;
    }

    uint64_t version = be64toh(hdr->common.version);
    if (version_out) {
        *version_out = version;
    }

    if (version <= CRED_ENV_VERSION_INVALID || version >= _CRED_ENV_VERSION_MAX) {
        return -EPROTONOSUPPORT;
    }

    decrypt_envelope_fn fn = envelope_decryptors[version];
    if (!fn) {
        return -EPROTONOSUPPORT;
    }

    return fn(enc_data, enc_len, rel_path, mode, out);
}

int decrypt_envelope(const uint8_t *enc_data, size_t enc_len,
                     const char *rel_path, mode_t mode,
                     struct decrypted_node *out) {
    if (CRED_ENV_CUR_VERSION <= CRED_ENV_VERSION_INVALID ||
        CRED_ENV_CUR_VERSION >= _CRED_ENV_VERSION_MAX) {
        return -EPROTONOSUPPORT;
    }

    decrypt_envelope_fn fn = envelope_decryptors[CRED_ENV_CUR_VERSION];
    if (!fn) {
        return -EPROTONOSUPPORT;
    }

    return fn(enc_data, enc_len, rel_path, mode, out);
}

static int read_file_fd(int fd, uint8_t **buf, size_t *len, mode_t *mode_out, size_t max_size) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        return -errno;
    }

    off_t size = st.st_size;
    if (size <= 0) {
        return size == 0 ? -ENODATA : -EIO;
    }

    if ((size_t)size > max_size) {
        return -EFBIG;
    }

    *buf = malloc_mlock(size);
    if (!*buf) {
        return -ENOMEM;
    }

    size_t bytes_read = 0;
    while (bytes_read < (size_t)size) {
        ssize_t r = pread(fd, *buf + bytes_read, (size_t)size - bytes_read, (off_t)bytes_read);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            int err = -errno;
            free_munlock(*buf, size);
            *buf = NULL;
            return err;
        }
        if (r == 0) {
            free_munlock(*buf, size);
            *buf = NULL;
            return -EIO;
        }
        bytes_read += (size_t)r;
    }

    *len = bytes_read;
    if (mode_out) {
        *mode_out = st.st_mode & 07777;
    }
    return 0;
}

int decrypt_credential(int fd, const char *rel_path, struct decrypted_node *out) {
    uint8_t *enc_data = NULL;
    size_t enc_len = 0;
    mode_t file_mode = 0;
    int r;

    size_t max_enc_size = (size_t)MAX_ALLOWED_FILE_SIZE + sizeof(struct cred_env_hdr);
    r = read_file_fd(fd, &enc_data, &enc_len, &file_mode, max_enc_size);
    if (r < 0) {
        return r;
    }

    r = decrypt_envelope(enc_data, enc_len, rel_path, file_mode, out);
    free_munlock(enc_data, enc_len);
    return r;
}

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
