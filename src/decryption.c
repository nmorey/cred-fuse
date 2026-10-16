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

#include "decryption.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <endian.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>

struct pinned_tpm_key {
    pthread_mutex_t lock;
    uint8_t modulus[TPM2_RSA4096_KEY_BYTES];
    size_t modulus_len;
    TPM2B_NAME name;
};

static struct pinned_tpm_key pinned_key = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .modulus = {0},
    .modulus_len = 0,
    .name = {0}
};

static long system_page_size = 4096;

static inline size_t get_aligned_size(size_t size) {
    if (mlockall_active) {
        return size;
    }
    size_t page_size = (size_t)system_page_size;
    if (size > SIZE_MAX - page_size + 1) {
        return SIZE_MAX;
    }
    return ((size + page_size - 1) / page_size) * page_size;
}

void *malloc_mlock(size_t size)
{
    void *ptr = NULL;
    if (!mlockall_active) {
        size_t aligned_size = get_aligned_size(size);
        size_t page_size = (size_t)system_page_size;
        int ret = posix_memalign(&ptr, page_size, aligned_size);
        if (ret != 0) {
            errno = ret;
            return NULL;
        }
        if (mlock(ptr, aligned_size) != 0) {
            int saved_errno = errno;
            free(ptr);
            errno = saved_errno;
            return NULL;
        }
        memset(ptr, 0, aligned_size);
    } else {
        ptr = malloc(size);
        if (ptr) {
            memset(ptr, 0, size);
        }
    }
    return ptr;
}

void free_munlock(void *ptr, size_t size)
{
    if (!ptr)
	return;

    size_t aligned_size = get_aligned_size(size);
    OPENSSL_cleanse(ptr, aligned_size);
    if (!mlockall_active) {
        munlock(ptr, aligned_size);
    }
    free(ptr);
}

void clean_decrypted_node(struct decrypted_node *node)
{
    if (!node || !node->buf)
	return;

    free_munlock(node->buf, node->allocated_size);
    memset(node, 0, sizeof(*node));
}

int validate_tcti(const char *tcti) {
    if (!tcti) {
        return 1;
    }

    const char *allowed_schemes[] = {
        "device",
#ifdef CRED_FUSE_ENABLE_SWTPM
        "swtpm",
#endif
        "tabrmd"
    };
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

    // Bare scheme without ':options' (e.g., "tabrmd", "device", "swtpm")
    if (!colon) {
#ifdef CRED_FUSE_ENABLE_SWTPM
        if (strcmp(scheme, "swtpm") == 0) {
            return 0; // Bare "swtpm" defaults to TCP; require "swtpm:path=/..."
        }
#endif
        if (strcmp(scheme, "device") == 0) {
            return 0; // Bare "device" can fall back to /dev/tpm0; require "device:/dev/tpmrm..."
        }
        return 1; // Bare "tabrmd" is valid
    }

    const char *options = colon + 1;
    if (*options == '\0') {
        return 0; // Empty options trailing a colon is invalid
    }

    // 2. Validate Options based on Scheme
    if (strcmp(scheme, "device") == 0) {
        // Must use the in-kernel TPM resource manager: e.g. /dev/tpmrm0
        if (strncmp(options, "/dev/tpmrm", 10) != 0 || options[10] == '\0') {
            return 0;
        }
        for (size_t i = 10; options[i] != '\0'; i++) {
            char c = options[i];
            if (!(c >= '0' && c <= '9')) {
                return 0; // Block raw /dev/tpm0, path traversal, or non-digits
            }
        }
#ifdef CRED_FUSE_ENABLE_SWTPM
    } else if (strcmp(scheme, "swtpm") == 0) {
        // Swtpm requires path=/absolute/path/to/socket
        if (strncmp(options, "path=", 5) != 0) {
            return 0;
        }
        const char *path = options + 5;
        if (path[0] != '/' || path[1] == '\0') {
            return 0; // Must be a non-root absolute path
        }
        if (strstr(path, "..") != NULL) {
            return 0; // Block path traversal sequences
        }
        for (size_t i = 0; path[i] != '\0'; i++) {
            char c = path[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '/' || c == '.' || c == '-' || c == '_')) {
                return 0; // Block commands, wildcard shells, etc.
            }
        }
#endif
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

int format_credential_aad(char *buf, size_t buf_sz, const char *rel_path, mode_t mode) {
    if (!buf || buf_sz == 0 || !rel_path) {
        return -EINVAL;
    }

    while (*rel_path == '/') {
        rel_path++;
    }
    if (*rel_path == '\0') {
        return -EINVAL;
    }

    const char *p = rel_path;
    while (*p) {
        if (*p == '/') {
            return -EINVAL; // Reject consecutive slashes
        }
        const char *end = p;
        while (*end && *end != '/') {
            end++;
        }
        size_t comp_len = (size_t)(end - p);
        if ((comp_len == 1 && p[0] == '.') ||
            (comp_len == 2 && p[0] == '.' && p[1] == '.')) {
            return -EINVAL;
        }
        for (size_t i = 0; i < comp_len; i++) {
            char c = p[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) {
                return -EINVAL;
            }
        }
        if (*end == '/') {
            if (*(end + 1) == '\0') {
                return -EINVAL; // Reject trailing slash
            }
            p = end + 1;
        } else {
            p = end;
        }
    }

    int ret = snprintf(buf, buf_sz, "%s:%04o", rel_path, (unsigned int)(mode & 07777));
    if (ret < 0 || (size_t)ret >= buf_sz) {
        return -ENAMETOOLONG;
    }
    return 0;
}

int compute_oaep_label(const char *aad, uint8_t label_buf[33]) {
    if (!aad || aad[0] == '\0' || !label_buf) {
        return -EINVAL;
    }

    uint8_t digest[32];
    unsigned int digest_len = 0;
    if (EVP_Digest(aad, strlen(aad), digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len != 32) {
        return -EIO;
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; i++) {
        label_buf[i * 2] = (uint8_t)hex_chars[(digest[i] >> 4) & 0x0f];
        label_buf[i * 2 + 1] = (uint8_t)hex_chars[digest[i] & 0x0f];
    }
    label_buf[32] = '\0';

    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

EVP_PKEY *load_rsa_pubkey_evp(const char *path, int require_secure_perms,
                              size_t *modulus_len_out, uint8_t modulus_out[TPM2_RSA4096_KEY_BYTES]) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        syslog(LOG_ERR, "load_rsa_pubkey_evp: Failed to open %s: %s", path, strerror(errno));
        fprintf(stderr, "Error: Failed to open public key %s: %s\n", path, strerror(errno));
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        syslog(LOG_ERR, "load_rsa_pubkey_evp: %s is not a regular file", path);
        fprintf(stderr, "Error: Public key %s must be a regular file.\n", path);
        close(fd);
        return NULL;
    }

    if (require_secure_perms) {
        if ((st.st_uid != 0 && st.st_uid != geteuid()) ||
            (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            syslog(LOG_ERR, "load_rsa_pubkey_evp: %s has insecure ownership or write permissions (uid=%u, mode=%04o)",
                   path, st.st_uid, (unsigned int)(st.st_mode & 07777));
            fprintf(stderr, "Error: tpm_pubkey %s must be owned by root and not writable by group or others.\n", path);
            close(fd);
            return NULL;
        }
    }

    if (st.st_size <= 0 || st.st_size > 8192) {
        syslog(LOG_ERR, "load_rsa_pubkey_evp: Invalid file size for %s", path);
        fprintf(stderr, "Error: Invalid file size for public key %s.\n", path);
        close(fd);
        return NULL;
    }

    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        close(fd);
        return NULL;
    }

    uint8_t buf[8192];
    size_t bytes_read = 0;
    while (bytes_read < (size_t)st.st_size) {
        ssize_t rd = pread(fd, buf + bytes_read, (size_t)st.st_size - bytes_read, (off_t)bytes_read);
        if (rd < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return NULL;
        }
        if (rd == 0) {
            close(fd);
            return NULL;
        }
        bytes_read += (size_t)rd;
    }
    close(fd);

    // 1. Try parsing as PEM public key (e.g. from tpm2_readpublic -f pem)
    BIO *bio = BIO_new_mem_buf(buf, (int)bytes_read);
    if (bio) {
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (pkey) {
            BIGNUM *bn_n = NULL;
            if (EVP_PKEY_is_a(pkey, "RSA") &&
                EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) == 1 && bn_n) {
                int num_bytes = BN_num_bytes(bn_n);
                if (num_bytes == TPM2_RSA2048_KEY_BYTES || num_bytes == TPM2_RSA4096_KEY_BYTES) {
                    if (modulus_out) {
                        BN_bn2bin(bn_n, modulus_out);
                    }
                    if (modulus_len_out) {
                        *modulus_len_out = (size_t)num_bytes;
                    }
                    BN_free(bn_n);
                    return pkey;
                }
                BN_free(bn_n);
            }
            EVP_PKEY_free(pkey);
            ERR_clear_error();
            fprintf(stderr, "Error: PEM public key %s is not a valid 2048/4096-bit RSA key.\n", path);
            return NULL;
        }
        ERR_clear_error();
    }

    // 2. Try parsing as TSS TPM2B_PUBLIC binary (e.g. from tpm2_create -u)
    TPM2B_PUBLIC pub = {0};
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(buf, bytes_read, &offset, &pub);
    if (rc == TSS2_RC_SUCCESS && offset == bytes_read) {
        if (pub.publicArea.type == TPM2_ALG_RSA &&
            (pub.publicArea.unique.rsa.size == TPM2_RSA2048_KEY_BYTES ||
             pub.publicArea.unique.rsa.size == TPM2_RSA4096_KEY_BYTES)) {
            uint32_t exp = pub.publicArea.parameters.rsaDetail.exponent;
            if (exp == 0) {
                exp = 65537;
            }
            BIGNUM *bn_n = BN_bin2bn(pub.publicArea.unique.rsa.buffer, pub.publicArea.unique.rsa.size, NULL);
            BIGNUM *bn_e = BN_new();
            if (bn_n && bn_e && BN_set_word(bn_e, exp) == 1) {
                OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
                if (bld) {
                    if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) == 1 &&
                        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e) == 1) {
                        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
                        if (params) {
                            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
                            EVP_PKEY *pkey = NULL;
                            if (pctx && EVP_PKEY_fromdata_init(pctx) == 1 &&
                                EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1 && pkey) {
                                EVP_PKEY_CTX_free(pctx);
                                OSSL_PARAM_free(params);
                                OSSL_PARAM_BLD_free(bld);
                                BN_free(bn_n);
                                BN_free(bn_e);
                                if (modulus_out) {
                                    memcpy(modulus_out, pub.publicArea.unique.rsa.buffer, pub.publicArea.unique.rsa.size);
                                }
                                if (modulus_len_out) {
                                    *modulus_len_out = pub.publicArea.unique.rsa.size;
                                }
                                return pkey;
                            }
                            EVP_PKEY_CTX_free(pctx);
                            OSSL_PARAM_free(params);
                        }
                    }
                    OSSL_PARAM_BLD_free(bld);
                }
            }
            BN_free(bn_n);
            BN_free(bn_e);
        }
    }

    syslog(LOG_ERR, "load_rsa_pubkey_evp: %s is neither a valid RSA PEM nor TPM2B_PUBLIC file", path);
    fprintf(stderr, "Error: Public key %s is neither a valid RSA PEM nor TPM2B_PUBLIC file.\n", path);
    return NULL;
}

static int verify_and_pin_tpm_key(ESYS_CONTEXT *esys_ctx, ESYS_TR key_handle) {
    int ret = 0;

    pthread_mutex_lock(&pinned_key.lock);

    if (pinned_key.name.size == 0) {
        TPM2B_PUBLIC *out_public = NULL;
        TPM2B_NAME *name = NULL;
        TPM2B_NAME *qualified_name = NULL;

        TSS2_RC rc = Esys_ReadPublic(esys_ctx, key_handle,
                                     ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &out_public, &name, &qualified_name);
        if (rc != TSS2_RC_SUCCESS || !out_public || !name) {
            syslog(LOG_ERR, "verify_and_pin_tpm_key: Esys_ReadPublic failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
            Esys_Free(out_public);
            Esys_Free(name);
            Esys_Free(qualified_name);
            ret = -ENODEV;
            goto out;
        }

        TPMA_OBJECT req_attrs = TPMA_OBJECT_FIXEDTPM |
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                TPMA_OBJECT_DECRYPT;

        if (out_public->publicArea.type != TPM2_ALG_RSA ||
            (out_public->publicArea.parameters.rsaDetail.keyBits != 2048 &&
             out_public->publicArea.parameters.rsaDetail.keyBits != 4096) ||
            (out_public->publicArea.objectAttributes & req_attrs) != req_attrs) {
            syslog(LOG_ERR, "verify_and_pin_tpm_key: TPM handle 0x%08x has invalid type, key size, or object attributes (0x%08x)",
                   global_opts.tpm_handle, out_public->publicArea.objectAttributes);
            fprintf(stderr, "Error: TPM handle 0x%08x is not a hardware-bound RSA-2048/4096 decryption key.\n",
                    global_opts.tpm_handle);
            Esys_Free(out_public);
            Esys_Free(name);
            Esys_Free(qualified_name);
            ret = -EKEYREJECTED;
            goto out;
        }

        if (pinned_key.modulus_len > 0) {
            if (out_public->publicArea.unique.rsa.size != pinned_key.modulus_len ||
                CRYPTO_memcmp(out_public->publicArea.unique.rsa.buffer,
                              pinned_key.modulus, pinned_key.modulus_len) != 0) {
                syslog(LOG_ERR, "verify_and_pin_tpm_key: TPM public key modulus mismatch for handle 0x%08x",
                       global_opts.tpm_handle);
                fprintf(stderr, "Error: TPM handle 0x%08x public key does not match tpm_pubkey %s.\n",
                        global_opts.tpm_handle, global_opts.tpm_pubkey);
                Esys_Free(out_public);
                Esys_Free(name);
                Esys_Free(qualified_name);
                ret = -EKEYREJECTED;
                goto out;
            }
        }

        if (name->size == 0 || name->size > sizeof(pinned_key.name.name)) {
            Esys_Free(out_public);
            Esys_Free(name);
            Esys_Free(qualified_name);
            ret = -EKEYREJECTED;
            goto out;
        }

        pinned_key.name = *name;
        Esys_Free(out_public);
        Esys_Free(name);
        Esys_Free(qualified_name);
    }

    TPM2B_NAME *tr_name = NULL;
    TSS2_RC rc = Esys_TR_GetName(esys_ctx, key_handle, &tr_name);
    if (rc != TSS2_RC_SUCCESS || !tr_name) {
        syslog(LOG_ERR, "verify_and_pin_tpm_key: Esys_TR_GetName failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        Esys_Free(tr_name);
        ret = -ENODEV;
        goto out;
    }

    if (tr_name->size != pinned_key.name.size ||
        CRYPTO_memcmp(tr_name->name, pinned_key.name.name, pinned_key.name.size) != 0) {
        syslog(LOG_ERR, "verify_and_pin_tpm_key: TPM object Name mismatch for handle 0x%08x", global_opts.tpm_handle);
        Esys_Free(tr_name);
        ret = -EKEYREJECTED;
        goto out;
    }
    Esys_Free(tr_name);

out:
    pthread_mutex_unlock(&pinned_key.lock);
    return ret;
}

int init_decryption(void) {
    long p_sz;

    pinned_key.modulus_len = 0;
    memset(&pinned_key.name, 0, sizeof(pinned_key.name));

    p_sz = sysconf(_SC_PAGESIZE);
    if (p_sz > 0) {
        system_page_size = p_sz;
    }

    if (global_opts.tpm_pubkey) {
        EVP_PKEY *pkey = load_rsa_pubkey_evp(global_opts.tpm_pubkey, 1,
                                             &pinned_key.modulus_len, pinned_key.modulus);
        if (!pkey) {
            return -1;
        }
        EVP_PKEY_free(pkey);
    }

    return 0;
}

int check_tpm_lockout(void) {
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR key_handle = ESYS_TR_NONE;
    int ret_err = 0;

    rc = Tss2_TctiLdr_Initialize(global_opts.tcti, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "check_tpm_lockout: Tss2_TctiLdr_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        fprintf(stderr, "Failed to initialize TCTI: %s (0x%x)\n", Tss2_RC_Decode(rc), rc);
        return -ENODEV;
    }

    rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "check_tpm_lockout: Esys_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        fprintf(stderr, "Failed to initialize ESYS: %s (0x%x)\n", Tss2_RC_Decode(rc), rc);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return -ENODEV;
    }

    TPMI_YES_NO more_data = 0;
    TPMS_CAPABILITY_DATA *cap_data = NULL;

    rc = Esys_GetCapability(
        esys_ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        TPM2_CAP_TPM_PROPERTIES,
        TPM2_PT_LOCKOUT_COUNTER,
        4,
        &more_data,
        &cap_data
    );

    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "check_tpm_lockout: Esys_GetCapability failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        fprintf(stderr, "Esys_GetCapability failed: %s (0x%x)\n", Tss2_RC_Decode(rc), rc);
        ret_err = -ENODEV;
        goto out;
    }

    uint32_t lockout_counter = 0;
    uint32_t max_auth_fail = 0;

    if (cap_data) {
        TPML_TAGGED_TPM_PROPERTY *props = &cap_data->data.tpmProperties;
        for (uint32_t i = 0; i < props->count; i++) {
            if (props->tpmProperty[i].property == TPM2_PT_LOCKOUT_COUNTER) {
                lockout_counter = props->tpmProperty[i].value;
            } else if (props->tpmProperty[i].property == TPM2_PT_MAX_AUTH_FAIL) {
                max_auth_fail = props->tpmProperty[i].value;
            }
        }
        Esys_Free(cap_data);
    }

    if (max_auth_fail > 0 && lockout_counter >= max_auth_fail) {
        syslog(LOG_ERR, "check_tpm_lockout: TPM is in lockout mode (lockout_counter=%u, max_auth_fail=%u)", lockout_counter, max_auth_fail);
        fprintf(stderr, "Error: TPM is in lockout mode (failed tries: %u, max allowed: %u). Reads will fail.\n", lockout_counter, max_auth_fail);
        ret_err = -EKEYREJECTED;
        goto out;
    }

    rc = Esys_TR_FromTPMPublic(esys_ctx, global_opts.tpm_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &key_handle);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "check_tpm_lockout: Esys_TR_FromTPMPublic failed for handle 0x%08x: %s (0x%x)",
               global_opts.tpm_handle, Tss2_RC_Decode(rc), rc);
        fprintf(stderr, "Failed to load TPM handle 0x%08x: %s (0x%x)\n",
                global_opts.tpm_handle, Tss2_RC_Decode(rc), rc);
        ret_err = -ENODEV;
        goto out;
    }

    ret_err = verify_and_pin_tpm_key(esys_ctx, key_handle);
    Esys_TR_Close(esys_ctx, &key_handle);

out:
    Esys_Finalize(&esys_ctx);
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    return ret_err;
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

static uint8_t *copy_tpm_message(TPM2B_PUBLIC_KEY_RSA *message) {
    uint8_t *ptr;

    if (message->size > sizeof(message->buffer)) {
        return NULL;
    }

    if (message->size == 0)
	return NULL;

    ptr = malloc_mlock(message->size);
    if (!ptr) {
        return NULL;
    }

    memcpy(ptr, message->buffer, message->size);

    return ptr;
}

static int tpm2_rsa_decrypt(const uint8_t *in_data, size_t in_len,
			    const char *aad,
			    struct decrypted_node *out) {
    if (in_len != TPM2_RSA2048_KEY_BYTES && in_len != TPM2_RSA4096_KEY_BYTES) {
        return -EMSGSIZE;
    }

    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR key_handle = ESYS_TR_NONE;
    ESYS_TR session_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC_KEY_RSA cipher_text = {0};
    TPMT_RSA_DECRYPT inScheme = {0};
    TPM2B_DATA label = { .size = 33 };
    TPM2B_PUBLIC_KEY_RSA *message = NULL;
    int ret_err = 0;
    int session_need_flush = 0;

    ret_err = compute_oaep_label(aad, label.buffer);
    if (ret_err != 0) {
        return ret_err;
    }

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = { .aes = TPM2_ALG_CFB }
    };
    TPMA_SESSION session_attrs = TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT;

    rc = Tss2_TctiLdr_Initialize(global_opts.tcti, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm2_rsa_decrypt: Tss2_TctiLdr_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        OPENSSL_cleanse(&label, sizeof(label));
	return -ENODEV;
    }

    rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm2_rsa_decrypt: Esys_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        ret_err = -ENODEV;
        goto out_tcti;
    }

    rc = Esys_TR_FromTPMPublic(esys_ctx, global_opts.tpm_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &key_handle);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm2_rsa_decrypt: Esys_TR_FromTPMPublic failed for handle 0x%08x: %s (0x%x)", global_opts.tpm_handle, Tss2_RC_Decode(rc), rc);
        ret_err = -ENODEV;
        goto out_esys;
    }

    ret_err = verify_and_pin_tpm_key(esys_ctx, key_handle);
    if (ret_err != 0) {
        goto out_key;
    }

    cipher_text.size = in_len;
    memcpy(cipher_text.buffer, in_data, in_len);

    inScheme.scheme = TPM2_ALG_OAEP;
    inScheme.details.oaep.hashAlg = TPM2_ALG_SHA256;

    rc = Esys_StartAuthSession(esys_ctx, key_handle, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL, TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                               &session_handle);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm2_rsa_decrypt: Esys_StartAuthSession failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        ret_err = -EACCES;
        goto out_key;
    }
    session_need_flush = 1;

    rc = Esys_TRSess_SetAttributes(esys_ctx, session_handle, session_attrs, 0xff);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm2_rsa_decrypt: Esys_TRSess_SetAttributes failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        ret_err = -EACCES;
        goto out_session;
    }

    /*
     * Note: If mlockall() is not supported or fails, there is a minimal
     * window here where the decrypted TPM message (the ephemeral AES key)
     * resides in standard, unlocked heap memory. The libtss2-esys library
     * uses a direct calloc() which we cannot easily override.
     * We cleanse it immediately after copying, but we cannot completely
     * prevent swapping during this specific window.
     */
    rc = Esys_RSA_Decrypt(esys_ctx, key_handle,
                          session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher_text, &inScheme, &label, &message);

    if (rc != TSS2_RC_SUCCESS || !message) {
        syslog(LOG_ERR, "tpm2_rsa_decrypt: Esys_RSA_Decrypt failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        TSS2_RC base_rc = rc & ~TPM2_RC_N_MASK;
        if (base_rc == TPM2_RC_LOCKOUT || base_rc == TPM2_RC_AUTH_FAIL) {
            ret_err = -EKEYREJECTED;
        } else {
            ret_err = -EACCES;
        }
        goto out_msg;
    }
    session_need_flush = 0;

    if (message->size == 0) {
        ret_err = -ENODATA;
        goto out_msg;
    }

    out->buf = copy_tpm_message(message);

    if (out->buf == NULL) {
        ret_err = -ENOMEM;
    } else {
        out->len = out->allocated_size = message->size;
    }
out_msg:
    if (message) {
        OPENSSL_cleanse(message->buffer, sizeof(message->buffer));
        Esys_Free(message);
    }
out_session:
    if (session_handle != ESYS_TR_NONE) {
        if (session_need_flush) {
            Esys_FlushContext(esys_ctx, session_handle);
        }
        Esys_TR_Close(esys_ctx, &session_handle);
    }
out_key:
    if (key_handle != ESYS_TR_NONE) {
        Esys_TR_Close(esys_ctx, &key_handle);
    }
out_esys:
    Esys_Finalize(&esys_ctx);
out_tcti:
    Tss2_TctiLdr_Finalize(&tcti_ctx);

    OPENSSL_cleanse(&cipher_text, sizeof(cipher_text));
    OPENSSL_cleanse(&inScheme, sizeof(inScheme));
    OPENSSL_cleanse(&label, sizeof(label));

    return ret_err;
}

static int do_aes_decrypt(const uint8_t *iv,
			  const uint8_t *tag,
			  const uint8_t *ciphertext, size_t ciphertext_len,
			  const char *aad,
			  const struct decrypted_node *eph_key,
			  struct decrypted_node *out) {
    uint8_t tag_buf[16];
    size_t aad_len;
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

    if (!aad || aad[0] == '\0') {
        return -EINVAL;
    }
    aad_len = strlen(aad);
    if (aad_len > INT_MAX) {
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

    out->len = (size_t)len1 + (size_t)len2;
    out->allocated_size = alloc_sz;
    out->buf = plain;

    return 0;

 decrypt_final_err:
 decrypt_update_err:
    free_munlock(plain, alloc_sz);
 decrypt_init_err:
    EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    return ret_err;
}

int decrypt_envelope(const uint8_t *enc_data, size_t enc_len,
                     const char *rel_path, mode_t mode,
                     struct decrypted_node *out) {
    if (!enc_data || !rel_path || !out) {
        return -EINVAL;
    }

    if (enc_len < CRED_ENV_MIN_OVERHEAD) {
        return -EBADMSG;
    }

    if (memcmp(enc_data, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN) != 0) {
        return -EBADMSG;
    }

    uint64_t version_be = 0;
    memcpy(&version_be, enc_data + 8, sizeof(version_be));
    uint64_t version = be64toh(version_be);
    if (version != CRED_ENV_VERSION_1) {
        return -EPROTONOSUPPORT;
    }

    uint16_t rsa_ct_len_be = 0;
    memcpy(&rsa_ct_len_be, enc_data + 16, sizeof(rsa_ct_len_be));
    uint16_t rsa_ct_len = be16toh(rsa_ct_len_be);
    if (rsa_ct_len != TPM2_RSA2048_KEY_BYTES && rsa_ct_len != TPM2_RSA4096_KEY_BYTES) {
        return -EBADMSG;
    }

    size_t header_len = CRED_ENV_FIXED_OVERHEAD + (size_t)rsa_ct_len;
    if (enc_len <= header_len) {
        return -EBADMSG;
    }

    char aad[PATH_MAX + 16];
    int r = format_credential_aad(aad, sizeof(aad), rel_path, mode);
    if (r < 0) {
        return r;
    }

    const uint8_t *rsa_ct = enc_data + 18;
    const uint8_t *iv = enc_data + 18 + rsa_ct_len;
    const uint8_t *tag = enc_data + 30 + rsa_ct_len;
    const uint8_t *ciphertext = enc_data + header_len;
    size_t ciphertext_len = enc_len - header_len;

    struct decrypted_node eph_key = { NULL, 0, 0 };
    r = tpm2_rsa_decrypt(rsa_ct, rsa_ct_len, aad, &eph_key);
    if (r < 0) {
        clean_decrypted_node(&eph_key);
        return r;
    }

    if (eph_key.len != 32) {
        clean_decrypted_node(&eph_key);
        return -EBADMSG;
    }

    r = do_aes_decrypt(iv, tag, ciphertext, ciphertext_len, aad, &eph_key, out);
    clean_decrypted_node(&eph_key);
    return r;
}

int decrypt_credential(int fd,
		       const char *rel_path,
		       struct decrypted_node *out) {
    uint8_t *enc_data = NULL;
    size_t enc_len = 0;
    mode_t file_mode = 0;
    int r;

    r = read_file_fd(fd, &enc_data, &enc_len, &file_mode, (size_t)global_opts.max_file_size);
    if (r < 0) {
        return r;
    }

    r = decrypt_envelope(enc_data, enc_len, rel_path, file_mode, out);
    free_munlock(enc_data, enc_len);
    return r;
}
