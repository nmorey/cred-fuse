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
#include "path.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>

#define AES_HEADER "Salted__"
#define AES_HEADER_LEN 8
#define TPM2_RSA2048_KEY_BYTES 256
#define TPM2_RSA4096_KEY_BYTES 512

struct cached_host_key {
    char path[PATH_MAX];
    dev_t dev;
    ino_t ino;
    uint8_t enc[512];
    size_t enc_len;
};

static struct cached_host_key host_key = {0};

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

static void *malloc_mlock(size_t size)
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

static void free_munlock(void *ptr, size_t size)
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

int is_host_key_inode(dev_t dev, ino_t ino) {
    return host_key.ino != 0 &&
           host_key.ino == ino &&
           host_key.dev == dev;
}

static int load_tpm_pubkey_file(const char *path) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        syslog(LOG_ERR, "load_tpm_pubkey_file: Failed to open %s: %s", path, strerror(errno));
        fprintf(stderr, "Error: Failed to open tpm_pubkey %s: %s\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        syslog(LOG_ERR, "load_tpm_pubkey_file: %s is not a regular file", path);
        fprintf(stderr, "Error: tpm_pubkey %s must be a regular file.\n", path);
        close(fd);
        return -1;
    }

    if ((st.st_uid != 0 && st.st_uid != geteuid()) ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        syslog(LOG_ERR, "load_tpm_pubkey_file: %s has insecure ownership or write permissions (uid=%u, mode=%04o)",
               path, st.st_uid, (unsigned int)(st.st_mode & 07777));
        fprintf(stderr, "Error: tpm_pubkey %s must be owned by root and not writable by group or others.\n", path);
        close(fd);
        return -1;
    }

    if (st.st_size <= 0 || st.st_size > 8192) {
        syslog(LOG_ERR, "load_tpm_pubkey_file: Invalid file size for %s", path);
        fprintf(stderr, "Error: Invalid file size for tpm_pubkey %s.\n", path);
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        close(fd);
        return -1;
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
            return -1;
        }
        if (rd == 0) {
            close(fd);
            return -1;
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
            if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) == 1 && bn_n) {
                int num_bytes = BN_num_bytes(bn_n);
                if (num_bytes == TPM2_RSA2048_KEY_BYTES || num_bytes == TPM2_RSA4096_KEY_BYTES) {
                    BN_bn2bin(bn_n, pinned_key.modulus);
                    pinned_key.modulus_len = (size_t)num_bytes;
                    BN_free(bn_n);
                    EVP_PKEY_free(pkey);
                    return 0;
                }
                BN_free(bn_n);
            }
            EVP_PKEY_free(pkey);
            ERR_clear_error();
            fprintf(stderr, "Error: PEM tpm_pubkey %s is not a valid 2048/4096-bit RSA key.\n", path);
            return -1;
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
            memcpy(pinned_key.modulus, pub.publicArea.unique.rsa.buffer, pub.publicArea.unique.rsa.size);
            pinned_key.modulus_len = pub.publicArea.unique.rsa.size;
            return 0;
        }
    }

    syslog(LOG_ERR, "load_tpm_pubkey_file: %s is neither a valid RSA PEM nor TPM2B_PUBLIC file", path);
    fprintf(stderr, "Error: tpm_pubkey %s is neither a valid RSA PEM nor TPM2B_PUBLIC file.\n", path);
    return -1;
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

int init_decryption(const char *source_dir) {
    char hostname[256] = {0};
    char *dot;
    int ret;
    int fd;
    long p_sz;

    memset(&host_key, 0, sizeof(host_key));
    pinned_key.modulus_len = 0;
    memset(&pinned_key.name, 0, sizeof(pinned_key.name));

    p_sz = sysconf(_SC_PAGESIZE);
    if (p_sz > 0) {
        system_page_size = p_sz;
    }

    if (global_opts.tpm_pubkey) {
        if (load_tpm_pubkey_file(global_opts.tpm_pubkey) != 0) {
            return -1;
        }
    }

    if (gethostname(hostname, sizeof(hostname)-1) != 0) {
        return -1;
    }
    // Make sure hostname is NULL terminated
    hostname[sizeof(hostname) - 1] = '\0';

    // Validate hostname to allow only alphanumeric, '.', and '-'
    if (hostname[0] == '\0') {
        return -1;
    }
    for (int i = 0; hostname[i] != '\0'; i++) {
        char c = hostname[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) {
            return -1;
        }
    }
    dot = strchr(hostname, '.');
    if (dot)
	*dot = '\0';

    if (hostname[0] == '\0') {
        return -1;
    }

    ret = snprintf(host_key.path, sizeof(host_key.path), "%s/%s.key", source_dir, hostname);
    if (ret < 0 || (size_t)ret >= sizeof(host_key.path)) {
        return -1;
    }

    // Open and validate the encrypted host key file using open_and_validate_path
    struct stat st;
    fd = open_and_validate_path(host_key.path, &st);
    if (fd >= 0) {
        struct stat real_st;
        if (fstat(fd, &real_st) == 0) {
            if ((real_st.st_uid != 0 && real_st.st_uid != geteuid()) ||
                (real_st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
                syslog(LOG_ERR, "init_decryption: Host key %s has insecure ownership or permissions (uid=%u, mode=%04o)",
                       host_key.path, real_st.st_uid, (unsigned int)(real_st.st_mode & 07777));
                fprintf(stderr, "Error: Host key %s must be owned by root and not accessible by group or others.\n",
                        host_key.path);
                close(fd);
                return -1;
            }
            if (real_st.st_size > 0 && real_st.st_size <= (off_t)sizeof(host_key.enc)) {
                size_t bytes_read = 0;
                while (bytes_read < (size_t)real_st.st_size) {
                    ssize_t rd = pread(fd, host_key.enc + bytes_read,
                                       (size_t)real_st.st_size - bytes_read, (off_t)bytes_read);
                    if (rd < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        close(fd);
                        return -1;
                    }
                    if (rd == 0) {
                        close(fd);
                        return -1;
                    }
                    bytes_read += (size_t)rd;
                }
                host_key.enc_len = bytes_read;
                host_key.dev = real_st.st_dev;
                host_key.ino = real_st.st_ino;
            } else {
                close(fd);
                return -1;
            }
        } else {
            close(fd);
            return -1;
        }
        close(fd);
    } else if (fd != -ENOENT) {
        return -1;
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
        for (UINT32 i = 0; i < props->count; i++) {
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

static int read_file_fd(int fd, uint8_t **buf, size_t *len, size_t max_size) {
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
			    struct decrypted_node *out) {
    if (in_len < TPM2_RSA2048_KEY_BYTES || in_len > sizeof(((TPM2B_PUBLIC_KEY_RSA*)0)->buffer)) {
        return -EMSGSIZE;
    }

    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR key_handle = ESYS_TR_NONE;
    ESYS_TR session_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC_KEY_RSA cipher_text = {0};
    TPMT_RSA_DECRYPT inScheme = {0};
    TPM2B_DATA label = { .size = 0 };
    TPM2B_PUBLIC_KEY_RSA *message = NULL;
    int ret_err = 0;
    int session_need_flush = 0;

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = { .aes = TPM2_ALG_CFB }
    };
    TPMA_SESSION session_attrs = TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT;

    rc = Tss2_TctiLdr_Initialize(global_opts.tcti, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm2_rsa_decrypt: Tss2_TctiLdr_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
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
     * window here where the decrypted TPM message (the AES passphrase)
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

static int do_aes_decrypt(const uint8_t *in_data, size_t in_len,
			  const struct decrypted_node *passphrase,
			  struct decrypted_node *out) {
    const uint8_t *iv;
    const uint8_t *tag;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    uint8_t *plain;
    size_t alloc_sz;
    int len1 = 0, len2 = 0;
    int ret_err = -EIO;

    if (in_len <= 36)
        return -EINVAL;

    if (memcmp(in_data, AES_HEADER, AES_HEADER_LEN) != 0)
        return -EINVAL;

    if (!passphrase || !passphrase->buf || passphrase->len != 32) {
        return -EINVAL;
    }

    iv = in_data + 8;
    tag = in_data + 20;
    ciphertext = in_data + 36;
    ciphertext_len = in_len - 36;

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

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, passphrase->buf, iv) != 1) {
        ret_err = -EIO;
        goto decrypt_init_err;
    }

    if (ciphertext_len > INT_MAX) {
        ret_err = -E2BIG;
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

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) != 1) {
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

int decrypt_credential(int fd,
		       struct decrypted_node *out) {
    uint8_t *enc_data = NULL;
    size_t enc_len = 0;
    int is_aes;
    struct decrypted_node passphrase = { NULL, 0, 0};
    int r;

    r = read_file_fd(fd, &enc_data, &enc_len, global_opts.max_file_size);
    if (r < 0)
        return r;

    is_aes = (enc_len >= 36 && memcmp(enc_data, AES_HEADER, 8) == 0);

    if (!is_aes) {
        // RSA directly
        r = tpm2_rsa_decrypt(enc_data, enc_len, out);
	goto read_err;
    }

    // AES flow: needs host key
    if (host_key.enc_len == 0) {
        r = -ENOKEY;
	goto read_err;
    }

    r = tpm2_rsa_decrypt(host_key.enc, host_key.enc_len, &passphrase);
    if (r < 0) {
	goto read_err;
    }

    r = do_aes_decrypt(enc_data, enc_len, &passphrase, out);

 read_err:
    clean_decrypted_node(&passphrase);
    free_munlock(enc_data, enc_len);

    return r;
}
