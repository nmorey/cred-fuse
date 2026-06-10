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

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

#define AES_HEADER "Salted__"
#define AES_HEADER_LEN 8

static char cached_host_key_path[PATH_MAX] = {0};
static uint8_t cached_host_key_enc[512] = {0};
static size_t cached_host_key_enc_len = 0;

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
        if (posix_memalign(&ptr, page_size, aligned_size) != 0) {
            return NULL;
        }
        if (mlock(ptr, aligned_size) != 0) {
            int saved_errno = errno;
            free(ptr);
            errno = saved_errno;
            return NULL;
        }
    } else {
        ptr = malloc(size);
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
    node->buf = NULL;

    return;
}

int init_decryption(const char *source_dir) {
    char hostname[256] = {0};
    char *dot;
    int ret;
    int fd;
    long p_sz;

    p_sz = sysconf(_SC_PAGESIZE);
    if (p_sz > 0) {
        system_page_size = p_sz;
    }

    if (gethostname(hostname, sizeof(hostname)-1) != 0) {
        return -1;
    }
    // Validate hostname to prevent path traversal and empty names
    if (hostname[0] == '\0' || strchr(hostname, '/') != NULL || strstr(hostname, "..") != NULL) {
        return -1;
    }
    dot = strchr(hostname, '.');
    if (dot)
	*dot = '\0';

    ret = snprintf(cached_host_key_path, sizeof(cached_host_key_path), "%s/%s.key", source_dir, hostname);
    if (ret < 0 || (size_t)ret >= sizeof(cached_host_key_path)) {
        return -1;
    }

    // Open, stat, and read the encrypted host key file if it exists
    fd = open(cached_host_key_path, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (st.st_size > 0 && st.st_size <= (off_t)sizeof(cached_host_key_enc)) {
                ssize_t rd = read(fd, cached_host_key_enc, st.st_size);
                if (rd == st.st_size) {
                    cached_host_key_enc_len = (size_t)st.st_size;
                } else {
                    close(fd);
                    return -1;
                }
            } else {
                close(fd);
                return -1;
            }
        } else {
            close(fd);
            return -1;
        }
        close(fd);
    } else if (errno != ENOENT) {
        return -1;
    }

    return 0;
}

static int read_file_fd(int fd, uint8_t **buf, size_t *len, size_t max_size) {
    FILE *f = NULL;
    long size;
    int err = 0;
    int dup_fd;

    dup_fd = dup(fd);
    if (dup_fd < 0) {
        return -errno;
    }

    f = fdopen(dup_fd, "rb");
    if (!f) {
        err = errno;
        close(dup_fd);
        return -err;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        err = errno;
        goto out_close;
    }

    size = ftell(f);
    if (size <= 0) {
        err = (size == 0) ? ENODATA : errno;
        goto out_close;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        err = errno;
        goto out_close;
    }

    if ((size_t)size > max_size) {
        err = EFBIG;
        goto out_close;
    }

    *buf = malloc(size);
    if (!*buf) {
        err = ENOMEM;
        goto out_close;
    }

    if (fread(*buf, 1, size, f) != (size_t)size) {
        err = ferror(f) ? errno : EIO;
        if (err == 0) {
            err = EIO;
        }
        goto out_free;
    }

    *len = size;

out_free:
    if (err) {
	free(*buf);
	*buf = NULL;
    }
out_close:
    fclose(f);
    return -err;
}

static uint8_t *copy_tpm_message(TPM2B_PUBLIC_KEY_RSA *message) {
    uint8_t *ptr;

    ptr = malloc_mlock(message->size);
    if (!ptr) {
        return NULL;
    }

    memcpy(ptr, message->buffer, message->size);

    return ptr;
}

static int tpm2_rsa_decrypt(const uint8_t *in_data, size_t in_len,
			    struct decrypted_node *out) {
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
    int mlocked = 0;

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = { .aes = TPM2_ALG_CFB }
    };
    TPMA_SESSION session_attrs = TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT;

    rc = Tss2_TctiLdr_Initialize(global_opts.tcti, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS)
	return -ENODEV;

    rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        ret_err = -ENODEV;
        goto out_tcti;
    }

    rc = Esys_TR_FromTPMPublic(esys_ctx, global_opts.tpm_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &key_handle);
    if (rc != TSS2_RC_SUCCESS) {
        ret_err = -ENODEV;
        goto out_esys;
    }

    if (in_len == 0 || in_len > sizeof(cipher_text.buffer)) {
        ret_err = -EMSGSIZE;
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
        ret_err = -EACCES;
        goto out_key;
    }

    rc = Esys_TRSess_SetAttributes(esys_ctx, session_handle, session_attrs, 0xff);
    if (rc != TSS2_RC_SUCCESS) {
        ret_err = -EACCES;
        goto out_session;
    }

    rc = Esys_RSA_Decrypt(esys_ctx, key_handle,
                          session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher_text, &inScheme, &label, &message);

    if (rc != TSS2_RC_SUCCESS || !message) {
        ret_err = -EACCES;
        goto out_msg;
    }

    if (message->size == 0) {
        ret_err = -ENODATA;
        goto out_msg;
    }

    if (!mlockall_active) {
        if (mlock(message->buffer, message->size) != 0) {
            ret_err = -errno;
            goto out_msg;
        }
        mlocked = 1;
    }

    out->buf = copy_tpm_message(message);

    if (out->buf == NULL) {
        ret_err = -ENOMEM;
    } else {
        out->len = out->allocated_size = message->size;
    }
out_msg:
    if (message) {
        OPENSSL_cleanse(message->buffer, message->size);
        if (mlocked) {
            munlock(message->buffer, message->size);
        }
        Esys_Free(message);
    }
out_session:
    if (session_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, session_handle);
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

    if (in_len < 36)
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
    if (cached_host_key_enc_len == 0) {
        r = -ENOKEY;
	goto read_err;
    }

    r = tpm2_rsa_decrypt(cached_host_key_enc, cached_host_key_enc_len, &passphrase);
    if (r < 0) {
	goto read_err;
    }

    r = do_aes_decrypt(enc_data, enc_len, &passphrase, out);

    clean_decrypted_node(&passphrase);
 read_err:
    free(enc_data);

    return r;
}
