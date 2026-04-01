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

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/mman.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

#define AES_HEADER "Salted__"
#define AES_SALT_LEN 8
#define AES_HEADER_LEN 8
#define PBKDF2_ITER 10000

static char cached_host_key_path[PATH_MAX] = {0};

void clean_decrypted_node(struct decrypted_node *node)
{
    if (!node || !node->buf)
	return;

    OPENSSL_cleanse(node->buf, node->allocated_size);
    munlock(node->buf, node->allocated_size);
    free(node->buf);
    node->buf = NULL;

    return;
}

static void *malloc_mlock(size_t size)
{
    uint8_t *ptr = NULL;

    ptr = malloc(size);
    if (!ptr) {
        return NULL;
    }
    if (mlock(ptr, size) != 0) {
        free(ptr);
        return NULL;
    }
    return ptr;
}

int init_decryption(const char *source_dir) {
    char hostname[256] = {0};
    char *dot;
    int ret;

    if (gethostname(hostname, sizeof(hostname)-1) != 0) {
        return -1;
    }
    dot = strchr(hostname, '.');
    if (dot)
	*dot = '\0';

    ret = snprintf(cached_host_key_path, sizeof(cached_host_key_path), "%s/%s.key", source_dir, hostname);
    if (ret < 0 || (size_t)ret >= sizeof(cached_host_key_path)) {
        return -1;
    }
    return 0;
}

/* Helper to read entire file into memory */
static int read_file(const char *path, uint8_t **buf, size_t *len, size_t max_size) {
    FILE *f = fopen(path, "rb");
    long size;
    int err;

    if (!f)
	return -errno;

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        err = (size == 0) ? ENODATA : errno;
        fclose(f);
        return -err;
    }

    if ((size_t)size > max_size) {
        fclose(f);
        return -EFBIG;
    }

    *buf = malloc(size);
    if (!*buf) {
        fclose(f);
        return -ENOMEM;
    }

    if (fread(*buf, 1, size, f) != (size_t)size) {
        err = ferror(f) ? errno : EIO;
        if (err == 0)
	    err = EIO;
        free(*buf);
        *buf = NULL;
        fclose(f);
        return -err;
    }

    fclose(f);
    *len = size;
    return 0;
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
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    TPMT_RSA_DECRYPT inScheme;
    TPM2B_DATA label = { .size = 0 };
    TPM2B_PUBLIC_KEY_RSA *message = NULL;
    int ret_err = 0;
    int mlocked = 0;

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

    rc = Esys_RSA_Decrypt(esys_ctx, key_handle,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher_text, &inScheme, &label, &message);

    if (rc != TSS2_RC_SUCCESS || !message) {
        ret_err = -EACCES;
        goto out_msg;
    }

    if (message->size == 0) {
        ret_err = -ENODATA;
        goto out_msg;
    }

    if (mlock(message->buffer, message->size) != 0) {
        ret_err = -errno;
        goto out_msg;
    }
    mlocked = 1;

    out->buf = copy_tpm_message(message);

    if (out->buf == NULL)
	ret_err = -errno;
    else
	out->len = out->allocated_size = message->size;
out_msg:
    if (message) {
        OPENSSL_cleanse(message->buffer, message->size);
        if (mlocked) {
            munlock(message->buffer, message->size);
        }
        Esys_Free(message);
    }
out_key:
    Esys_TR_Close(esys_ctx, &key_handle);
out_esys:
    Esys_Finalize(&esys_ctx);
out_tcti:
    Tss2_TctiLdr_Finalize(&tcti_ctx);

    return ret_err;
}

static int do_aes_decrypt(const uint8_t *in_data, size_t in_len,
			  const struct decrypted_node *passphrase,
			  struct decrypted_node *out) {
    const uint8_t *salt;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t key_iv[32 + 16];
    EVP_CIPHER_CTX *ctx;
    uint8_t *plain;
    size_t alloc_sz;
    int len1 = 0, len2 = 0;
    int ret_err = -EIO;

    if (in_len < AES_HEADER_LEN + AES_SALT_LEN)
	return -EINVAL;

    salt = in_data + AES_HEADER_LEN;
    ciphertext = in_data + AES_HEADER_LEN + AES_SALT_LEN;
    ciphertext_len = in_len - (AES_HEADER_LEN + AES_SALT_LEN);

    if (!PKCS5_PBKDF2_HMAC((const char *)passphrase->buf, passphrase->len,
                           salt, AES_SALT_LEN, PBKDF2_ITER,
                           EVP_sha256(), sizeof(key_iv), key_iv)){
        ret_err = -EACCES;
	goto ctx_err;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ret_err = -ENOMEM;
	goto ctx_err;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_iv, key_iv + 32)) {
        ret_err = -EIO;
	goto decrypt_init_err;
    }

    if (ciphertext_len > INT_MAX) {
        ret_err = -E2BIG;
        goto decrypt_init_err;
    }

    alloc_sz = ciphertext_len + EVP_MAX_BLOCK_LENGTH;
    plain = malloc_mlock(alloc_sz);
    if (!plain) {
        ret_err = -errno;
        goto decrypt_init_err;
    }

    if (!EVP_DecryptUpdate(ctx, plain, &len1, ciphertext, (int)ciphertext_len)) {
        ret_err = -EACCES;
	    goto decrypt_update_err;
    }

    if (!EVP_DecryptFinal_ex(ctx, plain + len1, &len2)) {
        ret_err = -EACCES;
	    goto decrypt_final_err;
    }

    EVP_CIPHER_CTX_free(ctx);

    out->len = len1 + len2;
    out->allocated_size = alloc_sz;
    out->buf = plain; // Returned buffer has exact plaintext

    OPENSSL_cleanse(key_iv, sizeof(key_iv));
    return 0;

 decrypt_final_err:
 decrypt_update_err:
    OPENSSL_cleanse(plain, alloc_sz);
    munlock(plain, alloc_sz);
    free(plain);
 decrypt_init_err:
    EVP_CIPHER_CTX_free(ctx);
 ctx_err:
    OPENSSL_cleanse(key_iv, sizeof(key_iv));
    return ret_err;
}

int decrypt_credential(const char *file_path,
		       struct decrypted_node *out) {
    uint8_t *enc_data = NULL;
    size_t enc_len = 0;
    int is_aes;
    uint8_t *host_key_enc = NULL;
    size_t host_enc_len = 0;
    struct decrypted_node passphrase = { NULL, 0, 0};
    int r;

    r = read_file(file_path, &enc_data, &enc_len, global_opts.max_file_size);
    if (r < 0)
        return r;

    is_aes = (enc_len > 8 && memcmp(enc_data, AES_HEADER, 8) == 0);

    if (!is_aes) {
        // RSA directly
        r = tpm2_rsa_decrypt(enc_data, enc_len, out);
	goto read_err;
    }

    // AES flow: needs host key
    if (cached_host_key_path[0] == '\0') {
        r = -ENOKEY;
	goto read_err;
    }

    r = read_file(cached_host_key_path, &host_key_enc, &host_enc_len, global_opts.max_file_size);
    if (r < 0) {
        if (r == -ENOENT)
	    r = -ENOKEY;
	goto read_err;
    }

    r = tpm2_rsa_decrypt(host_key_enc, host_enc_len, &passphrase);
    free(host_key_enc);
    if (r < 0) {
	goto read_err;
    }

    r = do_aes_decrypt(enc_data, enc_len, &passphrase, out);

    clean_decrypted_node(&passphrase);
 read_err:
    free(enc_data);

    return r;
}
