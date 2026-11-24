#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "pubkey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>

#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

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
            BIGNUM *bn_e = NULL;
            if (EVP_PKEY_is_a(pkey, "RSA") &&
                EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) == 1 && bn_n &&
                EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e) == 1 && bn_e) {
                int num_bytes = BN_num_bytes(bn_n);
                int exp_valid = (BN_is_word(bn_e, 65537) == 1);
                BN_free(bn_e);
                if (exp_valid && (num_bytes == TPM2_RSA2048_KEY_BYTES || num_bytes == TPM2_RSA4096_KEY_BYTES)) {
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
            } else {
                if (bn_n) BN_free(bn_n);
                if (bn_e) BN_free(bn_e);
            }
            EVP_PKEY_free(pkey);
            ERR_clear_error();
            fprintf(stderr, "Error: PEM public key %s is not a valid 2048/4096-bit RSA key with exponent 65537.\n", path);
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
            if (exp != 0 && exp != 65537) {
                fprintf(stderr, "Error: TPM2B_PUBLIC key %s has unsupported exponent %u (expected 65537).\n", path, exp);
                return NULL;
            }
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
