#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "tpm.h"
#include "secure_mem.h"
#include "pubkey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>

#include <openssl/crypto.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

struct pinned_tpm_key {
    pthread_mutex_t lock;
    uint8_t modulus[TPM2_RSA4096_KEY_BYTES];
    size_t modulus_len;
    TPM2B_NAME name;
    uint16_t session_aes_bits;
};

static struct pinned_tpm_key pinned_key = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .modulus = {0},
    .modulus_len = 0,
    .name = {0},
    .session_aes_bits = 0
};

static char *cached_tcti = NULL;
static uint32_t cached_handle = 0;
static char *cached_pubkey = NULL;

int validate_tcti(const char *tcti) {
    if (!tcti || *tcti == '\0') {
        return 0;
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
                                TPMA_OBJECT_DECRYPT |
                                TPMA_OBJECT_NODA;

        if (out_public->publicArea.type != TPM2_ALG_RSA ||
            (out_public->publicArea.parameters.rsaDetail.keyBits != 2048 &&
             out_public->publicArea.parameters.rsaDetail.keyBits != 4096) ||
            (out_public->publicArea.objectAttributes & req_attrs) != req_attrs) {
            syslog(LOG_ERR, "verify_and_pin_tpm_key: TPM handle 0x%08x has invalid type, key size, or object attributes (0x%08x)",
                   cached_handle, out_public->publicArea.objectAttributes);
            fprintf(stderr, "Error: TPM handle 0x%08x is not a hardware-bound RSA-2048/4096 decryption key.\n",
                    cached_handle);
            Esys_Free(out_public);
            Esys_Free(name);
            Esys_Free(qualified_name);
            ret = -EKEYREJECTED;
            goto out;
        }

        if (out_public->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED) {
            syslog(LOG_ERR, "verify_and_pin_tpm_key: TPM handle 0x%08x is a restricted decryption key (0x%08x)",
                   cached_handle, out_public->publicArea.objectAttributes);
            fprintf(stderr, "Error: TPM handle 0x%08x is a restricted decryption key (e.g. Storage Key). An unrestricted decryption key is required.\n",
                    cached_handle);
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
                       cached_handle);
                fprintf(stderr, "Error: TPM handle 0x%08x public key does not match tpm_pubkey %s.\n",
                        cached_handle, cached_pubkey ? cached_pubkey : "<unknown>");
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
        syslog(LOG_ERR, "verify_and_pin_tpm_key: TPM object Name mismatch for handle 0x%08x", cached_handle);
        Esys_Free(tr_name);
        ret = -EKEYREJECTED;
        goto out;
    }
    Esys_Free(tr_name);

out:
    pthread_mutex_unlock(&pinned_key.lock);
    return ret;
}

int tpm_init(const char *tcti, uint32_t handle, const char *pubkey_path) {
    init_secure_mem();

    pthread_mutex_lock(&pinned_key.lock);
    pinned_key.modulus_len = 0;
    memset(&pinned_key.name, 0, sizeof(pinned_key.name));
    __atomic_store_n(&pinned_key.session_aes_bits, 0, __ATOMIC_RELEASE);

    if (cached_tcti) {
        free(cached_tcti);
    }
    cached_tcti = tcti ? strdup(tcti) : strdup("device:/dev/tpmrm0");
    cached_handle = handle;

    if (cached_pubkey) {
        free(cached_pubkey);
        cached_pubkey = NULL;
    }
    if (pubkey_path) {
        cached_pubkey = strdup(pubkey_path);
        EVP_PKEY *pkey = load_rsa_pubkey_evp(cached_pubkey, 1,
                                             &pinned_key.modulus_len, pinned_key.modulus);
        if (!pkey) {
            pthread_mutex_unlock(&pinned_key.lock);
            return -1;
        }
        EVP_PKEY_free(pkey);
    }
    pthread_mutex_unlock(&pinned_key.lock);

    return 0;
}

int tpm_check_health(void) {
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *esys_ctx = NULL;
    ESYS_TR key_handle = ESYS_TR_NONE;
    int ret_err = 0;

    const char *tcti_str = cached_tcti ? cached_tcti : "device:/dev/tpmrm0";

    rc = Tss2_TctiLdr_Initialize(tcti_str, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_check_health: Tss2_TctiLdr_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        fprintf(stderr, "Failed to initialize TCTI: %s (0x%x)\n", Tss2_RC_Decode(rc), rc);
        return -ENODEV;
    }

    rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_check_health: Esys_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
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
        syslog(LOG_ERR, "tpm_check_health: Esys_GetCapability failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
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
        syslog(LOG_ERR, "tpm_check_health: TPM is in lockout mode (lockout_counter=%u, max_auth_fail=%u)", lockout_counter, max_auth_fail);
        fprintf(stderr, "Error: TPM is in lockout mode (failed tries: %u, max allowed: %u). Reads will fail.\n", lockout_counter, max_auth_fail);
        ret_err = -EKEYREJECTED;
        goto out;
    }

    rc = Esys_TR_FromTPMPublic(esys_ctx, cached_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &key_handle);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_check_health: Esys_TR_FromTPMPublic failed for handle 0x%08x: %s (0x%x)",
               cached_handle, Tss2_RC_Decode(rc), rc);
        fprintf(stderr, "Failed to load TPM handle 0x%08x: %s (0x%x)\n",
                cached_handle, Tss2_RC_Decode(rc), rc);
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

static uint8_t *copy_tpm_message(TPM2B_PUBLIC_KEY_RSA *message) {
    if (!message || message->size == 0 || message->size > sizeof(message->buffer)) {
        return NULL;
    }

    uint8_t *ptr = malloc_mlock(message->size);
    if (!ptr) {
        return NULL;
    }

    memcpy(ptr, message->buffer, message->size);
    return ptr;
}

int tpm_unwrap(const uint8_t *in_data, size_t in_len,
               const uint8_t oaep_label[33],
               struct decrypted_node *out) {
    if (in_len != TPM2_RSA2048_KEY_BYTES && in_len != TPM2_RSA4096_KEY_BYTES) {
        return -EMSGSIZE;
    }
    if (!oaep_label || !out) {
        return -EINVAL;
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

    memcpy(label.buffer, oaep_label, 33);

    uint16_t cached_bits = __atomic_load_n(&pinned_key.session_aes_bits, __ATOMIC_ACQUIRE);
    uint16_t aes_bits = cached_bits ? cached_bits : 256;
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = aes_bits },
        .mode = { .aes = TPM2_ALG_CFB }
    };
    TPMA_SESSION session_attrs = TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT;

    const char *tcti_str = cached_tcti ? cached_tcti : "device:/dev/tpmrm0";

    rc = Tss2_TctiLdr_Initialize(tcti_str, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_unwrap: Tss2_TctiLdr_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        OPENSSL_cleanse(&label, sizeof(label));
        return -ENODEV;
    }

    rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_unwrap: Esys_Initialize failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        ret_err = -ENODEV;
        goto out_tcti;
    }

    rc = Esys_TR_FromTPMPublic(esys_ctx, cached_handle,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &key_handle);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_unwrap: Esys_TR_FromTPMPublic failed for handle 0x%08x: %s (0x%x)", cached_handle, Tss2_RC_Decode(rc), rc);
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
    if (rc != TSS2_RC_SUCCESS && aes_bits == 256) {
        /* Discrete TPMs often support only 128-bit AES for transport auth sessions */
        symmetric.keyBits.aes = 128;
        rc = Esys_StartAuthSession(esys_ctx, key_handle, ESYS_TR_NONE,
                                   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                   NULL, TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                                   &session_handle);
        if (rc == TSS2_RC_SUCCESS) {
            __atomic_store_n(&pinned_key.session_aes_bits, 128, __ATOMIC_RELEASE);
        }
    } else if (rc == TSS2_RC_SUCCESS && cached_bits == 0) {
        __atomic_store_n(&pinned_key.session_aes_bits, 256, __ATOMIC_RELEASE);
    }
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_unwrap: Esys_StartAuthSession failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        ret_err = -EACCES;
        goto out_key;
    }
    session_need_flush = 1;

    rc = Esys_TRSess_SetAttributes(esys_ctx, session_handle, session_attrs, 0xff);
    if (rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "tpm_unwrap: Esys_TRSess_SetAttributes failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        ret_err = -EACCES;
        goto out_session;
    }

    rc = Esys_RSA_Decrypt(esys_ctx, key_handle,
                          session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                          &cipher_text, &inScheme, &label, &message);

    if (rc != TSS2_RC_SUCCESS || !message) {
        syslog(LOG_ERR, "tpm_unwrap: Esys_RSA_Decrypt failed: %s (0x%x)", Tss2_RC_Decode(rc), rc);
        TSS2_RC base_rc = rc & ~TPM2_RC_N_MASK;
        if ((rc & TPM2_RC_FMT1) ? (base_rc == TPM2_RC_AUTH_FAIL) : (rc == TPM2_RC_LOCKOUT)) {
            ret_err = -EKEYREJECTED;
        } else if (rc == TPM2_RC_RETRY || rc == TPM2_RC_OBJECT_MEMORY || rc == TPM2_RC_SESSION_MEMORY) {
            ret_err = -EAGAIN;
        } else {
            ret_err = -EIO;
        }
        goto out_msg;
    }
    session_need_flush = 0;

    if (message->size == 0) {
        ret_err = -ENODATA;
        goto out_msg;
    }

    out->buf = copy_tpm_message(message);
    if (!out->buf) {
        ret_err = -ENOMEM;
    } else {
        out->len = out->allocated_size = message->size;
    }

out_msg:
    if (message) {
        OPENSSL_cleanse(message, sizeof(*message));
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

void tpm_cleanup(void) {
    pthread_mutex_lock(&pinned_key.lock);
    if (cached_tcti) {
        free(cached_tcti);
        cached_tcti = NULL;
    }
    if (cached_pubkey) {
        free(cached_pubkey);
        cached_pubkey = NULL;
    }
    OPENSSL_cleanse(pinned_key.modulus, sizeof(pinned_key.modulus));
    pinned_key.modulus_len = 0;
    OPENSSL_cleanse(&pinned_key.name, sizeof(pinned_key.name));
    __atomic_store_n(&pinned_key.session_aes_bits, 0, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&pinned_key.lock);
}
