#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <endian.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "decryption.h"

struct cred_fuse_opts global_opts = {0};
int mlockall_active = 0;

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s -k <pubkey> -p <rel_path> -m <octal_mode> [-i <in_file>] [-o <out_file>]\n"
            "\n"
            "Encrypts a credential into a CRED_ENV v1 hybrid envelope bound to its FUSE path and mode.\n"
            "\n"
            "Required arguments:\n"
            "  -k, --pubkey <path>     RSA-2048/4096 public key file (PEM or TSS2 TPM2B_PUBLIC)\n"
            "  -p, --path <rel_path>   Relative path in the mounted FUSE filesystem\n"
            "  -m, --mode <octal_mode> File permissions in octal (e.g. 0600, 0400, 0640)\n"
            "\n"
            "Optional arguments:\n"
            "  -i, --input <path>      Input plaintext file (default: stdin)\n"
            "  -o, --output <path>     Output encrypted file (default: stdout)\n"
            "  -h, --help              Show this help message\n",
            prog);
}

static int read_all_stream(int fd, uint8_t **buf_out, size_t *len_out, size_t max_bytes) {
    uint8_t *buf = malloc_mlock(max_bytes + 1);
    if (!buf) {
        return -ENOMEM;
    }

    size_t total = 0;
    while (total < max_bytes + 1) {
        ssize_t r = read(fd, buf + total, (max_bytes + 1) - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            int err = -errno;
            OPENSSL_cleanse(buf, max_bytes + 1);
            free_munlock(buf, max_bytes + 1);
            return err;
        }
        if (r == 0) break;
        total += (size_t)r;
    }

    if (total > max_bytes) {
        OPENSSL_cleanse(buf, max_bytes + 1);
        free_munlock(buf, max_bytes + 1);
        return -EFBIG;
    }

    *buf_out = buf;
    *len_out = total;
    return 0;
}

static int write_all_fd(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t written = 0;
    while (written < len) {
        ssize_t w = write(fd, p + written, len - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        written += (size_t)w;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit core_limit = {0, 0};
    setrlimit(RLIMIT_CORE, &core_limit);

    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        mlockall_active = 1;
    }

    if (init_decryption() < 0) {
        fprintf(stderr, "Error: Failed to initialize cryptographic subsystem.\n");
        return 1;
    }

    const char *pubkey_path = NULL;
    const char *rel_path = NULL;
    const char *mode_str = NULL;
    const char *in_path = NULL;
    const char *out_path = NULL;

    static const struct option long_opts[] = {
        {"pubkey", required_argument, NULL, 'k'},
        {"path",   required_argument, NULL, 'p'},
        {"mode",   required_argument, NULL, 'm'},
        {"input",  required_argument, NULL, 'i'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "k:p:m:i:o:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'k': pubkey_path = optarg; break;
            case 'p': rel_path = optarg; break;
            case 'm': mode_str = optarg; break;
            case 'i': in_path = optarg; break;
            case 'o': out_path = optarg; break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!pubkey_path || !rel_path || !mode_str || optind < argc) {
        fprintf(stderr, "Error: --pubkey (-k), --path (-p), and --mode (-m) are required.\n");
        print_usage(argv[0]);
        return 1;
    }

    mode_t mode = 0;
    if (parse_octal_mode(mode_str, &mode) < 0) {
        fprintf(stderr, "Error: Invalid octal mode '%s' (expected octal value between 0000 and 07777).\n", mode_str);
        return 1;
    }

    char aad[PATH_MAX + 16];
    if (format_credential_aad(aad, sizeof(aad), rel_path, mode) < 0) {
        fprintf(stderr, "Error: Invalid relative path '%s' (must be non-empty and contain no '..' components).\n", rel_path);
        return 1;
    }

    uint8_t oaep_label[33];
    if (compute_oaep_label(aad, oaep_label) < 0) {
        fprintf(stderr, "Error: Failed to compute RSA-OAEP label from AAD.\n");
        return 1;
    }

    EVP_PKEY *pkey = load_rsa_pubkey_evp(pubkey_path, 0, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Error: Failed to load valid RSA-2048/4096 public key from '%s'.\n", pubkey_path);
        return 1;
    }

    int ret = 1;
    int in_fd = STDIN_FILENO;
    int out_fd = STDOUT_FILENO;
    uint8_t *pt_buf = NULL;
    size_t pt_len = 0;
    uint8_t *ct_buf = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    uint8_t eph_key[32];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t rsa_ct[TPM2_RSA4096_KEY_BYTES];

    if (in_path) {
        in_fd = open(in_path, O_RDONLY | O_CLOEXEC);
        if (in_fd < 0) {
            fprintf(stderr, "Error: Cannot open input file '%s': %s\n", in_path, strerror(errno));
            goto cleanup;
        }
    }

    int read_res = read_all_stream(in_fd, &pt_buf, &pt_len, MAX_ALLOWED_FILE_SIZE);
    if (read_res < 0) {
        if (read_res == -EFBIG) {
            fprintf(stderr, "Error: Input plaintext exceeds maximum allowed size (%d bytes).\n", MAX_ALLOWED_FILE_SIZE);
        } else {
            fprintf(stderr, "Error: Failed to read input plaintext: %s\n", strerror(-read_res));
        }
        goto cleanup;
    }

    if (pt_len == 0) {
        fprintf(stderr, "Error: Input plaintext is empty (0 bytes).\n");
        goto cleanup;
    }

    if (RAND_bytes(eph_key, sizeof(eph_key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Error: Failed to generate random key/IV via OpenSSL RAND_bytes.\n");
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0) {
        fprintf(stderr, "Error: Failed to initialize EVP_PKEY_encrypt.\n");
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "Error: Failed to configure RSA-OAEP-SHA256 parameters.\n");
        goto cleanup;
    }

    /* EVP_PKEY_CTX_set0_rsa_oaep_label takes ownership of the OPENSSL_malloc'd buffer */
    uint8_t *label_copy = OPENSSL_malloc(sizeof(oaep_label));
    if (!label_copy) {
        fprintf(stderr, "Error: Out of memory allocating RSA-OAEP label.\n");
        goto cleanup;
    }
    memcpy(label_copy, oaep_label, sizeof(oaep_label));
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label_copy, (int)sizeof(oaep_label)) <= 0) {
        OPENSSL_free(label_copy);
        fprintf(stderr, "Error: Failed to set RSA-OAEP label.\n");
        goto cleanup;
    }

    size_t rsa_ct_len = sizeof(rsa_ct);
    if (EVP_PKEY_encrypt(pctx, rsa_ct, &rsa_ct_len, eph_key, sizeof(eph_key)) <= 0 ||
        (rsa_ct_len != TPM2_RSA2048_KEY_BYTES && rsa_ct_len != TPM2_RSA4096_KEY_BYTES)) {
        fprintf(stderr, "Error: RSA-OAEP encryption of ephemeral key failed.\n");
        goto cleanup;
    }

    ct_buf = malloc(pt_len);
    if (!ct_buf) {
        fprintf(stderr, "Error: Out of memory allocating ciphertext buffer.\n");
        goto cleanup;
    }

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, eph_key, iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize AES-256-GCM encryption.\n");
        goto cleanup;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(cctx, NULL, &outlen, (const uint8_t *)aad, (int)strlen(aad)) != 1) {
        fprintf(stderr, "Error: Failed to feed AAD into AES-256-GCM.\n");
        goto cleanup;
    }

    int ct_len = 0;
    if (EVP_EncryptUpdate(cctx, ct_buf, &outlen, pt_buf, (int)pt_len) != 1) {
        fprintf(stderr, "Error: AES-256-GCM encryption failed.\n");
        goto cleanup;
    }
    ct_len = outlen;

    if (EVP_EncryptFinal_ex(cctx, ct_buf + ct_len, &outlen) != 1) {
        fprintf(stderr, "Error: AES-256-GCM finalization failed.\n");
        goto cleanup;
    }
    ct_len += outlen;

    if ((size_t)ct_len != pt_len ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, "Error: Failed to extract AES-256-GCM authentication tag.\n");
        goto cleanup;
    }

    if (out_path) {
        out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (out_fd < 0) {
            fprintf(stderr, "Error: Cannot open output file '%s': %s\n", out_path, strerror(errno));
            goto cleanup;
        }
    }

    uint64_t version_be = htobe64(CRED_ENV_VERSION_1);
    uint16_t rsa_len_be = htobe16((uint16_t)rsa_ct_len);

    if (write_all_fd(out_fd, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN) < 0 ||
        write_all_fd(out_fd, &version_be, sizeof(version_be)) < 0 ||
        write_all_fd(out_fd, &rsa_len_be, sizeof(rsa_len_be)) < 0 ||
        write_all_fd(out_fd, rsa_ct, rsa_ct_len) < 0 ||
        write_all_fd(out_fd, iv, sizeof(iv)) < 0 ||
        write_all_fd(out_fd, tag, sizeof(tag)) < 0 ||
        write_all_fd(out_fd, ct_buf, pt_len) < 0) {
        fprintf(stderr, "Error: Failed writing CRED_ENV output.\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    OPENSSL_cleanse(eph_key, sizeof(eph_key));
    OPENSSL_cleanse(oaep_label, sizeof(oaep_label));
    if (pt_buf) {
        OPENSSL_cleanse(pt_buf, MAX_ALLOWED_FILE_SIZE + 1);
        free_munlock(pt_buf, MAX_ALLOWED_FILE_SIZE + 1);
    }
    if (ct_buf) {
        free(ct_buf);
    }
    if (cctx) EVP_CIPHER_CTX_free(cctx);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (in_path && in_fd >= 0) close(in_fd);
    if (out_path && out_fd >= 0) close(out_fd);
    return ret;
}
