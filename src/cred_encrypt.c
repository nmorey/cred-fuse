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

#include "cred_opts.h"
#include "secure_mem.h"
#include "pubkey.h"
#include "envelope.h"

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
            "  -m, --mode <octal_mode> Target permissions in octal (e.g. 0600, 0400) bound into cryptographic AAD\n"
            "                          (output file created with 0600 unless --set-mode is passed)\n"
            "\n"
            "Optional arguments:\n"
            "  -s, --set-mode          Apply the specified octal mode directly to the output file on disk\n"
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

    init_secure_mem();

    const char *pubkey_path = NULL;
    const char *rel_path = NULL;
    const char *mode_str = NULL;
    const char *in_path = NULL;
    const char *out_path = NULL;
    int set_mode = 0;
    uint64_t format_version = CRED_ENV_CUR_VERSION;

    static const struct option long_opts[] = {
        {"pubkey",   required_argument, NULL, 'k'},
        {"path",     required_argument, NULL, 'p'},
        {"mode",     required_argument, NULL, 'm'},
        {"set-mode", no_argument,       NULL, 's'},
        {"input",    required_argument, NULL, 'i'},
        {"output",   required_argument, NULL, 'o'},
#ifdef CRED_FUSE_TESTING
        {"format-version", required_argument, NULL, 'V'},
#endif
        {"help",     no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "k:p:m:si:o:V:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'k': pubkey_path = optarg; break;
            case 'p': rel_path = optarg; break;
            case 'm': mode_str = optarg; break;
            case 's': set_mode = 1; break;
            case 'i': in_path = optarg; break;
            case 'o': out_path = optarg; break;
#ifdef CRED_FUSE_TESTING
            case 'V':
                format_version = (uint64_t)strtoull(optarg, NULL, 10);
                break;
#endif
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

    if (set_mode && !out_path) {
        fprintf(stderr, "Warning: --set-mode (-s) has no effect when writing to standard output.\n");
    }

    mode_t mode = 0;
    if (parse_octal_mode(mode_str, &mode) < 0) {
        fprintf(stderr, "Error: Invalid octal mode '%s' (expected octal value between 0000 and 07777).\n", mode_str);
        return 1;
    }

    EVP_PKEY *pkey = load_rsa_pubkey_evp(pubkey_path, 0, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Error: Failed to load valid RSA-2048/4096 public key from '%s'.\n", pubkey_path);
        return 1;
    }

    size_t rsa_mod_bytes = (size_t)EVP_PKEY_get_size(pkey);
    if (rsa_mod_bytes != TPM2_RSA2048_KEY_BYTES && rsa_mod_bytes != TPM2_RSA4096_KEY_BYTES) {
        fprintf(stderr, "Error: RSA public key %s must be 2048 or 4096 bits.\n", pubkey_path);
        EVP_PKEY_free(pkey);
        return 1;
    }

    int ret = 1;
    int in_fd = STDIN_FILENO;
    int out_fd = -1;
    char tmp_out_path[PATH_MAX] = {0};
    uint8_t *pt_buf = NULL;
    size_t pt_len = 0;
    uint8_t *envelope_buf = NULL;
    size_t envelope_len = 0;

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

    if (format_version <= CRED_ENV_VERSION_INVALID ||
        format_version >= _CRED_ENV_VERSION_MAX ||
        !envelope_encryptors[format_version]) {
        fprintf(stderr, "Error: Unsupported format version %llu\n", (unsigned long long)format_version);
        goto cleanup;
    }

    int enc_res = envelope_encryptors[format_version](pkey, rel_path, mode, pt_buf, pt_len,
                                                      &envelope_buf, &envelope_len);
    if (enc_res < 0) {
        fprintf(stderr, "Error: Envelope encryption failed.\n");
        goto cleanup;
    }

    if (out_path) {
        struct stat check_st;
        if (stat(out_path, &check_st) == 0) {
            fprintf(stderr, "Error: Output file '%s' already exists. Refusing to overwrite for security.\n", out_path);
            goto cleanup;
        }

        mode_t create_mode = set_mode ? (mode & 07777) : 0600;
        int sn_ret = snprintf(tmp_out_path, sizeof(tmp_out_path), "%s.tmp.%d", out_path, (int)getpid());
        if (sn_ret < 0 || (size_t)sn_ret >= sizeof(tmp_out_path)) {
            fprintf(stderr, "Error: Output path is too long.\n");
            goto cleanup;
        }

        out_fd = open(tmp_out_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, create_mode);
        if (out_fd < 0) {
            fprintf(stderr, "Error: Cannot create temporary output file '%s': %s\n", tmp_out_path, strerror(errno));
            goto cleanup;
        }
        if (set_mode) {
            if (fchmod(out_fd, mode & 07777) < 0) {
                fprintf(stderr, "Error: Cannot set permissions on '%s': %s\n", tmp_out_path, strerror(errno));
                goto cleanup;
            }
        }
    } else {
        out_fd = STDOUT_FILENO;
    }

    if (write_all_fd(out_fd, envelope_buf, envelope_len) < 0) {
        fprintf(stderr, "Error: Failed writing CRED_ENV output.\n");
        goto cleanup;
    }

    if (out_path) {
        if (fsync(out_fd) != 0) {
            fprintf(stderr, "Error: Failed to fsync '%s': %s\n", tmp_out_path, strerror(errno));
            goto cleanup;
        }
        close(out_fd);
        out_fd = -1;

        if (rename(tmp_out_path, out_path) != 0) {
            fprintf(stderr, "Error: Atomic rename '%s' -> '%s' failed: %s\n", tmp_out_path, out_path, strerror(errno));
            goto cleanup;
        }
        tmp_out_path[0] = '\0';
    }

    ret = 0;

cleanup:
    if (envelope_buf) {
        free(envelope_buf);
    }
    if (pt_buf) {
        OPENSSL_cleanse(pt_buf, MAX_ALLOWED_FILE_SIZE + 1);
        free_munlock(pt_buf, MAX_ALLOWED_FILE_SIZE + 1);
    }
    if (pkey) EVP_PKEY_free(pkey);
    if (in_path && in_fd >= 0) close(in_fd);
    if (out_fd >= 0 && out_fd != STDOUT_FILENO) close(out_fd);
    if (tmp_out_path[0] != '\0') {
        unlink(tmp_out_path);
    }
    return ret;
    return ret;
}
