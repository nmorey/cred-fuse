#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include <openssl/crypto.h>

#include "decryption.h"

struct cred_fuse_opts global_opts = {0};
int mlockall_active = 0;

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s -c <tpm_handle> -p <rel_path> -m <octal_mode> [-k <tpm_pubkey>] [-T <tcti>] [-i <in_file>] [-o <out_file>]\n"
            "\n"
            "Decrypts a CRED_ENV v1 hybrid envelope using a TPM 2.0 persistent RSA key.\n"
            "\n"
            "Required arguments:\n"
            "  -c, --handle <handle>   Persistent TPM 2.0 handle in hex (0x81000000 - 0x81FFFFFF)\n"
            "  -p, --path <rel_path>   Relative path in the mounted FUSE filesystem\n"
            "  -m, --mode <octal_mode> File permissions in octal (e.g. 0600, 0400, 0640)\n"
            "\n"
            "Optional arguments:\n"
            "  -k, --pubkey <path>     Pinned TPM RSA public key file (PEM or TSS2 TPM2B_PUBLIC)\n"
            "  -T, --tcti <tcti>       TCTI configuration string (default: device:/dev/tpmrm0)\n"
            "  -i, --input <path>      Input encrypted file (default: stdin)\n"
            "  -o, --output <path>     Output plaintext file (default: stdout)\n"
            "  -h, --help              Show this help message\n",
            prog);
}

static int read_all_stream(int fd, uint8_t **buf_out, size_t *len_out, size_t max_bytes) {
    uint8_t *buf = malloc(max_bytes + 1);
    if (!buf) {
        return -ENOMEM;
    }

    size_t total = 0;
    while (total < max_bytes + 1) {
        ssize_t r = read(fd, buf + total, (max_bytes + 1) - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            int err = -errno;
            free(buf);
            return err;
        }
        if (r == 0) break;
        total += (size_t)r;
    }

    if (total > max_bytes) {
        free(buf);
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

    unsetenv("TSS2_TCTI");
    unsetenv("TPM2TOOLS_TCTI");
    unsetenv("TCTI");

    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        mlockall_active = 1;
    }

    const char *handle_str = NULL;
    const char *rel_path = NULL;
    const char *mode_str = NULL;
    const char *pubkey_path = NULL;
    const char *tcti_str = NULL;
    const char *in_path = NULL;
    const char *out_path = NULL;

    static const struct option long_opts[] = {
        {"handle", required_argument, NULL, 'c'},
        {"path",   required_argument, NULL, 'p'},
        {"mode",   required_argument, NULL, 'm'},
        {"pubkey", required_argument, NULL, 'k'},
        {"tcti",   required_argument, NULL, 'T'},
        {"input",  required_argument, NULL, 'i'},
        {"output", required_argument, NULL, 'o'},
        {"help",   no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:m:k:T:i:o:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c': handle_str = optarg; break;
            case 'p': rel_path = optarg; break;
            case 'm': mode_str = optarg; break;
            case 'k': pubkey_path = optarg; break;
            case 'T': tcti_str = optarg; break;
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

    if (!handle_str || !rel_path || !mode_str || optind < argc) {
        fprintf(stderr, "Error: --handle (-c), --path (-p), and --mode (-m) are required.\n");
        print_usage(argv[0]);
        return 1;
    }

    char *endptr = NULL;
    errno = 0;
    unsigned long handle_val = strtoul(handle_str, &endptr, 16);
    if (errno != 0 || endptr == handle_str || *endptr != '\0' ||
        handle_val < 0x81000000UL || handle_val > 0x81FFFFFFUL) {
        fprintf(stderr, "Error: Invalid TPM handle '%s' (must be persistent handle in range 0x81000000 - 0x81FFFFFF).\n", handle_str);
        return 1;
    }
    global_opts.tpm_handle = (uint32_t)handle_val;

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

    if (tcti_str) {
        if (!validate_tcti(tcti_str)) {
            fprintf(stderr, "Error: Invalid or disallowed TCTI configuration '%s'.\n", tcti_str);
            return 1;
        }
        global_opts.tcti = (char *)tcti_str;
    }

    if (pubkey_path) {
        global_opts.tpm_pubkey = (char *)pubkey_path;
    }
    global_opts.max_file_size = MAX_ALLOWED_FILE_SIZE;

    if (init_decryption() < 0) {
        fprintf(stderr, "Error: Failed to initialize decryption subsystem.\n");
        return 1;
    }

    if (check_tpm_lockout() < 0) {
        fprintf(stderr, "Error: TPM lockout check or public key verification failed.\n");
        return 1;
    }

    int ret = 1;
    int in_fd = STDIN_FILENO;
    int out_fd = STDOUT_FILENO;
    uint8_t *enc_buf = NULL;
    size_t enc_len = 0;
    struct decrypted_node out_node = {0};

    if (in_path) {
        in_fd = open(in_path, O_RDONLY | O_CLOEXEC);
        if (in_fd < 0) {
            fprintf(stderr, "Error: Cannot open input file '%s': %s\n", in_path, strerror(errno));
            goto cleanup;
        }
    }

    size_t max_enc_size = (size_t)MAX_ALLOWED_FILE_SIZE + CRED_ENV_MAX_OVERHEAD;
    int read_res = read_all_stream(in_fd, &enc_buf, &enc_len, max_enc_size);
    if (read_res < 0) {
        if (read_res == -EFBIG) {
            fprintf(stderr, "Error: Encrypted input exceeds maximum envelope size (%zu bytes).\n", max_enc_size);
        } else {
            fprintf(stderr, "Error: Failed to read encrypted input: %s\n", strerror(-read_res));
        }
        goto cleanup;
    }

    if (decrypt_envelope(enc_buf, enc_len, rel_path, mode, &out_node) < 0) {
        fprintf(stderr, "Error: Envelope decryption failed (authentication failure, corrupted envelope, or mismatched path/mode).\n");
        goto cleanup;
    }

    if (out_path) {
        out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (out_fd < 0) {
            fprintf(stderr, "Error: Cannot open output file '%s': %s\n", out_path, strerror(errno));
            goto cleanup;
        }
    }

    if (write_all_fd(out_fd, out_node.buf, out_node.len) < 0) {
        fprintf(stderr, "Error: Failed writing decrypted plaintext.\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    clean_decrypted_node(&out_node);
    if (enc_buf) {
        free(enc_buf);
    }
    if (in_path && in_fd >= 0) close(in_fd);
    if (out_path && out_fd >= 0) close(out_fd);
    return ret;
}
