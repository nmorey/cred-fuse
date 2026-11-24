#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <endian.h>

#include "envelope.h"
#include "cred_opts.h"

struct cred_fuse_opts global_opts = {0};
int mlockall_active = 0;

/*
 * ============================================================================
 * Envelope Header Generation Test Suite
 * ============================================================================
 *
 * HOW TO ADD A NEW HEADER GENERATION (e.g., CRED_ENV v3):
 * 1. Add your version definition to `enum cred_env_version` in envelope.h.
 * 2. Add an entry to `GENERATION_TESTS[]` below specifying:
 *      - .version                    (e.g., CRED_ENV_VERSION_3)
 *      - .rsa_ct_len                 (e.g., TPM2_RSA2048_KEY_BYTES or TPM2_RSA4096_KEY_BYTES)
 *      - .payload_len                (sample plaintext byte count)
 *      - .expected_mount_supported   (1 if mount.cred-fuse accepts it [current format])
 *      - .expected_version_supported (1 if min_version=0 accepts it)
 * 3. Run: ctest -R test_envelope_inspect
 * ============================================================================
 */

struct header_generation_test_case {
    const char *name;
    uint64_t version;
    uint16_t rsa_ct_len;
    off_t payload_len;
    int expected_mount_supported;   /* 1 if mount.cred-fuse accepts it (current format only) */
    int expected_version_supported; /* 1 if supported across known versions (min_version=0) */
};

static const struct header_generation_test_case GENERATION_TESTS[] = {
    /* Generation 1: Legacy CRED_ENV v1 */
    {
        .name = "Generation 1 (v1, RSA-2048, 64-byte payload)",
        .version = CRED_ENV_VERSION_1,
        .rsa_ct_len = TPM2_RSA2048_KEY_BYTES,
        .payload_len = 64,
        .expected_mount_supported = 0,
        .expected_version_supported = 1,
    },
    {
        .name = "Generation 1 (v1, RSA-4096, 128-byte payload)",
        .version = CRED_ENV_VERSION_1,
        .rsa_ct_len = TPM2_RSA4096_KEY_BYTES,
        .payload_len = 128,
        .expected_mount_supported = 0,
        .expected_version_supported = 1,
    },

    /* Generation 2: Current CRED_ENV v2 */
    {
        .name = "Generation 2 (v2, RSA-2048, 1-byte payload [minimum])",
        .version = CRED_ENV_VERSION_2,
        .rsa_ct_len = TPM2_RSA2048_KEY_BYTES,
        .payload_len = 1,
        .expected_mount_supported = 1,
        .expected_version_supported = 1,
    },
    {
        .name = "Generation 2 (v2, RSA-2048, 42-byte payload)",
        .version = CRED_ENV_VERSION_2,
        .rsa_ct_len = TPM2_RSA2048_KEY_BYTES,
        .payload_len = 42,
        .expected_mount_supported = 1,
        .expected_version_supported = 1,
    },
    {
        .name = "Generation 2 (v2, RSA-4096, 1024-byte payload)",
        .version = CRED_ENV_VERSION_2,
        .rsa_ct_len = TPM2_RSA4096_KEY_BYTES,
        .payload_len = 1024,
        .expected_mount_supported = 1,
        .expected_version_supported = 1,
    },
    {
        .name = "Generation 2 (v2, RSA-2048, 65536-byte payload [max limit])",
        .version = CRED_ENV_VERSION_2,
        .rsa_ct_len = TPM2_RSA2048_KEY_BYTES,
        .payload_len = 65536,
        .expected_mount_supported = 1,
        .expected_version_supported = 1,
    },

    /* Generation 3: Future unreleased format */
    {
        .name = "Generation 3 (v3, future unreleased format)",
        .version = 3,
        .rsa_ct_len = TPM2_RSA2048_KEY_BYTES,
        .payload_len = 100,
        .expected_mount_supported = 0,
        .expected_version_supported = 0,
    },
    {
        .name = "Generation 999 (wildly invalid future version)",
        .version = 999,
        .rsa_ct_len = TPM2_RSA2048_KEY_BYTES,
        .payload_len = 100,
        .expected_mount_supported = 0,
        .expected_version_supported = 0,
    },
};

static const size_t NUM_GENERATION_TESTS = sizeof(GENERATION_TESTS) / sizeof(GENERATION_TESTS[0]);

static inline off_t get_v1_overhead(uint16_t rsa_ct_len) {
    size_t payload_meta_sz = (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) ?
                             sizeof(struct cred_env_v1_rsa2048) :
                             sizeof(struct cred_env_v1_rsa4096);
    return (off_t)(sizeof(struct cred_env_commonhdr) + sizeof(uint16_t) + payload_meta_sz);
}

static void init_mock_hdr(struct cred_env_hdr *hdr, const char *magic, uint64_t version, uint16_t rsa_ct_len) {
    memset(hdr, 0, sizeof(*hdr));
    memcpy(hdr->common.magic, magic, CRED_ENV_MAGIC_LEN);
    hdr->common.version = htobe64(version);
    hdr->v1.rsa_ct_len = htobe16(rsa_ct_len);
}

/* Test 1: All generations via strict mount and version-range interfaces */
static void test_all_generations(void) {
    printf("[1] Testing All Envelope Generations (v1, v2, future)...\n");

    for (size_t i = 0; i < NUM_GENERATION_TESTS; i++) {
        const struct header_generation_test_case *tc = &GENERATION_TESTS[i];
        struct cred_env_hdr hdr;
        init_mock_hdr(&hdr, CRED_ENV_MAGIC, tc->version, tc->rsa_ct_len);

        off_t overhead = get_v1_overhead(tc->rsa_ct_len);
        off_t raw_file_size = overhead + tc->payload_len;

        /* (A) Strict mount inspection (CRED_ENV_CUR_VERSION only) */
        ssize_t mount_res = envelope_inspect_header(&hdr, sizeof(hdr), raw_file_size, 65536);
        if (tc->expected_mount_supported) {
            assert(mount_res == tc->payload_len);
        } else {
            assert(mount_res == -EPROTONOSUPPORT);
        }

        /* (B) Version-aware inspection (min_version=0: all supported versions) */
        struct env_data ed = {0};
        ssize_t ver_res = envelope_inspect_header_version(&hdr, sizeof(hdr), raw_file_size, 65536, 0, &ed);
        if (tc->expected_version_supported) {
            assert(ver_res == tc->payload_len);
            assert(ed.version == tc->version);
            assert(ed.plaintext_len == (size_t)tc->payload_len);
        } else {
            assert(ver_res == -EPROTONOSUPPORT);
        }

        printf("  [PASS] %s\n", tc->name);
    }
}

/* Test 2: In-memory pointer extraction for full envelopes */
static void test_full_envelope_pointer_extraction(void) {
    printf("[2] Testing Typed Pointer Extraction for Full Envelopes...\n");

    uint8_t buffer[1024];
    memset(buffer, 0xAA, sizeof(buffer));

    struct cred_env_hdr *hdr = (struct cred_env_hdr *)buffer;
    init_mock_hdr(hdr, CRED_ENV_MAGIC, CRED_ENV_VERSION_2, TPM2_RSA2048_KEY_BYTES);

    /* Fill marker bytes */
    hdr->v2.rsa2048.rsa_ct[0] = 0x11;
    hdr->v2.rsa2048.iv[0]     = 0x22;
    hdr->v2.rsa2048.tag[0]    = 0x33;
    buffer[302]               = 0x44; /* first byte of ciphertext */

    struct env_data ed = {0};
    ssize_t res = inspect_envelope_v2(hdr, sizeof(buffer), sizeof(buffer), 65536, &ed);
    assert(res == (ssize_t)(sizeof(buffer) - 302));
    assert(ed.version == CRED_ENV_VERSION_2);
    assert(ed.v2.rsa_ct != NULL && ed.v2.rsa_ct[0] == 0x11);
    assert(ed.v2.iv != NULL && ed.v2.iv[0] == 0x22);
    assert(ed.v2.tag != NULL && ed.v2.tag[0] == 0x33);
    assert(ed.v2.ciphertext != NULL && ed.v2.ciphertext[0] == 0x44);

    printf("  [PASS] Envelope fields and payload pointers correctly resolved\n");
}

/* Test 3: Boundary conditions and corruptions */
static void test_generation_corruptions(void) {
    printf("[3] Testing Header Corruptions and Boundary Conditions Across Generations...\n");

    static const uint64_t SUPPORTED_VERSIONS[] = { CRED_ENV_VERSION_1, CRED_ENV_VERSION_2 };
    size_t num_versions = sizeof(SUPPORTED_VERSIONS) / sizeof(SUPPORTED_VERSIONS[0]);

    for (size_t i = 0; i < num_versions; i++) {
        uint64_t ver = SUPPORTED_VERSIONS[i];
        struct cred_env_hdr hdr;

        /* 1. Invalid Magic */
        init_mock_hdr(&hdr, "NOT_CRED", ver, TPM2_RSA2048_KEY_BYTES);
        ssize_t res = envelope_inspect_header_version(&hdr, sizeof(hdr), 500, 65536, 0, NULL);
        assert(res == -EBADMSG);

        /* 2. Truncated header buffer */
        init_mock_hdr(&hdr, CRED_ENV_MAGIC, ver, TPM2_RSA2048_KEY_BYTES);
        res = envelope_inspect_header_version(&hdr, sizeof(struct cred_env_commonhdr) - 1, 500, 65536, 0, NULL);
        assert(res == -EINVAL);

        /* 3. Unsupported RSA key lengths */
        static const uint16_t BAD_RSA_LENS[] = { 0, 128, 384, 1024, 2047, 4097 };
        for (size_t k = 0; k < sizeof(BAD_RSA_LENS) / sizeof(BAD_RSA_LENS[0]); k++) {
            init_mock_hdr(&hdr, CRED_ENV_MAGIC, ver, BAD_RSA_LENS[k]);
            res = envelope_inspect_header_version(&hdr, sizeof(hdr), 1000, 65536, 0, NULL);
            assert(res == -EBADMSG);
        }

        /* 4. Zero payload boundary (raw_size == overhead) */
        init_mock_hdr(&hdr, CRED_ENV_MAGIC, ver, TPM2_RSA2048_KEY_BYTES);
        off_t overhead = get_v1_overhead(TPM2_RSA2048_KEY_BYTES);
        res = envelope_inspect_header_version(&hdr, sizeof(hdr), overhead, 65536, 0, NULL);
        assert(res == -EBADMSG);

        /* 5. Undersized file (raw_size < overhead) */
        res = envelope_inspect_header_version(&hdr, sizeof(hdr), overhead - 1, 65536, 0, NULL);
        assert(res == -EBADMSG);

        /* 6. Oversized payload (raw_size - overhead > max_size) */
        res = envelope_inspect_header_version(&hdr, sizeof(hdr), overhead + 65537, 65536, 0, NULL);
        assert(res == -EFBIG);

        printf("  [PASS] Corruptions correctly rejected for Version %llu\n", (unsigned long long)ver);
    }
}

/* Test 4: File Descriptor Inspection via envelope_inspect_file and envelope_inspect_file_version */
static void test_file_descriptor_inspection(void) {
    printf("[4] Testing File Descriptor Inspection Across Generations...\n");

    char tmp_path[] = "/tmp/test_cred_env_fd_XXXXXX";
    int fd = mkstemp(tmp_path);
    assert(fd >= 0);
    unlink(tmp_path);

    /* Short file (< sizeof(struct cred_env_commonhdr) bytes) */
    assert(write(fd, "SHORT_DATA", 10) == 10);
    ssize_t res = envelope_inspect_file(fd, 10, 65536);
    assert(res == -ENOENT);

    /* Test Legacy v1 file via file descriptor */
    lseek(fd, 0, SEEK_SET);
    struct cred_env_hdr hdr_v1;
    init_mock_hdr(&hdr_v1, CRED_ENV_MAGIC, CRED_ENV_VERSION_1, TPM2_RSA2048_KEY_BYTES);
    size_t min_hdr_v1 = sizeof(struct cred_env_commonhdr) + sizeof(uint16_t);
    assert(write(fd, &hdr_v1, min_hdr_v1) == (ssize_t)min_hdr_v1);

    off_t raw_v1_size = get_v1_overhead(TPM2_RSA2048_KEY_BYTES) + 33;
    /* Strict mount inspection must reject legacy v1 */
    res = envelope_inspect_file(fd, raw_v1_size, 65536);
    assert(res == -EPROTONOSUPPORT);

    /* Version-aware inspection (min_version=0) must accept v1 and output version 1 */
    struct env_data ed = {0};
    res = envelope_inspect_file_version(fd, raw_v1_size, 65536, 0, &ed);
    assert(res == 33);
    assert(ed.version == CRED_ENV_VERSION_1);
    printf("  [PASS] Legacy v1 file descriptor inspection handled correctly\n");

    /* Test Current v2 file via file descriptor */
    lseek(fd, 0, SEEK_SET);
    struct cred_env_hdr hdr_v2;
    init_mock_hdr(&hdr_v2, CRED_ENV_MAGIC, CRED_ENV_CUR_VERSION, TPM2_RSA4096_KEY_BYTES);
    size_t min_hdr_v2 = sizeof(struct cred_env_commonhdr) + sizeof(uint16_t);
    assert(write(fd, &hdr_v2, min_hdr_v2) == (ssize_t)min_hdr_v2);

    off_t raw_v2_size = get_v1_overhead(TPM2_RSA4096_KEY_BYTES) + 77;
    res = envelope_inspect_file(fd, raw_v2_size, 65536);
    assert(res == 77);

    memset(&ed, 0, sizeof(ed));
    res = envelope_inspect_file_version(fd, raw_v2_size, 65536, 0, &ed);
    assert(res == 77);
    assert(ed.version == CRED_ENV_CUR_VERSION);
    printf("  [PASS] Current v2 file descriptor inspection handled correctly\n");

    close(fd);
}

int main(void) {
    printf("====================================================\n");
    printf("  CRED_ENV Envelope Header Multi-Generation Tests\n");
    printf("====================================================\n");

    test_all_generations();
    test_full_envelope_pointer_extraction();
    test_generation_corruptions();
    test_file_descriptor_inspection();

    printf("\nAll generation and envelope inspection tests passed successfully!\n");
    return 0;
}
