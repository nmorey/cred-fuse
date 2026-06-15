cmake_minimum_required(VERSION 3.15)
project(cred-fuse C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -Werror=format-security -fPIE")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now,-z,noexecstack")

# Require FUSE 3
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

# OpenSSL
find_package(OpenSSL REQUIRED)

# TSS2 Requirements (libtss2-esys, libtss2-rc, libtss2-tctildr)
pkg_check_modules(TSS2 REQUIRED tss2-esys tss2-rc tss2-tctildr)

add_executable(mount.cred-fuse main.c decryption.c inode.c path.c)

target_include_directories(mount.cred-fuse PRIVATE
    ${FUSE3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${TSS2_INCLUDE_DIRS}
)

target_link_libraries(mount.cred-fuse PRIVATE
    ${FUSE3_LIBRARIES}
    OpenSSL::Crypto
    ${TSS2_LIBRARIES}
)

install(TARGETS mount.cred-fuse DESTINATION sbin)

enable_testing()

add_test(NAME test_setup COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_setup.sh ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(test_setup PROPERTIES FIXTURES_SETUP tpm_fuse_fixture)

add_test(NAME test_cleanup COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cleanup.sh ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(test_cleanup PROPERTIES FIXTURES_CLEANUP tpm_fuse_fixture)

set(subtests
    test_ro_option
    test_valid
    test_aes_gcm
    test_permissions
    test_missing_size
    test_size_boundaries
    test_readdir_many
    test_dynamic_file
    test_max_file_size
    test_max_open_files
    test_inode_eviction
    test_tcti_validation
)

foreach(subtest ${subtests})
    add_test(NAME ${subtest} COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/${subtest}.sh $<TARGET_FILE:mount.cred-fuse> ${CMAKE_CURRENT_BINARY_DIR})
    set_tests_properties(${subtest} PROPERTIES
        FIXTURES_REQUIRED tpm_fuse_fixture
        RUN_SERIAL TRUE
    )
endforeach()
