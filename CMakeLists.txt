cmake_minimum_required(VERSION 3.15)
project(cred-fuse C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -g")

# Require FUSE 3
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

# OpenSSL
find_package(OpenSSL REQUIRED)

# TSS2 Requirements (libtss2-esys, libtss2-rc, libtss2-tctildr)
pkg_check_modules(TSS2 REQUIRED tss2-esys tss2-rc tss2-tctildr)

add_executable(cred-fuse main.c decryption.c)

target_include_directories(cred-fuse PRIVATE
    ${FUSE3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${TSS2_INCLUDE_DIRS}
)

target_link_libraries(cred-fuse PRIVATE
    ${FUSE3_LIBRARIES}
    OpenSSL::Crypto
    ${TSS2_LIBRARIES}
)

install(TARGETS cred-fuse DESTINATION sbin)

enable_testing()
add_test(NAME cred-fuse-tests COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_swtpm.sh $<TARGET_FILE:cred-fuse>)
