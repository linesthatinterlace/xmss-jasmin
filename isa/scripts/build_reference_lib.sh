#!/usr/bin/env bash
# isa/scripts/build_reference_lib.sh
#
# Cross-compile the upstream XMSS reference implementation
# (third_party/xmss-reference/) for RISC-V 64 and pack the object files
# into a static archive suitable for ISA profiling with analyse.sh.
#
# The reference's hash.c delegates SHA-256 and SHA-512 to OpenSSL via
# -lcrypto. Since we are producing an archive (not a linked binary), we
# do not need the OpenSSL runtime for RISC-V --- only the headers, which
# are architecture-independent. The resulting .a will therefore contain
# the fips202 SHAKE implementation but no SHA-2 internals (those live in
# libcrypto, which the reference links to at final-binary time).
#
# randombytes.c is excluded: it is an OS-boundary CSPRNG, not part of the
# XMSS algorithm. Including it would pollute the profile with syscall code.
#
# Usage:
#   ./build_reference_lib.sh [MARCH]
#
#   MARCH defaults to rv64gc. Pass rv64gc_zbb for the Zbb comparison build.
#
# Output:
#   isa/binaries/libxmss-ref-<march>.a

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REF_DIR="${REPO_ROOT}/third_party/xmss-reference"
BIN_DIR="${SCRIPT_DIR}/../binaries"

MARCH="${1:-rv64gc}"
CC="riscv64-linux-gnu-gcc"
AR="riscv64-linux-gnu-ar"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v "${CC}" >/dev/null 2>&1 || die "${CC} not found (apt install gcc-riscv64-linux-gnu)"
command -v "${AR}" >/dev/null 2>&1 || die "${AR} not found (apt install binutils-riscv64-linux-gnu)"
[[ -d "${REF_DIR}" ]] || die "${REF_DIR} not found (git submodule update --init)"
[[ -f "/usr/include/openssl/sha.h" ]] || die "OpenSSL headers missing (apt install libssl-dev)"

# Reference SOURCES_FAST = SOURCES with xmss_core.c replaced by xmss_core_fast.c.
# xmss_core_fast.c is the BDS variant (stateful, efficient signing) --- the
# apt comparison for algorithm-layer analysis.
SRCS=(
    params.c
    hash.c
    fips202.c
    hash_address.c
    wots.c
    xmss.c
    xmss_core_fast.c
    xmss_commons.c
    utils.c
)

mkdir -p "${BIN_DIR}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

CFLAGS=(
    "-march=${MARCH}"
    -mabi=lp64d
    -O3
    -Wall -Wextra -Wpedantic
    -I"${REF_DIR}"
    # Append host OpenSSL headers AFTER the cross toolchain's system includes
    # (-idirafter), so the cross riscv64 libc headers still take priority.
    # OpenSSL's *.h are effectively architecture-neutral for our header-only use
    # (we never link against libcrypto here).
    -idirafter /usr/include
    -idirafter /usr/include/x86_64-linux-gnu
)

echo "Cross-compiling xmss-reference with ${CC} -march=${MARCH}..." >&2
OBJS=()
for src in "${SRCS[@]}"; do
    obj="${WORK}/${src%.c}.o"
    "${CC}" "${CFLAGS[@]}" -c "${REF_DIR}/${src}" -o "${obj}" 2>&1 \
        | grep -v "warning:" || true
    OBJS+=("${obj}")
done

OUT="${BIN_DIR}/libxmss-ref-${MARCH}.a"
rm -f "${OUT}"
"${AR}" rcs "${OUT}" "${OBJS[@]}"

echo "Built ${OUT}" >&2
"${AR}" t "${OUT}" | sed 's/^/  /' >&2
