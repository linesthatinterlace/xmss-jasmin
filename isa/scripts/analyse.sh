#!/usr/bin/env bash
# isa/scripts/analyse.sh
#
# Profile which RISC-V ISA extensions are used by the XMSS C implementation.
#
# Methodology:
#   - Analyses libxmss.a (or specified .a/.o files), NOT test binaries.
#     This isolates pure XMSS code from libc/test-harness noise.
#   - Classifies mnemonics using a lookup table generated from the
#     riscv-opcodes submodule (authoritative source, not hand-written rules).
#   - Detects C (compressed) encoding from raw instruction byte width
#     (2 bytes = 16-bit compressed, 4 bytes = 32-bit standard), not from
#     mnemonic prefixes (which objdump doesn't emit for compressed aliases).
#   - Produces per-object-file breakdown so you can see WHERE each
#     extension is used (e.g. hash.c.o vs wots.c.o vs bds.c.o).
#
# Usage:
#   ./analyse.sh [INPUT] [REPORT]
#
#   INPUT defaults to impl/c/build-rv/libxmss.a relative to the repo root.
#   Can also be a .o file or a directory of .o files.
#
#   REPORT defaults to isa/reports/xmss_rv64_isa_profile.md. Use a different
#   path to avoid clobbering an existing report (e.g. the reference analysis).
#
# Prerequisites:
#   - riscv64-linux-gnu-objdump  (apt install binutils-riscv64-linux-gnu)
#   - Lookup table: run gen_lookup.sh first, or it will be auto-generated.
#
# Output: isa/reports/xmss_rv64_isa_profile.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/../reports"
LOOKUP="${SCRIPT_DIR}/mnemonic_extensions.tsv"
OBJDUMP="riscv64-linux-gnu-objdump"

INPUT="${1:-${REPO_ROOT}/impl/c/build-rv/libxmss.a}"
REPORT="${2:-${REPORTS_DIR}/xmss_rv64_isa_profile.md}"

# For display in the report, use a relative path if inside the repo
INPUT_DISPLAY="${INPUT#${REPO_ROOT}/}"

die() { echo "ERROR: $*" >&2; exit 1; }

# Check dependencies
command -v "${OBJDUMP}" >/dev/null 2>&1 \
    || die "${OBJDUMP} not found. Install: sudo apt install binutils-riscv64-linux-gnu"

# Auto-generate lookup table if missing
if [[ ! -f "${LOOKUP}" ]]; then
    echo "Lookup table not found; generating..." >&2
    "${SCRIPT_DIR}/gen_lookup.sh" "${LOOKUP}" \
        || die "Failed to generate lookup table"
fi

[[ -e "${INPUT}" ]] || die "Input not found: ${INPUT}"

TMPDIR_BASE="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_BASE}"' EXIT

mkdir -p "${REPORTS_DIR}"

# ---------------------------------------------------------------------------
# Phase 1: Disassemble and parse
#
# For each object file inside the archive (or the single .o), produce a TSV:
#   mnemonic<TAB>encoding<TAB>count
# where encoding is "C" (16-bit) or "std" (32-bit).
# ---------------------------------------------------------------------------

# Disassemble the input, producing per-object-file sections.
# objdump on a .a shows headers like "file.c.o:     file format elf64-littleriscv"
# before each object's disassembly.
DISASM="${TMPDIR_BASE}/disasm.txt"
"${OBJDUMP}" -d "${INPUT}" > "${DISASM}" 2>/dev/null

# Parse the disassembly into per-object TSV files.
# Each instruction line looks like:
#   <spaces><hex_addr>:<spaces><raw_hex><spaces><mnemonic><spaces><operands>
# Raw hex: 4 chars = 2 bytes (C encoding), 8 chars = 4 bytes (32-bit).
#
# We use awk to split by object file and extract mnemonic + byte width.

awk '
# Detect object file boundary
/^[^ ].*:     file format/ {
    # Extract the object filename (first field, strip trailing colon)
    split($0, parts, ":")
    current_obj = parts[1]
    next
}

# Match instruction lines: leading whitespace, hex address, colon
/^[[:space:]]+[0-9a-f]+:/ {
    # Skip lines without enough fields
    if (NF < 3) next

    # The raw hex bytes are in field 2 (after the "addr:" field).
    # But objdump formatting can vary. The pattern is:
    #   addr: <hex> <mnemonic> <operands...>
    # where <hex> is a single hex word (no spaces — little-endian merged).

    # Find the raw hex field: first field after the "addr:" that is pure hex
    raw = ""
    mnem = ""
    for (i = 2; i <= NF; i++) {
        if ($i ~ /^[0-9a-f]+$/ && raw == "") {
            raw = $i
        } else if (raw != "" && mnem == "") {
            mnem = $i
            break
        }
    }

    if (raw == "" || mnem == "") next

    # Determine encoding width from raw hex length
    # 4 hex chars = 2 bytes = C encoding
    # 8 hex chars = 4 bytes = standard 32-bit
    len = length(raw)
    if (len <= 4) {
        enc = "C"
    } else {
        enc = "std"
    }

    key = current_obj "\t" mnem "\t" enc
    count[key]++
}

END {
    for (k in count) {
        print k "\t" count[k]
    }
}
' "${DISASM}" | sort > "${TMPDIR_BASE}/parsed.tsv"

# ---------------------------------------------------------------------------
# Phase 2: Look up extensions from the authoritative table
# ---------------------------------------------------------------------------

# Load lookup table into an awk-friendly format
# Output: obj<TAB>mnemonic<TAB>encoding<TAB>count<TAB>extension
awk -F'\t' -v LOOKUP="${LOOKUP}" '
BEGIN {
    # Load lookup table
    while ((getline line < LOOKUP) > 0) {
        split(line, parts, "\t")
        ext[parts[1]] = parts[2]
    }
    close(LOOKUP)
}
{
    obj = $1; mnem = $2; enc = $3; cnt = $4
    e = (mnem in ext) ? ext[mnem] : "UNKNOWN"
    print obj "\t" mnem "\t" enc "\t" cnt "\t" e
}
' "${TMPDIR_BASE}/parsed.tsv" > "${TMPDIR_BASE}/classified.tsv"

# ---------------------------------------------------------------------------
# Phase 3: Generate report
# ---------------------------------------------------------------------------

# Gather toolchain version
OBJDUMP_VERSION="$("${OBJDUMP}" --version 2>/dev/null | head -1)"

# Count total instructions and C vs std
TOTAL_INSNS=$(awk -F'\t' '{s+=$4} END{print s+0}' "${TMPDIR_BASE}/classified.tsv")
C_INSNS=$(awk -F'\t' '$3=="C" {s+=$4} END{print s+0}' "${TMPDIR_BASE}/classified.tsv")
STD_INSNS=$(awk -F'\t' '$3=="std" {s+=$4} END{print s+0}' "${TMPDIR_BASE}/classified.tsv")

# Get list of object files
mapfile -t OBJ_FILES < <(awk -F'\t' '{print $1}' "${TMPDIR_BASE}/classified.tsv" | sort -u)

# Compute per-object totals
declare -A OBJ_TOTAL OBJ_C OBJ_UNIQUE
for obj in "${OBJ_FILES[@]}"; do
    OBJ_TOTAL["$obj"]=$(awk -F'\t' -v o="$obj" '$1==o {s+=$4} END{print s+0}' "${TMPDIR_BASE}/classified.tsv")
    OBJ_C["$obj"]=$(awk -F'\t' -v o="$obj" '$1==o && $3=="C" {s+=$4} END{print s+0}' "${TMPDIR_BASE}/classified.tsv")
    OBJ_UNIQUE["$obj"]=$(awk -F'\t' -v o="$obj" '$1==o {print $2}' "${TMPDIR_BASE}/classified.tsv" | sort -u | wc -l)
done

# Get list of semantic extensions found (excluding UNKNOWN)
mapfile -t EXTENSIONS < <(awk -F'\t' '$5!="UNKNOWN" {print $5}' "${TMPDIR_BASE}/classified.tsv" | sort -u)

# Extension totals
declare -A EXT_TOTAL EXT_UNIQUE
for ext in "${EXTENSIONS[@]}" UNKNOWN; do
    EXT_TOTAL["$ext"]=$(awk -F'\t' -v e="$ext" '$5==e {s+=$4} END{print s+0}' "${TMPDIR_BASE}/classified.tsv")
    EXT_UNIQUE["$ext"]=$(awk -F'\t' -v e="$ext" '$5==e {print $2}' "${TMPDIR_BASE}/classified.tsv" | sort -u | wc -l)
done

# Per-extension, per-object breakdown
# Format: ext -> "obj:count obj:count ..."
# Per-extension mnemonic detail
# Format: ext -> sorted list of "count mnemonic"

echo "Writing report to ${REPORT}..." >&2

{
# --- Header ---
cat <<HEADER
# XMSS RISC-V ISA Profile

Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Toolchain: \`${OBJDUMP_VERSION}\`
Input: \`${INPUT_DISPLAY}\`
Lookup source: \`third_party/riscv-opcodes/\` (generated by \`gen_lookup.sh\`)

## Methodology

This report analyses **\`libxmss.a\`** — the static library containing only
XMSS algorithm code (params, hash, WOTS, XMSS, XMSS-MT, BDS, utils).
Unlike test binaries, this excludes \`printf\`, \`malloc\`, stack guards,
and other libc/test-harness code that would pollute the ISA profile.

Mnemonic-to-extension classification uses an authoritative lookup table
generated from the \`riscv-opcodes\` submodule (the same database used by
the RISC-V toolchain). This avoids the hand-written classifier bugs of
the previous analysis (e.g. \`zext.h\` misclassified as I instead of Zbb).

C (compressed) encoding is detected from instruction byte width in the raw
objdump output: 2 bytes = 16-bit compressed, 4 bytes = 32-bit standard.
GNU objdump renders compressed instructions using uncompressed aliases
(\`sd\` not \`c.sd\`, \`li\` not \`c.li\`), so mnemonic-based C detection
would always report C=0.

HEADER

# --- Per-object summary ---
cat <<'TABLE_HDR'
## Per-object-file summary

| Object file | Total insns | Unique mnemonics | C-encoded | C % |
|-------------|-------------|------------------|-----------|-----|
TABLE_HDR

for obj in "${OBJ_FILES[@]}"; do
    total="${OBJ_TOTAL[$obj]}"
    c_cnt="${OBJ_C[$obj]}"
    uniq="${OBJ_UNIQUE[$obj]}"
    if [[ "$total" -gt 0 ]]; then
        pct=$(( c_cnt * 100 / total ))
    else
        pct=0
    fi
    printf '| `%s` | %d | %d | %d | %d%% |\n' "$obj" "$total" "$uniq" "$c_cnt" "$pct"
done

printf '\n**Total: %d instructions (%d unique mnemonics) across %d object files**\n\n' \
    "${TOTAL_INSNS}" \
    "$(awk -F'\t' '{print $2}' "${TMPDIR_BASE}/classified.tsv" | sort -u | wc -l)" \
    "${#OBJ_FILES[@]}"

# --- Extension summary ---
cat <<'EXT_HDR'

## Semantic extension summary

Instruction counts grouped by ISA extension (semantic, not encoding).
The "extension" is what the instruction DOES, regardless of whether it
was emitted in compressed (16-bit) or standard (32-bit) encoding.

| Extension | Refs | Unique mnemonics | Notes |
|-----------|------|------------------|-------|
EXT_HDR

# Define extension order and notes
ext_note() {
    case "$1" in
        I)        echo "Base integer (always required)" ;;
        M)        echo "Integer multiply/divide" ;;
        A)        echo "Atomics" ;;
        F)        echo "Single-precision float" ;;
        D)        echo "Double-precision float" ;;
        C)        echo "Compressed-only instructions" ;;
        Zba)      echo "Address generation (sh*add)" ;;
        Zbb)      echo "Bitmanip: rotate, clz, rev8, min/max" ;;
        Zbc)      echo "Carry-less multiply" ;;
        Zbs)      echo "Single-bit operations" ;;
        Zbkb)     echo "Bitmanip for crypto (pack, brev8)" ;;
        Zicsr)    echo "CSR access" ;;
        Zifencei) echo "Instruction-fetch fence" ;;
        UNKNOWN)  echo "Not in lookup table" ;;
        *)        echo "" ;;
    esac
}

# Preferred display order
for ext in I M A F D C Zba Zbb Zbc Zbs Zbkb Zicsr Zifencei; do
    refs="${EXT_TOTAL[$ext]:-0}"
    uniq="${EXT_UNIQUE[$ext]:-0}"
    [[ "$refs" -eq 0 ]] && continue
    printf '| **%s** | %d | %d | %s |\n' "$ext" "$refs" "$uniq" "$(ext_note "$ext")"
done

# Any extensions not in the preferred list
for ext in "${EXTENSIONS[@]}"; do
    case "$ext" in I|M|A|F|D|C|Zba|Zbb|Zbc|Zbs|Zbkb|Zicsr|Zifencei) continue ;; esac
    refs="${EXT_TOTAL[$ext]:-0}"
    uniq="${EXT_UNIQUE[$ext]:-0}"
    [[ "$refs" -eq 0 ]] && continue
    printf '| **%s** | %d | %d | %s |\n' "$ext" "$refs" "$uniq" "$(ext_note "$ext")"
done

# UNKNOWN last
if [[ "${EXT_TOTAL[UNKNOWN]:-0}" -gt 0 ]]; then
    printf '| **UNKNOWN** | %d | %d | %s |\n' \
        "${EXT_TOTAL[UNKNOWN]}" "${EXT_UNIQUE[UNKNOWN]}" "$(ext_note UNKNOWN)"
fi

echo ""

# --- Per-extension mnemonic detail ---
printf '## Per-extension mnemonic detail\n\n'

for ext in I M A F D C Zba Zbb Zbc Zbs Zbkb Zicsr Zifencei "${EXTENSIONS[@]}"; do
    refs="${EXT_TOTAL[$ext]:-0}"
    [[ "$refs" -eq 0 ]] && continue

    # Skip duplicates from the combined iteration
    if [[ -f "${TMPDIR_BASE}/printed_${ext}" ]]; then continue; fi
    touch "${TMPDIR_BASE}/printed_${ext}"

    printf '### %s\n\n' "$ext"
    printf '| Count | Mnemonic | Object files |\n'
    printf '|------:|----------|-------------|\n'

    # Aggregate mnemonic counts for this extension
    awk -F'\t' -v e="$ext" '$5==e {
        count[$2] += $4
        if (!($2 in objs)) objs[$2] = $1
        else if (index(objs[$2], $1) == 0) objs[$2] = objs[$2] ", " $1
    }
    END {
        for (m in count) print count[m] "\t" m "\t" objs[m]
    }' "${TMPDIR_BASE}/classified.tsv" | sort -rn -k1 | while IFS=$'\t' read -r cnt mnem objs; do
        printf '| %d | `%s` | %s |\n' "$cnt" "$mnem" "$objs"
    done

    echo ""
done

# --- UNKNOWN mnemonics ---
if [[ "${EXT_TOTAL[UNKNOWN]:-0}" -gt 0 ]]; then
    printf '### UNKNOWN\n\n'
    printf 'The following mnemonics were not found in the riscv-opcodes lookup table.\n'
    printf 'They may be objdump-specific pseudo-instructions or toolchain-specific\n'
    printf 'mnemonics. Investigate manually.\n\n'
    printf '| Count | Mnemonic | Object files |\n'
    printf '|------:|----------|-------------|\n'

    awk -F'\t' '$5=="UNKNOWN" {
        count[$2] += $4
        if (!($2 in objs)) objs[$2] = $1
        else if (index(objs[$2], $1) == 0) objs[$2] = objs[$2] ", " $1
    }
    END {
        for (m in count) print count[m] "\t" m "\t" objs[m]
    }' "${TMPDIR_BASE}/classified.tsv" | sort -rn -k1 | while IFS=$'\t' read -r cnt mnem objs; do
        printf '| %d | `%s` | %s |\n' "$cnt" "$mnem" "$objs"
    done

    echo ""
fi

# --- C encoding statistics ---
cat <<C_HDR

## Compressed (C) encoding statistics

The C extension provides 16-bit encodings for common instructions. The
assembler emits these automatically when targeting \`rv64gc\`. This is an
encoding optimisation (smaller code size) — it does not change semantics.

C_HDR

printf '| Metric | Value |\n'
printf '|--------|------:|\n'
printf '| Total instructions | %d |\n' "${TOTAL_INSNS}"
printf '| Standard (32-bit) | %d |\n' "${STD_INSNS}"
printf '| Compressed (16-bit) | %d |\n' "${C_INSNS}"
if [[ "${TOTAL_INSNS}" -gt 0 ]]; then
    printf '| C encoding ratio | %d%% |\n' "$(( C_INSNS * 100 / TOTAL_INSNS ))"
fi

echo ""

# Per-object C encoding
printf '### Per-object C encoding\n\n'
printf '| Object file | Total | C-encoded | C %% |\n'
printf '|-------------|------:|----------:|-----:|\n'

for obj in "${OBJ_FILES[@]}"; do
    total="${OBJ_TOTAL[$obj]}"
    c_cnt="${OBJ_C[$obj]}"
    if [[ "$total" -gt 0 ]]; then
        pct=$(( c_cnt * 100 / total ))
    else
        pct=0
    fi
    printf '| `%s` | %d | %d | %d%% |\n' "$obj" "$total" "$c_cnt" "$pct"
done

echo ""

# --- Per-object extension breakdown ---
printf '## Per-object extension breakdown\n\n'
printf 'Which extensions are used in each object file.\n\n'

for obj in "${OBJ_FILES[@]}"; do
    printf '### `%s`\n\n' "$obj"
    printf '| Extension | Refs | Mnemonics |\n'
    printf '|-----------|-----:|----------|\n'

    awk -F'\t' -v o="$obj" '$1==o {
        count[$5] += $4
        if (!($5 in mnems)) mnems[$5] = "`" $2 "`"
        else if (index(mnems[$5], $2) == 0) mnems[$5] = mnems[$5] ", `" $2 "`"
    }
    END {
        for (e in count) print count[e] "\t" e "\t" mnems[e]
    }' "${TMPDIR_BASE}/classified.tsv" | sort -rn -k1 | while IFS=$'\t' read -r cnt ext mnems; do
        printf '| **%s** | %d | %s |\n' "$ext" "$cnt" "$mnems"
    done

    echo ""
done

# --- Jasmin implications ---
cat <<'JASMIN'

## Implications for the Jasmin port

### Semantic extensions required

Based on the analysis of `libxmss.a`:

1. **I (base integer)**: Always required. Dominates the instruction mix
   (loads, stores, branches, arithmetic, shifts).

2. **M (multiply/divide)**: Used by the C compiler for address arithmetic
   and parameter derivation (`mulw`, `mul`, `divuw`). The Jasmin port
   must target at least **RV64IM**.

3. **A (atomics)**: Not expected in `libxmss.a` (XMSS is single-threaded).
   If present, investigate — may be a compiler intrinsic.

4. **F/D (float)**: Should be absent. XMSS is integer-only. If present,
   it's a compiler quirk from `-march=rv64gc` enabling the float ABI.

5. **Zba/Zbb/Zbs (bitmanip)**: Not emitted by the compiler with `-march=rv64gc`
   (Zb* is not part of rv64gc). The Jasmin port can **explicitly use**
   Zbb instructions (`ror`, `rev8`, `clz`) in the hash layer for SHA-2/SHAKE
   optimisation — these would be hand-written, not compiler-generated.

### C encoding

The assembler handles C encoding automatically. No explicit action needed
in Jasmin source code. The C encoding ratio in `libxmss.a` shows that a
significant fraction of instructions have compressed forms, confirming that
`rv64gc` produces compact code.

### Recommended Jasmin target ISA

- **Minimum**: `rv64im` — base integer + multiply/divide
- **Standard**: `rv64gc` (= `rv64imafd_zicsr_zifencei_c`) — for
  compatibility with standard Linux toolchains
- **Optimised hash layer**: `rv64gc_zbb` — adds `ror`/`rev8` for SHA-2
  and byte-reversal without breaking rv64gc compatibility for non-hash code

JASMIN

} > "${REPORT}"

echo "Done. Report: ${REPORT}" >&2
echo "  ${TOTAL_INSNS} instructions across ${#OBJ_FILES[@]} object files" >&2
echo "  C encoding: ${C_INSNS}/${TOTAL_INSNS} ($(( C_INSNS * 100 / TOTAL_INSNS ))%)" >&2
echo "  Extensions found: ${EXTENSIONS[*]}" >&2
