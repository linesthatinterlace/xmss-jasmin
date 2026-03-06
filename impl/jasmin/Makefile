# impl/jasmin/Makefile — build and test the Jasmin XMSS implementation
#
# All generated files (.s assemblies, test binaries) go in build/.
# Source directories (src/, test/, api/) stay clean.

JASMINC  := jasminc
JFLAGS   := -arch x86-64 -set0
CC       := gcc
CFLAGS   := -no-pie
BUILD    := build

# Every .jinc file — conservative dep tracking (jasminc has no -MMD)
ALL_JINC := $(wildcard src/*.jinc src/**/*.jinc)

# C implementation — used by KAT tests (shake_local) and interop tests (libxmss.a)
C_IMPL       := ../c
C_LIB        := $(C_IMPL)/build/libxmss.a
SHAKE_LOCAL_C := $(C_IMPL)/src/hash/shake_local.c
SHAKE_LOCAL_H := $(C_IMPL)/src/hash/shake_local.h

# Unit test names (without build/ prefix — used to derive source and output paths)
UNIT_TESTS := test_address test_utils test_sha256 \
              test_wots test_ltree test_treehash test_bds \
              test_xmss test_xmssmt

# Unit test jazz source files (for CT checks)
JAZZ_FILES := $(addprefix test/,$(addsuffix .jazz,$(UNIT_TESTS)))

# Production API names
API_NAMES := xmss_sha2_10_256 xmss_sha2_16_256 xmss_sha2_20_256 \
             xmssmt_sha2_20_2_256 xmssmt_sha2_20_4_256

API_JAZZ_FILES := $(addprefix api/,$(addsuffix .jazz,$(API_NAMES)))

# API test names split by speed
API_TESTS_FAST := test_api_xmss_sha2_10_256 \
                  test_api_xmssmt_sha2_20_2_256 \
                  test_api_xmssmt_sha2_20_4_256
API_TESTS_SLOW := test_api_xmss_sha2_16_256 \
                  test_api_xmss_sha2_20_256

# KAT / interop test names
KAT_TESTS          := test_kat_xmss_sha2_10_256 test_kat_xmssmt_sha2_20_2_256
INTEROP_TESTS      := test_interop_xmss_sha2_10_256 test_interop_xmssmt_sha2_20_2_256
INTEROP_DEEP_TESTS := test_interop_deep_xmss_sha2_10_256

# All test names (for the default build target)
ALL_TEST_NAMES := $(UNIT_TESTS) $(API_TESTS_FAST) $(API_TESTS_SLOW) \
                  $(KAT_TESTS) $(INTEROP_TESTS) $(INTEROP_DEEP_TESTS)

# All build outputs
UNIT_ASM    := $(addprefix $(BUILD)/test/,$(addsuffix .s,$(UNIT_TESTS)))
UNIT_BINS   := $(addprefix $(BUILD)/test/,$(UNIT_TESTS))
API_ASM     := $(addprefix $(BUILD)/api/,$(addsuffix .s,$(API_NAMES)))
ALL_BINS    := $(addprefix $(BUILD)/test/,$(ALL_TEST_NAMES))

JASMIN_CT := jasmin-ct

.PHONY: all test test-api test-api-slow test-kat test-interop test-interop-deep ct clean help

all: $(ALL_BINS)

# --- Directory creation ---
$(BUILD)/test $(BUILD)/api:
	mkdir -p $@

# --- Jasmin compilation: .jazz → .s ---

$(BUILD)/test/%.s: test/%.jazz $(ALL_JINC) | $(BUILD)/test
	$(JASMINC) $(JFLAGS) $< -o $@

$(BUILD)/api/%.s: api/%.jazz $(ALL_JINC) | $(BUILD)/api
	$(JASMINC) $(JFLAGS) $< -o $@

# --- Unit test binaries: .s + .c → binary ---

$(BUILD)/test/test_%: test/test_%.c $(BUILD)/test/test_%.s | $(BUILD)/test
	$(CC) -o $@ $^ $(CFLAGS)

# --- API test binaries: C test + API assembly ---

$(BUILD)/test/test_api_xmss_sha2_10_256: test/test_api_xmss_sha2_10_256.c $(BUILD)/api/xmss_sha2_10_256.s | $(BUILD)/test
	$(CC) -o $@ $^ $(CFLAGS)

$(BUILD)/test/test_api_xmss_sha2_16_256: test/test_api_xmss_sha2_16_256.c $(BUILD)/api/xmss_sha2_16_256.s | $(BUILD)/test
	$(CC) -o $@ $^ $(CFLAGS)

$(BUILD)/test/test_api_xmss_sha2_20_256: test/test_api_xmss_sha2_20_256.c $(BUILD)/api/xmss_sha2_20_256.s | $(BUILD)/test
	$(CC) -o $@ $^ $(CFLAGS)

$(BUILD)/test/test_api_xmssmt_sha2_20_2_256: test/test_api_xmssmt_sha2_20_2_256.c $(BUILD)/api/xmssmt_sha2_20_2_256.s | $(BUILD)/test
	$(CC) -o $@ $^ $(CFLAGS)

$(BUILD)/test/test_api_xmssmt_sha2_20_4_256: test/test_api_xmssmt_sha2_20_4_256.c $(BUILD)/api/xmssmt_sha2_20_4_256.s | $(BUILD)/test
	$(CC) -o $@ $^ $(CFLAGS)

# --- C library (for interop tests) ---

$(C_LIB):
	$(MAKE) -C $(C_IMPL)

# --- KAT tests: C test + API assembly + shake_local.c ---

$(BUILD)/test/test_kat_xmss_sha2_10_256: test/test_kat_xmss_sha2_10_256.c $(BUILD)/api/xmss_sha2_10_256.s $(SHAKE_LOCAL_C) $(SHAKE_LOCAL_H) | $(BUILD)/test
	$(CC) -o $@ test/test_kat_xmss_sha2_10_256.c $(BUILD)/api/xmss_sha2_10_256.s $(SHAKE_LOCAL_C) -I$(C_IMPL)/src/hash $(CFLAGS)

$(BUILD)/test/test_kat_xmssmt_sha2_20_2_256: test/test_kat_xmssmt_sha2_20_2_256.c $(BUILD)/api/xmssmt_sha2_20_2_256.s $(SHAKE_LOCAL_C) $(SHAKE_LOCAL_H) | $(BUILD)/test
	$(CC) -o $@ test/test_kat_xmssmt_sha2_20_2_256.c $(BUILD)/api/xmssmt_sha2_20_2_256.s $(SHAKE_LOCAL_C) -I$(C_IMPL)/src/hash $(CFLAGS)

# --- Interop tests: C test + API assembly + libxmss.a ---

$(BUILD)/test/test_interop_xmss_sha2_10_256: test/test_interop_xmss_sha2_10_256.c $(BUILD)/api/xmss_sha2_10_256.s $(C_LIB) | $(BUILD)/test
	$(CC) -o $@ test/test_interop_xmss_sha2_10_256.c $(BUILD)/api/xmss_sha2_10_256.s $(C_LIB) -I$(C_IMPL)/include $(CFLAGS)

$(BUILD)/test/test_interop_xmssmt_sha2_20_2_256: test/test_interop_xmssmt_sha2_20_2_256.c $(BUILD)/api/xmssmt_sha2_20_2_256.s $(C_LIB) | $(BUILD)/test
	$(CC) -o $@ test/test_interop_xmssmt_sha2_20_2_256.c $(BUILD)/api/xmssmt_sha2_20_2_256.s $(C_LIB) -I$(C_IMPL)/include $(CFLAGS)

$(BUILD)/test/test_interop_deep_xmss_sha2_10_256: test/test_interop_deep_xmss_sha2_10_256.c $(BUILD)/api/xmss_sha2_10_256.s $(C_LIB) | $(BUILD)/test
	$(CC) -o $@ test/test_interop_deep_xmss_sha2_10_256.c $(BUILD)/api/xmss_sha2_10_256.s $(C_LIB) -I$(C_IMPL)/include $(CFLAGS)

# --- Test runners ---

# Helper to run a list of test binaries
define run_tests
	@for t in $1; do \
		echo "=== $$t ==="; \
		./$(BUILD)/test/$$t || exit 1; \
	done
endef

test: $(ALL_BINS)
	$(call run_tests,$(UNIT_TESTS))
	$(call run_tests,$(API_TESTS_FAST))
	$(call run_tests,$(KAT_TESTS))
	$(call run_tests,$(INTEROP_TESTS))

test-api: $(addprefix $(BUILD)/test/,$(API_TESTS_FAST))
	$(call run_tests,$(API_TESTS_FAST))

test-api-slow: $(addprefix $(BUILD)/test/,$(API_TESTS_SLOW))
	$(call run_tests,$(API_TESTS_SLOW))

test-kat: $(addprefix $(BUILD)/test/,$(KAT_TESTS))
	$(call run_tests,$(KAT_TESTS))

test-interop: $(addprefix $(BUILD)/test/,$(INTEROP_TESTS))
	$(call run_tests,$(INTEROP_TESTS))

test-interop-deep: $(addprefix $(BUILD)/test/,$(INTEROP_DEEP_TESTS))
	$(call run_tests,$(INTEROP_DEEP_TESTS))

# CT checks run on source .jazz files (not built outputs)
ct:
	@for f in $(JAZZ_FILES) $(API_JAZZ_FILES); do \
		echo -n "$$f: "; \
		$(JASMIN_CT) -I Jasmin=. $$f && echo "PASS" || exit 1; \
	done
	@echo "All CT checks passed."

clean:
	rm -rf $(BUILD)

help:
	@echo "Available targets:"
	@echo "  make               Build all test binaries (into build/)"
	@echo "  make test          Unit + fast API + KAT + interop tests"
	@echo "  make test-api      Fast API tests only"
	@echo "  make test-api-slow Slow API tests (h=16, h=20)"
	@echo "  make test-kat      KAT cross-validation tests"
	@echo "  make test-interop  Shallow interop tests"
	@echo "  make test-interop-deep  Deep interop (64 sigs + BDS state comparison)"
	@echo "  make ct            Constant-time checks (all .jazz files)"
	@echo "  make clean         Remove build/"
