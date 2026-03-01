# impl/jasmin/Makefile — build and test the Jasmin XMSS implementation

JASMINC  := jasminc
JFLAGS   := -arch x86-64
CC       := gcc
CFLAGS   := -no-pie

# Every .jinc file — conservative dep tracking (jasminc has no -MMD)
ALL_JINC := $(wildcard src/*.jinc src/**/*.jinc)

# C implementation — used by KAT tests (shake_local) and interop tests (libxmss.a)
C_IMPL       := ../c
C_LIB        := $(C_IMPL)/build-rel/libxmss.a
SHAKE_LOCAL_C := $(C_IMPL)/src/hash/shake_local.c
SHAKE_LOCAL_H := $(C_IMPL)/src/hash/shake_local.h

# Unit tests (existing)
TESTS := test/test_address test/test_utils test/test_sha256 \
         test/test_wots test/test_ltree test/test_treehash test/test_bds \
         test/test_xmss test/test_xmssmt

JAZZ_FILES := $(addsuffix .jazz,$(TESTS))

ASM := $(addsuffix .s,$(TESTS))

# Production API .jazz files
API_JAZZ := api/xmss_sha2_10_256 api/xmss_sha2_16_256 api/xmss_sha2_20_256 \
            api/xmssmt_sha2_20_2_256

API_JAZZ_FILES := $(addsuffix .jazz,$(API_JAZZ))
API_ASM := $(addsuffix .s,$(API_JAZZ))

# API tests split by speed:
#   fast: h=10 XMSS + XMSS-MT 20/2 (keygen ~1s each, boundary ~30s)
#   slow: h=16 (~20s keygen) and h=20 (~4min keygen)
API_TESTS_FAST := test/test_api_xmss_sha2_10_256 \
                  test/test_api_xmssmt_sha2_20_2_256
API_TESTS_SLOW := test/test_api_xmss_sha2_16_256 \
                  test/test_api_xmss_sha2_20_256

API_TESTS := $(API_TESTS_FAST) $(API_TESTS_SLOW)

# KAT cross-validation tests (link Jasmin API .s + C shake_local.c)
KAT_TESTS := test/test_kat_xmss_sha2_10_256 \
              test/test_kat_xmssmt_sha2_20_2_256

# Cross-implementation interop tests (link Jasmin API .s + C libxmss.a)
INTEROP_TESTS := test/test_interop_xmss_sha2_10_256 \
                 test/test_interop_xmssmt_sha2_20_2_256

# Prevent Make from deleting .s files as intermediates
.PRECIOUS: $(ASM) $(API_ASM)

JASMIN_CT := jasmin-ct

.PHONY: all test test-api test-api-slow test-kat test-interop ct clean

all: $(TESTS) $(API_TESTS) $(KAT_TESTS) $(INTEROP_TESTS)

# Default test target: unit tests + fast API tests + KAT tests + interop tests
test: $(TESTS) $(API_TESTS_FAST) $(KAT_TESTS) $(INTEROP_TESTS)
	@for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done
	@for t in $(API_TESTS_FAST); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done
	@for t in $(KAT_TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done
	@for t in $(INTEROP_TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done

# KAT cross-validation tests only
test-kat: $(KAT_TESTS)
	@for t in $(KAT_TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done

# Fast API tests only
test-api: $(API_TESTS_FAST)
	@for t in $(API_TESTS_FAST); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done

# Slow API tests (h=16, h=20 — minutes per keygen)
test-api-slow: $(API_TESTS_SLOW)
	@for t in $(API_TESTS_SLOW); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done

ct:
	@for f in $(JAZZ_FILES) $(API_JAZZ_FILES); do \
		echo -n "$$f: "; \
		$(JASMIN_CT) -I Jasmin=. $$f && echo "PASS" || exit 1; \
	done
	@echo "All CT checks passed."

# .jazz → .s (unit tests)
test/%.s: test/%.jazz $(ALL_JINC)
	$(JASMINC) $(JFLAGS) $< -o $@

# .jazz → .s (production API)
api/%.s: api/%.jazz $(ALL_JINC)
	$(JASMINC) $(JFLAGS) $< -o $@

# .s + .c → binary (unit tests)
test/%: test/%.c test/%.s
	$(CC) -o $@ $^ $(CFLAGS)

# API test binaries: link C test against API assembly
# XMSS parameter sets
test/test_api_xmss_sha2_10_256: test/test_api_xmss_sha2_10_256.c api/xmss_sha2_10_256.s
	$(CC) -o $@ $^ $(CFLAGS)

test/test_api_xmss_sha2_16_256: test/test_api_xmss_sha2_16_256.c api/xmss_sha2_16_256.s
	$(CC) -o $@ $^ $(CFLAGS)

test/test_api_xmss_sha2_20_256: test/test_api_xmss_sha2_20_256.c api/xmss_sha2_20_256.s
	$(CC) -o $@ $^ $(CFLAGS)

# XMSS-MT parameter sets
test/test_api_xmssmt_sha2_20_2_256: test/test_api_xmssmt_sha2_20_2_256.c api/xmssmt_sha2_20_2_256.s
	$(CC) -o $@ $^ $(CFLAGS)

# Build C libxmss.a (for interop tests)
$(C_LIB):
	$(MAKE) -C $(C_IMPL)

# Cross-implementation interop tests: link C test + Jasmin API .s + libxmss.a
test/test_interop_xmss_sha2_10_256: test/test_interop_xmss_sha2_10_256.c api/xmss_sha2_10_256.s $(C_LIB)
	$(CC) -o $@ test/test_interop_xmss_sha2_10_256.c api/xmss_sha2_10_256.s $(C_LIB) -I$(C_IMPL)/include $(CFLAGS)

test/test_interop_xmssmt_sha2_20_2_256: test/test_interop_xmssmt_sha2_20_2_256.c api/xmssmt_sha2_20_2_256.s $(C_LIB)
	$(CC) -o $@ test/test_interop_xmssmt_sha2_20_2_256.c api/xmssmt_sha2_20_2_256.s $(C_LIB) -I$(C_IMPL)/include $(CFLAGS)

# Cross-implementation interop tests only
test-interop: $(INTEROP_TESTS)
	@for t in $(INTEROP_TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done

# KAT cross-validation tests: link C test + API assembly + shake_local.c
test/test_kat_xmss_sha2_10_256: test/test_kat_xmss_sha2_10_256.c api/xmss_sha2_10_256.s $(SHAKE_LOCAL_C) $(SHAKE_LOCAL_H)
	$(CC) -o $@ test/test_kat_xmss_sha2_10_256.c api/xmss_sha2_10_256.s $(SHAKE_LOCAL_C) -I$(C_IMPL)/src/hash $(CFLAGS)

test/test_kat_xmssmt_sha2_20_2_256: test/test_kat_xmssmt_sha2_20_2_256.c api/xmssmt_sha2_20_2_256.s $(SHAKE_LOCAL_C) $(SHAKE_LOCAL_H)
	$(CC) -o $@ test/test_kat_xmssmt_sha2_20_2_256.c api/xmssmt_sha2_20_2_256.s $(SHAKE_LOCAL_C) -I$(C_IMPL)/src/hash $(CFLAGS)

clean:
	rm -f $(ASM) $(TESTS) $(API_ASM) $(API_TESTS) $(KAT_TESTS) $(INTEROP_TESTS)
