# impl/jasmin/Makefile — build and test the Jasmin XMSS implementation

JASMINC  := jasminc
JFLAGS   := -arch x86-64
CC       := gcc
CFLAGS   := -no-pie

# Every .jinc file — conservative dep tracking (jasminc has no -MMD)
ALL_JINC := $(wildcard src/*.jinc src/**/*.jinc)

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

# Prevent Make from deleting .s files as intermediates
.PRECIOUS: $(ASM) $(API_ASM)

JASMIN_CT := jasmin-ct

.PHONY: all test test-api test-api-slow ct clean

all: $(TESTS) $(API_TESTS)

# Default test target: unit tests + fast API tests
test: $(TESTS) $(API_TESTS_FAST)
	@for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done
	@for t in $(API_TESTS_FAST); do \
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

clean:
	rm -f $(ASM) $(TESTS) $(API_ASM) $(API_TESTS)
