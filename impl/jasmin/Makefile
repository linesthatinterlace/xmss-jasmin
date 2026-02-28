# impl/jasmin/Makefile — build and test the Jasmin XMSS implementation

JASMINC  := jasminc
JFLAGS   := -arch x86-64
CC       := gcc
CFLAGS   := -no-pie

# Every .jinc file — conservative dep tracking (jasminc has no -MMD)
ALL_JINC := $(wildcard src/*.jinc src/**/*.jinc)

# Tests with both .jazz and .c (i.e. buildable)
TESTS := test/test_address test/test_utils test/test_sha256 \
         test/test_wots test/test_ltree test/test_treehash test/test_bds \
         test/test_xmss test/test_xmssmt

JAZZ_FILES := $(addsuffix .jazz,$(TESTS))

ASM := $(addsuffix .s,$(TESTS))

# Prevent Make from deleting .s files as intermediates
.PRECIOUS: $(ASM)

JASMIN_CT := jasmin-ct

.PHONY: all test ct clean

all: $(TESTS)

test: $(TESTS)
	@for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done

ct:
	@for f in $(JAZZ_FILES); do \
		echo -n "$$f: "; \
		$(JASMIN_CT) -I Jasmin=. $$f && echo "PASS" || exit 1; \
	done
	@echo "All CT checks passed."

# .jazz → .s (depends on all .jinc files)
test/%.s: test/%.jazz $(ALL_JINC)
	$(JASMINC) $(JFLAGS) $< -o $@

# .s + .c → binary
test/%: test/%.c test/%.s
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(ASM) $(TESTS)
