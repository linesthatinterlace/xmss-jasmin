# impl/jasmin/Makefile — build and test the Jasmin XMSS implementation

JASMINC  := jasminc
JFLAGS   := -arch x86-64
CC       := gcc
CFLAGS   := -no-pie

# Every .jinc file — conservative dep tracking (jasminc has no -MMD)
ALL_JINC := $(wildcard src/*.jinc src/**/*.jinc)

# Tests with both .jazz and .c (i.e. buildable)
TESTS := test/test_address test/test_utils test/test_sha256 \
         test/test_wots test/test_ltree test/test_bds test/test_xmss

ASM := $(addsuffix .s,$(TESTS))

# Prevent Make from deleting .s files as intermediates
.PRECIOUS: $(ASM)

.PHONY: all test clean

all: $(TESTS)

test: $(TESTS)
	@for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || exit 1; \
	done

# .jazz → .s (depends on all .jinc files)
test/%.s: test/%.jazz $(ALL_JINC)
	$(JASMINC) $(JFLAGS) $< -o $@

# .s + .c → binary
test/%: test/%.c test/%.s
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(ASM) $(TESTS)
