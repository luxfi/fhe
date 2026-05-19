# Lux TFHE constant-time analysis harness -- dudect bridge.
#
# Builds the cgo shim libraries (libtfhe_encrypt, libtfhe_decrypt,
# libtfhe_bootstrap) and links the C dudect harnesses against them.
#
# Prereqs (run once):
#   ./fetch.sh           # pulls dudect.h at the pinned commit
#
# Build:
#   make                 # all three
#   make encrypt         # just encrypt
#   make decrypt         # just decrypt
#   make bootstrap       # just bootstrap
#
# Run:
#   ./dudect_encrypt     # smoke test (10000 samples/batch x 100 batches)
#   ./dudect_decrypt     # smoke test
#   ./dudect_bootstrap   # smoke test (2000 samples/batch x 50 batches)
#
# Full submission run (10^9 samples on a pinned-CPU quiet host):
#   DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_encrypt
#
# Hosts:
#   - x86_64 Linux/macOS: builds cleanly against upstream dudect.h
#   - aarch64 Linux/macOS: dudect_compat.h is force-included to supply
#     ARM equivalents of _mm_mfence() / __rdtsc(); see header for the
#     accuracy disclaimer.

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Shared-library extension is .dylib on macOS, .so elsewhere.
ifeq ($(UNAME_S),Darwin)
    SHLIB_EXT := dylib
    RPATH_FLAG := -Wl,-rpath,@loader_path
else
    SHLIB_EXT := so
    RPATH_FLAG := -Wl,-rpath,'$$ORIGIN'
endif

# Source paths.
REPO_ROOT := $(shell cd ../.. && pwd)
DUDECT_HDR := dudect/src/dudect.h

# C compile flags. -O2 is the default per dudect's own build; the
# leakage signal is preserved at -O2 because the inner do_one_computation
# call boundary is opaque to the compiler.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wno-unused-parameter -I. -Idudect/src
LDFLAGS ?=
LDLIBS  := -lm

# Force-include the ARM compat shim on AArch64 hosts so dudect.h's
# x86 intrinsics resolve. On x86 we skip the shim.
ifeq ($(UNAME_M),arm64)
    CFLAGS += -include dudect_compat.h
endif
ifeq ($(UNAME_M),aarch64)
    CFLAGS += -include dudect_compat.h
endif

# Go env. GOWORK=off matches scripts/test.sh -- this repo uses a
# single-module layout and a stray go.work in any parent confuses
# the toolchain.
GO     ?= go
GOENV  := GOWORK=off CGO_ENABLED=1

.PHONY: all encrypt decrypt bootstrap clean check-dudect

all: encrypt decrypt bootstrap

# Build the cgo shim into a host-platform shared library, then link
# the C harness against it.

libtfhe_encrypt.$(SHLIB_EXT): encrypt_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags tfhe_encrypt_ct \
		-o libtfhe_encrypt.$(SHLIB_EXT) \
		./encrypt_ct.go

libtfhe_decrypt.$(SHLIB_EXT): decrypt_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags tfhe_decrypt_ct \
		-o libtfhe_decrypt.$(SHLIB_EXT) \
		./decrypt_ct.go

libtfhe_bootstrap.$(SHLIB_EXT): bootstrap_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags tfhe_bootstrap_ct \
		-o libtfhe_bootstrap.$(SHLIB_EXT) \
		./bootstrap_ct.go

dudect_encrypt: dudect_encrypt.c libtfhe_encrypt.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_encrypt dudect_encrypt.c \
		-L. -ltfhe_encrypt $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

dudect_decrypt: dudect_decrypt.c libtfhe_decrypt.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_decrypt dudect_decrypt.c \
		-L. -ltfhe_decrypt $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

dudect_bootstrap: dudect_bootstrap.c libtfhe_bootstrap.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_bootstrap dudect_bootstrap.c \
		-L. -ltfhe_bootstrap $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

encrypt: dudect_encrypt
decrypt: dudect_decrypt
bootstrap: dudect_bootstrap

check-dudect:
	@if [ ! -f $(DUDECT_HDR) ]; then \
		echo "==> dudect.h missing -- run ./fetch.sh"; \
		exit 1; \
	fi

clean:
	rm -f dudect_encrypt dudect_decrypt dudect_bootstrap
	rm -f libtfhe_encrypt.$(SHLIB_EXT) libtfhe_encrypt.h
	rm -f libtfhe_decrypt.$(SHLIB_EXT) libtfhe_decrypt.h
	rm -f libtfhe_bootstrap.$(SHLIB_EXT) libtfhe_bootstrap.h
