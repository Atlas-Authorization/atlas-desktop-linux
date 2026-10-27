# pam_atlas.so for Linux-PAM and its tests.
#   make                 build build/pam_atlas.so
#   make test            unit tests of the conversation logic (no PAM, no root)
#   sudo make itest      integration test through the real PAM stack with a fake helper (writes /etc/pam.d)
CC     ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -fstack-protector-strong
LDFLAGS_SO ?= -Wl,-z,relro,-z,now
OUT    ?= build

all: $(OUT)/pam_atlas.so

$(OUT):
	mkdir -p $(OUT)

$(OUT)/pam_atlas.so: pam_atlas.c atlas_pam_core.c atlas_pam_core.h | $(OUT)
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS_SO) -o $@ pam_atlas.c atlas_pam_core.c -lpam

# The test module swaps the helper path check; it is never installed.
$(OUT)/pam_atlas_test.so: pam_atlas.c atlas_pam_core.c atlas_pam_core.h | $(OUT)
	$(CC) $(CFLAGS) -DATLAS_PAM_TESTING -DATLAS_BEGIN_TIMEOUT_MS=1500 -DATLAS_PUSH_TIMEOUT_MS=1500 -DATLAS_CODE_TIMEOUT_MS=1500 \
	  -fPIC -shared -o $@ pam_atlas.c atlas_pam_core.c -lpam

$(OUT)/pam_testpw.so: tests/pam_testpw.c | $(OUT)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ tests/pam_testpw.c -lpam

$(OUT)/core_test: tests/core_test.c atlas_pam_core.c atlas_pam_core.h | $(OUT)
	$(CC) $(CFLAGS) -I. -o $@ tests/core_test.c atlas_pam_core.c

$(OUT)/harness: tests/harness.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ tests/harness.c -lpam

test: $(OUT)/core_test
	$(OUT)/core_test

itest: $(OUT)/pam_atlas_test.so $(OUT)/pam_testpw.so $(OUT)/harness
	sh tests/itest.sh $(OUT)

clean:
	rm -rf $(OUT)

.PHONY: all test itest clean
