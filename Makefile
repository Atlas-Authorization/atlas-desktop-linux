# Atlas desktop MFA for Linux. CI is the only place this runs for real.
#   make all        module (pam/build/pam_atlas.so) + helper binaries (bin/)
#   make test       C unit tests + Go tests (race detector)
#   sudo make itest PAM integration test through the real stack with a fake helper
#   make scripts-test   install/uninstall script tests on a staged filesystem
GO ?= go

all: module bin

module:
	$(MAKE) -C pam

# Static binaries: the same file runs on glibc and musl (Alpine).
bin:
	mkdir -p bin
	cd helper && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o ../bin/atlas-pam-helper ./cmd/atlas-pam-helper
	cd helper && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o ../bin/atlas-sync ./cmd/atlas-sync
	cd helper && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o ../bin/atlas-enroll ./cmd/atlas-enroll

test:
	$(MAKE) -C pam test
	cd helper && $(GO) vet ./... && $(GO) test -race -count=1 ./...

itest: module
	$(MAKE) -C pam itest

scripts-test:
	bash pam/tests/install_test.sh

clean:
	rm -rf bin pam/build

.PHONY: all module bin test itest scripts-test clean
