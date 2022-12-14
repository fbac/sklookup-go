.PHONY: generate build-cli build-test run test stop bpftool clean clean-ebpf clean-linux
.DEFAULT_TARGET = run

# main
BIN_DIR=bin
BIN_NAME=sk
PID=$(pidof bin/sk_dispatch)

# export compiler and flags
CLANG := clang
CFLAGS := -g -O2 -Wall -Wextra $(CFLAGS)
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	cd pkg/ebpf && go generate -v ./...

build: generate
	@echo -e "# bin/sk build started"
	mkdir -p bin
	go build -o ${BIN_DIR}/${BIN_NAME} .

test-e2e: build
	@echo -e "\n# running e2e test"
	@./test/e2e.pre
	@./test/e2e.bats
	@./test/e2e.post

e2e: test-e2e clean

stop:
	@echo -e "\n# kill sk"
	@pkill ${BIN_NAME}

clean: stop
	@echo -e "# clean binaries"
	@rm ${BIN_DIR}/${BIN_NAME}
