.PHONY: generate build-cli build-test run test stop bpftool clean clean-ebpf clean-linux
.DEFAULT_TARGET = run

# main
BIN_DIR=bin
BIN_NAME=sk
BIN_NAME_TEST=sk-t
PID=$(pidof bin/sk_dispatch)

# allow external CFLAGS
CC := clang
CFLAGS := -g -O2 -Wall -Wextra $(CFLAGS)

generate:
	@echo -e "# generate assets"
	go generate ./...

#test-go: generate
#	@echo -e "\n# executing test-target.sh"
#	@./test-target.sh

build-cli:
	@echo -e "# sklook build started"
	mkdir -p bin
	go build -o ${BIN_DIR}/${BIN_NAME} .

build-test: generate
	@echo -e "# sklook-test build started"
	mkdir -p bin
	go build -o ${BIN_DIR}/${BIN_NAME_TEST} test/*.go

run: build-test
	@echo -e "\n# running sklook"
	${BIN_DIR}/${BIN_NAME_TEST} &

#test-bin: run
#	@echo -e "\n# executing test-target.sh"
#	@./test-target.sh

stop:
	@echo -e "\n# kill sklook-t"
	@pkill ${BIN_NAME_TEST}

clean:
	@echo -e "# clean binaries"
	@rm ${BIN_DIR}/${BIN_NAME}
	@rm ${BIN_DIR}/${BIN_NAME_TEST}

#all: test stop clean
#	@echo -e "# all done"
