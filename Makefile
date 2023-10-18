include ./Makefile.arch

all: build-ebpf generate build

build-ebpf:
	mkdir -p ebpf/assets/bin
	clang -D__KERNEL__ \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-D__TARGET_ARCH_$(SRCARCH) \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/$(SRCARCH)/include \
		-I/lib/modules/$$(uname -r)/build/arch/$(SRCARCH)/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/$(SRCARCH)/include/generated \
		-Iebpf/include \
		-c -O2 -g -target bpf \
		ebpf/main.c \
		-o ebpf/assets/bin/probes.o

generate:
	go generate ./...

build:
	mkdir -p bin/
	go build -ldflags="-s -w" -o bin/ ./cmd/...
	upx bin/imds_tracker

run:
	sudo ./bin/imds_tracker --log-level debug

install:
	sudo cp ./bin/imds-tracker /usr/bin/imds-tracker
