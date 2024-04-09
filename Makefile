CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror -I /usr/include/aarch64-linux-gnu $(CFLAGS)

.PHONY: generate compile build build-docker test test-docker

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./internal/generated...

compile:
	go build -o build/durdur ./cmd/durdur

build: generate compile

build-docker:
	docker build -t durdur -f images/Dockerfile .

clean:
	rm -rf internal/generated/*bpf_bpfe*.go
	rm -rf internal/generated/*bpf_bpfe*.o

load-xdp:
	ip link set dev eth0 xdp obj internal/generated/xdpbpf_bpfel.o sec xdp_durdur_drop

unload-xdp:
	ip link set dev eth0 xdp off

status-xdp:
	ip link |grep xdp

load-tc:
	tc qdisc add dev eth0 clsact
# tc qdisc add dev [network-device] clsact
load-tc: reload-tc
reload-tc:
	tc filter add dev eth0 egress bpf da obj internal/generated/tcbpf_bpfel.o sec tc_durdur_drop

status-tc:
	tc filter show dev eth0 egress

unload-tc:
	tc filter del dev eth0 egress

test:
	go test ./... -v -cover -race

test-docker:
	docker build -t durdur-test -q -f images/Dockerfile.tests . && \
	docker run --rm --privileged -v /sys/fs/bpf:/sys/fs/bpf durdur-test
