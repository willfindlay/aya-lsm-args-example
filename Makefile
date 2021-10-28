TARGET =./target/debug/lsm-args

.PHONY: build
build: $(TARGET)

.PHONY: run
run: build
	sudo ./target/debug/lsm-args

$(TARGET): $(wildcard **/*.rs)
	cargo xtask build-ebpf && cargo build
