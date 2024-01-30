RFLAGS="-C link-arg=-s"

build: build-contract

build-contract:
	rustup target add wasm32-unknown-unknown
	RUSTFLAGS=$(RFLAGS) cargo build --target wasm32-unknown-unknown --release
	mkdir -p res
	cp target/wasm32-unknown-unknown/release/contract.wasm ./res/contract.wasm

	