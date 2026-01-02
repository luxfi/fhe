.PHONY: proto
proto:
	protoc -I ./proto --go_out=. --go-grpc_out=. ./proto/oracle/oracle.proto
	# rm the google api till we optimize the oracle proto generation in build.rs
	cd rust && cargo build --release --features="build_proto" && rm src/oracle/google.api.rs