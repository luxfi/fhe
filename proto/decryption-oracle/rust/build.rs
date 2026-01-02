fn main() {
    #[cfg(not(feature = "build_proto"))]
    {
        return;
    }

    // let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_dir = "./src/oracle";
    tonic_build::configure()
        .file_descriptor_set_path("oracle.bin")
        .out_dir(out_dir)
        .compile(&["oracle/oracle.proto"], &["../proto"])
        .unwrap();

    // tonic_build::configure()
    //     .server_mod_attribute("attrs", "#[cfg(feature = \"server\")]")
    //     .server_attribute("Echo", "#[derive(PartialEq)]")
    //     .client_mod_attribute("attrs", "#[cfg(feature = \"client\")]")
    //     .client_attribute("Echo", "#[derive(PartialEq)]")
    //     .compile(&["proto/attrs/attrs.proto"], &["proto"])
    //     .unwrap();

    // tonic_build::configure()
    //     .build_server(false)
    //     .compile(
    //         &["proto/googleapis/google/pubsub/v1/pubsub.proto"],
    //         &["proto/googleapis"],
    //     )
    //     .unwrap();

    build_json_codec_service();
}

// Manually define the json.oracle.DecryptionOracle service which used a custom JsonCodec to use json
// serialization instead of protobuf for sending messages on the wire.
// This will result in generated client and server code which relies on its request, response and
// codec types being defined in a module `crate::common`.
//
// See the client/server examples defined in `src/json-codec` for more information.
fn build_json_codec_service() {
    let oracle_service = tonic_build::manual::Service::builder()
        .name("DecryptionOracle")
        .package("json.oracle")
        .method(
            tonic_build::manual::Method::builder()
                .name("decrypt")
                .route_name("Decrypt")
                .input_type("crate::common::DecryptRequest")
                .output_type("crate::common::DecryptResponse")
                .codec_path("crate::common::JsonCodec")
                .build(),
        )
        .build();

    tonic_build::manual::Builder::new().compile(&[oracle_service]);
}
