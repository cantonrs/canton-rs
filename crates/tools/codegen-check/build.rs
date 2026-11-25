//! Generates the bindings of the codegen fixture DAR into `OUT_DIR` so that compiling this crate compiles them.
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let dar = root.join("tests/oracle/codegen/codegen-fixture.dar");
    println!("cargo:rerun-if-changed={}", dar.display());
    println!("cargo:rerun-if-changed=../../core/lf-eval/src/codegen.rs");
    let world = lf_eval::World::open(&dar).expect("the codegen fixture DAR opens");
    let generated = lf_eval::codegen::generate_rust(&world).expect("the bindings are generated");
    let out =
        PathBuf::from(std::env::var("OUT_DIR").expect("Cargo sets OUT_DIR for build scripts"))
            .join("bindings.rs");
    std::fs::write(out, generated.code).expect("write generated bindings.rs");
}
