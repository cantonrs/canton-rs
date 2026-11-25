//! The bindings generated from `tests/oracle/codegen/codegen-fixture.dar`, compiled. If the generator writes Rust that does not compile
//! (a reserved word, a recursive type without a box, a wrong path), this crate does not build.
#[allow(
    dead_code,
    non_camel_case_types,
    clippy::all,
    clippy::allow_attributes_without_reason,
    reason = "generated Rust fixture bindings compiled solely for codegen validation"
)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
