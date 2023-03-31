use std::path::PathBuf;

const SRC: &str = "src/bpf/prog.bpf.c";
const SRC_H: &str = "src/bpf/prog.bpf.h";

fn main() {
    let mut out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    out_dir.push("prog.bpf.rs");
    
    libbpf_cargo::SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(out_dir)
        .unwrap();

    bindgen::Builder::default()
        .header(SRC_H)
        .allowlist_type("per_cpu_data")
        .generate()
        .unwrap()
        .write_to_file("src/common.rs")
        .unwrap();

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed={SRC_H}");
    println!("cargo:rerun-if-changed=src/bpf/event_stack.bpf.h");
}