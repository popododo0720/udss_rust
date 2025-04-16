use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=filter.c");

    let clang_args = vec![
        "-O2", "-g", "-target", "bpf",
        "-c", "src/eBPF/filter.c",
        "-o", "src/eBPF/filter.o"
    ];

    let output = Command::new("clang")
        .args(&clang_args)
        .output()
        .expect("Failed to compile filter.c");

    if !output.status.success() {
        panic!(
            "Failed to build filter.c: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
